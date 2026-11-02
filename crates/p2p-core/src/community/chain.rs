//! Cadeia de configuração do servidor.
//!
//! Só a chave do servidor escreve blocos, então não há mineração nem consenso: é uma cadeia de
//! hashes assinada (como o histórico do Git). Cada bloco aponta para o hash do anterior e traz
//! a data UTC do dono. Todos os membros guardam a cadeia e calculam o mesmo estado a partir dela.
//!
//! Regras principais:
//! - **A ordem que vale é a da cadeia**, não as datas declaradas. Uma ação de moderador só tem
//!   efeito definitivo se entrar na cadeia enquanto o certificado dele é válido; se a revogação
//!   entrou antes, a ação é descartada por todos.
//! - **Níveis**: 0 é o dono; certificados têm nível 1 ou mais (número maior = menos autoridade).
//!   Só se age sobre quem tem nível maior, e só se desfaz ban de quem tem nível igual ou maior.
//! - **Fork** (dois blocos diferentes na mesma altura, ex.: chave do dono usada em dois lugares):
//!   vence o de menor hash, de forma determinística, e os membros convergem.

use super::cert::{ModAction, ModKind, ModeratorCert, UtcSecs};
use crate::identity::{verify_signature_hex, UserIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Tolerância para relógios adiantados (ações datadas mais no futuro que isso são recusadas)
pub const CLOCK_SKEW_SECS: u64 = 300;
/// Validade padrão dos certificados de moderador
pub const DEFAULT_CERT_VALIDITY_SECS: u64 = 7 * 86_400;
/// Janela de renovação padrão (antes de expirar)
pub const DEFAULT_RENEWAL_WINDOW_SECS: u64 = 2 * 86_400;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelType {
    Text,
    Voice,
    ScreenShare,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Channel {
    pub name: String,
    pub channel_type: ChannelType,
}

/// Alterações registradas num bloco
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Entry {
    /// Primeiro bloco: configuração inicial. `owner` é a identidade pessoal do dono (nível 0, como a
    /// chave do servidor), para que ele não seja tratado como membro comum no chat.
    Genesis {
        name: String,
        owner: String,
        channels: Vec<Channel>,
        closed: bool,
        cert_validity_secs: u64,
        renewal_window_secs: u64,
    },
    /// Transfere a posse para outra identidade pessoal
    SetOwner(String),
    SetName(String),
    AddChannel(Channel),
    RemoveChannel(String),
    SetClosed(bool),
    SetCertPolicy { validity_secs: u64, renewal_window_secs: u64 },
    AllowAdd(String),
    AllowRemove(String),
    IssueCert(ModeratorCert),
    RevokeCert { serial: String },
    /// Ban aplicado pelo dono (nível 0)
    Ban { target: String, until: Option<UtcSecs>, reason: String },
    Unban { target: String },
    /// Consolidação: ação de moderador que passa a fazer parte da cadeia
    IncludeModAction(ModAction),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BlockBody {
    pub server_id: String,
    pub height: u64,
    /// Hash do bloco anterior (vazio no bloco 0)
    pub prev_hash: String,
    /// Data UTC do dono ao criar o bloco
    pub timestamp: UtcSecs,
    pub entries: Vec<Entry>,
}

/// Bloco da cadeia, assinado pela chave do servidor
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Block {
    pub body: BlockBody,
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

impl Block {
    /// Cria o bloco seguinte a `prev` (ou o bloco 0)
    pub fn create(server_key: &UserIdentity, prev: Option<&Block>, timestamp: UtcSecs, entries: Vec<Entry>) -> Self {
        let body = BlockBody {
            server_id: server_key.public_key_hex(),
            height: prev.map_or(0, |p| p.body.height + 1),
            prev_hash: prev.map(Block::hash).unwrap_or_default(),
            timestamp,
            entries,
        };
        let signature = server_key.sign(&serde_json::to_vec(&body).expect("bloco serializável"));
        Self { body, signature }
    }

    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_vec(&self.body).unwrap_or_default());
        hasher.update(&self.signature);
        hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn verify_signature(&self, server_id: &str) -> bool {
        self.body.server_id == server_id
            && serde_json::to_vec(&self.body).is_ok_and(|bytes| verify_signature_hex(server_id, &bytes, &self.signature))
    }
}

/// Ban em vigor
#[derive(Clone, Debug, PartialEq)]
pub struct BanState {
    pub until: Option<UtcSecs>,
    pub reason: String,
    /// Pubkey de quem baniu (a do servidor, se foi o dono)
    pub by: String,
    pub by_level: u8,
    pub at: UtcSecs,
}

/// Por que uma ação de moderador foi recusada
#[derive(Debug, Clone, PartialEq)]
pub enum Rejection {
    BadSignature,
    CertRevoked,
    CertExpired,
    MissingPermission,
    FromTheFuture,
    TargetOutranks,
    BanFromHigherLevel,
    AlreadyApplied,
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Rejection::BadSignature => "assinatura ou certificado inválido",
            Rejection::CertRevoked => "certificado revogado",
            Rejection::CertExpired => "certificado fora da validade",
            Rejection::MissingPermission => "o certificado não dá essa permissão",
            Rejection::FromTheFuture => "ação datada no futuro",
            Rejection::TargetOutranks => "o alvo tem nível igual ou superior",
            Rejection::BanFromHigherLevel => "existe um ban de nível superior para esse alvo",
            Rejection::AlreadyApplied => "ação já aplicada",
        })
    }
}

/// Estado do servidor calculado a partir da cadeia
#[derive(Clone, Debug, Default)]
pub struct ServerState {
    pub server_id: String,
    /// Identidade pessoal do dono (nível 0)
    pub owner: String,
    pub name: String,
    pub channels: Vec<Channel>,
    pub closed: bool,
    pub cert_validity_secs: u64,
    pub renewal_window_secs: u64,
    pub allow_list: BTreeSet<String>,
    /// Certificados emitidos (por serial), inclusive os já revogados
    pub certs: BTreeMap<String, ModeratorCert>,
    pub revoked: BTreeSet<String>,
    pub bans: BTreeMap<String, BanState>,
    pub applied_actions: BTreeSet<String>,
}

impl ServerState {
    fn new(server_id: &str) -> Self {
        Self { server_id: server_id.to_string(), ..Self::default() }
    }

    /// Aplica um bloco. As entradas usam a data do bloco como "agora".
    fn apply_block(&mut self, block: &Block) {
        let at = block.body.timestamp;
        for entry in &block.body.entries {
            match entry {
                Entry::Genesis { name, owner, channels, closed, cert_validity_secs, renewal_window_secs } => {
                    self.owner = owner.clone();
                    self.name = name.clone();
                    self.channels = channels.clone();
                    self.closed = *closed;
                    self.cert_validity_secs = *cert_validity_secs;
                    self.renewal_window_secs = *renewal_window_secs;
                }
                Entry::SetOwner(owner) => self.owner = owner.clone(),
                Entry::SetName(name) => self.name = name.clone(),
                Entry::AddChannel(channel) => {
                    if !self.channels.iter().any(|c| c.name == channel.name) {
                        self.channels.push(channel.clone());
                    }
                }
                Entry::RemoveChannel(name) => self.channels.retain(|c| &c.name != name),
                Entry::SetClosed(closed) => self.closed = *closed,
                Entry::SetCertPolicy { validity_secs, renewal_window_secs } => {
                    self.cert_validity_secs = *validity_secs;
                    self.renewal_window_secs = (*renewal_window_secs).min(*validity_secs);
                }
                Entry::AllowAdd(pubkey) => {
                    self.allow_list.insert(pubkey.clone());
                }
                Entry::AllowRemove(pubkey) => {
                    self.allow_list.remove(pubkey);
                }
                Entry::IssueCert(cert) => {
                    if cert.verify(&self.server_id) {
                        self.certs.insert(cert.body.serial.clone(), cert.clone());
                    }
                }
                Entry::RevokeCert { serial } => {
                    self.revoked.insert(serial.clone());
                }
                Entry::Ban { target, until, reason } => {
                    if target != &self.server_id && target != &self.owner {
                        let ban =
                            BanState { until: *until, reason: reason.clone(), by: self.server_id.clone(), by_level: 0, at };
                        self.bans.insert(target.clone(), ban);
                    }
                }
                Entry::Unban { target } => {
                    self.bans.remove(target);
                }
                Entry::IncludeModAction(action) => {
                    // Recusas não invalidam o bloco: a ação simplesmente não tem efeito
                    let _ = self.apply_mod_action(action, at);
                }
            }
        }
    }

    /// Aplica uma ação de moderador avaliada no instante `at` (data do bloco que a inclui, ou
    /// "agora" para ações ainda provisórias), seguindo as regras de certificado e de nível.
    pub fn apply_mod_action(&mut self, action: &ModAction, at: UtcSecs) -> Result<(), Rejection> {
        self.check_mod_action(action, at)?;
        let body = &action.body;
        match &body.kind {
            ModKind::Ban { until } => {
                let ban = BanState {
                    until: *until,
                    reason: body.reason.clone(),
                    by: action.actor().to_string(),
                    by_level: action.cert.body.level,
                    at: body.created_at,
                };
                self.bans.insert(body.target.clone(), ban);
            }
            ModKind::Unban => {
                self.bans.remove(&body.target);
            }
            ModKind::Admit => {
                self.allow_list.insert(body.target.clone());
            }
            ModKind::Unadmit => {
                self.allow_list.remove(&body.target);
            }
        }
        self.applied_actions.insert(action.id());
        Ok(())
    }

    /// Valida uma ação sem aplicá-la
    pub fn check_mod_action(&self, action: &ModAction, at: UtcSecs) -> Result<(), Rejection> {
        if self.applied_actions.contains(&action.id()) {
            return Err(Rejection::AlreadyApplied);
        }
        if !action.verify_signatures(&self.server_id) {
            return Err(Rejection::BadSignature);
        }
        let cert = &action.cert;
        if self.revoked.contains(&cert.body.serial) {
            return Err(Rejection::CertRevoked);
        }
        if !cert.valid_at(at) {
            return Err(Rejection::CertExpired);
        }
        if !cert.allows(action.body.kind.permission()) {
            return Err(Rejection::MissingPermission);
        }
        if action.body.created_at > at + CLOCK_SKEW_SECS {
            return Err(Rejection::FromTheFuture);
        }
        let level = cert.body.level;
        if self.level_of(&action.body.target, at).is_some_and(|target_level| target_level <= level) {
            return Err(Rejection::TargetOutranks);
        }
        if matches!(action.body.kind, ModKind::Ban { .. } | ModKind::Unban)
            && self.bans.get(&action.body.target).is_some_and(|ban| ban.by_level < level)
        {
            return Err(Rejection::BanFromHigherLevel);
        }
        Ok(())
    }

    /// Certificados ativos em `at` (válidos e não revogados)
    pub fn active_certs(&self, at: UtcSecs) -> impl Iterator<Item = &ModeratorCert> {
        self.certs.values().filter(move |c| !self.revoked.contains(&c.body.serial) && c.valid_at(at))
    }

    /// Nível de autoridade: 0 para o dono, o menor nível entre os certificados ativos, ou None (membro)
    pub fn level_of(&self, pubkey: &str, at: UtcSecs) -> Option<u8> {
        if pubkey == self.server_id || (!self.owner.is_empty() && pubkey == self.owner) {
            return Some(0);
        }
        self.active_certs(at).filter(|c| c.body.subject == pubkey).map(|c| c.body.level).min()
    }

    /// Certificado ativo de mais autoridade de uma pubkey
    pub fn best_cert(&self, pubkey: &str, at: UtcSecs) -> Option<&ModeratorCert> {
        self.active_certs(at).filter(|c| c.body.subject == pubkey).min_by_key(|c| (c.body.level, u64::MAX - c.body.expires_at))
    }

    /// Moderadores ativos: (pubkey, nível, expira em)
    pub fn moderators(&self, at: UtcSecs) -> Vec<(String, u8, UtcSecs)> {
        let mut by_subject: BTreeMap<String, (u8, UtcSecs)> = BTreeMap::new();
        for cert in self.active_certs(at) {
            let entry = by_subject.entry(cert.body.subject.clone()).or_insert((cert.body.level, cert.body.expires_at));
            entry.0 = entry.0.min(cert.body.level);
            entry.1 = entry.1.max(cert.body.expires_at);
        }
        by_subject.into_iter().map(|(pk, (level, exp))| (pk, level, exp)).collect()
    }

    /// Ban em vigor em `at` (bans com prazo expiram sozinhos)
    pub fn is_banned(&self, pubkey: &str, at: UtcSecs) -> bool {
        self.bans.get(pubkey).is_some_and(|b| b.until.map_or(true, |until| at < until))
    }

    pub fn active_bans(&self, at: UtcSecs) -> Vec<(&String, &BanState)> {
        self.bans.iter().filter(|(pk, _)| self.is_banned(pk, at)).collect()
    }

    /// Pode participar: servidor aberto, ou dono, moderador ativo ou na allow-list
    pub fn is_allowed(&self, pubkey: &str, at: UtcSecs) -> bool {
        !self.closed || self.allow_list.contains(pubkey) || self.level_of(pubkey, at).is_some()
    }

    /// Certificados que entraram na janela de renovação e ainda não têm sucessor mais longo
    pub fn certs_due_for_renewal(&self, at: UtcSecs) -> Vec<&ModeratorCert> {
        let latest: BTreeMap<&str, UtcSecs> = self.active_certs(at).fold(BTreeMap::new(), |mut acc, c| {
            let e = acc.entry(c.body.subject.as_str()).or_insert(0);
            *e = (*e).max(c.body.expires_at);
            acc
        });
        self.active_certs(at)
            .filter(|c| c.body.expires_at.saturating_sub(at) <= self.renewal_window_secs)
            .filter(|c| latest.get(c.body.subject.as_str()) == Some(&c.body.expires_at))
            .collect()
    }
}

/// Resultado de tentar acrescentar um bloco recebido
#[derive(Debug, PartialEq)]
pub enum AppendResult {
    Appended,
    Duplicate,
    /// Faltam blocos antes deste: pedir a partir de `need_from`
    Gap { need_from: u64 },
    /// Bloco diferente na mesma altura; `replaced` = o novo venceu (menor hash) e a cadeia foi trocada
    Fork { height: u64, replaced: bool },
    Invalid(&'static str),
}

/// Cadeia de um servidor e o estado calculado a partir dela
#[derive(Clone, Debug)]
pub struct ServerChain {
    server_id: String,
    blocks: Vec<Block>,
    state: ServerState,
}

impl ServerChain {
    pub fn new(server_id: &str) -> Self {
        Self { server_id: server_id.to_string(), blocks: Vec::new(), state: ServerState::new(server_id) }
    }

    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    pub fn head(&self) -> Option<&Block> {
        self.blocks.last()
    }

    pub fn state(&self) -> &ServerState {
        &self.state
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Acrescenta o próximo bloco criado pelo dono e devolve uma cópia para publicar
    pub fn append_own(&mut self, server_key: &UserIdentity, timestamp: UtcSecs, entries: Vec<Entry>) -> Block {
        // A data de um bloco nunca é anterior à do anterior (relógio do dono atrasado)
        let timestamp = timestamp.max(self.head().map_or(0, |h| h.body.timestamp));
        let block = Block::create(server_key, self.head(), timestamp, entries);
        let result = self.try_append(block.clone());
        debug_assert_eq!(result, AppendResult::Appended);
        block
    }

    /// Valida e acrescenta um bloco recebido da rede
    pub fn try_append(&mut self, block: Block) -> AppendResult {
        if !block.verify_signature(&self.server_id) {
            return AppendResult::Invalid("assinatura do bloco inválida");
        }
        let height = block.body.height;
        let len = self.blocks.len() as u64;
        if height > len {
            return AppendResult::Gap { need_from: len };
        }
        let expected_prev = if height == 0 { String::new() } else { self.blocks[(height - 1) as usize].hash() };
        if block.body.prev_hash != expected_prev {
            return AppendResult::Invalid("bloco não encadeia com o anterior");
        }
        if height == 0 && !matches!(block.body.entries.first(), Some(Entry::Genesis { .. })) {
            return AppendResult::Invalid("bloco 0 sem configuração inicial");
        }
        if height < len {
            let current = &self.blocks[height as usize];
            if current.hash() == block.hash() {
                return AppendResult::Duplicate;
            }
            // Fork: vence o menor hash, para todos os membros escolherem o mesmo ramo
            if block.hash() < current.hash() {
                self.blocks.truncate(height as usize);
                self.blocks.push(block);
                self.rebuild_state();
                return AppendResult::Fork { height, replaced: true };
            }
            return AppendResult::Fork { height, replaced: false };
        }
        self.state.apply_block(&block);
        self.blocks.push(block);
        AppendResult::Appended
    }

    fn rebuild_state(&mut self) {
        let mut state = ServerState::new(&self.server_id);
        for block in &self.blocks {
            state.apply_block(block);
        }
        self.state = state;
    }
}

#[cfg(test)]
mod tests {
    use super::super::cert::{default_permissions, Permission};
    use super::*;

    const DAY: u64 = 86_400;
    const T0: u64 = 1_800_000_000;
    /// Identidade pessoal do dono (diferente da chave do servidor)
    const OWNER_PERSONAL: &str = "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d";

    struct Setup {
        owner: UserIdentity,
        chain: ServerChain,
    }

    impl Setup {
        fn new() -> Self {
            let owner = UserIdentity::generate();
            let mut chain = ServerChain::new(&owner.public_key_hex());
            chain.append_own(&owner, T0, vec![genesis(false)]);
            Self { owner, chain }
        }

        fn append(&mut self, at: u64, entries: Vec<Entry>) -> Block {
            self.chain.append_own(&self.owner, at, entries)
        }

        fn certify(&mut self, who: &UserIdentity, level: u8, at: u64) -> ModeratorCert {
            let cert = ModeratorCert::issue(&self.owner, &who.public_key_hex(), level, default_permissions(), at, 7 * DAY);
            self.append(at, vec![Entry::IssueCert(cert.clone())]);
            cert
        }

        fn state(&self) -> &ServerState {
            self.chain.state()
        }
    }

    fn genesis(closed: bool) -> Entry {
        Entry::Genesis {
            name: "Rust Guild".into(),
            owner: OWNER_PERSONAL.into(),
            channels: vec![Channel { name: "geral".into(), channel_type: ChannelType::Text }],
            closed,
            cert_validity_secs: 7 * DAY,
            renewal_window_secs: 2 * DAY,
        }
    }

    fn ban(by: &UserIdentity, cert: &ModeratorCert, target: &str, at: u64) -> ModAction {
        ModAction::create(by, cert, ModKind::Ban { until: None }, target, "spam", at)
    }

    fn pk(id: &UserIdentity) -> String {
        id.public_key_hex()
    }

    #[test]
    fn test_chain_links_and_verifies_blocks() {
        let mut s = Setup::new();
        s.append(T0 + 10, vec![Entry::AddChannel(Channel { name: "jogos".into(), channel_type: ChannelType::Text })]);
        assert_eq!(s.chain.blocks().len(), 2);
        assert_eq!(s.chain.blocks()[1].body.prev_hash, s.chain.blocks()[0].hash());
        assert_eq!(s.state().name, "Rust Guild");
        assert_eq!(s.state().channels.len(), 2);

        // Outro membro reconstrói o mesmo estado a partir dos blocos
        let mut copy = ServerChain::new(&pk(&s.owner));
        for b in s.chain.blocks() {
            assert_eq!(copy.try_append(b.clone()), AppendResult::Appended);
        }
        assert_eq!(copy.state().channels, s.state().channels);
        assert_eq!(copy.try_append(s.chain.blocks()[1].clone()), AppendResult::Duplicate);
    }

    #[test]
    fn test_rejects_forged_unlinked_and_gapped_blocks() {
        let s = Setup::new();
        let attacker = UserIdentity::generate();
        let mut member = ServerChain::new(&pk(&s.owner));

        let forged = Block::create(&attacker, None, T0, vec![genesis(false)]);
        assert!(matches!(member.try_append(forged), AppendResult::Invalid(_)), "assinado por outra chave");

        member.try_append(s.chain.blocks()[0].clone());
        let unlinked = Block::create(&s.owner, None, T0, vec![genesis(true)]); // altura 0 de novo, outro conteúdo
        let mut wrong_prev = Block::create(&s.owner, Some(&unlinked), T0 + 1, vec![Entry::SetClosed(true)]);
        wrong_prev.body.height = 1;
        assert!(matches!(member.try_append(wrong_prev), AppendResult::Invalid(_)));

        let far = Block::create(&s.owner, Some(&s.chain.blocks()[0]), T0, vec![]);
        let mut far = far;
        far.body.height = 5;
        // A assinatura cobre a altura: altura alterada invalida
        assert!(matches!(member.try_append(far), AppendResult::Invalid(_)));

        let mut full = s.chain.clone();
        let b1 = full.append_own(&s.owner, T0 + 1, vec![]);
        let b2 = full.append_own(&s.owner, T0 + 2, vec![]);
        let _ = b1;
        assert_eq!(member.try_append(b2), AppendResult::Gap { need_from: 1 });
    }

    #[test]
    fn test_fork_resolves_to_lowest_hash_on_every_member() {
        let s = Setup::new();
        let genesis_block = s.chain.blocks()[0].clone();
        let a = Block::create(&s.owner, Some(&genesis_block), T0 + 5, vec![Entry::SetName("A".into())]);
        let b = Block::create(&s.owner, Some(&genesis_block), T0 + 5, vec![Entry::SetName("B".into())]);
        let winner = if a.hash() < b.hash() { "A" } else { "B" };

        let mut m1 = ServerChain::new(&pk(&s.owner));
        let mut m2 = ServerChain::new(&pk(&s.owner));
        for m in [&mut m1, &mut m2] {
            m.try_append(genesis_block.clone());
        }
        m1.try_append(a.clone());
        m1.try_append(b.clone());
        m2.try_append(b);
        m2.try_append(a);
        assert_eq!(m1.state().name, winner);
        assert_eq!(m2.state().name, winner, "ordem de chegada não importa");
    }

    #[test]
    fn test_moderator_ban_is_applied_when_included() {
        let mut s = Setup::new();
        let moderator = UserIdentity::generate();
        let spammer = UserIdentity::generate();
        let cert = s.certify(&moderator, 1, T0 + 10);
        s.append(T0 + 20, vec![Entry::IncludeModAction(ban(&moderator, &cert, &pk(&spammer), T0 + 15))]);
        assert!(s.state().is_banned(&pk(&spammer), T0 + 30));
        assert_eq!(s.state().bans[&pk(&spammer)].by_level, 1);
    }

    /// Regra central: ação incluída depois da revogação é desfeita, mesmo que a data declarada
    /// pelo moderador seja anterior à revogação (backdating).
    #[test]
    fn test_actions_included_after_revocation_have_no_effect() {
        let mut s = Setup::new();
        let rogue = UserIdentity::generate();
        let early = UserIdentity::generate();
        let late = UserIdentity::generate();
        let cert = s.certify(&rogue, 1, T0 + 10);

        s.append(T0 + 20, vec![Entry::IncludeModAction(ban(&rogue, &cert, &pk(&early), T0 + 15))]);
        s.append(T0 + 30, vec![Entry::RevokeCert { serial: cert.body.serial.clone() }]);
        // Datada antes da revogação, mas entra na cadeia depois dela
        s.append(T0 + 40, vec![Entry::IncludeModAction(ban(&rogue, &cert, &pk(&late), T0 + 16))]);

        assert!(s.state().is_banned(&pk(&early), T0 + 50), "incluída antes da revogação: continua");
        assert!(!s.state().is_banned(&pk(&late), T0 + 50), "incluída depois da revogação: sem efeito");
        assert_eq!(s.state().level_of(&pk(&rogue), T0 + 50), None);
    }

    #[test]
    fn test_level_rules() {
        let mut s = Setup::new();
        let senior = UserIdentity::generate();
        let peer = UserIdentity::generate();
        let junior = UserIdentity::generate();
        let member = UserIdentity::generate();
        let c_senior = s.certify(&senior, 1, T0 + 1);
        let c_peer = s.certify(&peer, 1, T0 + 1);
        let c_junior = s.certify(&junior, 2, T0 + 1);
        let state = s.state().clone();
        let at = T0 + 100;

        assert_eq!(state.level_of(&pk(&s.owner), at), Some(0));
        assert_eq!(state.level_of(&pk(&junior), at), Some(2));
        assert_eq!(state.level_of(&pk(&member), at), None);

        assert_eq!(state.check_mod_action(&ban(&senior, &c_senior, &pk(&junior), at), at), Ok(()), "1 age sobre 2");
        assert_eq!(state.check_mod_action(&ban(&senior, &c_senior, &pk(&member), at), at), Ok(()));
        assert_eq!(state.check_mod_action(&ban(&senior, &c_senior, &pk(&peer), at), at), Err(Rejection::TargetOutranks), "mesmo nível");
        assert_eq!(state.check_mod_action(&ban(&junior, &c_junior, &pk(&senior), at), at), Err(Rejection::TargetOutranks));
        assert_eq!(state.check_mod_action(&ban(&senior, &c_senior, &pk(&s.owner), at), at), Err(Rejection::TargetOutranks), "ninguém age sobre o dono");
        let _ = c_peer;
    }

    /// O dono conversa com a identidade pessoal: ela também é nível 0
    #[test]
    fn test_owner_personal_identity_is_level_zero() {
        let mut s = Setup::new();
        let moderator = UserIdentity::generate();
        let cert = s.certify(&moderator, 1, T0);
        assert_eq!(s.state().level_of(OWNER_PERSONAL, T0 + 1), Some(0));
        assert_eq!(s.state().check_mod_action(&ban(&moderator, &cert, OWNER_PERSONAL, T0 + 1), T0 + 1), Err(Rejection::TargetOutranks));

        let new_owner = UserIdentity::generate();
        s.append(T0 + 2, vec![Entry::SetOwner(pk(&new_owner))]);
        assert_eq!(s.state().level_of(&pk(&new_owner), T0 + 3), Some(0), "posse transferida");
        assert_eq!(s.state().level_of(OWNER_PERSONAL, T0 + 3), None);
    }

    #[test]
    fn test_cannot_undo_ban_from_higher_authority() {
        let mut s = Setup::new();
        let moderator = UserIdentity::generate();
        let junior = UserIdentity::generate();
        let target = UserIdentity::generate();
        let cert = s.certify(&moderator, 1, T0 + 1);
        let c_junior = s.certify(&junior, 2, T0 + 1);

        s.append(T0 + 10, vec![Entry::Ban { target: pk(&target), until: None, reason: "dono".into() }]);
        let unban = ModAction::create(&moderator, &cert, ModKind::Unban, &pk(&target), "", T0 + 20);
        assert_eq!(s.state().check_mod_action(&unban, T0 + 20), Err(Rejection::BanFromHigherLevel), "ban do dono");

        s.append(T0 + 30, vec![Entry::Unban { target: pk(&target) }]);
        s.append(T0 + 40, vec![Entry::IncludeModAction(ban(&moderator, &cert, &pk(&target), T0 + 35))]);
        let junior_unban = ModAction::create(&junior, &c_junior, ModKind::Unban, &pk(&target), "", T0 + 50);
        assert_eq!(s.state().check_mod_action(&junior_unban, T0 + 50), Err(Rejection::BanFromHigherLevel), "nível 2 não desfaz nível 1");
        let same_level_unban = ModAction::create(&moderator, &cert, ModKind::Unban, &pk(&target), "", T0 + 50);
        assert_eq!(s.state().check_mod_action(&same_level_unban, T0 + 50), Ok(()));
    }

    #[test]
    fn test_temporary_ban_expires() {
        let mut s = Setup::new();
        let target = UserIdentity::generate();
        s.append(T0 + 10, vec![Entry::Ban { target: pk(&target), until: Some(T0 + 3600), reason: "1h".into() }]);
        assert!(s.state().is_banned(&pk(&target), T0 + 3599));
        assert!(!s.state().is_banned(&pk(&target), T0 + 3600));
        assert!(s.state().active_bans(T0 + 4000).is_empty());
    }

    #[test]
    fn test_expired_cert_missing_permission_and_future_actions_are_rejected() {
        let mut s = Setup::new();
        let moderator = UserIdentity::generate();
        let target = pk(&UserIdentity::generate());
        let cert = s.certify(&moderator, 1, T0);

        let after_expiry = T0 + 7 * DAY + 1;
        assert_eq!(s.state().check_mod_action(&ban(&moderator, &cert, &target, after_expiry), after_expiry), Err(Rejection::CertExpired));

        let future = ban(&moderator, &cert, &target, T0 + 10 + CLOCK_SKEW_SECS + 60);
        assert_eq!(s.state().check_mod_action(&future, T0 + 10), Err(Rejection::FromTheFuture));

        let admit_only = ModeratorCert::issue(&s.owner, &pk(&moderator), 1, vec![Permission::Admit], T0, DAY);
        s.append(T0 + 1, vec![Entry::IssueCert(admit_only.clone())]);
        assert_eq!(s.state().check_mod_action(&ban(&moderator, &admit_only, &target, T0 + 5), T0 + 5), Err(Rejection::MissingPermission));
    }

    #[test]
    fn test_same_action_is_not_applied_twice() {
        let mut s = Setup::new();
        let moderator = UserIdentity::generate();
        let cert = s.certify(&moderator, 1, T0);
        let action = ban(&moderator, &cert, &pk(&UserIdentity::generate()), T0 + 5);
        s.append(T0 + 10, vec![Entry::IncludeModAction(action.clone())]);
        assert_eq!(s.state().check_mod_action(&action, T0 + 20), Err(Rejection::AlreadyApplied));
    }

    #[test]
    fn test_closed_server_allow_list() {
        let owner = UserIdentity::generate();
        let mut chain = ServerChain::new(&pk(&owner));
        chain.append_own(&owner, T0, vec![genesis(true)]);
        let guest = UserIdentity::generate();
        let moderator = UserIdentity::generate();

        assert!(chain.state().is_allowed(&pk(&owner), T0));
        assert!(!chain.state().is_allowed(&pk(&guest), T0));
        chain.append_own(&owner, T0 + 1, vec![Entry::AllowAdd(pk(&guest))]);
        assert!(chain.state().is_allowed(&pk(&guest), T0 + 2));

        let cert = ModeratorCert::issue(&owner, &pk(&moderator), 1, default_permissions(), T0, DAY);
        chain.append_own(&owner, T0 + 2, vec![Entry::IssueCert(cert), Entry::AllowRemove(pk(&guest))]);
        assert!(chain.state().is_allowed(&pk(&moderator), T0 + 3), "moderador ativo participa");
        assert!(!chain.state().is_allowed(&pk(&guest), T0 + 3));
    }

    #[test]
    fn test_renewal_window() {
        let mut s = Setup::new();
        let moderator = UserIdentity::generate();
        let cert = s.certify(&moderator, 1, T0);
        assert!(s.state().certs_due_for_renewal(T0 + 4 * DAY).is_empty(), "faltam 3 dias");
        let due = s.state().certs_due_for_renewal(T0 + 5 * DAY);
        assert_eq!(due.len(), 1, "faltam 2 dias: entra na janela");

        let renewed = cert.renewed(&s.owner, T0 + 5 * DAY, 7 * DAY);
        s.append(T0 + 5 * DAY, vec![Entry::IssueCert(renewed)]);
        assert!(s.state().certs_due_for_renewal(T0 + 5 * DAY + 10).is_empty(), "o sucessor resolve");
        assert_eq!(s.state().level_of(&pk(&moderator), T0 + 8 * DAY), Some(1), "continua moderador após a validade original");
    }
}
