//! Cadeia de configuração do servidor.
//!
//! Só a chave do servidor escreve blocos, então não há mineração nem consenso: é uma cadeia de
//! hashes assinada (como o histórico do Git). Cada bloco aponta para o hash do anterior e traz
//! a data UTC do dono. Todos os membros guardam a cadeia e calculam o mesmo estado a partir dela.
//!
//! Governança (#84):
//! - **Passaporte é a única credencial.** Participar exige passaporte válido; não há allow-list.
//! - **Linhagem**: ninguém age sobre um ancestral da própria cadeia de passaporte.
//! - **Quem banir primeiro vence**: ações são ordenadas pelo tempo atestado. Cada ação tem um
//!   início (`created_at`, aceito só se um carimbo o confirmar dentro do atraso máximo da política;
//!   senão, o instante em que a ação foi comprovadamente vista) e uma prova de existência (o
//!   carimbo mais antigo, ou a data do bloco que a incluiu). Uma ação de A é anulada se um ban
//!   contra A foi comprovado antes do início dela. Intervalos sobrepostos = empate: ambos valem.
//! - **Ban é uma janela sobre a pubkey** `[início, until)`: invalida os passaportes do alvo emitidos
//!   antes dele e durante ele — exceto os emitidos pela Chave do Servidor depois do início (unban
//!   do dono). Passaportes emitidos depois de `until` valem normalmente.
//! - **Emissor banido**: um elo emitido por quem foi banido só vale se um carimbo provar que ele
//!   existia antes do ban.
//! - **Desban antecipado**: só a Chave do Servidor ou o próprio autor do ban.
//! - **Fork** (dois blocos diferentes na mesma altura): vence o de menor hash.

use super::cert::{ModAction, ModKind, UtcSecs};
use super::passport::{PassportError, PassportPermission, ServerPassport};
use super::timestamp::{verify_rfc3161, TimestampAttestation, TimestampPolicy};
use crate::identity::{verify_signature_hex, UserIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Tolerância para relógios adiantados
pub const CLOCK_SKEW_SECS: u64 = super::passport::CLOCK_SKEW_SECS;
/// Validade padrão dos passaportes emitidos por moderadores
pub const DEFAULT_PASSPORT_VALIDITY_SECS: u64 = 7 * 86_400;
/// Janela de renovação padrão (antes de expirar)
pub const DEFAULT_RENEWAL_WINDOW_SECS: u64 = 2 * 86_400;
/// Até quantos níveis de carimbo-de-testemunha-de-testemunha a verificação desce
const MAX_STAMP_DEPTH: u8 = 3;

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
    /// Primeiro bloco: configuração inicial. `owner` é a identidade pessoal do dono (protegida
    /// como a chave do servidor). `timestamp_policy` diz quais autoridades de tempo valem.
    Genesis {
        name: String,
        owner: String,
        channels: Vec<Channel>,
        /// `false` = público (moderadores emitem passaporte automaticamente a quem pedir)
        closed: bool,
        passport_validity_secs: u64,
        renewal_window_secs: u64,
        timestamp_policy: TimestampPolicy,
    },
    /// Transfere a posse para outra identidade pessoal
    SetOwner(String),
    SetName(String),
    AddChannel(Channel),
    RemoveChannel(String),
    SetClosed(bool),
    SetPassportPolicy { validity_secs: u64, renewal_window_secs: u64 },
    SetTimestampPolicy(TimestampPolicy),
    /// Dificuldade da prova de trabalho exigida nos pedidos de acesso (0 = desligada)
    SetAccessPow { bits: u8 },
    /// Revoga um passaporte específico
    RevokePassport { serial: String },
    /// Ban aplicado pela Chave do Servidor
    Ban { target: String, until: Option<UtcSecs>, reason: String },
    /// Desfaz todos os bans do alvo (só a Chave do Servidor)
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
        let signature = server_key.sign(&crate::wire::signing_bytes("block", &body));
        Self { body, signature }
    }

    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(crate::wire::to_bytes(&self.body));
        hasher.update(&self.signature);
        hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn verify_signature(&self, server_id: &str) -> bool {
        self.body.server_id == server_id
            && verify_signature_hex(server_id, &crate::wire::signing_bytes("block", &self.body), &self.signature)
    }
}

/// Um ban registrado sobre uma pubkey
#[derive(Clone, Debug, PartialEq)]
pub struct BanState {
    pub until: Option<UtcSecs>,
    pub reason: String,
    /// Pubkey de quem baniu (a do servidor, se foi pela Chave do Servidor)
    pub by: String,
    /// Início do ban (data declarada confirmada por carimbo, ou quando foi comprovadamente visto)
    pub starts_at: UtcSecs,
    /// Instante em que a existência do ban está provada (carimbo ou bloco)
    pub proven_at: UtcSecs,
    pub action_id: Option<String>,
}

/// Por que uma ação de moderador foi recusada
#[derive(Debug, Clone, PartialEq)]
pub enum Rejection {
    BadSignature,
    InvalidPassport(String),
    MissingPermission,
    FromTheFuture,
    TargetIsAncestor,
    ProtectedTarget,
    SelfTarget,
    ActorBanned,
    NotBanAuthor,
    NotOwnPassport,
    AlreadyApplied,
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rejection::BadSignature => f.write_str("assinatura inválida"),
            Rejection::InvalidPassport(why) => write!(f, "passaporte do autor inválido: {}", why),
            Rejection::MissingPermission => f.write_str("o passaporte não dá essa permissão"),
            Rejection::FromTheFuture => f.write_str("ação datada no futuro"),
            Rejection::TargetIsAncestor => f.write_str("o alvo é ancestral de quem age (emitiu o passaporte dele ou de alguém acima)"),
            Rejection::ProtectedTarget => f.write_str("o dono e a chave do servidor não podem ser alvo"),
            Rejection::SelfTarget => f.write_str("não é possível agir sobre si mesmo"),
            Rejection::ActorBanned => f.write_str("o autor já estava banido quando agiu"),
            Rejection::NotBanAuthor => f.write_str("só quem aplicou o ban (ou o dono) pode desfazê-lo antes do prazo"),
            Rejection::NotOwnPassport => f.write_str("só o titular renuncia, e só ao passaporte que apresenta"),
            Rejection::AlreadyApplied => f.write_str("ação já aplicada"),
        }
    }
}

/// Evento de governança, guardado para reavaliar tudo na ordem do tempo atestado
#[derive(Clone, Debug)]
enum GovSource {
    OwnerBan { target: String, until: Option<UtcSecs>, reason: String },
    OwnerUnban { target: String },
    OwnerRevoke { serial: String },
    Mod(ModAction),
}

#[derive(Clone, Debug)]
struct GovEvent {
    source: GovSource,
    /// Data do bloco que o incluiu, ou quando este nó o viu (ação provisória)
    seen_at: UtcSecs,
}

/// Estado do servidor calculado a partir da cadeia
#[derive(Clone, Debug, Default)]
pub struct ServerState {
    pub server_id: String,
    /// Identidade pessoal do dono
    pub owner: String,
    pub name: String,
    pub channels: Vec<Channel>,
    /// `false` = público: moderadores emitem passaporte de membro automaticamente
    pub closed: bool,
    pub passport_validity_secs: u64,
    pub renewal_window_secs: u64,
    pub timestamp_policy: TimestampPolicy,
    /// Bits zero exigidos na prova de trabalho dos pedidos de acesso (0 = sem prova)
    pub access_pow_bits: u8,
    /// Seriais de passaporte revogados
    pub revoked: BTreeSet<String>,
    pub bans: BTreeMap<String, Vec<BanState>>,
    pub applied_actions: BTreeSet<String>,
    /// Ações avaliadas e recusadas (por id), com o motivo
    pub rejected_actions: BTreeMap<String, Rejection>,
    events: Vec<GovEvent>,
}

impl ServerState {
    fn new(server_id: &str) -> Self {
        Self { server_id: server_id.to_string(), ..Self::default() }
    }

    /// Aplica um bloco. Entradas de governança usam a data do bloco como prova de existência.
    fn apply_block(&mut self, block: &Block) {
        let at = block.body.timestamp;
        let mut governance = false;
        for entry in &block.body.entries {
            match entry {
                Entry::Genesis { name, owner, channels, closed, passport_validity_secs, renewal_window_secs, timestamp_policy } => {
                    self.owner = owner.clone();
                    self.name = name.clone();
                    self.channels = channels.clone();
                    self.closed = *closed;
                    self.passport_validity_secs = *passport_validity_secs;
                    self.renewal_window_secs = *renewal_window_secs;
                    self.timestamp_policy = timestamp_policy.clone();
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
                Entry::SetPassportPolicy { validity_secs, renewal_window_secs } => {
                    self.passport_validity_secs = *validity_secs;
                    self.renewal_window_secs = (*renewal_window_secs).min(*validity_secs);
                }
                Entry::SetTimestampPolicy(policy) => {
                    self.timestamp_policy = policy.clone();
                    governance = true; // carimbos aceitos mudaram: reavaliar
                }
                Entry::SetAccessPow { bits } => self.access_pow_bits = (*bits).min(super::access_proof::MAX_POW_BITS),
                Entry::RevokePassport { serial } => {
                    self.events.push(GovEvent { source: GovSource::OwnerRevoke { serial: serial.clone() }, seen_at: at });
                    governance = true;
                }
                Entry::Ban { target, until, reason } => {
                    let source = GovSource::OwnerBan { target: target.clone(), until: *until, reason: reason.clone() };
                    self.events.push(GovEvent { source, seen_at: at });
                    governance = true;
                }
                Entry::Unban { target } => {
                    self.events.push(GovEvent { source: GovSource::OwnerUnban { target: target.clone() }, seen_at: at });
                    governance = true;
                }
                Entry::IncludeModAction(action) => {
                    self.events.push(GovEvent { source: GovSource::Mod(action.clone()), seen_at: at });
                    governance = true;
                }
            }
        }
        if governance {
            self.recompute();
        }
    }

    /// Acrescenta ações provisórias (ainda fora da cadeia) vistas por este nó e reavalia
    pub fn add_provisional<'a>(&mut self, actions: impl IntoIterator<Item = (&'a ModAction, UtcSecs)>) {
        for (action, seen_at) in actions {
            self.events.push(GovEvent { source: GovSource::Mod(action.clone()), seen_at });
        }
        self.recompute();
    }

    /// Recalcula bans, revogações e ações aplicadas, na ordem do início atestado de cada evento
    fn recompute(&mut self) {
        // Os tempos são calculados sobre um estado sem bans: só assinaturas, política e linhagem
        let base = ServerState { bans: BTreeMap::new(), events: Vec::new(), ..self.clone() };
        let mut ordered: Vec<(UtcSecs, UtcSecs, String, usize)> = self
            .events
            .iter()
            .enumerate()
            .map(|(index, event)| {
                let (start, proven, id) = match &event.source {
                    GovSource::Mod(action) => {
                        let (start, proven) = base.action_times(action, event.seen_at);
                        (start, proven, action.id())
                    }
                    _ => (event.seen_at, event.seen_at, String::new()),
                };
                (start, proven, id, index)
            })
            .collect();
        ordered.sort_by(|a, b| (a.0, &a.2, a.3).cmp(&(b.0, &b.2, b.3)));

        self.revoked.clear();
        self.bans.clear();
        self.applied_actions.clear();
        self.rejected_actions.clear();
        let events = std::mem::take(&mut self.events);
        for (start, proven, _, index) in &ordered {
            match &events[*index].source {
                GovSource::OwnerBan { target, until, reason } => {
                    if target != &self.server_id && target != &self.owner {
                        let ban = BanState {
                            until: *until,
                            reason: reason.clone(),
                            by: self.server_id.clone(),
                            starts_at: *start,
                            proven_at: *proven,
                            action_id: None,
                        };
                        self.bans.entry(target.clone()).or_default().push(ban);
                    }
                }
                GovSource::OwnerUnban { target } => {
                    self.bans.remove(target);
                }
                GovSource::OwnerRevoke { serial } => {
                    self.revoked.insert(serial.clone());
                }
                GovSource::Mod(action) => {
                    let id = action.id();
                    match self.check_timed(action, *start, *proven) {
                        Ok(()) => self.apply_checked(action, *start, *proven),
                        Err(rejection) => {
                            if !self.applied_actions.contains(&id) {
                                self.rejected_actions.insert(id, rejection);
                            }
                        }
                    }
                }
            }
        }
        self.events = events;
    }

    fn apply_checked(&mut self, action: &ModAction, start: UtcSecs, proven: UtcSecs) {
        let body = &action.body;
        match &body.kind {
            ModKind::Ban { until } => {
                let ban = BanState {
                    until: *until,
                    reason: body.reason.clone(),
                    by: action.actor().to_string(),
                    starts_at: start,
                    proven_at: proven,
                    action_id: Some(action.id()),
                };
                self.bans.entry(body.target.clone()).or_default().push(ban);
            }
            ModKind::Unban => {
                if let Some(list) = self.bans.get_mut(&body.target) {
                    list.retain(|b| !(b.by == action.actor() && b.starts_at <= start));
                    if list.is_empty() {
                        self.bans.remove(&body.target);
                    }
                }
            }
            ModKind::Revoke { serial } | ModKind::Renounce { serial } => {
                self.revoked.insert(serial.clone());
            }
        }
        self.applied_actions.insert(action.id());
    }

    /// Início e prova de existência de uma ação vista em `seen_at` (bloco ou recebimento)
    fn action_times(&self, action: &ModAction, seen_at: UtcSecs) -> (UtcSecs, UtcSecs) {
        let imprint = action.imprint();
        let attested = action.stamps.iter().filter_map(|s| self.stamp_time(s, &imprint, action.actor(), MAX_STAMP_DEPTH)).min();
        let proven = attested.map_or(seen_at, |t| t.min(seen_at));
        let created = action.body.created_at;
        let confirmed = proven + CLOCK_SKEW_SECS >= created && proven <= created + self.timestamp_policy.max_delay_secs;
        let start = if confirmed { created } else { proven };
        (start, proven)
    }

    /// Instante atestado por um carimbo sobre `imprint`, se ele for aceito.
    /// `excluded` é quem gerou o conteúdo: não pode testemunhar nem ser ancestral da testemunha.
    pub fn stamp_time(&self, stamp: &TimestampAttestation, imprint: &[u8; 32], excluded: &str, depth: u8) -> Option<UtcSecs> {
        match stamp {
            TimestampAttestation::Rfc3161 { token_der, .. } => {
                verify_rfc3161(token_der, imprint, &self.timestamp_policy.tsas).ok().map(|(at, _)| at)
            }
            TimestampAttestation::Peer(token) => {
                let at = token.verify_structure(&self.server_id, imprint).ok()?;
                let witness = &token.witness_passport;
                if token.body.witness == excluded || witness.has_ancestor(excluded) {
                    return None; // linhagem: quem descende do autor não atesta por ele
                }
                if depth == 0 || !witness.allows(PassportPermission::EnterServer) {
                    return None;
                }
                self.verify_passport_inner(witness, at, true, depth - 1).ok()?;
                Some(at)
            }
        }
    }

    /// Valida uma ação ainda não incluída, como se fosse vista agora
    pub fn check_mod_action(&self, action: &ModAction, at: UtcSecs) -> Result<(), Rejection> {
        let (start, proven) = self.action_times(action, at);
        self.check_timed(action, start, proven)
    }

    fn check_timed(&self, action: &ModAction, start: UtcSecs, proven: UtcSecs) -> Result<(), Rejection> {
        if self.applied_actions.contains(&action.id()) {
            return Err(Rejection::AlreadyApplied);
        }
        if !action.verify_signatures(&self.server_id) {
            return Err(Rejection::BadSignature);
        }
        if action.body.created_at > proven + CLOCK_SKEW_SECS {
            return Err(Rejection::FromTheFuture);
        }
        let passport = &action.passport;
        let actor = action.actor();
        // Bans contra o próprio autor seguem a regra de precedência abaixo, não a do titular
        self.verify_passport_inner(passport, start, false, MAX_STAMP_DEPTH)
            .map_err(|e| Rejection::InvalidPassport(e.to_string()))?;
        if let Some(bans) = self.bans.get(actor) {
            if bans.iter().any(|ban| ban.proven_at < start && !self.cleared(passport, ban)) {
                return Err(Rejection::ActorBanned);
            }
        }
        if !passport.allows(action.body.kind.permission()) {
            return Err(Rejection::MissingPermission);
        }
        let target = &action.body.target;
        // Renúncia: o titular abre mão do próprio passaporte (o anexado à ação)
        if let ModKind::Renounce { serial } = &action.body.kind {
            if target != actor || serial != &passport.body.serial {
                return Err(Rejection::NotOwnPassport);
            }
            return Ok(());
        }
        if target == actor {
            return Err(Rejection::SelfTarget);
        }
        if target == &self.server_id || (!self.owner.is_empty() && target == &self.owner) {
            return Err(Rejection::ProtectedTarget);
        }
        if passport.has_ancestor(target) {
            return Err(Rejection::TargetIsAncestor);
        }
        if action.body.kind == ModKind::Unban
            && !self.bans.get(target).is_some_and(|bans| bans.iter().any(|b| b.by == actor && b.starts_at <= start))
        {
            return Err(Rejection::NotBanAuthor);
        }
        Ok(())
    }

    /// Passaporte emitido depois do ban de forma que o libera: pela Chave do Servidor depois do
    /// início do ban, ou por qualquer emissor depois do fim do prazo
    fn cleared(&self, passport: &ServerPassport, ban: &BanState) -> bool {
        (passport.body.issuer == self.server_id && passport.body.issued_at > ban.starts_at)
            || ban.until.is_some_and(|until| passport.body.issued_at >= until)
    }

    /// Bans sobre `pubkey` já iniciados em `at`
    fn bans_started<'a>(&'a self, pubkey: &str, at: UtcSecs) -> impl Iterator<Item = &'a BanState> + 'a {
        self.bans.get(pubkey).into_iter().flatten().filter(move |b| b.starts_at <= at)
    }

    /// Valida um passaporte em `at`: cadeia criptográfica, revogação e bans de titular e emissores
    pub fn verify_passport(&self, passport: &ServerPassport, at: UtcSecs) -> Result<(), PassportError> {
        self.verify_passport_inner(passport, at, true, MAX_STAMP_DEPTH)
    }

    fn verify_passport_inner(&self, passport: &ServerPassport, at: UtcSecs, holder_bans: bool, depth: u8) -> Result<(), PassportError> {
        passport.verify_at(&self.server_id, at)?;
        if self.revoked.contains(&passport.body.serial) {
            return Err(PassportError::RevokedOrBanned(passport.body.serial.clone()));
        }
        let holder = &passport.body.holder;
        if holder_bans && holder != &self.owner && self.bans_started(holder, at).any(|ban| !self.cleared(passport, ban)) {
            return Err(PassportError::RevokedOrBanned(holder.clone()));
        }
        // Emissores banidos: o elo filho precisa de prova de que existia antes do ban
        let links = passport.links();
        for pair in links.windows(2) {
            let (child, parent) = (pair[0], pair[1]);
            let issuer = &child.body.issuer;
            if issuer == &self.server_id || issuer == &self.owner {
                continue;
            }
            for ban in self.bans_started(issuer, at) {
                if self.cleared(parent, ban) || (depth > 0 && self.proven_before(child, ban.starts_at, issuer, depth - 1)) {
                    continue;
                }
                return Err(PassportError::RevokedOrBanned(issuer.clone()));
            }
        }
        Ok(())
    }

    /// Algum carimbo aceito prova que o elo existia antes de `t`
    fn proven_before(&self, link: &ServerPassport, t: UtcSecs, issuer: &str, depth: u8) -> bool {
        let imprint = link.imprint();
        link.stamps.iter().filter_map(|s| self.stamp_time(s, &imprint, issuer, depth)).any(|at| at < t)
    }

    /// Ban em vigor em `at` (bans com prazo expiram sozinhos)
    pub fn is_banned(&self, pubkey: &str, at: UtcSecs) -> bool {
        self.bans_started(pubkey, at).any(|b| b.until.map_or(true, |until| at < until))
    }

    pub fn active_bans(&self, at: UtcSecs) -> Vec<(&String, &BanState)> {
        self.bans
            .iter()
            .flat_map(|(pk, list)| list.iter().map(move |b| (pk, b)))
            .filter(|(_, b)| b.starts_at <= at && b.until.map_or(true, |until| at < until))
            .collect()
    }

    /// Dono e chave do servidor sempre participam
    pub fn is_owner_key(&self, pubkey: &str) -> bool {
        pubkey == self.server_id || (!self.owner.is_empty() && pubkey == self.owner)
    }

    /// Pode participar: dono/chave do servidor, ou passaporte válido do próprio `pubkey`
    pub fn is_allowed_with_passport(&self, pubkey: &str, passport: Option<&ServerPassport>, at: UtcSecs) -> bool {
        if self.is_owner_key(pubkey) {
            return true;
        }
        passport.is_some_and(|p| p.body.holder == pubkey && p.allows(PassportPermission::EnterServer) && self.verify_passport(p, at).is_ok())
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
pub(crate) mod tests {
    use super::super::passport::PassportPermission as P;
    use super::super::timestamp::{test_tsa::LocalTsa, PeerTimestampToken};
    use super::*;

    const T0: u64 = 1_800_000_000;
    /// Identidade pessoal do dono (diferente da chave do servidor)
    const OWNER_PERSONAL: &str = "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d";

    fn pk(id: &UserIdentity) -> String {
        id.public_key_hex()
    }

    pub(crate) fn genesis(closed: bool, policy: TimestampPolicy) -> Entry {
        Entry::Genesis {
            name: "Rust Guild".into(),
            owner: OWNER_PERSONAL.into(),
            channels: vec![Channel { name: "geral".into(), channel_type: ChannelType::Text }],
            closed,
            passport_validity_secs: 7 * 86_400,
            renewal_window_secs: 2 * 86_400,
            timestamp_policy: policy,
        }
    }

    /// Servidor com uma TSA local de teste na política
    struct Setup {
        key: UserIdentity,
        tsa: LocalTsa,
        chain: ServerChain,
    }

    impl Setup {
        fn new() -> Self {
            let key = UserIdentity::generate();
            let tsa = LocalTsa::new();
            let policy = TimestampPolicy { tsas: vec![tsa.trusted("local")], max_delay_secs: 600 };
            let mut chain = ServerChain::new(&pk(&key));
            chain.append_own(&key, T0, vec![genesis(false, policy)]);
            Self { key, tsa, chain }
        }

        fn sid(&self) -> String {
            pk(&self.key)
        }

        fn append(&mut self, at: u64, entries: Vec<Entry>) {
            self.chain.append_own(&self.key, at, entries);
        }

        fn state(&self) -> &ServerState {
            self.chain.state()
        }

        /// Moderador emitido direto pela chave do servidor
        fn moderator(&self, who: &UserIdentity, at: u64) -> ServerPassport {
            ServerPassport::issue_root(&self.key, &pk(who), P::default_moderator(), at, Some(at + 30 * 86_400))
        }

        /// Ação carimbada pela TSA local `delay` segundos depois de criada
        fn stamped(&self, mut action: ModAction, delay: u64) -> ModAction {
            let stamp = self.tsa.stamp(&action.imprint(), action.body.created_at + delay);
            action.add_stamp(stamp);
            action
        }
    }

    fn ban(by: &UserIdentity, passport: &ServerPassport, target: &str, at: u64) -> ModAction {
        ModAction::create(by, passport, ModKind::Ban { until: None }, target, "spam", at)
    }

    #[test]
    fn test_chain_links_and_verifies_blocks() {
        let mut s = Setup::new();
        s.append(T0 + 10, vec![Entry::AddChannel(Channel { name: "jogos".into(), channel_type: ChannelType::Text })]);
        assert_eq!(s.chain.blocks().len(), 2);
        assert_eq!(s.chain.blocks()[1].body.prev_hash, s.chain.blocks()[0].hash());
        assert_eq!(s.state().channels.len(), 2);

        let mut copy = ServerChain::new(&s.sid());
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
        let mut member = ServerChain::new(&s.sid());
        let forged = Block::create(&attacker, None, T0, vec![genesis(false, TimestampPolicy::default())]);
        assert!(matches!(member.try_append(forged), AppendResult::Invalid(_)), "assinado por outra chave");

        member.try_append(s.chain.blocks()[0].clone());
        let unlinked = Block::create(&s.key, None, T0, vec![genesis(true, TimestampPolicy::default())]);
        let mut wrong_prev = Block::create(&s.key, Some(&unlinked), T0 + 1, vec![Entry::SetClosed(true)]);
        wrong_prev.body.height = 1;
        assert!(matches!(member.try_append(wrong_prev), AppendResult::Invalid(_)));

        let mut full = s.chain.clone();
        full.append_own(&s.key, T0 + 1, vec![]);
        let b2 = full.append_own(&s.key, T0 + 2, vec![]);
        assert_eq!(member.try_append(b2), AppendResult::Gap { need_from: 1 });
    }

    #[test]
    fn test_fork_resolves_to_lowest_hash_on_every_member() {
        let s = Setup::new();
        let genesis_block = s.chain.blocks()[0].clone();
        let a = Block::create(&s.key, Some(&genesis_block), T0 + 5, vec![Entry::SetName("A".into())]);
        let b = Block::create(&s.key, Some(&genesis_block), T0 + 5, vec![Entry::SetName("B".into())]);
        let winner = if a.hash() < b.hash() { "A" } else { "B" };
        let (mut m1, mut m2) = (ServerChain::new(&s.sid()), ServerChain::new(&s.sid()));
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
        let (moderator, spammer) = (UserIdentity::generate(), UserIdentity::generate());
        let passport = s.moderator(&moderator, T0);
        s.append(T0 + 20, vec![Entry::IncludeModAction(ban(&moderator, &passport, &pk(&spammer), T0 + 15))]);
        assert!(s.state().is_banned(&pk(&spammer), T0 + 30));
        assert_eq!(s.state().bans[&pk(&spammer)][0].by, pk(&moderator));
    }

    #[test]
    fn test_member_without_ban_permission_cannot_moderate() {
        let s = Setup::new();
        let member = UserIdentity::generate();
        let passport = ServerPassport::issue_root(&s.key, &pk(&member), P::member(), T0, Some(T0 + 86_400));
        let action = ban(&member, &passport, &pk(&UserIdentity::generate()), T0 + 5);
        assert_eq!(s.state().check_mod_action(&action, T0 + 5), Err(Rejection::MissingPermission));
    }

    /// Regra de linhagem: ninguém age sobre quem emitiu o próprio passaporte (nem acima dele)
    #[test]
    fn test_moderator_cannot_ban_ancestor_or_owner() {
        let s = Setup::new();
        let (alice, bob) = (UserIdentity::generate(), UserIdentity::generate());
        let alice_p = ServerPassport::issue_root(&s.key, &pk(&alice), P::all(), T0, Some(T0 + 30 * 86_400));
        let bob_p = alice_p.issue_subordinate(&alice, &pk(&bob), P::default_moderator(), T0, T0 + 86_400).unwrap();
        let at = T0 + 10;
        assert_eq!(s.state().check_mod_action(&ban(&bob, &bob_p, &pk(&alice), at), at), Err(Rejection::TargetIsAncestor));
        assert_eq!(s.state().check_mod_action(&ban(&bob, &bob_p, OWNER_PERSONAL, at), at), Err(Rejection::ProtectedTarget));
        assert_eq!(s.state().check_mod_action(&ban(&bob, &bob_p, &s.sid(), at), at), Err(Rejection::ProtectedTarget));
        assert_eq!(s.state().check_mod_action(&ban(&alice, &alice_p, &pk(&bob), at), at), Ok(()), "de cima para baixo pode");
    }

    /// Moderadores de ramos diferentes: vale quem banir primeiro (comprovado por carimbo)
    #[test]
    fn test_first_attested_ban_wins_regardless_of_arrival_order() {
        let s = Setup::new();
        let (a, b) = (UserIdentity::generate(), UserIdentity::generate());
        let (a_p, b_p) = (s.moderator(&a, T0), s.moderator(&b, T0));
        let a_bans_b = s.stamped(ban(&a, &a_p, &pk(&b), T0 + 100), 5);
        let b_bans_a = s.stamped(ban(&b, &b_p, &pk(&a), T0 + 1000), 5);

        for order in [[&a_bans_b, &b_bans_a], [&b_bans_a, &a_bans_b]] {
            let mut state = s.state().clone();
            state.add_provisional(order.iter().map(|action| (*action, T0 + 2000)));
            assert!(state.is_banned(&pk(&b), T0 + 2000), "A baniu primeiro");
            assert!(!state.is_banned(&pk(&a), T0 + 2000), "ban de B veio depois de B estar banido");
            assert_eq!(state.rejected_actions.get(&b_bans_a.id()), Some(&Rejection::ActorBanned));
        }
    }

    /// Intervalos sobrepostos: não dá para saber quem veio primeiro, os dois ficam banidos
    #[test]
    fn test_overlapping_bans_ban_both() {
        let s = Setup::new();
        let (a, b) = (UserIdentity::generate(), UserIdentity::generate());
        let (a_p, b_p) = (s.moderator(&a, T0), s.moderator(&b, T0));
        let a_bans_b = s.stamped(ban(&a, &a_p, &pk(&b), T0 + 100), 30);
        let b_bans_a = s.stamped(ban(&b, &b_p, &pk(&a), T0 + 110), 30);
        let mut state = s.state().clone();
        state.add_provisional([(&a_bans_b, T0 + 500), (&b_bans_a, T0 + 500)]);
        assert!(state.is_banned(&pk(&a), T0 + 500) && state.is_banned(&pk(&b), T0 + 500));
    }

    /// Ação sem carimbo e datada no passado vale como criada quando foi vista (backdating)
    #[test]
    fn test_unstamped_backdated_action_after_ban_is_rejected() {
        let mut s = Setup::new();
        let (rogue, victim) = (UserIdentity::generate(), UserIdentity::generate());
        let rogue_p = s.moderator(&rogue, T0);
        s.append(T0 + 1000, vec![Entry::Ban { target: pk(&rogue), until: None, reason: "abuso".into() }]);
        let backdated = ban(&rogue, &rogue_p, &pk(&victim), T0 + 500);
        s.append(T0 + 2000, vec![Entry::IncludeModAction(backdated.clone())]);
        assert!(!s.state().is_banned(&pk(&victim), T0 + 2000));
        assert_eq!(s.state().rejected_actions.get(&backdated.id()), Some(&Rejection::ActorBanned));

        // Carimbo com atraso maior que a política não confirma a data declarada
        let late_stamp = s.stamped(ban(&rogue, &rogue_p, &pk(&victim), T0 + 501), 1400);
        assert_eq!(s.state().check_mod_action(&late_stamp, T0 + 2100), Err(Rejection::ActorBanned));
        // Carimbo dentro do prazo prova que a ação foi antes do ban
        let honest = s.stamped(ban(&rogue, &rogue_p, &pk(&victim), T0 + 502), 10);
        assert_eq!(s.state().check_mod_action(&honest, T0 + 2100), Ok(()));
    }

    #[test]
    fn test_only_ban_author_or_server_key_unbans_early() {
        let mut s = Setup::new();
        let (a, b, target) = (UserIdentity::generate(), UserIdentity::generate(), UserIdentity::generate());
        let (a_p, b_p) = (s.moderator(&a, T0), s.moderator(&b, T0));
        s.append(T0 + 10, vec![Entry::IncludeModAction(ban(&a, &a_p, &pk(&target), T0 + 10))]);

        let other = ModAction::create(&b, &b_p, ModKind::Unban, &pk(&target), "", T0 + 20);
        assert_eq!(s.state().check_mod_action(&other, T0 + 20), Err(Rejection::NotBanAuthor));
        let own = ModAction::create(&a, &a_p, ModKind::Unban, &pk(&target), "engano", T0 + 20);
        s.append(T0 + 20, vec![Entry::IncludeModAction(own)]);
        assert!(!s.state().is_banned(&pk(&target), T0 + 30), "autor desfez o próprio ban");

        s.append(T0 + 40, vec![Entry::IncludeModAction(ban(&a, &a_p, &pk(&target), T0 + 40))]);
        s.append(T0 + 50, vec![Entry::Unban { target: pk(&target) }]);
        assert!(!s.state().is_banned(&pk(&target), T0 + 60), "a chave do servidor desfaz qualquer ban");
    }

    #[test]
    fn test_banned_author_cannot_undo_own_ban() {
        let mut s = Setup::new();
        let (a, target) = (UserIdentity::generate(), UserIdentity::generate());
        let a_p = s.moderator(&a, T0);
        s.append(T0 + 10, vec![Entry::IncludeModAction(ban(&a, &a_p, &pk(&target), T0 + 10))]);
        s.append(T0 + 20, vec![Entry::Ban { target: pk(&a), until: None, reason: "".into() }]);
        let unban = ModAction::create(&a, &a_p, ModKind::Unban, &pk(&target), "", T0 + 30);
        assert_eq!(s.state().check_mod_action(&unban, T0 + 30), Err(Rejection::ActorBanned));
    }

    #[test]
    fn test_ban_window_and_reissue_rules() {
        let mut s = Setup::new();
        let (moderator, member) = (UserIdentity::generate(), UserIdentity::generate());
        let mod_p = s.moderator(&moderator, T0);
        let old = mod_p.issue_subordinate(&moderator, &pk(&member), P::member(), T0 + 10, T0 + 20 * 86_400).unwrap();
        s.append(T0 + 100, vec![Entry::Ban { target: pk(&member), until: Some(T0 + 3600), reason: "1h".into() }]);
        let st = s.state();
        assert!(st.verify_passport(&old, T0 + 200).is_err(), "emitido antes do ban: invalidado");
        assert!(st.verify_passport(&old, T0 + 7200).is_err(), "continua inválido depois do prazo");

        let during = mod_p.issue_subordinate(&moderator, &pk(&member), P::member(), T0 + 200, T0 + 20 * 86_400).unwrap();
        assert!(st.verify_passport(&during, T0 + 300).is_err(), "moderador não fura o ban (emissão automática inclusa)");
        let by_server = ServerPassport::issue_root(&s.key, &pk(&member), P::member(), T0 + 200, Some(T0 + 86_400));
        assert!(st.verify_passport(&by_server, T0 + 300).is_ok(), "Chave do Servidor libera durante a janela");
        let after = mod_p.issue_subordinate(&moderator, &pk(&member), P::member(), T0 + 3600, T0 + 20 * 86_400).unwrap();
        assert!(st.verify_passport(&after, T0 + 3700).is_ok(), "depois do prazo qualquer emissor reabilita");
        assert!(st.verify_passport(&after, T0 + 300).is_err(), "datado no futuro não vale antes");
    }

    /// Ban derruba também passaportes cruzados (A emite para B, B emite de volta para A)
    #[test]
    fn test_ban_invalidates_cross_issued_passports() {
        let mut s = Setup::new();
        let (a, b) = (UserIdentity::generate(), UserIdentity::generate());
        let a_p = ServerPassport::issue_root(&s.key, &pk(&a), P::all(), T0, Some(T0 + 30 * 86_400));
        let b_p = a_p.issue_subordinate(&a, &pk(&b), P::all(), T0 + 1, T0 + 30 * 86_400).unwrap();
        let a_again = b_p.issue_subordinate(&b, &pk(&a), P::all(), T0 + 2, T0 + 30 * 86_400).unwrap();
        s.append(T0 + 100, vec![Entry::Ban { target: pk(&a), until: None, reason: "".into() }]);
        assert!(s.state().verify_passport(&a_p, T0 + 200).is_err());
        assert!(s.state().verify_passport(&a_again, T0 + 200).is_err(), "o passaporte cruzado também cai");
    }

    /// #84: passaporte emitido por moderador banido só vale com carimbo anterior ao ban
    #[test]
    fn test_passport_from_banned_issuer_needs_prior_timestamp() {
        let mut s = Setup::new();
        let (bob, carol, dave, eve) = (UserIdentity::generate(), UserIdentity::generate(), UserIdentity::generate(), UserIdentity::generate());
        let bob_p = s.moderator(&bob, T0);
        let mut carol_p = bob_p.issue_subordinate(&bob, &pk(&carol), P::member(), T0 + 100, T0 + 20 * 86_400).unwrap();
        carol_p.add_stamp(s.tsa.stamp(&carol_p.imprint(), T0 + 101));
        let unstamped = bob_p.issue_subordinate(&bob, &pk(&dave), P::member(), T0 + 100, T0 + 20 * 86_400).unwrap();

        s.append(T0 + 1000, vec![Entry::Ban { target: pk(&bob), until: None, reason: "infração".into() }]);
        let st = s.state();
        assert!(st.verify_passport(&carol_p, T0 + 2000).is_ok(), "carimbo anterior ao ban: legítimo");
        assert!(st.verify_passport(&unstamped, T0 + 2000).is_err(), "emissor banido e sem prova: rejeita");

        // Bob forja depois do ban com data anterior: o carimbo só pode ser posterior
        let mut forged = bob_p.issue_subordinate(&bob, &pk(&eve), P::member(), T0 + 500, T0 + 20 * 86_400).unwrap();
        forged.add_stamp(s.tsa.stamp(&forged.imprint(), T0 + 1500));
        assert!(st.verify_passport(&forged, T0 + 2000).is_err(), "carimbo posterior ao ban: forjado");

        // Carimbo adulterado ou de autoridade fora da política
        let mut other_tsa = bob_p.issue_subordinate(&bob, &pk(&eve), P::member(), T0 + 100, T0 + 20 * 86_400).unwrap();
        other_tsa.add_stamp(LocalTsa::new().stamp(&other_tsa.imprint(), T0 + 101));
        assert!(st.verify_passport(&other_tsa, T0 + 2000).is_err(), "TSA não homologada");
        let mut tampered = bob_p.issue_subordinate(&bob, &pk(&eve), P::member(), T0 + 100, T0 + 20 * 86_400).unwrap();
        let TimestampAttestation::Rfc3161 { tsa, mut token_der } = s.tsa.stamp(&tampered.imprint(), T0 + 101) else { unreachable!() };
        let n = token_der.len();
        token_der[n - 3] ^= 0x10;
        tampered.add_stamp(TimestampAttestation::Rfc3161 { tsa, token_der });
        assert!(st.verify_passport(&tampered, T0 + 2000).is_err(), "carimbo adulterado");
    }

    /// Testemunha da rede no papel de TSA, com a regra de linhagem
    #[test]
    fn test_peer_witness_counts_only_outside_issuer_lineage() {
        let mut s = Setup::new();
        let (bob, carol, sock, witness) = (UserIdentity::generate(), UserIdentity::generate(), UserIdentity::generate(), UserIdentity::generate());
        let bob_p = s.moderator(&bob, T0);
        let sock_p = bob_p.issue_subordinate(&bob, &pk(&sock), P::member(), T0, T0 + 20 * 86_400).unwrap();
        let witness_p = ServerPassport::issue_root(&s.key, &pk(&witness), P::member(), T0, Some(T0 + 20 * 86_400));

        let carol_base = bob_p.issue_subordinate(&bob, &pk(&carol), P::member(), T0 + 100, T0 + 20 * 86_400).unwrap();
        let mut by_sock = carol_base.clone();
        by_sock.add_stamp(TimestampAttestation::Peer(Box::new(PeerTimestampToken::issue(&sock, &sock_p, &carol_base.imprint(), "n", T0 + 101))));
        let mut by_witness = carol_base.clone();
        by_witness.add_stamp(TimestampAttestation::Peer(Box::new(PeerTimestampToken::issue(&witness, &witness_p, &carol_base.imprint(), "n", T0 + 101))));

        s.append(T0 + 1000, vec![Entry::Ban { target: pk(&bob), until: None, reason: "".into() }]);
        assert!(s.state().verify_passport(&by_sock, T0 + 2000).is_err(), "testemunha descendente do emissor não vale");
        assert!(s.state().verify_passport(&by_witness, T0 + 2000).is_ok(), "testemunha independente vale como TSA");
    }

    #[test]
    fn test_temporary_ban_expires_and_owner_cannot_be_banned() {
        let mut s = Setup::new();
        let target = UserIdentity::generate();
        s.append(T0 + 10, vec![
            Entry::Ban { target: pk(&target), until: Some(T0 + 3600), reason: "1h".into() },
            Entry::Ban { target: OWNER_PERSONAL.into(), until: None, reason: "".into() },
        ]);
        assert!(s.state().is_banned(&pk(&target), T0 + 3599));
        assert!(!s.state().is_banned(&pk(&target), T0 + 3600));
        assert!(!s.state().is_banned(OWNER_PERSONAL, T0 + 20));
        assert!(s.state().is_allowed_with_passport(OWNER_PERSONAL, None, T0 + 20));
    }

    #[test]
    fn test_revocation_by_server_key_and_by_moderator() {
        let mut s = Setup::new();
        let (moderator, member) = (UserIdentity::generate(), UserIdentity::generate());
        let mod_p = s.moderator(&moderator, T0);
        let p1 = ServerPassport::issue_root(&s.key, &pk(&member), P::member(), T0, Some(T0 + 86_400));
        let p2 = ServerPassport::issue_root(&s.key, &pk(&member), P::member(), T0, Some(T0 + 86_400));
        s.append(T0 + 1, vec![Entry::RevokePassport { serial: p1.body.serial.clone() }]);
        let revoke = ModAction::create(&moderator, &mod_p, ModKind::Revoke { serial: p2.body.serial.clone() }, &pk(&member), "", T0 + 2);
        s.append(T0 + 3, vec![Entry::IncludeModAction(revoke)]);
        assert!(s.state().verify_passport(&p1, T0 + 5).is_err());
        assert!(s.state().verify_passport(&p2, T0 + 5).is_err());
        assert!(!s.state().is_allowed_with_passport(&pk(&member), Some(&p2), T0 + 5));
    }

    /// Sair do servidor: o próprio titular renuncia ao passaporte, sem precisar de poder de moderação
    #[test]
    fn test_holder_renounces_own_passport_only() {
        let mut s = Setup::new();
        let (member, other) = (UserIdentity::generate(), UserIdentity::generate());
        let mine = ServerPassport::issue_root(&s.key, &pk(&member), P::member(), T0, Some(T0 + 86_400));
        let theirs = ServerPassport::issue_root(&s.key, &pk(&other), P::member(), T0, Some(T0 + 86_400));

        let wrong_serial = ModAction::create(&member, &mine, ModKind::Renounce { serial: theirs.body.serial.clone() }, &pk(&member), "", T0 + 1);
        assert_eq!(s.state().check_mod_action(&wrong_serial, T0 + 1), Err(Rejection::NotOwnPassport));
        let for_other = ModAction::create(&member, &mine, ModKind::Renounce { serial: mine.body.serial.clone() }, &pk(&other), "", T0 + 1);
        assert_eq!(s.state().check_mod_action(&for_other, T0 + 1), Err(Rejection::NotOwnPassport));

        let renounce = ModAction::create(&member, &mine, ModKind::Renounce { serial: mine.body.serial.clone() }, &pk(&member), "saiu", T0 + 2);
        assert_eq!(s.state().check_mod_action(&renounce, T0 + 2), Ok(()), "membro comum renuncia sem permissão de moderação");
        s.append(T0 + 3, vec![Entry::IncludeModAction(renounce)]);
        assert!(s.state().verify_passport(&mine, T0 + 4).is_err(), "passaporte renunciado não vale mais");
        assert!(s.state().verify_passport(&theirs, T0 + 4).is_ok());
    }

    #[test]
    fn test_same_action_is_not_applied_twice() {
        let mut s = Setup::new();
        let moderator = UserIdentity::generate();
        let mod_p = s.moderator(&moderator, T0);
        let action = ban(&moderator, &mod_p, &pk(&UserIdentity::generate()), T0 + 5);
        s.append(T0 + 10, vec![Entry::IncludeModAction(action.clone())]);
        assert_eq!(s.state().check_mod_action(&action, T0 + 20), Err(Rejection::AlreadyApplied));
    }
}
