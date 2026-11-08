//! Passaportes criptográficos do servidor (`ServerPassport`).
//!
//! O passaporte é a única credencial de um servidor: entrar, moderar e emitir passaportes para
//! outros dependem dele. Não existe allow-list nem certificado de moderador à parte.
//!
//! Regras:
//! 1. **Raiz única**: o `server_id` (chave pública Ed25519 do servidor) é a raiz de confiança.
//!    Toda cadeia começa num elo assinado por ela.
//! 2. **Permissões, não níveis**: o que o titular pode fazer é a lista `permissions`. Um elo só
//!    concede permissões que o emissor tem (sem escalação de privilégio). Emitir passaporte de
//!    membro exige `IssueMember`; emitir passaporte com qualquer poder de moderação exige `Delegate`.
//! 3. **Linhagem**: os emissores de todos os elos são os *ancestrais* do titular. Ninguém age sobre
//!    um ancestral, e ninguém atesta o tempo de algo emitido por um ancestral seu.
//! 4. **Vitalício só da raiz**: `expires_at: None` só é aceito quando `issuer == server_id`.
//!    Para os demais, `child.expires_at <= issuer.expires_at`.
//! 5. **Prova de tempo** (#84): cada elo pode carregar carimbos sobre o próprio hash. Eles provam
//!    que o elo existia antes de um ban do emissor (ver `ServerState::verify_passport`).
//! 6. **Achatamento**: um ancestral online (ou a Chave do Servidor) reemite o passaporte como filho
//!    direto, com as mesmas permissões e a mesma validade, encurtando a cadeia.

use super::timestamp::TimestampAttestation;
use crate::identity::{verify_signature_hex, UserIdentity};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Segundos Unix (UTC)
pub type UtcSecs = u64;

/// Tolerância padrão para desvios de relógio (5 minutos)
pub const CLOCK_SKEW_SECS: u64 = 300;

/// O que um passaporte do servidor permite ao portador fazer
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PassportPermission {
    /// Conectar ao servidor e descriptografar canais (MLS / chat / voz)
    EnterServer,
    /// Emitir passaportes de membro (só `EnterServer`)
    IssueMember,
    /// Emitir passaportes com poderes de moderação (subconjunto dos próprios)
    Delegate,
    /// Banir, desfazer os próprios bans e revogar passaportes (fora da própria linhagem)
    Ban,
    /// Criar, alterar e remover canais
    ManageChannels,
    /// Alterar nome e configurações estruturais do servidor
    ManageConfig,
}

impl PassportPermission {
    /// Conjunto completo (concedido ao dono pela Chave do Servidor)
    pub fn all() -> Vec<Self> {
        vec![
            PassportPermission::EnterServer,
            PassportPermission::IssueMember,
            PassportPermission::Delegate,
            PassportPermission::Ban,
            PassportPermission::ManageChannels,
            PassportPermission::ManageConfig,
        ]
    }

    /// Permissões de um moderador padrão
    pub fn default_moderator() -> Vec<Self> {
        vec![PassportPermission::EnterServer, PassportPermission::IssueMember, PassportPermission::Ban]
    }

    /// Permissões de um membro comum
    pub fn member() -> Vec<Self> {
        vec![PassportPermission::EnterServer]
    }

    /// Lista de permissões que dá algum poder além de participar
    pub fn is_moderation(permissions: &[Self]) -> bool {
        permissions.iter().any(|p| *p != PassportPermission::EnterServer)
    }

    /// Reconhece uma permissão a partir de código textual ou alias em PT/EN
    pub fn parse_permission(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "enterserver" | "enter" | "acesso" | "entrar" => Some(PassportPermission::EnterServer),
            "issuemember" | "issue" | "convidar" | "membro" => Some(PassportPermission::IssueMember),
            "delegate" | "delegar" => Some(PassportPermission::Delegate),
            "ban" | "banir" => Some(PassportPermission::Ban),
            "managechannels" | "channels" | "canais" => Some(PassportPermission::ManageChannels),
            "manageconfig" | "config" | "configuracao" | "configuracoes" | "configurações" => {
                Some(PassportPermission::ManageConfig)
            }
            _ => None,
        }
    }

    /// Identificador textual curto para linha de comando e serialização
    pub fn code(&self) -> &'static str {
        match self {
            PassportPermission::EnterServer => "enter",
            PassportPermission::IssueMember => "issue",
            PassportPermission::Delegate => "delegate",
            PassportPermission::Ban => "ban",
            PassportPermission::ManageChannels => "channels",
            PassportPermission::ManageConfig => "config",
        }
    }

    /// Rótulo visual descritivo para menus da interface
    pub fn display_name(&self) -> &'static str {
        match self {
            PassportPermission::EnterServer => "🚪 Acessar Servidor (EnterServer)",
            PassportPermission::IssueMember => "🎫 Convidar/Emitir Membros (IssueMember)",
            PassportPermission::Delegate => "👑 Delegar Moderadores (Delegate)",
            PassportPermission::Ban => "🔨 Banir Membros (Ban)",
            PassportPermission::ManageChannels => "💬 Gerenciar Canais (ManageChannels)",
            PassportPermission::ManageConfig => "⚙️ Gerenciar Configurações (ManageConfig)",
        }
    }
}

/// Corpo de dados canônico de um passaporte do servidor
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PassportBody {
    /// Identificador único deste passaporte (usado para revogação pontual na ServerChain)
    pub serial: String,
    /// ID da Raiz do Servidor (pubkey hex de 64 caracteres do servidor)
    pub server_id: String,
    /// Pubkey hex do titular (dono deste passaporte)
    pub holder: String,
    /// Pubkey hex de quem assinou este elo (a chave do servidor ou o titular do elo anterior)
    pub issuer: String,
    /// Permissões outorgadas ao titular
    pub permissions: Vec<PassportPermission>,
    /// Momento UTC da emissão (declarado pelo emissor; a prova vem dos carimbos)
    pub issued_at: UtcSecs,
    /// Prazo de expiração UTC. `None` = Vitalício (PERMITIDO EXCLUSIVAMENTE quando `issuer == server_id`)
    pub expires_at: Option<UtcSecs>,
}

/// Passaporte Criptográfico do Servidor com Cadeia de Assinaturas
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ServerPassport {
    pub body: PassportBody,
    /// Elo anterior da cadeia quando emitido por moderador (None se assinado diretamente pela Chave do Servidor)
    pub issuer_passport: Option<Box<ServerPassport>>,
    /// Assinatura Ed25519 do `body.issuer` sobre os `signing_bytes` de `body`
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
    /// Carimbos de tempo sobre [`ServerPassport::imprint`] (fora do corpo assinado: chegam depois)
    #[serde(default)]
    pub stamps: Vec<TimestampAttestation>,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum PassportError {
    #[error("ID de servidor incompatível: esperado {expected}, encontrado {found}")]
    ServerMismatch { expected: String, found: String },
    #[error("O primeiro elo da cadeia não foi assinado pela Chave do Servidor ({server_id})")]
    RootNotServerKey { server_id: String },
    #[error("Assinatura Ed25519 inválida do emissor {issuer}")]
    BadSignature { issuer: String },
    #[error("Inconsistência na cadeia: o emissor declarado ({issuer}) não coincide com o titular do passaporte pai ({parent_holder})")]
    IssuerMismatch { parent_holder: String, issuer: String },
    #[error("Passaporte expirado: válido até {expires_at}, validado em {at}")]
    Expired { expires_at: UtcSecs, at: UtcSecs },
    #[error("Passaporte datado no futuro: emitido em {issued_at}, validado em {at}")]
    FromTheFuture { issued_at: UtcSecs, at: UtcSecs },
    #[error("Passaporte vitalício (sem expiração) é restrito à Chave do Servidor; moderadores não podem emitir vitalícios")]
    LifetimeOnlyForRoot,
    #[error("Validade excede a do emissor: pai expira em {parent_exp:?}, mas filho foi emitido até {child_exp:?}")]
    ValidityExceedsIssuer { parent_exp: Option<UtcSecs>, child_exp: Option<UtcSecs> },
    #[error("Emissor não possui permissão para emitir esse passaporte (IssueMember para membros, Delegate para moderação)")]
    MissingDelegationPermission,
    #[error("Escalação de privilégio: permissão {0:?} não é concedida pelo passaporte do emissor")]
    EscalatedPermission(PassportPermission),
    #[error("Titular ou emissor revogado ou banido na cadeia do servidor: {0}")]
    RevokedOrBanned(String),
    #[error("Só um ancestral do titular pode reemitir o passaporte")]
    NotAnAncestor,
}

impl ServerPassport {
    /// Emite um passaporte assinado diretamente pela Chave do Servidor (`server_key`).
    /// Somente ela pode emitir passaportes vitalícios (`expires_at: None`).
    pub fn issue_root(
        server_key: &UserIdentity,
        holder_pubkey: &str,
        permissions: Vec<PassportPermission>,
        issued_at: UtcSecs,
        expires_at: Option<UtcSecs>,
    ) -> Self {
        let server_id = server_key.public_key_hex();
        let body = PassportBody {
            serial: random_serial(),
            server_id: server_id.clone(),
            holder: holder_pubkey.to_string(),
            issuer: server_id,
            permissions,
            issued_at,
            expires_at,
        };
        let signature = server_key.sign(&crate::wire::signing_bytes("passport", &body));
        Self { body, issuer_passport: None, signature, stamps: Vec::new() }
    }

    /// Emite um passaporte subordinado a partir do passaporte do emissor (`self`), estendendo a cadeia.
    ///
    /// Regras: permissões ⊆ as do emissor; `IssueMember` para membro, `Delegate` para moderação;
    /// validade limitada à do emissor (nunca vitalício).
    pub fn issue_subordinate(
        &self,
        issuer_identity: &UserIdentity,
        holder_pubkey: &str,
        permissions: Vec<PassportPermission>,
        issued_at: UtcSecs,
        requested_expires_at: UtcSecs,
    ) -> Result<Self, PassportError> {
        let issuer_pubkey = issuer_identity.public_key_hex();
        if self.body.holder != issuer_pubkey {
            return Err(PassportError::IssuerMismatch { parent_holder: self.body.holder.clone(), issuer: issuer_pubkey });
        }
        check_delegation(&self.body.permissions, &permissions)?;
        let effective_expires_at = match self.effective_expires_at() {
            Some(parent_exp) => requested_expires_at.min(parent_exp),
            None => requested_expires_at,
        };
        let body = PassportBody {
            serial: random_serial(),
            server_id: self.body.server_id.clone(),
            holder: holder_pubkey.to_string(),
            issuer: issuer_pubkey,
            permissions,
            issued_at,
            expires_at: Some(effective_expires_at),
        };
        let signature = issuer_identity.sign(&crate::wire::signing_bytes("passport", &body));
        Ok(Self { body, issuer_passport: Some(Box::new(self.clone())), signature, stamps: Vec::new() })
    }

    /// Hash carimbado deste elo (corpo + assinatura)
    pub fn imprint(&self) -> [u8; 32] {
        super::timestamp::imprint("passport", &crate::wire::signing_bytes("passport", &self.body), &self.signature)
    }

    /// Serializa o passaporte em um token compacto Base64 (URL-safe) para transporte em convites
    pub fn to_token(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Desserializa um passaporte a partir do token Base64 do convite
    pub fn from_token(token: &str) -> Option<Self> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token.trim()).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Valida toda a cadeia criptográfica até a Raiz do Servidor: assinaturas, escopo de
    /// permissões e prazos em `at`. Bans e revogações são conferidos pela `ServerChain`.
    pub fn verify_at(&self, expected_server_id: &str, at: UtcSecs) -> Result<(), PassportError> {
        if self.body.server_id != expected_server_id {
            return Err(PassportError::ServerMismatch { expected: expected_server_id.to_string(), found: self.body.server_id.clone() });
        }
        let signing_bytes = crate::wire::signing_bytes("passport", &self.body);
        if !verify_signature_hex(&self.body.issuer, &signing_bytes, &self.signature) {
            return Err(PassportError::BadSignature { issuer: self.body.issuer.clone() });
        }
        if self.body.issued_at > at + CLOCK_SKEW_SECS {
            return Err(PassportError::FromTheFuture { issued_at: self.body.issued_at, at });
        }
        if let Some(exp) = self.body.expires_at {
            if at >= exp {
                return Err(PassportError::Expired { expires_at: exp, at });
            }
        }
        match &self.issuer_passport {
            None => {
                if self.body.issuer != expected_server_id {
                    return Err(PassportError::RootNotServerKey { server_id: expected_server_id.to_string() });
                }
            }
            Some(parent) => {
                if self.body.expires_at.is_none() {
                    return Err(PassportError::LifetimeOnlyForRoot);
                }
                if let (Some(child_exp), Some(parent_exp)) = (self.body.expires_at, parent.body.expires_at) {
                    if child_exp > parent_exp {
                        return Err(PassportError::ValidityExceedsIssuer { parent_exp: Some(parent_exp), child_exp: Some(child_exp) });
                    }
                }
                if self.body.issuer != parent.body.holder {
                    return Err(PassportError::IssuerMismatch { parent_holder: parent.body.holder.clone(), issuer: self.body.issuer.clone() });
                }
                check_delegation(&parent.body.permissions, &self.body.permissions)?;
                parent.verify_at(expected_server_id, at)?;
            }
        }
        Ok(())
    }

    /// Profundidade da cadeia (1 = direto da Chave do Servidor)
    pub fn chain_depth(&self) -> usize {
        1 + self.issuer_passport.as_ref().map_or(0, |p| p.chain_depth())
    }

    /// Elos da cadeia, do próprio passaporte até o elo raiz
    pub fn links(&self) -> Vec<&ServerPassport> {
        let mut out = vec![self];
        let mut curr = self;
        while let Some(parent) = &curr.issuer_passport {
            out.push(parent);
            curr = parent;
        }
        out
    }

    /// Ancestrais do titular: os emissores de todos os elos (inclui a Chave do Servidor)
    pub fn ancestors(&self) -> Vec<String> {
        let mut list: Vec<String> = self.links().iter().map(|l| l.body.issuer.clone()).collect();
        list.dedup();
        list
    }

    /// `pubkey` assinou algum elo desta cadeia
    pub fn has_ancestor(&self, pubkey: &str) -> bool {
        self.links().iter().any(|l| l.body.issuer == pubkey)
    }

    /// Todas as pubkeys da cadeia (`[holder, issuers..., root]`)
    pub fn all_participants(&self) -> Vec<String> {
        let mut list = vec![self.body.holder.clone()];
        list.extend(self.ancestors());
        list.dedup();
        list
    }

    /// Seriais de todos os elos
    pub fn all_serials(&self) -> Vec<String> {
        self.links().iter().map(|l| l.body.serial.clone()).collect()
    }

    pub fn allows(&self, permission: PassportPermission) -> bool {
        self.body.permissions.contains(&permission)
    }

    /// Passaporte de moderação (algum poder além de participar)
    pub fn is_moderator(&self) -> bool {
        PassportPermission::is_moderation(&self.body.permissions)
    }

    /// Menor data de expiração em toda a cadeia (a cadeia vence quando o elo mais curto vencer)
    pub fn effective_expires_at(&self) -> Option<UtcSecs> {
        self.links().iter().filter_map(|l| l.body.expires_at).min()
    }

    /// Acrescenta um carimbo (sem duplicar). Devolve `true` se era novo.
    pub fn add_stamp(&mut self, stamp: TimestampAttestation) -> bool {
        if self.stamps.contains(&stamp) {
            return false;
        }
        self.stamps.push(stamp);
        true
    }

    /// Procura o elo com este hash e acrescenta o carimbo nele
    pub fn add_stamp_to_link(&mut self, imprint: &[u8; 32], stamp: &TimestampAttestation) -> bool {
        if &self.imprint() == imprint {
            return self.add_stamp(stamp.clone());
        }
        self.issuer_passport.as_mut().is_some_and(|p| p.add_stamp_to_link(imprint, stamp))
    }

    /// **Achatamento pela Chave do Servidor**: reemite como elo único, com as mesmas permissões e validade.
    pub fn flatten_with_server_key(&self, server_key: &UserIdentity, at: UtcSecs) -> Result<Self, PassportError> {
        let server_id = server_key.public_key_hex();
        self.verify_at(&server_id, at)?;
        let body = PassportBody {
            serial: random_serial(),
            server_id: server_id.clone(),
            holder: self.body.holder.clone(),
            issuer: server_id,
            permissions: self.body.permissions.clone(),
            issued_at: at,
            expires_at: self.effective_expires_at(),
        };
        let signature = server_key.sign(&crate::wire::signing_bytes("passport", &body));
        Ok(Self { body, issuer_passport: None, signature, stamps: Vec::new() })
    }

    /// **Achatamento por ancestral**: quem está na cadeia acima do titular reemite o passaporte
    /// como filho direto do seu, com as mesmas permissões e validade.
    pub fn flatten_with_superior(
        &self,
        superior_identity: &UserIdentity,
        superior_passport: &ServerPassport,
        at: UtcSecs,
    ) -> Result<Self, PassportError> {
        let server_id = &superior_passport.body.server_id;
        self.verify_at(server_id, at)?;
        superior_passport.verify_at(server_id, at)?;
        if !self.has_ancestor(&superior_passport.body.holder) || self.body.issuer == superior_passport.body.holder {
            return Err(PassportError::NotAnAncestor);
        }
        let effective_exp = match (self.effective_expires_at(), superior_passport.effective_expires_at()) {
            (Some(c), Some(p)) => c.min(p),
            (Some(c), None) => c,
            (None, Some(p)) => p,
            (None, None) => return Err(PassportError::LifetimeOnlyForRoot),
        };
        superior_passport.issue_subordinate(superior_identity, &self.body.holder, self.body.permissions.clone(), at, effective_exp)
    }
}

/// Emissor com `parent` pode conceder `child`? (sem escalação; IssueMember/Delegate)
fn check_delegation(parent: &[PassportPermission], child: &[PassportPermission]) -> Result<(), PassportError> {
    let needed = if PassportPermission::is_moderation(child) { PassportPermission::Delegate } else { PassportPermission::IssueMember };
    if !parent.contains(&needed) {
        return Err(PassportError::MissingDelegationPermission);
    }
    for p in child {
        if !parent.contains(p) {
            return Err(PassportError::EscalatedPermission(*p));
        }
    }
    Ok(())
}

fn random_serial() -> String {
    rand::random::<[u8; 8]>().iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(id: &UserIdentity) -> String {
        id.public_key_hex()
    }

    #[test]
    fn test_root_issue_and_verify_lifetime() {
        let server = UserIdentity::generate();
        let alice = UserIdentity::generate();
        let passport = ServerPassport::issue_root(&server, &pk(&alice), PassportPermission::all(), 1000, None);
        assert_eq!(passport.chain_depth(), 1);
        assert!(passport.verify_at(&pk(&server), 2_000_000_000).is_ok(), "vitalício não expira");
        assert!(passport.allows(PassportPermission::Ban) && passport.is_moderator());
        assert_eq!(passport.ancestors(), vec![pk(&server)]);
    }

    #[test]
    fn test_delegation_chain_and_lineage() {
        let server = UserIdentity::generate();
        let (alice, bob, carol) = (UserIdentity::generate(), UserIdentity::generate(), UserIdentity::generate());
        let alice_p = ServerPassport::issue_root(&server, &pk(&alice), PassportPermission::all(), 1000, None);
        let bob_p = alice_p.issue_subordinate(&alice, &pk(&bob), PassportPermission::default_moderator(), 1000, 1000 + 7 * 86_400).unwrap();
        let carol_p = bob_p.issue_subordinate(&bob, &pk(&carol), PassportPermission::member(), 1000, 1000 + 3 * 86_400).unwrap();
        assert_eq!(carol_p.chain_depth(), 3);
        assert!(carol_p.verify_at(&pk(&server), 1000 + 3 * 86_400 - 1).is_ok());
        assert!(carol_p.verify_at(&pk(&server), 1000 + 3 * 86_400).is_err(), "carol expirou");
        assert!(carol_p.has_ancestor(&pk(&bob)) && carol_p.has_ancestor(&pk(&alice)) && carol_p.has_ancestor(&pk(&server)));
        assert!(!carol_p.has_ancestor(&pk(&carol)), "o titular não é ancestral de si mesmo");
        assert!(!bob_p.is_moderator() || bob_p.allows(PassportPermission::Ban));
        assert!(!carol_p.is_moderator());
    }

    #[test]
    fn test_member_issuer_needs_issue_member_and_moderation_needs_delegate() {
        let server = UserIdentity::generate();
        let (moderator, other) = (UserIdentity::generate(), UserIdentity::generate());
        let mod_p = ServerPassport::issue_root(&server, &pk(&moderator), PassportPermission::default_moderator(), 0, Some(5000));
        assert!(mod_p.issue_subordinate(&moderator, &pk(&other), PassportPermission::member(), 0, 100).is_ok());
        assert_eq!(
            mod_p.issue_subordinate(&moderator, &pk(&other), vec![PassportPermission::EnterServer, PassportPermission::Ban], 0, 100),
            Err(PassportError::MissingDelegationPermission),
            "sem Delegate não cria moderador"
        );
        let delegate_p = ServerPassport::issue_root(&server, &pk(&moderator), vec![PassportPermission::EnterServer, PassportPermission::Delegate], 0, Some(5000));
        assert_eq!(
            delegate_p.issue_subordinate(&moderator, &pk(&other), vec![PassportPermission::EnterServer, PassportPermission::Ban], 0, 100),
            Err(PassportError::EscalatedPermission(PassportPermission::Ban))
        );
        let member_p = ServerPassport::issue_root(&server, &pk(&other), PassportPermission::member(), 0, Some(5000));
        assert_eq!(member_p.issue_subordinate(&other, &pk(&moderator), PassportPermission::member(), 0, 100), Err(PassportError::MissingDelegationPermission));
    }

    #[test]
    fn test_monotonic_time_rule_child_cannot_outlive_parent() {
        let server = UserIdentity::generate();
        let (alice, bob) = (UserIdentity::generate(), UserIdentity::generate());
        let alice_p = ServerPassport::issue_root(&server, &pk(&alice), PassportPermission::all(), 1000, Some(2000));
        let bob_p = alice_p.issue_subordinate(&alice, &pk(&bob), PassportPermission::default_moderator(), 1000, 5000).unwrap();
        assert_eq!(bob_p.body.expires_at, Some(2000));

        let mut forged = bob_p.clone();
        forged.body.expires_at = Some(5000);
        forged.signature = alice.sign(&crate::wire::signing_bytes("passport", &forged.body));
        assert_eq!(forged.verify_at(&pk(&server), 1000), Err(PassportError::ValidityExceedsIssuer { parent_exp: Some(2000), child_exp: Some(5000) }));
    }

    #[test]
    fn test_lifetime_only_allowed_for_server_key_root() {
        let server = UserIdentity::generate();
        let (alice, bob) = (UserIdentity::generate(), UserIdentity::generate());
        let alice_p = ServerPassport::issue_root(&server, &pk(&alice), PassportPermission::all(), 1000, None);
        let mut bob_body = alice_p.issue_subordinate(&alice, &pk(&bob), PassportPermission::default_moderator(), 1000, 2000).unwrap().body;
        bob_body.expires_at = None;
        let forged = ServerPassport {
            signature: alice.sign(&crate::wire::signing_bytes("passport", &bob_body)),
            body: bob_body,
            issuer_passport: Some(Box::new(alice_p)),
            stamps: Vec::new(),
        };
        assert_eq!(forged.verify_at(&pk(&server), 1000), Err(PassportError::LifetimeOnlyForRoot));
    }

    #[test]
    fn test_flattening_by_server_key_and_by_ancestor_keeps_validity() {
        let server = UserIdentity::generate();
        let (alice, bob, carol, stranger) = (UserIdentity::generate(), UserIdentity::generate(), UserIdentity::generate(), UserIdentity::generate());
        let alice_p = ServerPassport::issue_root(&server, &pk(&alice), PassportPermission::all(), 1000, None);
        let bob_p = alice_p.issue_subordinate(&alice, &pk(&bob), PassportPermission::default_moderator(), 1000, 2000).unwrap();
        let carol_p = bob_p.issue_subordinate(&bob, &pk(&carol), PassportPermission::member(), 1000, 1500).unwrap();

        let flat = carol_p.flatten_with_server_key(&server, 1100).unwrap();
        assert_eq!((flat.chain_depth(), flat.body.expires_at), (1, Some(1500)));
        assert!(flat.verify_at(&pk(&server), 1100).is_ok());

        let by_alice = carol_p.flatten_with_superior(&alice, &alice_p, 1100).unwrap();
        assert_eq!((by_alice.chain_depth(), by_alice.body.expires_at), (2, Some(1500)), "mesma validade");
        let stranger_p = ServerPassport::issue_root(&server, &pk(&stranger), PassportPermission::all(), 1000, None);
        assert_eq!(carol_p.flatten_with_superior(&stranger, &stranger_p, 1100), Err(PassportError::NotAnAncestor));
    }

    #[test]
    fn test_stamps_are_outside_signature_and_attach_by_imprint() {
        let server = UserIdentity::generate();
        let (alice, bob) = (UserIdentity::generate(), UserIdentity::generate());
        let alice_p = ServerPassport::issue_root(&server, &pk(&alice), PassportPermission::all(), 1000, None);
        let mut bob_p = alice_p.issue_subordinate(&alice, &pk(&bob), PassportPermission::member(), 1000, 2000).unwrap();
        let stamp = TimestampAttestation::Rfc3161 { tsa: "x".into(), token_der: vec![1, 2, 3] };
        let parent_imprint = alice_p.imprint();
        assert!(bob_p.add_stamp_to_link(&parent_imprint, &stamp));
        assert!(!bob_p.add_stamp_to_link(&parent_imprint, &stamp), "sem duplicar");
        assert_eq!(bob_p.issuer_passport.as_ref().unwrap().stamps.len(), 1);
        assert!(bob_p.verify_at(&pk(&server), 1000).is_ok(), "carimbos não alteram assinaturas");
    }

    #[test]
    fn test_passport_token_roundtrip() {
        let server = UserIdentity::generate();
        let member = UserIdentity::generate();
        let passport = ServerPassport::issue_root(
            &server,
            &member.public_key_hex(),
            PassportPermission::member(),
            1000,
            Some(2000),
        );
        let token = passport.to_token();
        assert!(!token.is_empty());
        let restored = ServerPassport::from_token(&token).expect("deve decodificar o token");
        assert_eq!(passport, restored);
    }
}
