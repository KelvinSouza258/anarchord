//! Certificados de moderador e ações de moderação assinadas.
//!
//! O dono (chave do servidor) emite certificados dizendo "a pubkey X é moderadora, nível N,
//! com estas permissões, até tal data". O moderador anexa o certificado a cada ação que assina,
//! então qualquer membro valida a ação sem precisar da configuração mais recente.

use crate::identity::{verify_signature_hex, UserIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Segundos Unix (UTC)
pub type UtcSecs = u64;

/// O que um certificado permite fazer
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Permission {
    /// Banir e desbanir
    Ban,
    /// Admitir e remover pessoas da allow-list (servidor fechado)
    Admit,
}

/// Permissões padrão de um moderador
pub fn default_permissions() -> Vec<Permission> {
    vec![Permission::Ban, Permission::Admit]
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CertBody {
    /// Identificador único do certificado (usado para revogar)
    pub serial: String,
    pub server_id: String,
    /// Pubkey do moderador
    pub subject: String,
    /// 0 é o dono; certificados têm nível 1 ou maior (número maior = menos autoridade)
    pub level: u8,
    pub permissions: Vec<Permission>,
    pub issued_at: UtcSecs,
    pub expires_at: UtcSecs,
}

/// Certificado de moderador assinado pela chave do servidor
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ModeratorCert {
    pub body: CertBody,
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

impl ModeratorCert {
    /// Emite um certificado (assinado pela chave do servidor)
    pub fn issue(
        server_key: &UserIdentity,
        subject: &str,
        level: u8,
        permissions: Vec<Permission>,
        issued_at: UtcSecs,
        validity_secs: u64,
    ) -> Self {
        let body = CertBody {
            serial: random_serial(),
            server_id: server_key.public_key_hex(),
            subject: subject.to_string(),
            level: level.max(1),
            permissions,
            issued_at,
            expires_at: issued_at + validity_secs,
        };
        let signature = server_key.sign(&crate::wire::signing_bytes("cert", &body));
        Self { body, signature }
    }

    /// Mesmo moderador, nível e permissões, com validade nova a partir de `now`
    pub fn renewed(&self, server_key: &UserIdentity, now: UtcSecs, validity_secs: u64) -> Self {
        Self::issue(server_key, &self.body.subject, self.body.level, self.body.permissions.clone(), now, validity_secs)
    }

    /// Assinatura válida da chave do servidor `server_id`
    pub fn verify(&self, server_id: &str) -> bool {
        self.body.server_id == server_id
            && self.body.level >= 1
            && verify_signature_hex(server_id, &crate::wire::signing_bytes("cert", &self.body), &self.signature)
    }

    /// Dentro do período de validade em `at` (tolerando relógios um pouco adiantados)
    pub fn valid_at(&self, at: UtcSecs) -> bool {
        self.body.issued_at <= at + super::chain::CLOCK_SKEW_SECS && at < self.body.expires_at
    }

    pub fn allows(&self, permission: Permission) -> bool {
        self.body.permissions.contains(&permission)
    }
}

/// O que uma ação de moderação faz
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ModKind {
    /// Ban até `until` (UTC); `None` = permanente
    Ban { until: Option<UtcSecs> },
    Unban,
    /// Inclui na allow-list (servidor fechado)
    Admit,
    /// Remove da allow-list
    Unadmit,
}

impl ModKind {
    pub fn permission(&self) -> Permission {
        match self {
            ModKind::Ban { .. } | ModKind::Unban => Permission::Ban,
            ModKind::Admit | ModKind::Unadmit => Permission::Admit,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ModActionBody {
    pub server_id: String,
    pub cert_serial: String,
    pub kind: ModKind,
    pub target: String,
    /// Data declarada pelo moderador. Só serve para prazos e desempate: a ordem que vale é a da cadeia.
    pub created_at: UtcSecs,
    pub reason: String,
}

/// Ação de moderação assinada pelo moderador, com o certificado dele anexado
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ModAction {
    pub body: ModActionBody,
    pub cert: ModeratorCert,
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

impl ModAction {
    pub fn create(
        moderator: &UserIdentity,
        cert: &ModeratorCert,
        kind: ModKind,
        target: &str,
        reason: &str,
        created_at: UtcSecs,
    ) -> Self {
        let body = ModActionBody {
            server_id: cert.body.server_id.clone(),
            cert_serial: cert.body.serial.clone(),
            kind,
            target: target.to_string(),
            created_at,
            reason: reason.to_string(),
        };
        let signature = moderator.sign(&crate::wire::signing_bytes("modaction", &body));
        Self { body, cert: cert.clone(), signature }
    }

    /// Identificador da ação (para não aplicar duas vezes)
    pub fn id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(crate::wire::to_bytes(&self.body));
        hasher.update(&self.signature);
        hasher.finalize()[..16].iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Certificado emitido pelo servidor e ação assinada pelo dono do certificado
    pub fn verify_signatures(&self, server_id: &str) -> bool {
        self.body.server_id == server_id
            && self.cert.verify(server_id)
            && self.cert.body.serial == self.body.cert_serial
            && verify_signature_hex(&self.cert.body.subject, &crate::wire::signing_bytes("modaction", &self.body), &self.signature)
    }

    pub fn actor(&self) -> &str {
        &self.cert.body.subject
    }
}

fn random_serial() -> String {
    rand::random::<[u8; 8]>().iter().map(|b| format!("{:02x}", b)).collect()
}

/// Lê uma duração: `30m`, `12h`, `3d`, `2w` ou `perm`/`permanente`.
/// Retorna `Some(None)` para permanente, `Some(Some(segundos))` para prazo e `None` se não for duração.
pub fn parse_duration(text: &str) -> Option<Option<u64>> {
    let text = text.trim().to_lowercase();
    if matches!(text.as_str(), "perm" | "permanente" | "permanent") {
        return Some(None);
    }
    let (number, unit) = text.split_at(text.find(|c: char| !c.is_ascii_digit())?);
    let value: u64 = number.parse().ok()?;
    let seconds = match unit {
        "m" | "min" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" | "sem" => 7 * 86_400,
        _ => return None,
    };
    (value > 0).then_some(Some(value * seconds))
}

/// Duração legível: "3d", "12h", "permanente"
pub fn format_duration(seconds: Option<u64>) -> String {
    match seconds {
        None => "permanente".to_string(),
        Some(s) if s % 86_400 == 0 => format!("{}d", s / 86_400),
        Some(s) if s % 3600 == 0 => format!("{}h", s / 3600),
        Some(s) => format!("{}m", (s / 60).max(1)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_issued_by_server_verifies() {
        let server = UserIdentity::generate();
        let moderator = UserIdentity::generate();
        let cert = ModeratorCert::issue(&server, &moderator.public_key_hex(), 1, default_permissions(), 1000, 7 * 86_400);
        assert!(cert.verify(&server.public_key_hex()));
        assert!(cert.valid_at(1000) && cert.valid_at(1000 + 7 * 86_400 - 1));
        assert!(!cert.valid_at(1000 + 7 * 86_400), "expira");
        assert!(cert.allows(Permission::Ban));
    }

    #[test]
    fn test_forged_or_tampered_cert_fails() {
        let server = UserIdentity::generate();
        let attacker = UserIdentity::generate();
        let forged = ModeratorCert::issue(&attacker, &attacker.public_key_hex(), 1, default_permissions(), 0, 100);
        assert!(!forged.verify(&server.public_key_hex()), "emitido por outra chave");

        let mut tampered = ModeratorCert::issue(&server, &attacker.public_key_hex(), 2, default_permissions(), 0, 100);
        tampered.body.level = 1;
        assert!(!tampered.verify(&server.public_key_hex()), "nível alterado depois de assinado");
    }

    #[test]
    fn test_action_needs_cert_subject_signature() {
        let server = UserIdentity::generate();
        let moderator = UserIdentity::generate();
        let thief = UserIdentity::generate();
        let cert = ModeratorCert::issue(&server, &moderator.public_key_hex(), 1, default_permissions(), 0, 100);
        let sid = server.public_key_hex();

        let ok = ModAction::create(&moderator, &cert, ModKind::Unban, "alvo", "", 10);
        assert!(ok.verify_signatures(&sid));
        assert_eq!(ok.actor(), moderator.public_key_hex());

        // Certificado roubado sem a chave do moderador não serve
        let stolen = ModAction::create(&thief, &cert, ModKind::Unban, "alvo", "", 10);
        assert!(!stolen.verify_signatures(&sid));
        assert_ne!(ok.id(), stolen.id());
    }

    #[test]
    fn test_parse_and_format_durations() {
        assert_eq!(parse_duration("30m"), Some(Some(1800)));
        assert_eq!(parse_duration("12h"), Some(Some(43_200)));
        assert_eq!(parse_duration("3d"), Some(Some(259_200)));
        assert_eq!(parse_duration("2w"), Some(Some(1_209_600)));
        assert_eq!(parse_duration("perm"), Some(None));
        assert_eq!(parse_duration("spam"), None);
        assert_eq!(parse_duration("0d"), None);
        assert_eq!(parse_duration("3x"), None);
        assert_eq!(format_duration(Some(259_200)), "3d");
        assert_eq!(format_duration(Some(7200)), "2h");
        assert_eq!(format_duration(None), "permanente");
    }
}
