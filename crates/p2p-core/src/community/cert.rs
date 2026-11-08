//! Ações de moderação assinadas.
//!
//! Quem modera anexa o próprio passaporte a cada ação que assina, então qualquer membro valida a
//! ação sem precisar falar com o dono. A ordem entre ações vem do tempo atestado (#84): a data
//! declarada `created_at` só vale se um carimbo de terceiro confirmar que ela não foi recuada.

use super::passport::{PassportPermission, ServerPassport};
use super::timestamp::TimestampAttestation;
use crate::identity::{verify_signature_hex, UserIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Segundos Unix (UTC)
pub type UtcSecs = u64;

/// O que uma ação de moderação faz
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ModKind {
    /// Ban até `until` (UTC); `None` = permanente
    Ban { until: Option<UtcSecs> },
    /// Desfaz bans aplicados **pelo próprio autor** (correção de acidente)
    Unban,
    /// Revoga um passaporte específico do alvo
    Revoke { serial: String },
}

impl ModKind {
    pub fn permission(&self) -> PassportPermission {
        PassportPermission::Ban
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ModActionBody {
    pub server_id: String,
    /// Serial do passaporte do autor (anexado em `ModAction::passport`)
    pub passport_serial: String,
    pub kind: ModKind,
    pub target: String,
    /// Data declarada pelo autor. Só é aceita como início da ação se um carimbo a confirmar.
    pub created_at: UtcSecs,
    pub reason: String,
}

/// Ação de moderação assinada pelo titular do passaporte anexado
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ModAction {
    pub body: ModActionBody,
    pub passport: ServerPassport,
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
    /// Carimbos de tempo sobre [`ModAction::imprint`] (chegam depois da ação)
    #[serde(default)]
    pub stamps: Vec<TimestampAttestation>,
}

impl ModAction {
    pub fn create(actor: &UserIdentity, passport: &ServerPassport, kind: ModKind, target: &str, reason: &str, created_at: UtcSecs) -> Self {
        let body = ModActionBody {
            server_id: passport.body.server_id.clone(),
            passport_serial: passport.body.serial.clone(),
            kind,
            target: target.to_string(),
            created_at,
            reason: reason.to_string(),
        };
        let signature = actor.sign(&crate::wire::signing_bytes("modaction", &body));
        Self { body, passport: passport.clone(), signature, stamps: Vec::new() }
    }

    /// Identificador da ação (para não aplicar duas vezes). Não muda quando chegam carimbos.
    pub fn id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(crate::wire::to_bytes(&self.body));
        hasher.update(&self.signature);
        hasher.finalize()[..16].iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Hash carimbado da ação (corpo + assinatura)
    pub fn imprint(&self) -> [u8; 32] {
        super::timestamp::imprint("modaction", &crate::wire::signing_bytes("modaction", &self.body), &self.signature)
    }

    /// Ação assinada pelo titular do passaporte anexado, do mesmo servidor
    pub fn verify_signatures(&self, server_id: &str) -> bool {
        self.body.server_id == server_id
            && self.passport.body.server_id == server_id
            && self.passport.body.serial == self.body.passport_serial
            && verify_signature_hex(&self.passport.body.holder, &crate::wire::signing_bytes("modaction", &self.body), &self.signature)
    }

    pub fn actor(&self) -> &str {
        &self.passport.body.holder
    }

    /// Acrescenta um carimbo (sem duplicar). Devolve `true` se era novo.
    pub fn add_stamp(&mut self, stamp: TimestampAttestation) -> bool {
        if self.stamps.contains(&stamp) {
            return false;
        }
        self.stamps.push(stamp);
        true
    }
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
    fn test_action_needs_passport_holder_signature() {
        let server = UserIdentity::generate();
        let moderator = UserIdentity::generate();
        let thief = UserIdentity::generate();
        let passport = ServerPassport::issue_root(&server, &moderator.public_key_hex(), PassportPermission::default_moderator(), 0, Some(100));
        let sid = server.public_key_hex();

        let ok = ModAction::create(&moderator, &passport, ModKind::Unban, "alvo", "", 10);
        assert!(ok.verify_signatures(&sid));
        assert_eq!(ok.actor(), moderator.public_key_hex());

        // Passaporte roubado sem a chave do titular não serve
        let stolen = ModAction::create(&thief, &passport, ModKind::Unban, "alvo", "", 10);
        assert!(!stolen.verify_signatures(&sid));
        assert_ne!(ok.id(), stolen.id());

        let mut stamped = ok.clone();
        assert!(stamped.add_stamp(TimestampAttestation::Rfc3161 { tsa: "x".into(), token_der: vec![1] }));
        assert_eq!(stamped.id(), ok.id(), "carimbo não muda a identidade da ação");
        assert_eq!(stamped.imprint(), ok.imprint());
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
