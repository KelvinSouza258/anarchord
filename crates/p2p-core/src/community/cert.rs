//! Ações de moderação: tipo de exibição e durações.
//!
//! As ações em si são eventos de governança ([`super::chain::GovEvent`]); [`ModKind`] é a visão
//! resumida de uma entrada de moderação, usada pela interface.

use super::chain::Entry;
use serde::{Deserialize, Serialize};

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
    /// O próprio titular abre mão do passaporte (saiu do servidor). Alvo = o autor.
    Renounce { serial: String },
}

impl ModKind {
    /// Alvo e tipo de uma entrada de moderação (`None` = não é moderação). Na renúncia, o alvo é o autor.
    pub fn from_entry(entry: &Entry, author: &str) -> Option<(String, ModKind)> {
        Some(match entry {
            Entry::Ban { target, until, .. } => (target.clone(), ModKind::Ban { until: *until }),
            Entry::Unban { target } => (target.clone(), ModKind::Unban),
            Entry::Revoke { target, serial } => (target.clone(), ModKind::Revoke { serial: serial.clone() }),
            Entry::Renounce { serial } => (author.to_string(), ModKind::Renounce { serial: serial.clone() }),
            _ => return None,
        })
    }

    /// Entrada correspondente (motivo só no ban)
    pub fn into_entry(self, target: &str, reason: &str) -> Entry {
        match self {
            ModKind::Ban { until } => Entry::Ban { target: target.to_string(), until, reason: reason.to_string() },
            ModKind::Unban => Entry::Unban { target: target.to_string() },
            ModKind::Revoke { serial } => Entry::Revoke { target: target.to_string(), serial },
            ModKind::Renounce { serial } => Entry::Renounce { serial },
        }
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
