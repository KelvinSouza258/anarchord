//! Prova de trabalho dos pedidos de acesso (#91).
//!
//! Um servidor pode exigir que cada pedido de acesso venha com uma prova de trabalho, para
//! encarecer a inundação de moderadores por identidades descartáveis. A prova não pode ser
//! calculada com antecedência: ela é feita **sobre um carimbo de tempo** (TSA ou testemunha) de um
//! valor aleatório, e a assinatura do carimbo é imprevisível. Quem verifica confere que o carimbo
//! é recente e que o hash atinge a dificuldade da política.

use super::timestamp::{self, TimestampAttestation};
use super::UtcSecs;
use crate::identity::{verify_signature_hex, UserIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Idade máxima do carimbo que alimenta a prova
pub const MAX_PROOF_AGE_SECS: u64 = 10 * 60;
/// Dificuldade máxima aceita na política (acima disso o pedido ficaria impraticável)
pub const MAX_POW_BITS: u8 = 32;

/// Campos assinados por quem pede
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AccessProofBody {
    pub server_id: String,
    /// Pubkey de quem pede
    pub requester: String,
    /// Valor aleatório (hex) carimbado antes da prova
    pub seed: String,
    /// Carimbo sobre [`seed_imprint`]
    pub freshness: TimestampAttestation,
    /// Nonce que faz o hash atingir a dificuldade
    pub nonce: u64,
}

/// Prova de trabalho anexada a um pedido de acesso
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AccessProof {
    pub body: AccessProofBody,
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

/// Hash carimbado da semente de uma prova
pub fn seed_imprint(server_id: &str, requester: &str, seed: &str) -> [u8; 32] {
    timestamp::imprint("access-seed", format!("{}|{}|{}", server_id, requester, seed).as_bytes(), &[])
}

/// Hash da prova: depende do carimbo (imprevisível), de quem pede, do servidor e do nonce
fn work_hash(server_id: &str, requester: &str, freshness: &TimestampAttestation, nonce: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"anarchord-access-pow/");
    hasher.update(server_id.as_bytes());
    hasher.update(requester.as_bytes());
    hasher.update(crate::wire::to_bytes(freshness));
    hasher.update(nonce.to_le_bytes());
    hasher.finalize().into()
}

fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut bits = 0;
    for byte in hash {
        if *byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

/// Calcula a prova (pode levar segundos: chamar fora do loop de eventos)
pub fn compute(server_id: &str, requester: &str, seed: &str, freshness: TimestampAttestation, bits: u8) -> AccessProofBody {
    let mut nonce = 0u64;
    while leading_zero_bits(&work_hash(server_id, requester, &freshness, nonce)) < bits as u32 {
        nonce += 1;
    }
    AccessProofBody { server_id: server_id.to_string(), requester: requester.to_string(), seed: seed.to_string(), freshness, nonce }
}

impl AccessProof {
    pub fn sign(identity: &UserIdentity, body: AccessProofBody) -> Self {
        let signature = identity.sign(&crate::wire::signing_bytes("access-proof", &body));
        Self { body, signature }
    }

    /// Confere tudo que não depende da cadeia: assinatura de quem pede, servidor e dificuldade.
    /// O instante do carimbo (e se a autoridade é aceita) é conferido por quem conhece a política.
    pub fn verify_work(&self, server_id: &str, requester: &str, bits: u8) -> bool {
        let body = &self.body;
        body.server_id == server_id
            && body.requester == requester
            && verify_signature_hex(requester, &crate::wire::signing_bytes("access-proof", body), &self.signature)
            && leading_zero_bits(&work_hash(server_id, requester, &body.freshness, body.nonce)) >= bits as u32
    }

    /// Carimbo recente em `now` (não do futuro além da tolerância, nem mais velho que o limite)
    pub fn fresh_at(stamp_time: UtcSecs, now: UtcSecs) -> bool {
        stamp_time <= now + super::chain::CLOCK_SKEW_SECS && now.saturating_sub(stamp_time) <= MAX_PROOF_AGE_SECS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp() -> TimestampAttestation {
        TimestampAttestation::Rfc3161 { tsa: "x".into(), token_der: vec![1, 2, 3] }
    }

    #[test]
    fn test_proof_meets_difficulty_and_binds_requester_and_server() {
        let me = UserIdentity::generate();
        let pk = me.public_key_hex();
        let server = "ab".repeat(32);
        let proof = AccessProof::sign(&me, compute(&server, &pk, "semente", stamp(), 12));
        assert!(proof.verify_work(&server, &pk, 12));
        assert!(!proof.verify_work(&server, &pk, 30), "dificuldade maior não é atingida");
        assert!(!proof.verify_work(&"cd".repeat(32), &pk, 12), "prova de outro servidor");
        assert!(!proof.verify_work(&server, &UserIdentity::generate().public_key_hex(), 12), "prova de outra pessoa");

        let mut other_stamp = proof.clone();
        other_stamp.body.freshness = TimestampAttestation::Rfc3161 { tsa: "x".into(), token_der: vec![9] };
        assert!(!other_stamp.verify_work(&server, &pk, 0), "trocar o carimbo invalida a assinatura");
    }

    #[test]
    fn test_freshness_window() {
        assert!(AccessProof::fresh_at(1000, 1000 + MAX_PROOF_AGE_SECS));
        assert!(!AccessProof::fresh_at(1000, 1001 + MAX_PROOF_AGE_SECS), "carimbo velho");
        assert!(!AccessProof::fresh_at(5000, 1000), "carimbo do futuro");
    }
}
