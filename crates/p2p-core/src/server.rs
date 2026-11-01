use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Assinatura digital inválida! Comando forjado ou corrompido.")]
    InvalidSignature,
    #[error("Permissão negada. Apenas moderadores podem executar esta ação.")]
    PermissionDenied,
    #[error("Erro de serialização: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ChannelType {
    Text,
    Voice,
    ScreenShare,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Channel {
    pub id: String,
    pub name: String,
    pub channel_type: ChannelType,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerPayload {
    pub server_id: String,
    pub name: String,
    pub version: u64,
    pub channels: Vec<Channel>,
    pub moderators: Vec<String>,
    pub banned_users: Vec<String>,
}

/// Manifesto do Servidor/Sala assinado pelo Criador/Moderador
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerMetadata {
    pub payload: ServerPayload,
    pub signature: Vec<u8>,
}

impl ServerMetadata {
    /// Valida matematicamente se este manifesto foi realmente assinado pelo criador do servidor
    pub fn verify_signature(&self) -> Result<(), ServerError> {
        let pub_bytes = hex_decode_32(&self.payload.server_id).map_err(|_| ServerError::InvalidSignature)?;
        let verifying_key = VerifyingKey::from_bytes(&pub_bytes).map_err(|_| ServerError::InvalidSignature)?;

        let serialized_payload = serde_json::to_vec(&self.payload)?;
        let sig = Signature::from_slice(&self.signature).map_err(|_| ServerError::InvalidSignature)?;

        verifying_key.verify(&serialized_payload, &sig).map_err(|_| ServerError::InvalidSignature)
    }

    /// Verifica se um usuário possui permissão de moderador
    pub fn is_moderator(&self, user_pubkey: &str) -> bool {
        self.payload.server_id == user_pubkey || self.payload.moderators.iter().any(|m| m == user_pubkey)
    }

    /// Verifica se um usuário está banido deste servidor
    pub fn is_banned(&self, user_pubkey: &str) -> bool {
        self.payload.banned_users.iter().any(|b| b == user_pubkey)
    }
}

fn hex_decode_32(s: &str) -> Result<[u8; 32], ()> {
    if s.len() != 64 {
        return Err(());
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::UserIdentity;

    #[test]
    fn test_server_creation_and_signature_verification() {
        let creator = UserIdentity::generate();
        let payload = ServerPayload {
            server_id: creator.public_key_hex(),
            name: "Servidor Teste P2P".to_string(),
            version: 1,
            channels: vec![
                Channel {
                    id: "c1".to_string(),
                    name: "geral".to_string(),
                    channel_type: ChannelType::Text,
                },
                Channel {
                    id: "v1".to_string(),
                    name: "sala-voz".to_string(),
                    channel_type: ChannelType::Voice,
                },
            ],
            moderators: vec![],
            banned_users: vec![],
        };

        let serialized = serde_json::to_vec(&payload).unwrap();
        let signature = creator.sign(&serialized);

        let server = ServerMetadata { payload, signature };

        // Assinatura deve ser válida
        assert!(server.verify_signature().is_ok());
        assert!(server.is_moderator(&creator.public_key_hex()));
    }

    #[test]
    fn test_forged_server_metadata_must_fail() {
        let creator = UserIdentity::generate();
        let attacker = UserIdentity::generate();

        let payload = ServerPayload {
            server_id: creator.public_key_hex(),
            name: "Servidor Legítimo".to_string(),
            version: 1,
            channels: vec![],
            moderators: vec![],
            banned_users: vec![],
        };

        // Atacante tenta assinar um servidor que diz ser do Criador
        let serialized = serde_json::to_vec(&payload).unwrap();
        let forged_signature = attacker.sign(&serialized);

        let server = ServerMetadata { payload, signature: forged_signature };

        // Deve falhar na validação da assinatura
        assert!(server.verify_signature().is_err());
    }
}
