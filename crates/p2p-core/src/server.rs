use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use std::path::Path;
use crate::identity::{IdentityError, UserIdentity};

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Assinatura digital inválida! Comando forjado ou corrompido.")]
    InvalidSignature,
    #[error("Permissão negada. Apenas moderadores podem executar esta ação.")]
    PermissionDenied,
    #[error("Erro de serialização: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Erro de identidade: {0}")]
    Identity(#[from] IdentityError),
    #[error("Erro de E/S: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ChannelType {
    Text,
    Voice,
    ScreenShare,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Channel {
    pub id: String,
    pub name: String,
    pub channel_type: ChannelType,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ServerPayload {
    pub server_id: String,
    pub name: String,
    pub version: u64,
    pub channels: Vec<Channel>,
    pub moderators: Vec<String>,
    pub banned_users: Vec<String>,
}

/// Ação de Moderação assinada por um Moderador ou pelo Dono do Servidor
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ModerationType {
    Ban,
    Unban,
    Kick,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ModerationActionPayload {
    pub server_id: String,
    pub action: ModerationType,
    pub target_pubkey: String,
    pub moderator_pubkey: String,
    pub timestamp: u64,
    pub reason: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ModerationAction {
    pub payload: ModerationActionPayload,
    pub signature: Vec<u8>,
}

impl ModerationAction {
    /// Assina e gera uma ação de moderação
    pub fn create_and_sign(
        moderator: &UserIdentity,
        server_id: String,
        action: ModerationType,
        target_pubkey: String,
        reason: String,
    ) -> Result<Self, ServerError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let payload = ModerationActionPayload {
            server_id,
            action,
            target_pubkey,
            moderator_pubkey: moderator.public_key_hex(),
            timestamp: now,
            reason,
        };

        let bytes = serde_json::to_vec(&payload)?;
        let signature = moderator.sign(&bytes);

        Ok(Self { payload, signature })
    }

    /// Valida matematicamente se a ação foi assinada pelo moderador e se ele tem autoridade no servidor
    pub fn verify(&self, server: &ServerMetadata) -> Result<(), ServerError> {
        if self.payload.server_id != server.payload.server_id {
            return Err(ServerError::PermissionDenied);
        }

        if !server.is_moderator(&self.payload.moderator_pubkey) {
            return Err(ServerError::PermissionDenied);
        }

        let pub_bytes = hex_decode_32(&self.payload.moderator_pubkey)
            .map_err(|_| ServerError::InvalidSignature)?;
        let verifying_key = VerifyingKey::from_bytes(&pub_bytes)
            .map_err(|_| ServerError::InvalidSignature)?;

        let serialized = serde_json::to_vec(&self.payload)?;
        let sig = Signature::from_slice(&self.signature)
            .map_err(|_| ServerError::InvalidSignature)?;

        verifying_key.verify(&serialized, &sig).map_err(|_| ServerError::InvalidSignature)
    }
}

/// Manifesto do Servidor/Sala assinado pelo Criador/Dono do Servidor
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ServerMetadata {
    pub payload: ServerPayload,
    pub signature: Vec<u8>,
}

impl ServerMetadata {
    /// Cria um novo manifesto inicial assinado pela identidade soberana do servidor
    pub fn new_signed(
        server_identity: &UserIdentity,
        name: String,
        channels: Vec<Channel>,
    ) -> Result<Self, ServerError> {
        let payload = ServerPayload {
            server_id: server_identity.public_key_hex(),
            name,
            version: 1,
            channels,
            moderators: vec![],
            banned_users: vec![],
        };

        let bytes = serde_json::to_vec(&payload)?;
        let signature = server_identity.sign(&bytes);

        Ok(Self { payload, signature })
    }

    /// Gera e assina uma nova versão do manifesto aplicando moderação ou canais
    pub fn sign_update(&mut self, server_identity: &UserIdentity) -> Result<(), ServerError> {
        if server_identity.public_key_hex() != self.payload.server_id {
            return Err(ServerError::PermissionDenied);
        }
        self.payload.version += 1;
        let bytes = serde_json::to_vec(&self.payload)?;
        self.signature = server_identity.sign(&bytes);
        Ok(())
    }

    /// Salva o manifesto assinado em disco
    pub fn save_to<P: AsRef<Path>>(&self, path: P) -> Result<(), ServerError> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Carrega e valida um manifesto do disco
    pub fn load_from<P: AsRef<Path>>(path: P) -> Result<Self, ServerError> {
        let bytes = std::fs::read(path)?;
        let meta: Self = serde_json::from_slice(&bytes)?;
        meta.verify_signature()?;
        Ok(meta)
    }

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

    /// Adiciona um moderador (requer assinatura do servidor)
    pub fn add_moderator(&mut self, user_pubkey: String, server_identity: &UserIdentity) -> Result<(), ServerError> {
        if !self.payload.moderators.contains(&user_pubkey) {
            self.payload.moderators.push(user_pubkey);
            self.sign_update(server_identity)?;
        }
        Ok(())
    }

    /// Remove um moderador (requer assinatura do servidor)
    pub fn remove_moderator(&mut self, user_pubkey: &str, server_identity: &UserIdentity) -> Result<(), ServerError> {
        if let Some(pos) = self.payload.moderators.iter().position(|m| m == user_pubkey) {
            self.payload.moderators.remove(pos);
            self.sign_update(server_identity)?;
        }
        Ok(())
    }

    /// Bane um usuário (requer assinatura do servidor)
    pub fn ban_user(&mut self, user_pubkey: String, server_identity: &UserIdentity) -> Result<(), ServerError> {
        if !self.payload.banned_users.contains(&user_pubkey) {
            self.payload.banned_users.push(user_pubkey);
            self.sign_update(server_identity)?;
        }
        Ok(())
    }

    /// Desbane um usuário (requer assinatura do servidor)
    pub fn unban_user(&mut self, user_pubkey: &str, server_identity: &UserIdentity) -> Result<(), ServerError> {
        if let Some(pos) = self.payload.banned_users.iter().position(|b| b == user_pubkey) {
            self.payload.banned_users.remove(pos);
            self.sign_update(server_identity)?;
        }
        Ok(())
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

    #[test]
    fn test_moderation_action_flow() {
        let server_id = UserIdentity::generate();
        let moderator = UserIdentity::generate();
        let target_user = UserIdentity::generate();

        let mut server = ServerMetadata::new_signed(
            &server_id,
            "Rust Guild".to_string(),
            vec![Channel {
                id: "c1".to_string(),
                name: "geral".to_string(),
                channel_type: ChannelType::Text,
            }],
        ).unwrap();

        // Adiciona o moderador oficialmente
        server.add_moderator(moderator.public_key_hex(), &server_id).unwrap();
        assert!(server.is_moderator(&moderator.public_key_hex()));

        // Moderador assina um BAN contra o target
        let ban_action = ModerationAction::create_and_sign(
            &moderator,
            server.payload.server_id.clone(),
            ModerationType::Ban,
            target_user.public_key_hex(),
            "Spam no canal".to_string(),
        ).unwrap();

        // Verificação matemática da ação de moderação deve passar
        assert!(ban_action.verify(&server).is_ok());

        // Agora um usuário qualquer tenta banir sem ser moderador
        let imposter = UserIdentity::generate();
        let forged_action = ModerationAction::create_and_sign(
            &imposter,
            server.payload.server_id.clone(),
            ModerationType::Ban,
            target_user.public_key_hex(),
            "Fake ban".to_string(),
        ).unwrap();

        // Verificação deve falhar com PermissionDenied
        assert!(forged_action.verify(&server).is_err());
    }
}
