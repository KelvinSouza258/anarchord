//! Mensagens Diretas Privadas (DM 1:1) com Tópico Mútuo Gossipsub, Criptografia E2EE
//! (X25519 + HKDF-SHA256 + ChaCha20-Poly1305), Sessões Efêmeras (Forward Secrecy)
//! e Mailbox Offline Descentralizada (Store-and-Forward via Guardiões Amigos).

use crate::config::NodeConfig;
#[cfg(test)]
use crate::config::DmPolicyConfig;
use crate::identity::{verify_signature_hex, UserIdentity};
use crate::wire;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Prefixo do tópico Gossipsub mútuo de DM
pub const DM_TOPIC_PREFIX: &str = "p2p-anarchord/dm/";
/// Tópico Gossipsub do protocolo de Mailbox Offline (guardiões)
pub const MAILBOX_TOPIC: &str = "p2p-anarchord/mailbox/v1";

const DM_HKDF_INFO: &[u8] = b"anarchord-dm-v1";
const DM_SESSION_HKDF_INFO: &[u8] = b"anarchord-dm-session-v1";
const DM_SEALED_HKDF_INFO: &[u8] = b"anarchord-dm-sealed-box-v1";
const DM_SIGN_DOMAIN: &[u8] = b"anarchord-dm-sig-v1\0";
const DM_KEY_OFFER_DOMAIN: &[u8] = b"anarchord-dm-eph-key-v1\0";
const FRIEND_REQ_DOMAIN: &[u8] = b"anarchord-friend-req-v1\0";
const FRIEND_RESP_DOMAIN: &[u8] = b"anarchord-friend-resp-v1\0";

#[derive(Error, Debug, PartialEq, Eq)]
pub enum DmError {
    #[error("Chave pública inválida")]
    InvalidPublicKey,
    #[error("Falha na autenticação ou decifragem E2EE")]
    DecryptionFailed,
    #[error("Assinatura digital Ed25519 inválida")]
    InvalidSignature,
    #[error("Mensagem não é destinada a este nó")]
    WrongRecipient,
    #[error("Mailbox desativada neste nó")]
    MailboxDisabled,
    #[error("Remetente não está na lista de amigos deste guardião")]
    NotAFriend,
    #[error("Envelope excede o tamanho máximo permitido")]
    EnvelopeTooLarge,
    #[error("Cota de disco da mailbox atingida")]
    StorageQuotaExceeded,
}

/// Deriva o tópico determinístico de DM entre duas chaves públicas Ed25519 hexadecimais:
/// `p2p-anarchord/dm/` + primeiros 16 bytes (32 chars hex) de `SHA256(min(pk_A, pk_B) || ":" || max(pk_A, pk_B))`
pub fn dm_topic(pubkey_a: &str, pubkey_b: &str) -> String {
    let a = pubkey_a.trim().to_lowercase();
    let b = pubkey_b.trim().to_lowercase();
    let (pk1, pk2) = if a <= b { (a, b) } else { (b, a) };
    let mut hasher = Sha256::new();
    hasher.update(pk1.as_bytes());
    hasher.update(b":");
    hasher.update(pk2.as_bytes());
    let digest = hasher.finalize();
    let hex16: String = digest[..16].iter().map(|byte| format!("{:02x}", byte)).collect();
    format!("{}{}", DM_TOPIC_PREFIX, hex16)
}

/// Converte uma chave privada Ed25519 (seed de 32 bytes) para um `StaticSecret` X25519 (RFC 8032)
pub fn ed25519_priv_to_x25519(ed_secret_bytes: &[u8; 32]) -> StaticSecret {
    crate::identity::ed25519_priv_to_x25519(ed_secret_bytes)
}

/// Converte uma chave pública Ed25519 (hex de 64 chars) para `X25519PublicKey` (ponto Montgomery biracionalmente equivalente)
pub fn ed25519_pub_hex_to_x25519(pubkey_hex: &str) -> Result<X25519PublicKey, DmError> {
    crate::identity::ed25519_pub_hex_to_x25519(pubkey_hex).map_err(|_| DmError::InvalidPublicKey)
}

/// Deriva chave simétrica ChaCha20-Poly1305 de 256 bits a partir de um segredo compartilhado X25519 via HKDF-SHA256
fn derive_aead_key(shared_secret: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("32 bytes é um tamanho válido para HKDF-SHA256");
    okm
}

/// Deriva a chave base estática ECDH entre a chave de criptografia local X25519 e a chave pública do par
pub fn derive_static_dm_key(identity: &UserIdentity, peer_pubkey_hex: &str) -> Result<[u8; 32], DmError> {
    let my_x25519 = identity.encryption_secret();
    let peer_x25519 = identity
        .resolve_encryption_public_key(peer_pubkey_hex)
        .map_err(|_| DmError::InvalidPublicKey)?;
    let shared = my_x25519.diffie_hellman(&peer_x25519);
    Ok(derive_aead_key(shared.as_bytes(), DM_HKDF_INFO))
}

fn default_payload_topic() -> String {
    DEFAULT_MAILBOX_TOPIC.to_string()
}

/// Carga interna autenticada e assinada pelo autor (Sign-then-Seal)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SignedDmPayload {
    pub sender_pubkey: String,
    pub sender_nick: String,
    pub recipient_pubkey: String,
    /// Tópico da mensagem interna (ex: "dm", "friend_request", "friend_response").
    /// Fica completamente cifrado para que guardiões intermediários não conheçam o metadado.
    #[serde(default = "default_payload_topic")]
    pub topic: String,
    pub text: String,
    pub timestamp: u64,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl SignedDmPayload {
    pub fn new_signed(
        identity: &UserIdentity,
        recipient_pubkey: &str,
        text: &str,
        timestamp: u64,
    ) -> Self {
        Self::new_signed_with_topic(identity, recipient_pubkey, DEFAULT_MAILBOX_TOPIC, text, timestamp)
    }

    pub fn new_signed_with_topic(
        identity: &UserIdentity,
        recipient_pubkey: &str,
        topic: &str,
        text: &str,
        timestamp: u64,
    ) -> Self {
        let sender_pubkey = identity.public_key_hex();
        let sender_nick = identity.profile.display_name.clone();
        let recipient_pubkey = recipient_pubkey.trim().to_lowercase();
        let sig_bytes = Self::signing_bytes(&sender_pubkey, &sender_nick, &recipient_pubkey, topic, text, timestamp);
        let signature = identity.sign(&sig_bytes);
        Self {
            sender_pubkey,
            sender_nick,
            recipient_pubkey,
            topic: topic.to_string(),
            text: text.to_string(),
            timestamp,
            signature,
        }
    }

    pub fn signing_bytes(
        sender_pubkey: &str,
        sender_nick: &str,
        recipient_pubkey: &str,
        topic: &str,
        text: &str,
        timestamp: u64,
    ) -> Vec<u8> {
        let tuple = (sender_pubkey, sender_nick, recipient_pubkey, topic, text, timestamp);
        postcard::to_extend(&tuple, b"anarchord-dm-v2\0".to_vec()).expect("serializável")
    }

    fn legacy_signing_bytes(
        sender_pubkey: &str,
        sender_nick: &str,
        recipient_pubkey: &str,
        text: &str,
        timestamp: u64,
    ) -> Vec<u8> {
        let tuple = (sender_pubkey, sender_nick, recipient_pubkey, text, timestamp);
        postcard::to_extend(&tuple, DM_SIGN_DOMAIN.to_vec()).expect("serializável")
    }

    /// Verifica a assinatura Ed25519 da mensagem interna
    pub fn verify(&self) -> bool {
        let bytes = Self::signing_bytes(
            &self.sender_pubkey,
            &self.sender_nick,
            &self.recipient_pubkey,
            &self.topic,
            &self.text,
            self.timestamp,
        );
        if verify_signature_hex(&self.sender_pubkey, &bytes, &self.signature) {
            return true;
        }
        // Retrocompatibilidade: payloads legados assinados sem o campo topic
        if self.topic == DEFAULT_MAILBOX_TOPIC {
            let legacy_bytes = Self::legacy_signing_bytes(
                &self.sender_pubkey,
                &self.sender_nick,
                &self.recipient_pubkey,
                &self.text,
                self.timestamp,
            );
            return verify_signature_hex(&self.sender_pubkey, &legacy_bytes, &self.signature);
        }
        false
    }
}

/// Oferta de chave pública efêmera X25519 assinada pela identidade Ed25519 para Forward Secrecy
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EphemeralKeyOffer {
    pub sender_pubkey: String,
    pub recipient_pubkey: String,
    pub ephemeral_pubkey: [u8; 32],
    pub timestamp: u64,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl EphemeralKeyOffer {
    pub fn new_signed(
        identity: &UserIdentity,
        recipient_pubkey: &str,
        ephemeral_pubkey: [u8; 32],
        timestamp: u64,
    ) -> Self {
        let sender_pubkey = identity.public_key_hex();
        let recipient_pubkey = recipient_pubkey.trim().to_lowercase();
        let bytes = Self::signing_bytes(&sender_pubkey, &recipient_pubkey, &ephemeral_pubkey, timestamp);
        let signature = identity.sign(&bytes);
        Self {
            sender_pubkey,
            recipient_pubkey,
            ephemeral_pubkey,
            timestamp,
            signature,
        }
    }

    pub fn signing_bytes(
        sender_pubkey: &str,
        recipient_pubkey: &str,
        ephemeral_pubkey: &[u8; 32],
        timestamp: u64,
    ) -> Vec<u8> {
        let tuple = (sender_pubkey, recipient_pubkey, ephemeral_pubkey, timestamp);
        postcard::to_extend(&tuple, DM_KEY_OFFER_DOMAIN.to_vec()).expect("serializável")
    }

    pub fn verify(&self) -> bool {
        let bytes = Self::signing_bytes(
            &self.sender_pubkey,
            &self.recipient_pubkey,
            &self.ephemeral_pubkey,
            self.timestamp,
        );
        verify_signature_hex(&self.sender_pubkey, &bytes, &self.signature)
    }
}

/// Envelope de Mensagem Direta 1:1 (E2EE) trafegado no tópico mútuo Gossipsub
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DirectMessageEnvelope {
    pub sender_pubkey: String,
    pub recipient_pubkey: String,
    /// Chave efêmera pública X25519 do remetente (garante sigilo mesmo antes do handshake completo)
    pub ephemeral_pubkey: [u8; 32],
    /// Indica se foi cifrado com a chave de sessão efêmera mútua (`true`) ou sealed-box efêmero->identidade (`false`)
    pub uses_session_key: bool,
    pub nonce: [u8; 12],
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    pub timestamp: u64,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Pedido mútuo de amizade assinado digitalmente pela chave de assinatura raiz (Ed25519)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FriendRequest {
    /// Chave pública Ed25519 do remetente (Alice) em hexadecimal (64 chars)
    pub sender_pubkey: String,
    /// Apelido / Display name público de quem envia
    pub sender_nick: String,
    /// Chave pública Ed25519 do destinatário (Bob) em hexadecimal (64 chars)
    pub recipient_pubkey: String,
    /// Mensagem de saudação ou apresentação opcional
    pub message: Option<String>,
    /// Anúncio assinado da chave de criptografia X25519 de quem envia
    pub encryption_advertisement: crate::identity::SignedEncryptionKeyAdvertisement,
    /// Timestamp Unix (segundos)
    pub timestamp: u64,
    /// Assinatura Ed25519 sobre os campos do pedido
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl FriendRequest {
    pub fn new_signed(
        identity: &UserIdentity,
        recipient_pubkey: &str,
        message: Option<&str>,
        timestamp: u64,
    ) -> Self {
        let sender_pubkey = identity.public_key_hex();
        let sender_nick = identity.profile.display_name.clone();
        let recipient_pubkey = recipient_pubkey.trim().to_lowercase();
        let message = message.map(|m| m.trim().to_string()).filter(|m| !m.is_empty());
        let encryption_advertisement = identity.create_key_advertisement();
        let sig_bytes = Self::signing_bytes(
            &sender_pubkey,
            &sender_nick,
            &recipient_pubkey,
            message.as_deref(),
            &encryption_advertisement,
            timestamp,
        );
        let signature = identity.sign(&sig_bytes);
        Self {
            sender_pubkey,
            sender_nick,
            recipient_pubkey,
            message,
            encryption_advertisement,
            timestamp,
            signature,
        }
    }

    pub fn signing_bytes(
        sender_pubkey: &str,
        sender_nick: &str,
        recipient_pubkey: &str,
        message: Option<&str>,
        advertisement: &crate::identity::SignedEncryptionKeyAdvertisement,
        timestamp: u64,
    ) -> Vec<u8> {
        let tuple = (
            sender_pubkey,
            sender_nick,
            recipient_pubkey,
            message,
            &advertisement.advertisement.encryption_public_key,
            advertisement.advertisement.epoch,
            timestamp,
        );
        postcard::to_extend(&tuple, FRIEND_REQ_DOMAIN.to_vec()).expect("serializável")
    }

    pub fn verify(&self) -> bool {
        if !self.encryption_advertisement.verify() {
            return false;
        }
        if !self.encryption_advertisement.advertisement.user_id.eq_ignore_ascii_case(&self.sender_pubkey) {
            return false;
        }
        let bytes = Self::signing_bytes(
            &self.sender_pubkey,
            &self.sender_nick,
            &self.recipient_pubkey,
            self.message.as_deref(),
            &self.encryption_advertisement,
            self.timestamp,
        );
        verify_signature_hex(&self.sender_pubkey, &bytes, &self.signature)
    }
}

/// Resposta ao pedido de amizade (Aceite ou Recusa) assinada digitalmente
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FriendResponse {
    /// Chave pública Ed25519 de quem responde em hexadecimal (64 chars)
    pub sender_pubkey: String,
    /// Apelido / Display name de quem responde
    pub sender_nick: String,
    /// Chave pública Ed25519 de quem enviou o pedido original
    pub recipient_pubkey: String,
    /// `true` se aceitou a amizade, `false` se recusou
    pub accepted: bool,
    /// Anúncio assinado da chave de criptografia X25519 (se aceito)
    pub encryption_advertisement: Option<crate::identity::SignedEncryptionKeyAdvertisement>,
    /// Timestamp Unix (segundos)
    pub timestamp: u64,
    /// Assinatura Ed25519 sobre os campos da resposta
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl FriendResponse {
    pub fn new_signed(
        identity: &UserIdentity,
        recipient_pubkey: &str,
        accepted: bool,
        timestamp: u64,
    ) -> Self {
        let sender_pubkey = identity.public_key_hex();
        let sender_nick = identity.profile.display_name.clone();
        let recipient_pubkey = recipient_pubkey.trim().to_lowercase();
        let encryption_advertisement = if accepted {
            Some(identity.create_key_advertisement())
        } else {
            None
        };
        let adv_pub = encryption_advertisement.as_ref().map(|a| a.advertisement.encryption_public_key.as_str());
        let adv_epoch = encryption_advertisement.as_ref().map(|a| a.advertisement.epoch);
        let sig_bytes = Self::signing_bytes(
            &sender_pubkey,
            &sender_nick,
            &recipient_pubkey,
            accepted,
            adv_pub,
            adv_epoch,
            timestamp,
        );
        let signature = identity.sign(&sig_bytes);
        Self {
            sender_pubkey,
            sender_nick,
            recipient_pubkey,
            accepted,
            encryption_advertisement,
            timestamp,
            signature,
        }
    }

    pub fn signing_bytes(
        sender_pubkey: &str,
        sender_nick: &str,
        recipient_pubkey: &str,
        accepted: bool,
        adv_pub: Option<&str>,
        adv_epoch: Option<u64>,
        timestamp: u64,
    ) -> Vec<u8> {
        let tuple = (
            sender_pubkey,
            sender_nick,
            recipient_pubkey,
            accepted,
            adv_pub,
            adv_epoch,
            timestamp,
        );
        postcard::to_extend(&tuple, FRIEND_RESP_DOMAIN.to_vec()).expect("serializável")
    }

    pub fn verify(&self) -> bool {
        if let Some(ref adv) = self.encryption_advertisement {
            if !adv.verify() {
                return false;
            }
            if !adv.advertisement.user_id.eq_ignore_ascii_case(&self.sender_pubkey) {
                return false;
            }
        }
        let adv_pub = self.encryption_advertisement.as_ref().map(|a| a.advertisement.encryption_public_key.as_str());
        let adv_epoch = self.encryption_advertisement.as_ref().map(|a| a.advertisement.epoch);
        let bytes = Self::signing_bytes(
            &self.sender_pubkey,
            &self.sender_nick,
            &self.recipient_pubkey,
            self.accepted,
            adv_pub,
            adv_epoch,
            self.timestamp,
        );
        verify_signature_hex(&self.sender_pubkey, &bytes, &self.signature)
    }
}

/// Notificação de bloqueio / rate-limiting temporário enviada por cortesia pelo firewall (Issue #73)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BlockNotice {
    pub sender_pubkey: String,
    pub sender_nick: String,
    pub recipient_pubkey: String,
    pub duration_secs: u64,
    pub blocked_until: u64,
    pub reason: String,
    pub timestamp: u64,
}

/// Mensagens que circulam no tópico de DM
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum DmWireMessage {
    KeyOffer(EphemeralKeyOffer),
    Message(DirectMessageEnvelope),
    KeyAdvertisement(crate::identity::SignedEncryptionKeyAdvertisement),
    FriendRequest(FriendRequest),
    FriendResponse(FriendResponse),
    BlockNotice(BlockNotice),
}

impl wire::WireMessage for DmWireMessage {
    const KIND: wire::Kind = wire::Kind::DirectMessage;
}

impl DirectMessageEnvelope {
    /// Cifra e assina uma DM. Se `session_key` estiver presente (ambos trocaram chaves efêmeras),
    /// usa a chave de sessão com Forward Secrecy completa; caso contrário, usa ECDH(efêmera_A, estática_B).
    pub fn seal(
        identity: &UserIdentity,
        recipient_pubkey: &str,
        text: &str,
        timestamp: u64,
        session_key: Option<&[u8; 32]>,
    ) -> Result<Self, DmError> {
        let recipient_clean = recipient_pubkey.trim().to_lowercase();
        let payload = SignedDmPayload::new_signed(identity, &recipient_clean, text, timestamp);
        let plaintext = postcard::to_allocvec(&payload).map_err(|_| DmError::DecryptionFailed)?;

        let mut rng = rand::thread_rng();
        let mut eph_secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut eph_secret_bytes);
        let eph_secret = StaticSecret::from(eph_secret_bytes);
        let eph_pub = X25519PublicKey::from(&eph_secret);

        let (aead_key, uses_session_key) = match session_key {
            Some(k) => (*k, true),
            None => {
                let recipient_x25519 = identity
                    .resolve_encryption_public_key(&recipient_clean)
                    .map_err(|_| DmError::InvalidPublicKey)?;
                let shared = eph_secret.diffie_hellman(&recipient_x25519);
                (derive_aead_key(shared.as_bytes(), DM_HKDF_INFO), false)
            }
        };

        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
            .map_err(|_| DmError::DecryptionFailed)?;

        let sender_pubkey = identity.public_key_hex();
        let ephemeral_pubkey = eph_pub.to_bytes();
        let sig_bytes = Self::signing_bytes(
            &sender_pubkey,
            &recipient_clean,
            &ephemeral_pubkey,
            uses_session_key,
            &nonce_bytes,
            &ciphertext,
            timestamp,
        );
        let signature = identity.sign(&sig_bytes);

        Ok(Self {
            sender_pubkey,
            recipient_pubkey: recipient_clean,
            ephemeral_pubkey,
            uses_session_key,
            nonce: nonce_bytes,
            ciphertext,
            timestamp,
            signature,
        })
    }

    /// Abre, decifra e autentica o envelope recebido (tanto a assinatura externa quanto a interna)
    pub fn open(
        &self,
        recipient_identity: &UserIdentity,
        session_key: Option<&[u8; 32]>,
    ) -> Result<SignedDmPayload, DmError> {
        let my_pub = recipient_identity.public_key_hex();
        if !self.recipient_pubkey.eq_ignore_ascii_case(&my_pub) {
            return Err(DmError::WrongRecipient);
        }

        let sig_bytes = Self::signing_bytes(
            &self.sender_pubkey,
            &self.recipient_pubkey,
            &self.ephemeral_pubkey,
            self.uses_session_key,
            &self.nonce,
            &self.ciphertext,
            self.timestamp,
        );
        if !verify_signature_hex(&self.sender_pubkey, &sig_bytes, &self.signature) {
            return Err(DmError::InvalidSignature);
        }

        if self.uses_session_key {
            let key = *session_key.ok_or(DmError::DecryptionFailed)?;
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
            let plaintext = cipher
                .decrypt(Nonce::from_slice(&self.nonce), self.ciphertext.as_ref())
                .map_err(|_| DmError::DecryptionFailed)?;
            let payload: SignedDmPayload =
                postcard::from_bytes(&plaintext).map_err(|_| DmError::DecryptionFailed)?;
            if !payload.sender_pubkey.eq_ignore_ascii_case(&self.sender_pubkey)
                || !payload.recipient_pubkey.eq_ignore_ascii_case(&my_pub)
                || !payload.verify()
            {
                return Err(DmError::InvalidSignature);
            }
            return Ok(payload);
        }

        // 1. Tenta decifrar com a chave estática X25519 atual
        let sender_eph = X25519PublicKey::from(self.ephemeral_pubkey);
        let my_x25519 = recipient_identity.encryption_secret();
        let shared = my_x25519.diffie_hellman(&sender_eph);
        let aead_key = derive_aead_key(shared.as_bytes(), DM_HKDF_INFO);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));

        if let Ok(plaintext) = cipher.decrypt(Nonce::from_slice(&self.nonce), self.ciphertext.as_ref()) {
            if let Ok(payload) = postcard::from_bytes::<SignedDmPayload>(&plaintext) {
                if payload.sender_pubkey.eq_ignore_ascii_case(&self.sender_pubkey)
                    && payload.recipient_pubkey.eq_ignore_ascii_case(&my_pub)
                    && payload.verify()
                {
                    return Ok(payload);
                }
            }
        }

        // 2. Se falhou, tenta as chaves anteriores do histórico arquivadas em identity.json
        for hist in recipient_identity.previous_encryption_keys().iter().rev() {
            let shared = hist.secret.diffie_hellman(&sender_eph);
            let aead_key = derive_aead_key(shared.as_bytes(), DM_HKDF_INFO);
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
            if let Ok(plaintext) = cipher.decrypt(Nonce::from_slice(&self.nonce), self.ciphertext.as_ref()) {
                if let Ok(payload) = postcard::from_bytes::<SignedDmPayload>(&plaintext) {
                    if payload.sender_pubkey.eq_ignore_ascii_case(&self.sender_pubkey)
                        && payload.recipient_pubkey.eq_ignore_ascii_case(&my_pub)
                        && payload.verify()
                    {
                        return Ok(payload);
                    }
                }
            }
        }

        Err(DmError::DecryptionFailed)
    }

    pub fn signing_bytes(
        sender_pubkey: &str,
        recipient_pubkey: &str,
        ephemeral_pubkey: &[u8; 32],
        uses_session_key: bool,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        timestamp: u64,
    ) -> Vec<u8> {
        let tuple = (
            sender_pubkey,
            recipient_pubkey,
            ephemeral_pubkey,
            uses_session_key,
            nonce,
            ciphertext,
            timestamp,
        );
        postcard::to_extend(&tuple, DM_SIGN_DOMAIN.to_vec()).expect("serializável")
    }

    /// Verifica a assinatura Ed25519 externa do envelope (sem precisar da chave de decifragem)
    pub fn verify_outer(&self) -> bool {
        let sig_bytes = Self::signing_bytes(
            &self.sender_pubkey,
            &self.recipient_pubkey,
            &self.ephemeral_pubkey,
            self.uses_session_key,
            &self.nonce,
            &self.ciphertext,
            self.timestamp,
        );
        verify_signature_hex(&self.sender_pubkey, &sig_bytes, &self.signature)
    }
}

/// Sessão efêmera de DM em memória (Forward Secrecy) com um par
pub struct DmPeerSession {
    my_ephemeral_secret: StaticSecret,
    pub my_ephemeral_public: [u8; 32],
    pub peer_ephemeral_public: Option<[u8; 32]>,
    pub shared_session_key: Option<[u8; 32]>,
}

impl DmPeerSession {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let secret = StaticSecret::from(bytes);
        let public = X25519PublicKey::from(&secret).to_bytes();
        Self {
            my_ephemeral_secret: secret,
            my_ephemeral_public: public,
            peer_ephemeral_public: None,
            shared_session_key: None,
        }
    }

    pub fn apply_peer_offer(&mut self, peer_eph: [u8; 32]) {
        self.peer_ephemeral_public = Some(peer_eph);
        let peer_pub = X25519PublicKey::from(peer_eph);
        let shared = self.my_ephemeral_secret.diffie_hellman(&peer_pub);
        self.shared_session_key = Some(derive_aead_key(shared.as_bytes(), DM_SESSION_HKDF_INFO));
    }
}

impl Default for DmPeerSession {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ISSUE #37: MENSAGENS OFFLINE VIA GUARDIÕES AMIGOS (STORE-AND-FORWARD MAILBOX)
// ============================================================================

pub const DEFAULT_MAILBOX_TOPIC: &str = "dm";
pub const KEY_ADV_MAILBOX_TOPIC: &str = "key_adv";
pub const FRIEND_REQUEST_MAILBOX_TOPIC: &str = "friend_request";
pub const FRIEND_RESPONSE_MAILBOX_TOPIC: &str = "friend_response";

/// Envelope cifrado Sign-then-Seal armazenado por guardiões amigos quando o destinatário está offline.
/// O guardião (Carol) vê apenas `sender_pubkey`, `recipient_pubkey` e metadados de expiração, sem conhecer
/// o conteúdo ou o tópico interno (DM, friend_request, etc.); a rede atua como middleware cego para entrega assíncrona.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct StoredEnvelope {
    /// Identificador único determinístico (SHA-256 do ciphertext + nonce) para deduplicação
    pub envelope_id: String,
    /// Chave pública Ed25519 do remetente (Alice) — permite a Carol verificar que Alice é amiga dela
    pub sender_pubkey: String,
    /// Chave pública Ed25519 do destinatário (Bob) — permite a Carol saber para quem entregar
    pub recipient_pubkey: String,
    /// Chave efêmera pública X25519 gerada por Alice exclusivamente para este envelope
    #[serde(with = "crate::b64::arr32")]
    pub ephemeral_pubkey: [u8; 32],
    /// Nonce ChaCha20-Poly1305
    #[serde(with = "crate::b64::arr12")]
    pub nonce: [u8; 12],
    /// Carga cifrada contendo `SignedDmPayload` (texto + timestamp + assinatura Ed25519 de Alice)
    #[serde(with = "crate::b64")]
    pub ciphertext: Vec<u8>,
    /// Timestamp UNIX de criação
    pub created_at: u64,
    /// Sugestão opcional de TTL em segundos pedida por Alice
    pub suggested_ttl: Option<u64>,
    /// Timestamp UNIX de expiração calculado pelo guardião (`created_at + effective_ttl`)
    pub expires_at: u64,
    /// Assinatura externa de Alice sobre os metadados do envelope (impede que terceiros forjem pedidos em nome de Alice)
    #[serde(with = "crate::b64")]
    pub outer_signature: Vec<u8>,
}

/// Confirmação de recebimento emitida pelo destinatário (Bob) para que os guardiões apaguem o envelope
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ReceiptAck {
    pub envelope_id: String,
    pub recipient_pubkey: String,
    pub timestamp: u64,
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

impl ReceiptAck {
    pub fn new_signed(identity: &UserIdentity, envelope_id: &str, timestamp: u64) -> Self {
        let recipient_pubkey = identity.public_key_hex();
        let sig_bytes = Self::signing_bytes(envelope_id, &recipient_pubkey, timestamp);
        let signature = identity.sign(&sig_bytes);
        Self {
            envelope_id: envelope_id.to_string(),
            recipient_pubkey,
            timestamp,
            signature,
        }
    }

    pub fn signing_bytes(envelope_id: &str, recipient_pubkey: &str, timestamp: u64) -> Vec<u8> {
        postcard::to_extend(&(envelope_id, recipient_pubkey, timestamp), b"anarchord-mailbox-ack-v1\0".to_vec())
            .expect("serializável")
    }

    pub fn verify(&self) -> bool {
        let bytes = Self::signing_bytes(&self.envelope_id, &self.recipient_pubkey, self.timestamp);
        verify_signature_hex(&self.recipient_pubkey, &bytes, &self.signature)
    }
}

/// Mensagens de protocolo da Mailbox Offline
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum MailboxMessage {
    /// Alice pede aos seus amigos guardiões para armazenarem (ou entregarem) um envelope
    Store(StoredEnvelope),
    /// Guardião entrega envelopes pendentes quando o destinatário entra online
    Deliver(StoredEnvelope),
    /// Destinatário confirma o recebimento e autoriza os guardiões a liberarem o espaço em disco
    Ack(ReceiptAck),
    /// Anúncio de rotação de chave de criptografia propagado e sincronizado via guardiões amigos
    KeyAdvertisement(crate::identity::SignedEncryptionKeyAdvertisement),
}

impl wire::WireMessage for MailboxMessage {
    const KIND: wire::Kind = wire::Kind::Mailbox;
}

impl StoredEnvelope {
    /// Converte um timestamp que pode estar em segundos ou em milissegundos Unix (UTC) para segundos,
    /// usado nos cálculos de TTL (`expires_at = created_at_secs + effective_ttl`).
    pub fn created_at_secs(ts: u64) -> u64 {
        if ts >= 100_000_000_000 {
            ts / 1_000
        } else {
            ts
        }
    }

    /// Alice cria um `StoredEnvelope` Sign-then-Seal para Bob, com tópico padrão "dm"
    pub fn create_signed_and_sealed(
        sender_identity: &UserIdentity,
        recipient_pubkey: &str,
        text: &str,
        created_at: u64,
        suggested_ttl: Option<u64>,
    ) -> Result<Self, DmError> {
        Self::create_signed_and_sealed_topic(
            sender_identity,
            recipient_pubkey,
            DEFAULT_MAILBOX_TOPIC,
            text,
            created_at,
            suggested_ttl,
        )
    }

    /// Cria um envelope genérico orientado a tópico armazenado pelos guardiões amigos
    pub fn create_signed_and_sealed_topic(
        sender_identity: &UserIdentity,
        recipient_pubkey: &str,
        topic: &str,
        text: &str,
        created_at: u64,
        suggested_ttl: Option<u64>,
    ) -> Result<Self, DmError> {
        let recipient_clean = recipient_pubkey.trim().to_lowercase();
        let recipient_x25519 = sender_identity
            .resolve_encryption_public_key(&recipient_clean)
            .map_err(|_| DmError::InvalidPublicKey)?;

        // 1. Sign: Alice assina o payload interno COM O TÓPICO cifrado dentro (Blind Guardian)
        let signed_inner = SignedDmPayload::new_signed_with_topic(
            sender_identity,
            &recipient_clean,
            topic,
            text,
            created_at,
        );
        let inner_bytes = postcard::to_allocvec(&signed_inner).map_err(|_| DmError::DecryptionFailed)?;

        // 2. Seal: Alice gera chave efêmera X25519 e cifra para a chave pública de Bob
        let mut rng = rand::thread_rng();
        let mut eph_bytes = [0u8; 32];
        rng.fill_bytes(&mut eph_bytes);
        let eph_secret = StaticSecret::from(eph_bytes);
        let eph_pub = X25519PublicKey::from(&eph_secret);

        let shared = eph_secret.diffie_hellman(&recipient_x25519);
        let aead_key = derive_aead_key(shared.as_bytes(), DM_SEALED_HKDF_INFO);

        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), inner_bytes.as_ref())
            .map_err(|_| DmError::DecryptionFailed)?;

        // Calcula envelope_id determinístico
        let mut id_hasher = Sha256::new();
        id_hasher.update(&nonce);
        id_hasher.update(&ciphertext);
        let envelope_id: String = id_hasher.finalize()[..16].iter().map(|b| format!("{:02x}", b)).collect();

        let sender_pubkey = sender_identity.public_key_hex();
        let ephemeral_pubkey = eph_pub.to_bytes();
        let default_expires = Self::created_at_secs(created_at).saturating_add(suggested_ttl.unwrap_or(7 * 86_400));

        let outer_sig_bytes = Self::outer_signing_bytes(
            &envelope_id,
            &sender_pubkey,
            &recipient_clean,
            &ephemeral_pubkey,
            &nonce,
            &ciphertext,
            created_at,
            suggested_ttl,
        );
        let outer_signature = sender_identity.sign(&outer_sig_bytes);

        Ok(Self {
            envelope_id,
            sender_pubkey,
            recipient_pubkey: recipient_clean,
            ephemeral_pubkey,
            nonce,
            ciphertext,
            created_at,
            suggested_ttl,
            expires_at: default_expires,
            outer_signature,
        })
    }

    pub fn outer_signing_bytes(
        envelope_id: &str,
        sender_pubkey: &str,
        recipient_pubkey: &str,
        ephemeral_pubkey: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        created_at: u64,
        suggested_ttl: Option<u64>,
    ) -> Vec<u8> {
        let tuple = (
            envelope_id,
            sender_pubkey,
            recipient_pubkey,
            ephemeral_pubkey,
            nonce,
            ciphertext,
            created_at,
            suggested_ttl,
        );
        postcard::to_extend(&tuple, b"anarchord-sealed-outer-v3\0".to_vec()).expect("serializável")
    }

    /// Verifica se o pedido de armazenamento foi realmente assinado por `sender_pubkey`
    pub fn verify_outer(&self) -> bool {
        let bytes = Self::outer_signing_bytes(
            &self.envelope_id,
            &self.sender_pubkey,
            &self.recipient_pubkey,
            &self.ephemeral_pubkey,
            &self.nonce,
            &self.ciphertext,
            self.created_at,
            self.suggested_ttl,
        );
        if verify_signature_hex(&self.sender_pubkey, &bytes, &self.outer_signature) {
            return true;
        }

        // Retrocompatibilidade para envelopes antigos (v1 sem topic na tupla)
        let tuple_v1 = (
            &self.envelope_id,
            &self.sender_pubkey,
            &self.recipient_pubkey,
            &self.ephemeral_pubkey,
            &self.nonce,
            &self.ciphertext,
            self.created_at,
            self.suggested_ttl,
        );
        let bytes_v1 = postcard::to_extend(&tuple_v1, b"anarchord-sealed-outer-v1\0".to_vec()).expect("serializável");
        if verify_signature_hex(&self.sender_pubkey, &bytes_v1, &self.outer_signature) {
            return true;
        }

        false
    }

    /// Bob decifra o envelope (mesmo tendo vindo de Carol, uma estranha) e valida a assinatura interna de Alice
    pub fn unseal_and_verify(&self, recipient_identity: &UserIdentity) -> Result<SignedDmPayload, DmError> {
        let my_pub = recipient_identity.public_key_hex();
        if !self.recipient_pubkey.eq_ignore_ascii_case(&my_pub) {
            return Err(DmError::WrongRecipient);
        }

        let eph_pub = X25519PublicKey::from(self.ephemeral_pubkey);

        // 1. Tenta decifrar com a chave X25519 atual
        let my_x25519 = recipient_identity.encryption_secret();
        let shared = my_x25519.diffie_hellman(&eph_pub);
        let aead_key = derive_aead_key(shared.as_bytes(), DM_SEALED_HKDF_INFO);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));

        if let Ok(plaintext) = cipher.decrypt(Nonce::from_slice(&self.nonce), self.ciphertext.as_ref()) {
            if let Ok(inner) = postcard::from_bytes::<SignedDmPayload>(&plaintext) {
                if inner.sender_pubkey.eq_ignore_ascii_case(&self.sender_pubkey)
                    && inner.recipient_pubkey.eq_ignore_ascii_case(&my_pub)
                    && inner.verify()
                {
                    return Ok(inner);
                }
            }
        }

        // 2. Se falhou, tenta as chaves anteriores do histórico arquivadas em identity.json
        for hist in recipient_identity.previous_encryption_keys().iter().rev() {
            let shared = hist.secret.diffie_hellman(&eph_pub);
            let aead_key = derive_aead_key(shared.as_bytes(), DM_SEALED_HKDF_INFO);
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
            if let Ok(plaintext) = cipher.decrypt(Nonce::from_slice(&self.nonce), self.ciphertext.as_ref()) {
                if let Ok(inner) = postcard::from_bytes::<SignedDmPayload>(&plaintext) {
                    if inner.sender_pubkey.eq_ignore_ascii_case(&self.sender_pubkey)
                        && inner.recipient_pubkey.eq_ignore_ascii_case(&my_pub)
                        && inner.verify()
                    {
                        return Ok(inner);
                    }
                }
            }
        }

        Err(DmError::DecryptionFailed)
    }

    /// Tamanho estimado ocupado pelo envelope em bytes
    pub fn size_bytes(&self) -> usize {
        self.ciphertext.len() + self.outer_signature.len() + 180
    }
}

fn deserialize_acks<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<ReceiptAck>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum AcksRepr {
        List(Vec<ReceiptAck>),
        Map(HashMap<String, ReceiptAck>),
    }
    match AcksRepr::deserialize(deserializer)? {
        AcksRepr::List(list) => Ok(list),
        AcksRepr::Map(map) => Ok(map.into_values().collect()),
    }
}

/// Estado persistido em `mailbox.json` no disco
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct PersistedMailbox {
    envelopes: Vec<StoredEnvelope>,
    /// ACKs assinados pelos destinatários para sincronizar outros guardiões e deduplicar entregas
    #[serde(deserialize_with = "deserialize_acks")]
    acks: Vec<ReceiptAck>,
    /// Quais amigos guardiões já receberam o pedido de guarda de cada envelope da outbox (`envelope_id` -> conjunto de `guardian_pubkey`)
    delegated_guardians: HashMap<String, HashSet<String>>,
    /// Campo legado ignorado na serialização para retrocompatibilidade ao ler JSONs antigos
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    delivered_ids: HashMap<String, u64>,
    /// Tópicos internos dos envelopes criados por este nó (outbox local) para filtragem e descarte seletivo
    #[serde(default)]
    own_topics: HashMap<String, String>,
}

/// Armazenamento local do Guardião (Carol/Bob) e Outbox do Remetente (Alice)
pub struct MailboxStore {
    storage_path: Option<PathBuf>,
    /// Envelopes guardados por este nó: envelope_id -> StoredEnvelope
    envelopes: HashMap<String, StoredEnvelope>,
    /// ACKs assinados conhecidos por este nó: envelope_id -> ReceiptAck
    /// (Single Source of Truth para comprovante de entrega e deduplicação persistida)
    acks: HashMap<String, ReceiptAck>,
    /// Controle orientado a eventos da Outbox: `envelope_id` -> `HashSet<guardian_pubkey>` para os quais já pedimos guarda
    delegated_guardians: HashMap<String, HashSet<String>>,
    /// Tópico interno dos envelopes gerados localmente: `envelope_id` -> `topic`
    own_topics: HashMap<String, String>,
}

impl MailboxStore {
    pub fn load(storage_path: Option<PathBuf>, now: u64) -> Self {
        let mut envelopes = HashMap::new();
        let mut acks = HashMap::new();
        let mut delegated_guardians = HashMap::new();
        let mut own_topics = HashMap::new();
        const MAX_ACK_RETENTION_SECS: u64 = 7 * 86_400;
        if let Some(ref path) = storage_path {
            if let Ok(bytes) = fs::read(path) {
                if let Ok(persisted) = serde_json::from_slice::<PersistedMailbox>(&bytes) {
                    for env in persisted.envelopes {
                        if env.expires_at > now {
                            envelopes.insert(env.envelope_id.clone(), env);
                        }
                    }
                    for ack in persisted.acks {
                        let ack_ts_secs = StoredEnvelope::created_at_secs(ack.timestamp);
                        if now.saturating_sub(ack_ts_secs) < MAX_ACK_RETENTION_SECS && ack.verify() {
                            acks.insert(ack.envelope_id.clone(), ack);
                        }
                    }
                    for (id, guardians) in persisted.delegated_guardians {
                        if envelopes.contains_key(&id) {
                            delegated_guardians.insert(
                                id,
                                guardians.into_iter().map(|pk| pk.to_lowercase()).collect(),
                            );
                        }
                    }
                    for (id, top) in persisted.own_topics {
                        if envelopes.contains_key(&id) {
                            own_topics.insert(id, top);
                        }
                    }
                } else if let Ok(legacy_list) = serde_json::from_slice::<Vec<StoredEnvelope>>(&bytes) {
                    for env in legacy_list {
                        if env.expires_at > now {
                            envelopes.insert(env.envelope_id.clone(), env);
                        }
                    }
                }
            }
        }
        Self {
            storage_path,
            envelopes,
            acks,
            delegated_guardians,
            own_topics,
        }
    }

    fn persist(&self) {
        if let Some(ref path) = self.storage_path {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = fs::create_dir_all(parent);
                }
            }
            let data = PersistedMailbox {
                envelopes: self.envelopes.values().cloned().collect(),
                acks: self.acks.values().cloned().collect(),
                delegated_guardians: self.delegated_guardians.clone(),
                delivered_ids: HashMap::new(),
                own_topics: self.own_topics.clone(),
            };
            if let Ok(json) = serde_json::to_string_pretty(&data) {
                let _ = fs::write(path, json);
            }
        }
    }

    /// Guarda um envelope enviado pelo próprio nó (outbox local para reentrega direta ou a guardiões)
    pub fn insert_own(&mut self, envelope: StoredEnvelope, config: &NodeConfig, now: u64) {
        self.insert_own_with_topic(envelope, DEFAULT_MAILBOX_TOPIC, config, now);
    }

    /// Guarda um envelope enviado pelo próprio nó com um tópico específico na outbox local
    pub fn insert_own_with_topic(&mut self, mut envelope: StoredEnvelope, topic: &str, config: &NodeConfig, now: u64) {
        let effective_ttl = config.calculate_effective_ttl(envelope.suggested_ttl);
        envelope.expires_at = now.saturating_add(effective_ttl);
        let id = envelope.envelope_id.clone();
        self.own_topics.insert(id.clone(), topic.to_string());
        self.envelopes.insert(id, envelope);
        self.persist();
    }

    /// Retorna o tópico interno de um envelope de outbox criado por este nó, se conhecido
    pub fn get_own_topic(&self, envelope_id: &str) -> Option<&str> {
        self.own_topics.get(envelope_id).map(|s| s.as_str())
    }

    /// Guardião (Carol) avalia e armazena um envelope enviado por um amigo (Alice)
    pub fn store_for_friend(
        &mut self,
        mut envelope: StoredEnvelope,
        is_sender_friend: bool,
        config: &NodeConfig,
        now: u64,
    ) -> Result<u64, DmError> {
        if !config.mailbox.enabled {
            return Err(DmError::MailboxDisabled);
        }
        if !is_sender_friend {
            return Err(DmError::NotAFriend);
        }
        if !envelope.verify_outer() {
            return Err(DmError::InvalidSignature);
        }
        if self.acks.contains_key(&envelope.envelope_id) {
            // Já foi entregue anteriormente
            let effective_ttl = config.calculate_effective_ttl(envelope.suggested_ttl);
            return Ok(effective_ttl);
        }
        if self.envelopes.contains_key(&envelope.envelope_id) {
            let existing = &self.envelopes[&envelope.envelope_id];
            return Ok(existing.expires_at.saturating_sub(now));
        }

        self.purge_expired(now);

        let env_size = envelope.size_bytes();
        if env_size > config.max_envelope_bytes() {
            return Err(DmError::EnvelopeTooLarge);
        }

        let total_used = self.total_bytes();
        if total_used.saturating_add(env_size as u64) > config.max_storage_bytes() {
            return Err(DmError::StorageQuotaExceeded);
        }

        let friend_used = self.friend_bytes(&envelope.sender_pubkey);
        if friend_used.saturating_add(env_size as u64) > config.max_friend_storage_bytes() {
            return Err(DmError::StorageQuotaExceeded);
        }

        // Regra Soberana de Carol: TTL_Efetivo = min(sugerido_por_Alice, max_de_Carol)
        let effective_ttl = config.calculate_effective_ttl(envelope.suggested_ttl);
        envelope.expires_at = now.saturating_add(effective_ttl);

        self.envelopes.insert(envelope.envelope_id.clone(), envelope);
        self.persist();
        Ok(effective_ttl)
    }

    /// Retorna todos os envelopes pendentes para `recipient_pubkey`
    pub fn pending_for_recipient(&self, recipient_pubkey: &str, now: u64) -> Vec<StoredEnvelope> {
        self.envelopes
            .values()
            .filter(|e| e.expires_at > now && e.recipient_pubkey.eq_ignore_ascii_case(recipient_pubkey))
            .cloned()
            .collect()
    }

    /// Retorna envelopes enviados por `sender_pubkey` (útil para delegar a novos amigos guardiões que entrarem online)
    pub fn pending_from_sender(&self, sender_pubkey: &str, now: u64) -> Vec<StoredEnvelope> {
        self.envelopes
            .values()
            .filter(|e| e.expires_at > now && e.sender_pubkey.eq_ignore_ascii_case(sender_pubkey))
            .cloned()
            .collect()
    }

    /// Retorna todos os envelopes na outbox local criados por `sender_pubkey` destinados a `recipient_pubkey`
    pub fn pending_outbox_for(&self, sender_pubkey: &str, recipient_pubkey: &str) -> Vec<StoredEnvelope> {
        let r_clean = recipient_pubkey.trim().to_lowercase();
        self.envelopes
            .values()
            .filter(|e| {
                e.sender_pubkey.eq_ignore_ascii_case(sender_pubkey)
                    && e.recipient_pubkey.eq_ignore_ascii_case(&r_clean)
            })
            .cloned()
            .collect()
    }

    /// Descarta envelopes na outbox local destinados a `recipient_pubkey` (opcionalmente filtrado por tópico, ex.: pedidos de amizade)
    pub fn discard_outbox_for(
        &mut self,
        sender_pubkey: &str,
        recipient_pubkey: &str,
        topic_filter: Option<&str>,
    ) -> usize {
        let r_clean = recipient_pubkey.trim().to_lowercase();
        let before = self.envelopes.len();
        let own_topics = &mut self.own_topics;
        let delegated = &mut self.delegated_guardians;
        self.envelopes.retain(|id, env| {
            let matches = env.sender_pubkey.eq_ignore_ascii_case(sender_pubkey)
                && env.recipient_pubkey.eq_ignore_ascii_case(&r_clean)
                && topic_filter.map_or(true, |t| own_topics.get(id).map_or(false, |top| top == t));
            if matches {
                delegated.remove(id);
                own_topics.remove(id);
                false
            } else {
                true
            }
        });
        let removed = before.saturating_sub(self.envelopes.len());
        if removed > 0 {
            self.persist();
        }
        removed
    }

    /// Retorna apenas os envelopes enviados por `sender_pubkey` que AINDA NÃO foram delegados ao amigo `guardian_pubkey`
    pub fn undelegated_for_guardian(
        &self,
        sender_pubkey: &str,
        guardian_pubkey: &str,
        now: u64,
    ) -> Vec<StoredEnvelope> {
        let g_clean = guardian_pubkey.trim().to_lowercase();
        self.envelopes
            .values()
            .filter(|e| {
                e.expires_at > now
                    && e.sender_pubkey.eq_ignore_ascii_case(sender_pubkey)
                    && !e.recipient_pubkey.eq_ignore_ascii_case(&g_clean)
                    && !self
                        .delegated_guardians
                        .get(&e.envelope_id)
                        .is_some_and(|set| set.contains(&g_clean))
            })
            .cloned()
            .collect()
    }

    /// Registra que o envelope `envelope_id` já foi delegado para o amigo guardião `guardian_pubkey`
    pub fn mark_delegated_to_guardian(&mut self, envelope_id: &str, guardian_pubkey: &str) {
        let g_clean = guardian_pubkey.trim().to_lowercase();
        let entry = self
            .delegated_guardians
            .entry(envelope_id.to_string())
            .or_default();
        if entry.insert(g_clean) {
            self.persist();
        }
    }

    /// Marca um envelope como recebido pelo destinatário local e guarda o ACK assinado;
    /// retorna `true` se é inédito (não duplicado), mesmo após reiniciar o app!
    pub fn mark_delivered_to_me(&mut self, envelope_id: &str, ack: ReceiptAck) -> bool {
        self.envelopes.remove(envelope_id);
        self.delegated_guardians.remove(envelope_id);
        let is_new = !self.acks.contains_key(envelope_id);
        self.acks.insert(envelope_id.to_string(), ack);
        self.persist();
        is_new
    }

    /// Retorna o ACK já assinado para um envelope (se já tiver sido entregue)
    pub fn get_ack(&self, envelope_id: &str) -> Option<ReceiptAck> {
        self.acks.get(envelope_id).cloned()
    }

    /// Processa um `ReceiptAck` assinado pelo destinatário e remove o envelope do disco do guardião/remetente
    pub fn apply_ack(&mut self, ack: &ReceiptAck) -> bool {
        if !ack.verify() {
            return false;
        }
        if let Some(env) = self.envelopes.get(&ack.envelope_id) {
            if !env.recipient_pubkey.eq_ignore_ascii_case(&ack.recipient_pubkey) {
                return false;
            }
        }
        let is_new_ack = !self.acks.contains_key(&ack.envelope_id);
        self.acks.insert(ack.envelope_id.clone(), ack.clone());
        self.delegated_guardians.remove(&ack.envelope_id);
        self.own_topics.remove(&ack.envelope_id);
        let removed = self.envelopes.remove(&ack.envelope_id).is_some();
        if removed || is_new_ack {
            self.persist();
        }
        removed
    }

    /// Remove envelopes e registros de entrega expirados
    pub fn purge_expired(&mut self, now: u64) -> usize {
        let before = self.envelopes.len();
        self.envelopes.retain(|_, env| env.expires_at > now);
        self.delegated_guardians
            .retain(|id, _| self.envelopes.contains_key(id));
        self.own_topics
            .retain(|id, _| self.envelopes.contains_key(id));
        let removed = before.saturating_sub(self.envelopes.len());

        // Issue #71: Expurgar ACKs antigos (reter por no máximo 7 dias para evitar acúmulo no disco)
        const MAX_ACK_RETENTION_SECS: u64 = 7 * 86_400;
        let ack_before = self.acks.len();
        self.acks.retain(|_, ack| {
            let ack_ts_secs = StoredEnvelope::created_at_secs(ack.timestamp);
            now.saturating_sub(ack_ts_secs) < MAX_ACK_RETENTION_SECS
        });
        let acks_removed = ack_before.saturating_sub(self.acks.len());

        if removed > 0 || acks_removed > 0 {
            self.persist();
        }
        removed
    }

    /// Retorna todos os ACKs conhecidos (útil para avisar amigos/guardiões de entregas já concluídas)
    pub fn known_acks(&self) -> Vec<ReceiptAck> {
        self.acks.values().cloned().collect()
    }

    pub fn total_bytes(&self) -> u64 {
        self.envelopes.values().map(|e| e.size_bytes() as u64).sum()
    }

    pub fn friend_bytes(&self, sender_pubkey: &str) -> u64 {
        self.envelopes
            .values()
            .filter(|e| e.sender_pubkey.eq_ignore_ascii_case(sender_pubkey))
            .map(|e| e.size_bytes() as u64)
            .sum()
    }

    /// Verifica se o envelope já está armazenado ou já foi entregue/confirmado neste nó
    pub fn has_envelope_or_ack(&self, envelope_id: &str) -> bool {
        self.envelopes.contains_key(envelope_id) || self.acks.contains_key(envelope_id)
    }

    pub fn envelope_count(&self) -> usize {
        self.envelopes.len()
    }
}

// ============================================================================
// FIREWALL UNIFICADO DO NÓ (REEXPORTADO DE `crate::firewall`)
// ============================================================================

pub use crate::firewall::{
    DmFirewall, DmFirewallVerdict, FirewallBlockEntry, FirewallCategory, FirewallVerdict,
    NodeFirewall, RelayAccessControl,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dm_topic_is_deterministic_and_symmetric() {
        let alice = UserIdentity::generate_with_nick("Alice");
        let bob = UserIdentity::generate_with_nick("Bob");
        let t1 = dm_topic(&alice.public_key_hex(), &bob.public_key_hex());
        let t2 = dm_topic(&bob.public_key_hex(), &alice.public_key_hex());
        assert_eq!(t1, t2);
        assert!(t1.starts_with(DM_TOPIC_PREFIX));
        assert_eq!(t1.len(), DM_TOPIC_PREFIX.len() + 32);
    }

    #[test]
    fn test_e2ee_direct_message_and_ephemeral_session_forward_secrecy() {
        let alice = UserIdentity::generate_with_nick("Alice");
        let bob = UserIdentity::generate_with_nick("Bob");
        let mallory = UserIdentity::generate_with_nick("Mallory");

        // 1. Envio sem sessão prévia (Sealed Box efêmero -> identidade de Bob)
        let env1 = DirectMessageEnvelope::seal(
            &alice,
            &bob.public_key_hex(),
            "Oi Bob, mensagem 1!",
            1000,
            None,
        )
        .unwrap();

        // Mallory (intermediária no Gossipsub) não consegue decifrar
        assert!(env1.open(&mallory, None).is_err());

        // Bob decifra e verifica assinatura de Alice
        let dec1 = env1.open(&bob, None).unwrap();
        assert_eq!(dec1.text, "Oi Bob, mensagem 1!");
        assert_eq!(dec1.sender_nick, "Alice");
        assert_eq!(dec1.sender_pubkey, alice.public_key_hex());

        // 2. Handshake de Sessão Efêmera X25519 assinada (Forward Secrecy)
        let mut alice_sess = DmPeerSession::new();
        let mut bob_sess = DmPeerSession::new();

        let offer_a = EphemeralKeyOffer::new_signed(
            &alice,
            &bob.public_key_hex(),
            alice_sess.my_ephemeral_public,
            1001,
        );
        let offer_b = EphemeralKeyOffer::new_signed(
            &bob,
            &alice.public_key_hex(),
            bob_sess.my_ephemeral_public,
            1001,
        );
        assert!(offer_a.verify());
        assert!(offer_b.verify());

        alice_sess.apply_peer_offer(offer_b.ephemeral_pubkey);
        bob_sess.apply_peer_offer(offer_a.ephemeral_pubkey);
        assert_eq!(alice_sess.shared_session_key, bob_sess.shared_session_key);

        // Mensagem cifrada com a chave de sessão efêmera
        let env2 = DirectMessageEnvelope::seal(
            &alice,
            &bob.public_key_hex(),
            "Mensagem com Forward Secrecy!",
            1002,
            alice_sess.shared_session_key.as_ref(),
        )
        .unwrap();
        assert!(env2.uses_session_key);

        // Sem a chave de sessão efêmera, nem mesmo a chave de identidade de Bob decifra
        assert!(env2.open(&bob, None).is_err());
        // Com a chave de sessão efêmera, Bob decifra normalmente
        let dec2 = env2.open(&bob, bob_sess.shared_session_key.as_ref()).unwrap();
        assert_eq!(dec2.text, "Mensagem com Forward Secrecy!");
    }

    #[test]
    fn test_offline_mailbox_sign_then_seal_via_stranger_guardian_and_ttl_negotiation() {
        let mut alice = UserIdentity::generate_with_nick("Alice");
        let mut carol = UserIdentity::generate_with_nick("Carol"); // Amiga da Alice, estranha para Bob
        let bob = UserIdentity::generate_with_nick("Bob");
        let mallory = UserIdentity::generate_with_nick("Mallory");

        // Alice e Carol são amigas; Bob NÃO conhece Carol
        alice.add_friend(&carol.public_key_hex(), Some("Carol")).unwrap();
        carol.add_friend(&alice.public_key_hex(), Some("Alice")).unwrap();

        let carol_cfg = NodeConfig::default(); // max_message_ttl_days = 7 dias
        let mut carol_store = MailboxStore::load(None, 2000);

        // Alice cria envelope offline para Bob sugerindo TTL de 2 horas (7200s)
        let env = StoredEnvelope::create_signed_and_sealed(
            &alice,
            &bob.public_key_hex(),
            "Bob, me liga quando entrar!",
            2000,
            Some(7200),
        )
        .unwrap();

        // Guardião recusa se o remetente não for amigo (ex: Mallory tentando usar o disco de Carol)
        let mallory_env = StoredEnvelope::create_signed_and_sealed(
            &mallory,
            &bob.public_key_hex(),
            "Spam!",
            2000,
            None,
        )
        .unwrap();
        assert_eq!(
            carol_store.store_for_friend(mallory_env, false, &carol_cfg, 2000),
            Err(DmError::NotAFriend)
        );

        // Carol aceita guardar o envelope da amiga Alice e negocia o TTL efetivo = min(2h, 7d) = 2h
        let effective_ttl = carol_store
            .store_for_friend(env.clone(), true, &carol_cfg, 2000)
            .unwrap();
        assert_eq!(effective_ttl, 7200);
        assert_eq!(carol_store.envelope_count(), 1);

        // Carol NÃO consegue decifrar o envelope que está guardando
        assert!(env.unseal_and_verify(&carol).is_err());

        // Quando Bob entra online, Carol encontra o envelope para Bob e entrega
        let pending = carol_store.pending_for_recipient(&bob.public_key_hex(), 2100);
        assert_eq!(pending.len(), 1);

        // Bob (que não conhece Carol) decifra com sua chave privada e valida a assinatura interna de Alice!
        let delivered = &pending[0];
        let payload = delivered.unseal_and_verify(&bob).unwrap();
        assert_eq!(payload.sender_pubkey, alice.public_key_hex());
        assert_eq!(payload.sender_nick, "Alice");
        assert_eq!(payload.text, "Bob, me liga quando entrar!");

        // Bob emite ReceiptAck e Carol apaga do disco
        let ack = ReceiptAck::new_signed(&bob, &delivered.envelope_id, 2105);
        assert!(carol_store.apply_ack(&ack));
        assert_eq!(carol_store.envelope_count(), 0);
    }

    #[test]
    fn test_mailbox_ttl_expiration_and_quota_enforcement() {
        let alice = UserIdentity::generate_with_nick("Alice");
        let bob = UserIdentity::generate_with_nick("Bob");

        let mut cfg = NodeConfig::default();
        cfg.mailbox.max_envelope_size_kb = 1; // 1 KB máx por envelope
        cfg.mailbox.max_message_ttl_days = 1; // 1 dia máx (86400s)

        let mut store = MailboxStore::load(None, 1000);

        // Alice pede 30 dias, mas Carol limita em 1 dia (86400s)
        let env = StoredEnvelope::create_signed_and_sealed(
            &alice,
            &bob.public_key_hex(),
            "Curta",
            1000,
            Some(30 * 86_400),
        )
        .unwrap();
        let ttl = store.store_for_friend(env, true, &cfg, 1000).unwrap();
        assert_eq!(ttl, 86_400);

        // Envelope maior que 1 KB é recusado
        let huge_text = "x".repeat(2048);
        let huge_env = StoredEnvelope::create_signed_and_sealed(
            &alice,
            &bob.public_key_hex(),
            &huge_text,
            1000,
            None,
        )
        .unwrap();
        assert_eq!(
            store.store_for_friend(huge_env, true, &cfg, 1000),
            Err(DmError::EnvelopeTooLarge)
        );

        // Após 1000 + 86401 segundos, o envelope expira e é purgado
        assert_eq!(store.purge_expired(1000 + 86_401), 1);
        assert_eq!(store.envelope_count(), 0);
    }

    #[test]
    fn test_delivered_ids_and_acks_persist_across_restarts_preventing_duplicate_delivery() {
        let alice = UserIdentity::generate_with_nick("Alice");
        let carol = UserIdentity::generate_with_nick("Carol");
        let dir = std::env::temp_dir().join(format!("anarchord_mailbox_dedup_{}", rand::random::<u64>()));
        let _ = fs::create_dir_all(&dir);
        let carol_file = dir.join("carol_mailbox.json");
        let alice_file = dir.join("alice_mailbox.json");

        let cfg = NodeConfig::default();
        let env = StoredEnvelope::create_signed_and_sealed(
            &alice,
            &carol.public_key_hex(),
            "Oi Carol, mensagem única!",
            5000,
            Some(3600),
        )
        .unwrap();

        // Alice guarda na sua outbox local
        let mut alice_store = MailboxStore::load(Some(alice_file.clone()), 5000);
        alice_store.insert_own(env.clone(), &cfg, 5000);
        assert_eq!(alice_store.envelope_count(), 1);

        // Carol recebe de Bob (enquanto Alice estava offline) e marca como entregue
        let mut carol_store = MailboxStore::load(Some(carol_file.clone()), 5010);
        let ack = ReceiptAck::new_signed(&carol, &env.envelope_id, 5010);
        assert!(carol_store.mark_delivered_to_me(&env.envelope_id, ack.clone()));
        // Na mesma sessão já retorna false
        assert!(!carol_store.mark_delivered_to_me(&env.envelope_id, ack));

        // Verifica que o JSON persistido NÃO contém 'delivered_ids' redundante e serializa 'acks' como lista compacta
        let saved_json = fs::read_to_string(&carol_file).unwrap();
        assert!(!saved_json.contains(r#""delivered_ids""#), "delivered_ids redundante não deve ser persistido no disco");
        assert!(saved_json.contains(r#""acks": ["#), "acks deve ser serializado como lista de objetos JSON");

        // Carol FECHA e ABRE o programa novamente (recarrega do disco)
        let mut carol_restarted = MailboxStore::load(Some(carol_file), 5020);
        let saved_ack = carol_restarted.get_ack(&env.envelope_id).expect("ACK deve estar salvo no disco");
        assert!(
            !carol_restarted.mark_delivered_to_me(&env.envelope_id, saved_ack.clone()),
            "Carol NÃO deve aceitar a mesma mensagem novamente após reiniciar o app!"
        );

        // E o ACK salvo por Carol limpa a outbox da Alice quando elas se reconectam
        assert!(alice_store.apply_ack(&saved_ack));
        assert_eq!(alice_store.envelope_count(), 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_dm_firewall_asymmetric_friend_vs_stranger_limits_and_progressive_block() {
        let alice = UserIdentity::generate_with_nick("Alice");
        let bob = UserIdentity::generate_with_nick("Bob");
        let mut fw = DmFirewall::new();
        let policy = DmPolicyConfig::default(); // stranger = 3 msg/min (1024B), friend = 30 msg/min (8192B)

        // Alice adicionou Carol como amiga, mas Carol NÃO tem Alice nos amigos (is_my_friend = false para Carol!)
        // As 3 primeiras mensagens de Alice (desconhecida para Carol) passam:
        for i in 0..3 {
            assert_eq!(
                fw.check_incoming_dm(&alice.public_key_hex(), false, 100, false, &policy, 1000 + i),
                DmFirewallVerdict::Allowed
            );
        }

        // A 4ª mensagem no mesmo minuto excede o limite de desconhecido (3/min) -> Bloqueio Nível 1 (60s) + aviso de cortesia!
        let v4 = fw.check_incoming_dm(&alice.public_key_hex(), false, 100, false, &policy, 1005);
        assert_eq!(
            v4,
            DmFirewallVerdict::NewlyBlocked {
                reason: "limite de taxa para desconhecido excedido (3 msg/min)".to_string(),
                duration_secs: 60,
                blocked_until: 1065,
                offense_level: 1,
                send_courtesy: true,
            }
        );

        // Enquanto bloqueada (t = 1020), novas tentativas são descartadas silenciosamente sem reenviar cortesia
        let v5 = fw.check_incoming_dm(&alice.public_key_hex(), false, 100, false, &policy, 1020);
        assert!(matches!(v5, DmFirewallVerdict::DroppedSilently { .. }));

        // Enquanto isso, Bob (que É amigo de Carol: is_my_friend = true) manda 10 mensagens grandes (2000B) e todas passam!
        for i in 0..10 {
            assert_eq!(
                fw.check_incoming_dm(&bob.public_key_hex(), true, 2000, false, &policy, 1010 + i),
                DmFirewallVerdict::Allowed
            );
        }

        // Após expirar o 1º bloqueio de Alice (t = 1070), se ela reincidir enviando mensagem > 1024B para desconhecido,
        // o bloqueio sobe para Nível 2 = 300s (5 min)!
        let v_reoffend = fw.check_incoming_dm(&alice.public_key_hex(), false, 2048, false, &policy, 1070);
        assert_eq!(
            v_reoffend,
            DmFirewallVerdict::NewlyBlocked {
                reason: "mensagem excedeu tamanho máximo para desconhecido (2048 > 1024 bytes)".to_string(),
                duration_secs: 300,
                blocked_until: 1370,
                offense_level: 2,
                send_courtesy: true,
            }
        );

        // Se Carol decidir adicionar Alice como amiga (ou rodar /firewall unblock), o bloqueio é removido imediatamente
        assert!(fw.unblock(&alice.public_key_hex()));
        assert_eq!(
            fw.check_incoming_dm(&alice.public_key_hex(), true, 2048, false, &policy, 1075),
            DmFirewallVerdict::Allowed
        );
    }

    #[test]
    fn test_event_driven_guardian_delegation_tracking() {
        let alice = UserIdentity::generate_with_nick("Alice");
        let bob = UserIdentity::generate_with_nick("Bob");
        let carol = UserIdentity::generate_with_nick("Carol");
        let dave = UserIdentity::generate_with_nick("Dave");

        let cfg = NodeConfig::default();
        let mut alice_store = MailboxStore::load(None, 3000);
        let env = StoredEnvelope::create_signed_and_sealed(
            &alice,
            &bob.public_key_hex(),
            "Oi Bob!",
            3000,
            Some(3600),
        )
        .unwrap();
        let env_id = env.envelope_id.clone();
        alice_store.insert_own(env, &cfg, 3000);

        // Quando Carol fica online pela 1ª vez, Alice ainda não pediu para Carol ser guardiã:
        let for_carol = alice_store.undelegated_for_guardian(
            &alice.public_key_hex(),
            &carol.public_key_hex(),
            3010,
        );
        assert_eq!(for_carol.len(), 1);

        // Alice publica Store para Carol e marca que Carol já recebeu o pedido:
        alice_store.mark_delegated_to_guardian(&env_id, &carol.public_key_hex());

        // Se Carol oscilar ou outro evento chegar, Alice sabe que JÁ pediu para Carol e não reenvia:
        let for_carol_again = alice_store.undelegated_for_guardian(
            &alice.public_key_hex(),
            &carol.public_key_hex(),
            3020,
        );
        assert!(for_carol_again.is_empty());

        // Porém, quando um segundo amigo (Dave) entra online depois, Alice sabe que AINDA NÃO pediu para Dave!
        let for_dave = alice_store.undelegated_for_guardian(
            &alice.public_key_hex(),
            &dave.public_key_hex(),
            3025,
        );
        assert_eq!(for_dave.len(), 1);
    }

    #[test]
    fn test_e2ee_dm_with_encryption_key_rotation() {
        let mut alice = UserIdentity::generate_with_nick("Alice");
        let mut bob = UserIdentity::generate_with_nick("Bob");

        let bob_uid = bob.public_key_hex();
        alice.add_friend(&bob_uid, Some("Bob")).unwrap();

        // 1. Mensagem inicial antes da rotação (usa chave inicial)
        let env1 = DirectMessageEnvelope::seal(&alice, &bob_uid, "Olá Bob antes da rotação", 1000, None).unwrap();
        let dec1 = env1.open(&bob, None).unwrap();
        assert_eq!(dec1.text, "Olá Bob antes da rotação");

        // 2. Bob rotaciona sua chave de criptografia
        let ad = bob.rotate_encryption_key();
        assert_eq!(bob.encryption_epoch(), 1);

        // Bob anuncia para Alice e Alice atualiza a chave de Bob
        assert!(alice.update_friend_encryption_key(&ad).unwrap());
        assert_eq!(
            alice.friend_encryption_public_key(&bob_uid).unwrap().to_bytes(),
            bob.encryption_public_key().to_bytes()
        );

        // 3. Alice agora envia uma nova DM cifrada com a nova chave X25519 de Bob
        let env2 = DirectMessageEnvelope::seal(&alice, &bob_uid, "Olá Bob com chave rotacionada!", 2000, None).unwrap();

        // Bob decifra com sucesso usando sua nova chave nativa
        let dec2 = env2.open(&bob, None).unwrap();
        assert_eq!(dec2.text, "Olá Bob com chave rotacionada!");
        assert_eq!(dec2.sender_pubkey, alice.public_key_hex());
    }

    #[test]
    fn test_offline_mailbox_and_dm_decrypts_with_historical_keys_after_multiple_rotations() {
        let alice = UserIdentity::generate_with_nick("Alice");
        let mut bob = UserIdentity::generate_with_nick("Bob");
        let bob_uid = bob.public_key_hex();

        // 1. Alice cria um StoredEnvelope offline e uma DM para Bob na época 0
        let offline_env_epoch0 = StoredEnvelope::create_signed_and_sealed(
            &alice,
            &bob_uid,
            "Mensagem offline guardada na época 0",
            1000,
            Some(3600),
        ).unwrap();
        assert!(offline_env_epoch0.verify_outer());

        let dm_env_epoch0 = DirectMessageEnvelope::seal(
            &alice,
            &bob_uid,
            "DM em voo cifrada na época 0",
            1000,
            None,
        ).unwrap();

        // 2. Bob rotaciona a chave duas vezes antes de receber as mensagens (vai para época 1 e depois 2)
        let _ad1 = bob.rotate_encryption_key();
        assert_eq!(bob.encryption_epoch(), 1);
        assert_eq!(bob.previous_encryption_keys().len(), 1);

        let _ad2 = bob.rotate_encryption_key();
        assert_eq!(bob.encryption_epoch(), 2);
        assert_eq!(bob.previous_encryption_keys().len(), 2);

        // 3. Bob recebe a DM em voo e o StoredEnvelope antigo da Mailbox
        // Graças ao histórico de chaves arquivado no UserIdentity, Bob decifra ambos com sucesso!
        let dec_dm = dm_env_epoch0.open(&bob, None).unwrap();
        assert_eq!(dec_dm.text, "DM em voo cifrada na época 0");

        let dec_offline = offline_env_epoch0.unseal_and_verify(&bob).unwrap();
        assert_eq!(dec_offline.text, "Mensagem offline guardada na época 0");
        assert_eq!(dec_offline.topic, DEFAULT_MAILBOX_TOPIC);

        // 4. Teste de envelope com tópico genérico personalizado (rede de guardiões cega ao conteúdo/tópico)
        let custom_env = StoredEnvelope::create_signed_and_sealed_topic(
            &alice,
            &bob_uid,
            "presence_update",
            "offline presence payload",
            2000,
            Some(7200),
        ).unwrap();
        assert!(custom_env.verify_outer());
        let dec_custom = custom_env.unseal_and_verify(&bob).unwrap();
        assert_eq!(dec_custom.text, "offline presence payload");
        assert_eq!(dec_custom.topic, "presence_update");
    }

    #[test]
    fn test_friend_request_and_response_signed_protocol() {
        let alice = UserIdentity::generate_with_nick("Alice");
        let bob = UserIdentity::generate_with_nick("Bob");
        let mallory = UserIdentity::generate_with_nick("Mallory");

        let alice_pk = alice.public_key_hex();
        let bob_pk = bob.public_key_hex();

        // 1. Alice cria pedido de amizade assinado para Bob
        let req = FriendRequest::new_signed(&alice, &bob_pk, Some("Olá Bob, vamos conectar!"), 1000);
        assert!(req.verify());
        assert_eq!(req.sender_pubkey, alice_pk);
        assert_eq!(req.recipient_pubkey, bob_pk);
        assert_eq!(req.message.as_deref(), Some("Olá Bob, vamos conectar!"));
        assert!(req.encryption_advertisement.verify());

        // Forjamento: se Mallory tentar assinar com sua própria chave fingindo ser Alice
        let mut tampered_req = req.clone();
        tampered_req.signature = mallory.sign(b"fake");
        assert!(!tampered_req.verify());

        // 2. Bob responde Aceitando com resposta assinada e seu anúncio de chave
        let resp_accept = FriendResponse::new_signed(&bob, &alice_pk, true, 1005);
        assert!(resp_accept.verify());
        assert!(resp_accept.accepted);
        assert!(resp_accept.encryption_advertisement.is_some());
        assert!(resp_accept.encryption_advertisement.as_ref().unwrap().verify());

        // 3. Bob responde Rejeitando
        let resp_reject = FriendResponse::new_signed(&bob, &alice_pk, false, 1010);
        assert!(resp_reject.verify());
        assert!(!resp_reject.accepted);
        assert!(resp_reject.encryption_advertisement.is_none());

        // 4. Transporte assíncrono via Guardiões (Mailbox offline)
        let offline_req = StoredEnvelope::create_signed_and_sealed_topic(
            &alice,
            &bob_pk,
            FRIEND_REQUEST_MAILBOX_TOPIC,
            "Pedido offline via Guardiões",
            1020,
            None,
        ).unwrap();
        assert!(offline_req.verify_outer());

        // Bob desempacota e autentica Alice
        let unsealed = offline_req.unseal_and_verify(&bob).unwrap();
        assert_eq!(unsealed.sender_pubkey, alice_pk);
        assert_eq!(unsealed.text, "Pedido offline via Guardiões");
        assert_eq!(unsealed.topic, FRIEND_REQUEST_MAILBOX_TOPIC);
    }

    #[test]
    fn test_blind_guardian_base64_optimization_and_ack_purging() {
        let alice = UserIdentity::generate_with_nick("Alice");
        let bob = UserIdentity::generate_with_nick("Bob");
        let bob_pk = bob.public_key_hex();

        // 1. Cria StoredEnvelope com tópico interno
        let env = StoredEnvelope::create_signed_and_sealed_topic(
            &alice,
            &bob_pk,
            "topico_secreto",
            "conteúdo confidencial",
            1_000_000,
            Some(3600),
        ).unwrap();

        // 2. Verifica que a serialização JSON usa Base64 e NÃO vaza 'topic' para o guardião
        let json = serde_json::to_string(&env).unwrap();
        assert!(!json.contains(r#""topic""#), "O guardião não deve ter acesso ao campo topic");
        assert!(!json.contains(r#""topic_legacy""#));
        // Confirma que campos binários são strings Base64 e não arrays numéricos
        assert!(json.contains(r#""ciphertext":""#));
        assert!(json.contains(r#""ephemeral_pubkey":""#));
        assert!(json.contains(r#""nonce":""#));
        assert!(json.contains(r#""outer_signature":""#));

        // Deserializa o JSON de volta para StoredEnvelope
        let decoded: StoredEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.envelope_id, env.envelope_id);
        assert!(decoded.verify_outer());

        // Bob decifra e encontra o tópico original
        let unsealed = decoded.unseal_and_verify(&bob).unwrap();
        assert_eq!(unsealed.topic, "topico_secreto");
        assert_eq!(unsealed.text, "conteúdo confidencial");

        // 3. ReceiptAck serializa assinatura em Base64
        let ack = ReceiptAck::new_signed(&bob, &env.envelope_id, 1_000_100);
        let ack_json = serde_json::to_string(&ack).unwrap();
        assert!(ack_json.contains(r#""signature":""#));
        assert_eq!(serde_json::from_str::<ReceiptAck>(&ack_json).unwrap(), ack);

        // 4. Retrocompatibilidade: aceita envelopes antigos com arrays numéricos e 'topic' externo no JSON
        let legacy_json = format!(
            r#"{{"envelope_id":"test1234","sender_pubkey":"{}","recipient_pubkey":"{}","topic":"dm","ephemeral_pubkey":{:?},"nonce":{:?},"ciphertext":{:?},"created_at":1000,"suggested_ttl":3600,"expires_at":4600,"outer_signature":{:?}}}"#,
            alice.public_key_hex(),
            bob_pk,
            vec![1u8; 32],
            vec![2u8; 12],
            vec![3u8; 20],
            vec![4u8; 64],
        );
        let legacy_env: Result<StoredEnvelope, _> = serde_json::from_str(&legacy_json);
        assert!(legacy_env.is_ok(), "Deve deserializar JSON legado com arrays numéricos e topic ignorado");

        // 5. Expurgar ACKs antigos no MailboxStore
        let mut store = MailboxStore::load(None, 1000);
        store.acks.insert(ack.envelope_id.clone(), ack);
        assert_eq!(store.acks.len(), 1);

        // Se passar menos de 7 dias (ex.: 1 dia = 86400s), ACK é preservado
        store.purge_expired(1_000_100 + 86_400);
        assert_eq!(store.acks.len(), 1, "ACK recente não deve ser expurgado");

        // Se passar mais de 7 dias (ex.: 8 dias), ACK é expurgado
        store.purge_expired(1_000_100 + 8 * 86_400);
        assert_eq!(store.acks.len(), 0, "ACK com mais de 7 dias deve ser expurgado");
    }

    #[test]
    fn test_outbox_retention_and_topic_discard() {
        let alice = UserIdentity::generate_with_nick("Alice");
        let bob = UserIdentity::generate_with_nick("Bob");
        let cfg = NodeConfig::default();
        let mut store = MailboxStore::load(None, 1000);

        let env_dm = StoredEnvelope::create_signed_and_sealed(
            &alice,
            &bob.public_key_hex(),
            "DM text",
            1000,
            None,
        ).unwrap();
        let env_req = StoredEnvelope::create_signed_and_sealed_topic(
            &alice,
            &bob.public_key_hex(),
            FRIEND_REQUEST_MAILBOX_TOPIC,
            "Req text",
            1000,
            None,
        ).unwrap();

        store.insert_own_with_topic(env_dm.clone(), DEFAULT_MAILBOX_TOPIC, &cfg, 1000);
        store.insert_own_with_topic(env_req.clone(), FRIEND_REQUEST_MAILBOX_TOPIC, &cfg, 1000);

        let pending = store.pending_outbox_for(&alice.public_key_hex(), &bob.public_key_hex());
        assert_eq!(pending.len(), 2);
        assert_eq!(store.get_own_topic(&env_dm.envelope_id), Some(DEFAULT_MAILBOX_TOPIC));
        assert_eq!(store.get_own_topic(&env_req.envelope_id), Some(FRIEND_REQUEST_MAILBOX_TOPIC));

        // Descarta apenas o pedido de amizade
        let discarded = store.discard_outbox_for(&alice.public_key_hex(), &bob.public_key_hex(), Some(FRIEND_REQUEST_MAILBOX_TOPIC));
        assert_eq!(discarded, 1);

        let remaining = store.pending_outbox_for(&alice.public_key_hex(), &bob.public_key_hex());
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].envelope_id, env_dm.envelope_id);
    }

    #[test]
    fn test_firewall_purge_expired_blocks() {
        let mut fw = DmFirewall::new();
        let alice_pk = "a".repeat(64);
        let bob_pk = "b".repeat(64);

        // Bloqueia Alice até t=1050 e Bob até t=2000
        fw.peers.entry(alice_pk.clone()).or_default().blocked_until = Some(1050);
        fw.peers.entry(bob_pk.clone()).or_default().blocked_until = Some(2000);

        assert!(fw.is_blocked(&alice_pk, 1000));
        assert!(fw.is_blocked(&bob_pk, 1000));

        // Em t=1000 nada é purgado
        let unblocked = fw.purge_expired_blocks(1000);
        assert!(unblocked.is_empty());

        // Em t=1100 Alice é purgada e desbloqueada
        let unblocked = fw.purge_expired_blocks(1100);
        assert_eq!(unblocked.len(), 1);
        assert_eq!(unblocked[0], alice_pk);
        assert!(!fw.is_blocked(&alice_pk, 1100));
        assert!(fw.is_blocked(&bob_pk, 1100));

        // Em t=2005 Bob é purgado e desbloqueado
        let unblocked = fw.purge_expired_blocks(2005);
        assert_eq!(unblocked.len(), 1);
        assert_eq!(unblocked[0], bob_pk);
        assert!(!fw.is_blocked(&bob_pk, 2005));
    }
}
