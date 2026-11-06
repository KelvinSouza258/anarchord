//! Mensagens Diretas Privadas (DM 1:1) com Tópico Mútuo Gossipsub, Criptografia E2EE
//! (X25519 + HKDF-SHA256 + ChaCha20-Poly1305), Sessões Efêmeras (Forward Secrecy)
//! e Mailbox Offline Descentralizada (Store-and-Forward via Guardiões Amigos).

use crate::config::{DmPolicyConfig, NodeConfig};
use crate::identity::{verify_signature_hex, UserIdentity};
use crate::wire;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
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

/// Carga interna autenticada e assinada pelo autor (Sign-then-Seal)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SignedDmPayload {
    pub sender_pubkey: String,
    pub sender_nick: String,
    pub recipient_pubkey: String,
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
        let sender_pubkey = identity.public_key_hex();
        let sender_nick = identity.profile.display_name.clone();
        let recipient_pubkey = recipient_pubkey.trim().to_lowercase();
        let sig_bytes = Self::signing_bytes(&sender_pubkey, &sender_nick, &recipient_pubkey, text, timestamp);
        let signature = identity.sign(&sig_bytes);
        Self {
            sender_pubkey,
            sender_nick,
            recipient_pubkey,
            text: text.to_string(),
            timestamp,
            signature,
        }
    }

    fn signing_bytes(
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
            &self.text,
            self.timestamp,
        );
        verify_signature_hex(&self.sender_pubkey, &bytes, &self.signature)
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

/// Mensagens que circulam no tópico de DM
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum DmWireMessage {
    KeyOffer(EphemeralKeyOffer),
    Message(DirectMessageEnvelope),
    KeyAdvertisement(crate::identity::SignedEncryptionKeyAdvertisement),
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

fn default_envelope_topic() -> String {
    DEFAULT_MAILBOX_TOPIC.to_string()
}

/// Envelope cifrado Sign-then-Seal armazenado por guardiões amigos quando o destinatário está offline.
/// O guardião (Carol) vê apenas `sender_pubkey`, `recipient_pubkey` e `topic`, sem conhecer o conteúdo interno;
/// a rede de guardiões atua como middleware agnóstico ao conteúdo para entrega assíncrona.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct StoredEnvelope {
    /// Identificador único determinístico (SHA-256 do ciphertext + nonce) para deduplicação
    pub envelope_id: String,
    /// Chave pública Ed25519 do remetente (Alice) — permite a Carol verificar que Alice é amiga dela
    pub sender_pubkey: String,
    /// Chave pública Ed25519 do destinatário (Bob) — permite a Carol saber para quem entregar
    pub recipient_pubkey: String,
    /// Tópico / Finalidade do envelope (ex.: "dm", "key_adv", etc.).
    #[serde(default = "default_envelope_topic")]
    pub topic: String,
    /// Chave efêmera pública X25519 gerada por Alice exclusivamente para este envelope
    pub ephemeral_pubkey: [u8; 32],
    /// Nonce ChaCha20-Poly1305
    pub nonce: [u8; 12],
    /// Carga cifrada contendo `SignedDmPayload` (texto + timestamp + assinatura Ed25519 de Alice)
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    /// Timestamp UNIX de criação
    pub created_at: u64,
    /// Sugestão opcional de TTL em segundos pedida por Alice
    pub suggested_ttl: Option<u64>,
    /// Timestamp UNIX de expiração calculado pelo guardião (`created_at + effective_ttl`)
    pub expires_at: u64,
    /// Assinatura externa de Alice sobre os metadados do envelope (impede que terceiros forjem pedidos em nome de Alice)
    #[serde(with = "serde_bytes")]
    pub outer_signature: Vec<u8>,
}

/// Confirmação de recebimento emitida pelo destinatário (Bob) para que os guardiões apaguem o envelope
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ReceiptAck {
    pub envelope_id: String,
    pub recipient_pubkey: String,
    pub timestamp: u64,
    #[serde(with = "serde_bytes")]
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

        // 1. Sign: Alice assina o payload interno com sua chave privada Ed25519
        let signed_inner = SignedDmPayload::new_signed(sender_identity, &recipient_clean, text, created_at);
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
            topic,
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
            topic: topic.to_string(),
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
        topic: &str,
        ephemeral_pubkey: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        created_at: u64,
        suggested_ttl: Option<u64>,
    ) -> Vec<u8> {
        if topic == DEFAULT_MAILBOX_TOPIC {
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
            postcard::to_extend(&tuple, b"anarchord-sealed-outer-v1\0".to_vec()).expect("serializável")
        } else {
            let tuple = (
                envelope_id,
                sender_pubkey,
                recipient_pubkey,
                topic,
                ephemeral_pubkey,
                nonce,
                ciphertext,
                created_at,
                suggested_ttl,
            );
            postcard::to_extend(&tuple, b"anarchord-sealed-outer-v2\0".to_vec()).expect("serializável")
        }
    }

    /// Verifica se o pedido de armazenamento foi realmente assinado por `sender_pubkey`
    pub fn verify_outer(&self) -> bool {
        let bytes = Self::outer_signing_bytes(
            &self.envelope_id,
            &self.sender_pubkey,
            &self.recipient_pubkey,
            &self.topic,
            &self.ephemeral_pubkey,
            &self.nonce,
            &self.ciphertext,
            self.created_at,
            self.suggested_ttl,
        );
        verify_signature_hex(&self.sender_pubkey, &bytes, &self.outer_signature)
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

/// Estado persistido em `mailbox.json` no disco
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct PersistedMailbox {
    envelopes: Vec<StoredEnvelope>,
    /// IDs de envelopes já recebidos pelo destinatário local (`envelope_id` -> `expires_at`)
    delivered_ids: HashMap<String, u64>,
    /// ACKs assinados pelos destinatários (`envelope_id` -> `ReceiptAck`) para sincronizar outros guardiões
    acks: HashMap<String, ReceiptAck>,
    /// Quais amigos guardiões já receberam o pedido de guarda de cada envelope da outbox (`envelope_id` -> conjunto de `guardian_pubkey`)
    delegated_guardians: HashMap<String, HashSet<String>>,
}

/// Armazenamento local do Guardião (Carol/Bob) e Outbox do Remetente (Alice)
pub struct MailboxStore {
    storage_path: Option<PathBuf>,
    /// Envelopes guardados por este nó: envelope_id -> StoredEnvelope
    envelopes: HashMap<String, StoredEnvelope>,
    /// IDs de envelopes já recebidos e processados por este nó: envelope_id -> expires_at
    /// (persistido em disco para não exibir duplicado após reiniciar o app!)
    delivered_ids: HashMap<String, u64>,
    /// ACKs assinados conhecidos por este nó: envelope_id -> ReceiptAck
    /// (permite que o destinatário ou um guardião informe ao remetente/outros guardiões que já foi entregue)
    acks: HashMap<String, ReceiptAck>,
    /// Controle orientado a eventos da Outbox: `envelope_id` -> `HashSet<guardian_pubkey>` para os quais já pedimos guarda
    delegated_guardians: HashMap<String, HashSet<String>>,
}

impl MailboxStore {
    pub fn load(storage_path: Option<PathBuf>, now: u64) -> Self {
        let mut envelopes = HashMap::new();
        let mut delivered_ids = HashMap::new();
        let mut acks = HashMap::new();
        let mut delegated_guardians = HashMap::new();
        if let Some(ref path) = storage_path {
            if let Ok(bytes) = fs::read(path) {
                if let Ok(persisted) = serde_json::from_slice::<PersistedMailbox>(&bytes) {
                    for env in persisted.envelopes {
                        if env.expires_at > now {
                            envelopes.insert(env.envelope_id.clone(), env);
                        }
                    }
                    for (id, exp) in persisted.delivered_ids {
                        if exp > now {
                            delivered_ids.insert(id, exp);
                        }
                    }
                    for (id, ack) in persisted.acks {
                        if ack.verify() {
                            acks.insert(id, ack);
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
            delivered_ids,
            acks,
            delegated_guardians,
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
                delivered_ids: self.delivered_ids.clone(),
                acks: self.acks.clone(),
                delegated_guardians: self.delegated_guardians.clone(),
            };
            if let Ok(json) = serde_json::to_string_pretty(&data) {
                let _ = fs::write(path, json);
            }
        }
    }

    /// Guarda um envelope enviado pelo próprio nó (outbox local para reentrega direta ou a guardiões)
    pub fn insert_own(&mut self, mut envelope: StoredEnvelope, config: &NodeConfig, now: u64) {
        let effective_ttl = config.calculate_effective_ttl(envelope.suggested_ttl);
        envelope.expires_at = now.saturating_add(effective_ttl);
        self.envelopes.insert(envelope.envelope_id.clone(), envelope);
        self.persist();
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
        if self.delivered_ids.contains_key(&envelope.envelope_id) || self.acks.contains_key(&envelope.envelope_id) {
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
    pub fn mark_delivered_to_me(&mut self, envelope_id: &str, expires_at: u64, ack: ReceiptAck) -> bool {
        self.envelopes.remove(envelope_id);
        self.delegated_guardians.remove(envelope_id);
        self.acks.insert(envelope_id.to_string(), ack);
        let is_new = !self.delivered_ids.contains_key(envelope_id);
        self.delivered_ids.insert(envelope_id.to_string(), expires_at);
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
        let exp = ack.timestamp.saturating_add(7 * 86_400);
        self.delivered_ids.entry(ack.envelope_id.clone()).or_insert(exp);
        let is_new_ack = !self.acks.contains_key(&ack.envelope_id);
        self.acks.insert(ack.envelope_id.clone(), ack.clone());
        self.delegated_guardians.remove(&ack.envelope_id);
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
        self.delivered_ids.retain(|_, &mut exp| exp > now);
        let removed = before.saturating_sub(self.envelopes.len());
        if removed > 0 {
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
        self.envelopes.contains_key(envelope_id)
            || self.delivered_ids.contains_key(envelope_id)
            || self.acks.contains_key(envelope_id)
    }

    pub fn envelope_count(&self) -> usize {
        self.envelopes.len()
    }
}

// ============================================================================
// FIREWALL ASSIMÉTRICO DE DMs (AMIGOS vs DESCONHECIDOS) COM BLOQUEIO PROGRESSIVO
// ============================================================================

/// Estado de um remetente monitorado pelo Firewall de DMs
#[derive(Clone, Debug, Default)]
struct SenderRateState {
    /// Timestamps UNIX de DMs online recebidas nos últimos 60s
    online_timestamps: Vec<u64>,
    /// Timestamps UNIX de DMs offline (Mailbox) abertas na última 1h (3600s)
    offline_timestamps: Vec<u64>,
    /// Nível de reincidência de infrações (1 = 60s, 2 = 300s, 3 = 1800s, 4+ = 86400s)
    offense_level: u32,
    /// Timestamp UNIX da última infração (para decaimento por bom comportamento)
    last_offense_at: u64,
    /// Se estiver bloqueado, até qual timestamp UNIX o bloqueio vale
    blocked_until: Option<u64>,
    /// Motivo do bloqueio atual
    block_reason: String,
    /// Se já enviamos aviso de cortesia para o bloqueio atual (evita ping-pong / amplificação)
    courtesy_sent_for_current_block: bool,
}

/// Entrada resumida de um par bloqueado pelo Firewall
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FirewallBlockEntry {
    pub pubkey: String,
    pub reason: String,
    pub blocked_until: u64,
    pub offense_level: u32,
}

/// Resultado da inspeção de uma DM pelo Firewall local da Carol
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DmFirewallVerdict {
    /// Mensagem permitida
    Allowed,
    /// Remetente já estava bloqueado ou o modo `allow_strangers = false` recusou silenciosamente
    DroppedSilently { reason: String },
    /// Remetente acabou de violar um limite e entrou em bloqueio progressivo!
    /// `send_courtesy`: true se devemos enviar 1 única mensagem de cortesia avisando do bloqueio.
    NewlyBlocked {
        reason: String,
        duration_secs: u64,
        blocked_until: u64,
        offense_level: u32,
        send_courtesy: bool,
    },
}

/// Firewall local de DMs: aplica políticas distintas para Amigos (na sua lista local) vs Desconhecidos
#[derive(Default)]
pub struct DmFirewall {
    peers: HashMap<String, SenderRateState>,
}

impl DmFirewall {
    pub fn new() -> Self {
        Self::default()
    }

    /// Calcula a duração do bloqueio progressivo segundo o nível de reincidência:
    /// Nível 1 = 1 min (60s), Nível 2 = 5 min (300s), Nível 3 = 30 min (1800s), Nível 4+ = 24h (86400s)
    pub fn block_duration_for_level(level: u32) -> u64 {
        match level {
            0 | 1 => 60,
            2 => 300,
            3 => 1_800,
            _ => 86_400,
        }
    }

    /// Verifica se uma DM (online ou offline) vinda de `sender_pubkey` deve ser aceita ou bloqueada.
    /// Importante: `is_my_friend` indica se **este nó (Carol)** tem `sender_pubkey` (Alice) na sua lista de amigos!
    pub fn check_incoming_dm(
        &mut self,
        sender_pubkey: &str,
        is_my_friend: bool,
        message_len_bytes: usize,
        is_offline_envelope: bool,
        policy: &DmPolicyConfig,
        now: u64,
    ) -> DmFirewallVerdict {
        let pk = sender_pubkey.trim().to_lowercase();
        let state = self.peers.entry(pk).or_default();

        // 1. Verifica se já está bloqueado ativamente
        if let Some(until) = state.blocked_until {
            if now < until {
                return DmFirewallVerdict::DroppedSilently {
                    reason: state.block_reason.clone(),
                };
            } else {
                // Bloqueio expirou! Limpa janelas e libera
                state.blocked_until = None;
                state.courtesy_sent_for_current_block = false;
                state.online_timestamps.clear();
                state.offline_timestamps.clear();
            }
        }

        // Decaimento por bom comportamento: se passou mais de 1h sem infração, reduz o nível de reincidência
        if state.offense_level > 0 && now.saturating_sub(state.last_offense_at) >= 3_600 {
            let hours_clean = (now.saturating_sub(state.last_offense_at) / 3_600) as u32;
            state.offense_level = state.offense_level.saturating_sub(hours_clean);
        }

        // 2. Se não é amigo nosso e `allow_strangers == false`, recusa
        if !is_my_friend && !policy.allow_strangers {
            return Self::trigger_block(
                state,
                "DMs de desconhecidos desativadas (apenas amigos)".to_string(),
                policy.send_courtesy_notice,
                now,
            );
        }

        // 3. Limite de tamanho da mensagem (diferenciado entre Amigo e Desconhecido)
        let max_bytes = if is_my_friend {
            policy.friend_max_message_bytes
        } else {
            policy.stranger_max_message_bytes
        };
        if message_len_bytes > max_bytes {
            let role = if is_my_friend { "amigo" } else { "desconhecido" };
            return Self::trigger_block(
                state,
                format!("mensagem excedeu tamanho máximo para {} ({} > {} bytes)", role, message_len_bytes, max_bytes),
                policy.send_courtesy_notice,
                now,
            );
        }

        // 4. Limite de taxa em janela deslizante
        if is_offline_envelope && !is_my_friend {
            // Janela de 1 hora (3600s) para envelopes offline de desconhecidos
            state.offline_timestamps.retain(|&t| now.saturating_sub(t) < 3_600);
            if state.offline_timestamps.len() as u32 >= policy.stranger_offline_limit_per_hour {
                return Self::trigger_block(
                    state,
                    format!(
                        "limite de DMs offline de desconhecido excedido ({}/h)",
                        policy.stranger_offline_limit_per_hour
                    ),
                    policy.send_courtesy_notice,
                    now,
                );
            }
            state.offline_timestamps.push(now);
        } else {
            // Janela de 60 segundos para DMs
            state.online_timestamps.retain(|&t| now.saturating_sub(t) < 60);
            let max_per_min = if is_my_friend {
                policy.friend_rate_limit_per_min
            } else {
                policy.stranger_rate_limit_per_min
            };
            if state.online_timestamps.len() as u32 >= max_per_min {
                let role = if is_my_friend { "amigo" } else { "desconhecido" };
                return Self::trigger_block(
                    state,
                    format!("limite de taxa para {} excedido ({} msg/min)", role, max_per_min),
                    policy.send_courtesy_notice,
                    now,
                );
            }
            state.online_timestamps.push(now);
        }

        DmFirewallVerdict::Allowed
    }

    /// Registra uma infração de pacote inválido/assinatura corrompida (bloqueia rapidamente)
    pub fn record_invalid_packet(&mut self, sender_pubkey: &str, now: u64) -> Option<(u64, u64, u32)> {
        let pk = sender_pubkey.trim().to_lowercase();
        let state = self.peers.entry(pk).or_default();
        if let DmFirewallVerdict::NewlyBlocked { duration_secs, blocked_until, offense_level, .. } =
            Self::trigger_block(state, "assinatura ou pacote DM inválido".to_string(), false, now)
        {
            Some((duration_secs, blocked_until, offense_level))
        } else {
            None
        }
    }

    fn trigger_block(
        state: &mut SenderRateState,
        reason: String,
        allow_courtesy: bool,
        now: u64,
    ) -> DmFirewallVerdict {
        state.offense_level = state.offense_level.saturating_add(1);
        state.last_offense_at = now;
        let duration_secs = Self::block_duration_for_level(state.offense_level);
        let blocked_until = now.saturating_add(duration_secs);
        state.blocked_until = Some(blocked_until);
        state.block_reason = reason.clone();
        let send_courtesy = allow_courtesy && !state.courtesy_sent_for_current_block;
        if send_courtesy {
            state.courtesy_sent_for_current_block = true;
        }
        DmFirewallVerdict::NewlyBlocked {
            reason,
            duration_secs,
            blocked_until,
            offense_level: state.offense_level,
            send_courtesy,
        }
    }

    /// Desbloqueia manualmente um par (ou automaticamente quando Carol adiciona como amigo!)
    pub fn unblock(&mut self, pubkey: &str) -> bool {
        let pk = pubkey.trim().to_lowercase();
        if let Some(state) = self.peers.get_mut(&pk) {
            let was_blocked = state.blocked_until.is_some();
            state.blocked_until = None;
            state.offense_level = 0;
            state.courtesy_sent_for_current_block = false;
            state.online_timestamps.clear();
            state.offline_timestamps.clear();
            was_blocked
        } else {
            false
        }
    }

    /// Lista todos os pares atualmente bloqueados
    pub fn active_blocks(&self, now: u64) -> Vec<FirewallBlockEntry> {
        let mut out: Vec<FirewallBlockEntry> = self
            .peers
            .iter()
            .filter_map(|(pk, s)| {
                let until = s.blocked_until?;
                (until > now).then(|| FirewallBlockEntry {
                    pubkey: pk.clone(),
                    reason: s.block_reason.clone(),
                    blocked_until: until,
                    offense_level: s.offense_level,
                })
            })
            .collect();
        out.sort_by(|a, b| a.pubkey.cmp(&b.pubkey));
        out
    }
}

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
        assert!(carol_store.mark_delivered_to_me(&env.envelope_id, env.expires_at, ack.clone()));
        // Na mesma sessão já retorna false
        assert!(!carol_store.mark_delivered_to_me(&env.envelope_id, env.expires_at, ack));

        // Carol FECHA e ABRE o programa novamente (recarrega do disco)
        let mut carol_restarted = MailboxStore::load(Some(carol_file), 5020);
        let saved_ack = carol_restarted.get_ack(&env.envelope_id).expect("ACK deve estar salvo no disco");
        assert!(
            !carol_restarted.mark_delivered_to_me(&env.envelope_id, env.expires_at, saved_ack.clone()),
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
        assert_eq!(offline_env_epoch0.topic, DEFAULT_MAILBOX_TOPIC);
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

        // 4. Teste de envelope com tópico genérico personalizado (rede de guardiões agnóstica ao conteúdo)
        let custom_env = StoredEnvelope::create_signed_and_sealed_topic(
            &alice,
            &bob_uid,
            "presence_update",
            "offline presence payload",
            2000,
            Some(7200),
        ).unwrap();
        assert_eq!(custom_env.topic, "presence_update");
        assert!(custom_env.verify_outer());
        let dec_custom = custom_env.unseal_and_verify(&bob).unwrap();
        assert_eq!(dec_custom.text, "offline presence payload");
    }
}
