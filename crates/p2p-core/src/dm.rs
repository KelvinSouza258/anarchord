//! Mensagens Diretas Privadas (DM 1:1) com Tópico Mútuo Gossipsub, Criptografia E2EE
//! (X25519 + HKDF-SHA256 + ChaCha20-Poly1305), Sessões Efêmeras (Forward Secrecy)
//! e Mailbox Offline Descentralizada (Store-and-Forward via Guardiões Amigos).

use crate::config::NodeConfig;
use crate::identity::{hex_decode_32, verify_signature_hex, UserIdentity};
use crate::wire;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use curve25519_dalek::edwards::CompressedEdwardsY;
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
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
    let hash = Sha512::digest(ed_secret_bytes);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    StaticSecret::from(scalar)
}

/// Converte uma chave pública Ed25519 (hex de 64 chars) para `X25519PublicKey` (ponto Montgomery biracionalmente equivalente)
pub fn ed25519_pub_hex_to_x25519(pubkey_hex: &str) -> Result<X25519PublicKey, DmError> {
    let bytes = hex_decode_32(pubkey_hex).map_err(|_| DmError::InvalidPublicKey)?;
    let compressed = CompressedEdwardsY(bytes);
    let edwards_point = compressed.decompress().ok_or(DmError::InvalidPublicKey)?;
    let montgomery = edwards_point.to_montgomery();
    Ok(X25519PublicKey::from(montgomery.to_bytes()))
}

/// Deriva chave simétrica ChaCha20-Poly1305 de 256 bits a partir de um segredo compartilhado X25519 via HKDF-SHA256
fn derive_aead_key(shared_secret: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("32 bytes é um tamanho válido para HKDF-SHA256");
    okm
}

/// Deriva a chave base estática ECDH entre a identidade local e a chave pública do par
pub fn derive_static_dm_key(identity: &UserIdentity, peer_pubkey_hex: &str) -> Result<[u8; 32], DmError> {
    let my_x25519 = ed25519_priv_to_x25519(&identity.signing_key_bytes());
    let peer_x25519 = ed25519_pub_hex_to_x25519(peer_pubkey_hex)?;
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

    fn signing_bytes(
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
                let recipient_x25519 = ed25519_pub_hex_to_x25519(&recipient_clean)?;
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

        let aead_key = if self.uses_session_key {
            *session_key.ok_or(DmError::DecryptionFailed)?
        } else {
            let my_x25519 = ed25519_priv_to_x25519(&recipient_identity.signing_key_bytes());
            let sender_eph = X25519PublicKey::from(self.ephemeral_pubkey);
            let shared = my_x25519.diffie_hellman(&sender_eph);
            derive_aead_key(shared.as_bytes(), DM_HKDF_INFO)
        };

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
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

        Ok(payload)
    }

    fn signing_bytes(
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

/// Envelope cifrado Sign-then-Seal armazenado por guardiões amigos quando o destinatário está offline.
/// O guardião (Carol) vê apenas `sender_pubkey` e `recipient_pubkey`, mas não consegue ler o conteúdo;
/// o destinatário (Bob) pode receber o envelope de um completo estranho (Carol) e verificar a
/// assinatura interna de Alice.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct StoredEnvelope {
    /// Identificador único determinístico (SHA-256 do ciphertext + nonce) para deduplicação
    pub envelope_id: String,
    /// Chave pública Ed25519 do remetente (Alice) — permite a Carol verificar que Alice é amiga dela
    pub sender_pubkey: String,
    /// Chave pública Ed25519 do destinatário (Bob) — permite a Carol saber para quem entregar
    pub recipient_pubkey: String,
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

    fn signing_bytes(envelope_id: &str, recipient_pubkey: &str, timestamp: u64) -> Vec<u8> {
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
}

impl wire::WireMessage for MailboxMessage {
    const KIND: wire::Kind = wire::Kind::Mailbox;
}

impl StoredEnvelope {
    /// Alice cria um `StoredEnvelope` Sign-then-Seal para Bob, com sugestão opcional de TTL
    pub fn create_signed_and_sealed(
        sender_identity: &UserIdentity,
        recipient_pubkey: &str,
        text: &str,
        created_at: u64,
        suggested_ttl: Option<u64>,
    ) -> Result<Self, DmError> {
        let recipient_clean = recipient_pubkey.trim().to_lowercase();
        let recipient_x25519 = ed25519_pub_hex_to_x25519(&recipient_clean)?;

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
        let default_expires = created_at.saturating_add(suggested_ttl.unwrap_or(7 * 86_400));

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

    fn outer_signing_bytes(
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
        postcard::to_extend(&tuple, b"anarchord-sealed-outer-v1\0".to_vec()).expect("serializável")
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
        verify_signature_hex(&self.sender_pubkey, &bytes, &self.outer_signature)
    }

    /// Bob decifra o envelope (mesmo tendo vindo de Carol, uma estranha) e valida a assinatura interna de Alice
    pub fn unseal_and_verify(&self, recipient_identity: &UserIdentity) -> Result<SignedDmPayload, DmError> {
        let my_pub = recipient_identity.public_key_hex();
        if !self.recipient_pubkey.eq_ignore_ascii_case(&my_pub) {
            return Err(DmError::WrongRecipient);
        }

        let my_x25519 = ed25519_priv_to_x25519(&recipient_identity.signing_key_bytes());
        let eph_pub = X25519PublicKey::from(self.ephemeral_pubkey);
        let shared = my_x25519.diffie_hellman(&eph_pub);
        let aead_key = derive_aead_key(shared.as_bytes(), DM_SEALED_HKDF_INFO);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&self.nonce), self.ciphertext.as_ref())
            .map_err(|_| DmError::DecryptionFailed)?;

        let inner: SignedDmPayload =
            postcard::from_bytes(&plaintext).map_err(|_| DmError::DecryptionFailed)?;

        // Verifica que o autor dentro do ciphertext assinou com sua chave Ed25519 e corresponde ao sender externo
        if !inner.sender_pubkey.eq_ignore_ascii_case(&self.sender_pubkey)
            || !inner.recipient_pubkey.eq_ignore_ascii_case(&my_pub)
            || !inner.verify()
        {
            return Err(DmError::InvalidSignature);
        }

        Ok(inner)
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
}

impl MailboxStore {
    pub fn load(storage_path: Option<PathBuf>, now: u64) -> Self {
        let mut envelopes = HashMap::new();
        let mut delivered_ids = HashMap::new();
        let mut acks = HashMap::new();
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

    /// Marca um envelope como recebido pelo destinatário local e guarda o ACK assinado;
    /// retorna `true` se é inédito (não duplicado), mesmo após reiniciar o app!
    pub fn mark_delivered_to_me(&mut self, envelope_id: &str, expires_at: u64, ack: ReceiptAck) -> bool {
        self.envelopes.remove(envelope_id);
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

    pub fn envelope_count(&self) -> usize {
        self.envelopes.len()
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
}
