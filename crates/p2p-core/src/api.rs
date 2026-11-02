use crate::identity::UserIdentity;
use crate::identity::{hex_decode_32, verify_signature_hex};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChatMessage {
    pub channel_id: String,
    pub author_pubkey: String,
    pub author_name: String,
    pub text: String,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

impl ChatMessage {
    /// Conteúdo assinado pelo autor: "canal:texto:timestamp"
    fn signing_payload(channel_id: &str, text: &str, timestamp: u64) -> String {
        format!("{}:{}:{}", channel_id, text, timestamp)
    }

    /// Cria uma mensagem assinada pela identidade do autor
    pub fn new_signed(identity: &UserIdentity, channel_id: &str, text: &str, timestamp: u64) -> Self {
        let signature = identity.sign(Self::signing_payload(channel_id, text, timestamp).as_bytes());
        Self {
            channel_id: channel_id.to_string(),
            author_pubkey: identity.public_key_hex(),
            author_name: identity.profile.display_name.clone(),
            text: text.to_string(),
            timestamp,
            signature,
        }
    }

    /// Verifica se a mensagem é autêntica:
    /// 1. a assinatura confere com `author_pubkey`;
    /// 2. quem publicou na rede (`publisher`, o `source` do Gossipsub) é o próprio autor.
    ///
    /// Sem a segunda checagem, um nó poderia republicar mensagens antigas de outra pessoa ou,
    /// combinada com a primeira, não haveria como saber quem está de fato falando.
    pub fn verify(&self, publisher: Option<&PeerId>) -> bool {
        let Some(author_peer) = peer_id_from_pubkey_hex(&self.author_pubkey) else { return false };
        if publisher != Some(&author_peer) {
            return false;
        }
        let payload = Self::signing_payload(&self.channel_id, &self.text, self.timestamp);
        verify_signature_hex(&self.author_pubkey, payload.as_bytes(), &self.signature)
    }
}

/// Pubkey Ed25519 em hex (User ID) embutida num PeerId do libp2p (PeerIds Ed25519 carregam a chave)
pub fn pubkey_hex_from_peer_id(peer_id: &PeerId) -> Option<String> {
    let multihash = peer_id.as_ref();
    if multihash.code() != 0 {
        return None; // não é multihash "identity": a chave não está embutida (ex.: RSA)
    }
    let key = libp2p::identity::PublicKey::try_decode_protobuf(multihash.digest()).ok()?;
    let ed = key.try_into_ed25519().ok()?;
    Some(ed.to_bytes().iter().map(|b| format!("{:02x}", b)).collect())
}

/// PeerId do libp2p correspondente a uma pubkey Ed25519 em hex (User ID)
pub fn peer_id_from_pubkey_hex(pubkey_hex: &str) -> Option<PeerId> {
    let bytes = hex_decode_32(pubkey_hex).ok()?;
    let key = libp2p::identity::ed25519::PublicKey::try_from_bytes(&bytes).ok()?;
    Some(libp2p::identity::PublicKey::from(key).to_peer_id())
}

#[derive(Debug, Clone)]
pub enum CoreCommand {
    CreateServer { name: String },
    JoinServer { server_id: String },
    SendTextMessage { channel_id: String, text: String },
    JoinVoiceChannel { channel_id: String },
    LeaveVoiceChannel,
    SetMute(bool),
    KickPeer { peer_id: String },
    ListPeers,
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum CoreEvent {
    ServerCreated { server_id: String, name: String },
    ServerDiscovered { server_id: String, name: String },
    PeerJoined { peer_id: String },
    PeerLeft { peer_id: String },
    TextMessageReceived(ChatMessage),
    PeerSpeaking { peer_id: String, is_speaking: bool },
    VoiceDataReady { peer_id: String, samples: Vec<f32> },
    Error(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_of(identity: &UserIdentity) -> PeerId {
        identity.to_libp2p_keypair().public().to_peer_id()
    }

    #[test]
    fn test_signed_message_verifies_when_published_by_author() {
        let alice = UserIdentity::generate_with_nick("Alice");
        let msg = ChatMessage::new_signed(&alice, "geral", "olá", 1000);
        assert_eq!(peer_id_from_pubkey_hex(&alice.public_key_hex()), Some(peer_of(&alice)));
        assert!(msg.verify(Some(&peer_of(&alice))));
    }

    #[test]
    fn test_pubkey_roundtrip_through_peer_id() {
        let alice = UserIdentity::generate_with_nick("Alice");
        assert_eq!(pubkey_hex_from_peer_id(&peer_of(&alice)), Some(alice.public_key_hex()));
    }

    #[test]
    fn test_tampered_text_fails() {
        let alice = UserIdentity::generate_with_nick("Alice");
        let mut msg = ChatMessage::new_signed(&alice, "geral", "olá", 1000);
        msg.text = "texto adulterado".into();
        assert!(!msg.verify(Some(&peer_of(&alice))));
    }

    #[test]
    fn test_impersonation_fails() {
        let alice = UserIdentity::generate_with_nick("Alice");
        let mallory = UserIdentity::generate_with_nick("Mallory");

        // Mallory diz ser Alice, mas assina com a própria chave
        let mut forged = ChatMessage::new_signed(&mallory, "geral", "sou a Alice", 1000);
        forged.author_pubkey = alice.public_key_hex();
        forged.author_name = "Alice".into();
        assert!(!forged.verify(Some(&peer_of(&mallory))));

        // Mallory republica uma mensagem legítima de Alice como se fosse dela
        let genuine = ChatMessage::new_signed(&alice, "geral", "olá", 1000);
        assert!(!genuine.verify(Some(&peer_of(&mallory))), "publicada por outro par");
        assert!(!genuine.verify(None), "sem publicador conhecido");
    }
}
