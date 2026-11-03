//! Formato binário das mensagens de tópico.
//!
//! Toda mensagem publicada vai num envelope `[versão][tipo][corpo]`: o tipo vem no byte (nada
//! de tentar desserializar em sequência) e o corpo é postcard, compacto e determinístico. Bytes
//! (áudio, vídeo, assinaturas) viajam como bytes, sem virar texto.
//!
//! Assinaturas são feitas sobre [`signing_bytes`]: um prefixo de domínio mais o postcard do corpo.
//! Assim a mesma estrutura sempre gera os mesmos bytes, em qualquer implementação que siga a
//! especificação do postcard, e uma assinatura de um tipo não serve para outro.

use crate::api::ChatMessage;
use crate::community::ServerMessage;
use crate::files::SwarmMessage;
use crate::screen::{ScreenAnnounce, ScreenPacket};
use crate::voice::VoicePacket;
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Versão do formato. Nós com versões diferentes não se entendem (as mensagens são descartadas).
pub const VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Chat = 1,
    Voice = 2,
    Swarm = 3,
    ScreenFrame = 4,
    ScreenAnnounce = 5,
    Server = 6,
}

impl Kind {
    fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            1 => Kind::Chat,
            2 => Kind::Voice,
            3 => Kind::Swarm,
            4 => Kind::ScreenFrame,
            5 => Kind::ScreenAnnounce,
            6 => Kind::Server,
            _ => return None,
        })
    }
}

/// Mensagem que pode ir num tópico
pub trait WireMessage: Serialize + DeserializeOwned {
    const KIND: Kind;
}

impl WireMessage for ChatMessage {
    const KIND: Kind = Kind::Chat;
}
impl WireMessage for VoicePacket {
    const KIND: Kind = Kind::Voice;
}
impl WireMessage for SwarmMessage {
    const KIND: Kind = Kind::Swarm;
}
impl WireMessage for ScreenPacket {
    const KIND: Kind = Kind::ScreenFrame;
}
impl WireMessage for ScreenAnnounce {
    const KIND: Kind = Kind::ScreenAnnounce;
}
impl WireMessage for ServerMessage {
    const KIND: Kind = Kind::Server;
}

/// Mensagem recebida, já identificada pelo tipo
#[derive(Debug, Clone)]
pub enum Incoming {
    Chat(ChatMessage),
    Voice(VoicePacket),
    Swarm(SwarmMessage),
    ScreenFrame(ScreenPacket),
    ScreenAnnounce(ScreenAnnounce),
    Server(ServerMessage),
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("mensagem vazia")]
    Empty,
    #[error("versão {0} do formato não suportada")]
    Version(u8),
    #[error("tipo de mensagem desconhecido: {0}")]
    UnknownKind(u8),
    #[error("corpo ilegível")]
    Body,
}

pub fn encode<T: WireMessage>(message: &T) -> Vec<u8> {
    let bytes = vec![VERSION, T::KIND as u8];
    postcard::to_extend(message, bytes).expect("mensagem serializável")
}

/// Lê o envelope esperando um tipo específico (ex.: tópico de controle de servidor)
pub fn decode_as<T: WireMessage>(bytes: &[u8]) -> Result<T, WireError> {
    let (kind, body) = header(bytes)?;
    if kind != T::KIND {
        return Err(WireError::UnknownKind(kind as u8));
    }
    postcard::from_bytes(body).map_err(|_| WireError::Body)
}

pub fn decode(bytes: &[u8]) -> Result<Incoming, WireError> {
    let (kind, body) = header(bytes)?;
    fn read<T: DeserializeOwned>(body: &[u8]) -> Result<T, WireError> {
        postcard::from_bytes(body).map_err(|_| WireError::Body)
    }
    Ok(match kind {
        Kind::Chat => Incoming::Chat(read(body)?),
        Kind::Voice => Incoming::Voice(read(body)?),
        Kind::Swarm => Incoming::Swarm(read(body)?),
        Kind::ScreenFrame => Incoming::ScreenFrame(read(body)?),
        Kind::ScreenAnnounce => Incoming::ScreenAnnounce(read(body)?),
        Kind::Server => Incoming::Server(read(body)?),
    })
}

fn header(bytes: &[u8]) -> Result<(Kind, &[u8]), WireError> {
    let [version, kind, body @ ..] = bytes else { return Err(WireError::Empty) };
    if *version != VERSION {
        return Err(WireError::Version(*version));
    }
    let kind = Kind::from_byte(*kind).ok_or(WireError::UnknownKind(*kind))?;
    Ok((kind, body))
}

/// Bytes assinados de uma estrutura: `anarchord/<domínio>/v1` + 0x00 + postcard do corpo
pub fn signing_bytes<T: Serialize>(domain: &str, body: &T) -> Vec<u8> {
    let mut bytes = format!("anarchord/{}/v1", domain).into_bytes();
    bytes.push(0);
    postcard::to_extend(body, bytes).expect("corpo serializável")
}

/// Postcard puro (sem envelope), para estruturas guardadas ou comparadas por hash
pub fn to_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    postcard::to_allocvec(value).expect("valor serializável")
}

pub fn from_bytes<T: DeserializeOwned>(bytes: &[u8]) -> Option<T> {
    postcard::from_bytes(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::UserIdentity;

    #[test]
    fn test_envelope_roundtrip_and_kind_dispatch() {
        let alice = UserIdentity::generate_with_nick("Alice");
        let chat = ChatMessage::new_signed(&alice, "geral", "olá", 1000);
        let bytes = encode(&chat);
        assert_eq!(&bytes[..2], &[VERSION, Kind::Chat as u8]);
        assert!(matches!(decode(&bytes), Ok(Incoming::Chat(c)) if c == chat));
        assert_eq!(decode_as::<ChatMessage>(&bytes), Ok(chat));
        assert!(decode_as::<VoicePacket>(&bytes).is_err(), "tipo errado não é aceito");
    }

    #[test]
    fn test_rejects_other_versions_and_garbage() {
        assert_eq!(decode(&[]).err(), Some(WireError::Empty));
        assert_eq!(decode(&[9, 1, 0]).err(), Some(WireError::Version(9)));
        assert_eq!(decode(&[VERSION, 200]).err(), Some(WireError::UnknownKind(200)));
        assert_eq!(decode(&[VERSION, Kind::Chat as u8, 0xff]).err(), Some(WireError::Body));
        assert!(decode(br#"{"channel_id":"geral"}"#).is_err(), "JSON antigo é descartado");
    }

    #[test]
    fn test_binary_is_much_smaller_than_json_for_media() {
        let frame = ScreenPacket {
            stream_id: "screen:abcd1234".into(),
            sender_pubkey: "ab".repeat(32),
            sender_name: "Alice".into(),
            frame_seq: 42,
            width: 1280,
            height: 720,
            timestamp_ms: 1_700_000_000_000,
            codec: crate::screen::VideoCodec::H264,
            is_keyframe: false,
            video_data: (0..20_000).map(|i| (i % 256) as u8).collect(),
        };
        let binary = encode(&frame).len();
        let json = serde_json::to_vec(&frame).unwrap().len();
        assert!(binary < 20_200, "binário quase do tamanho do vídeo: {}", binary);
        assert!(json > binary * 3, "JSON {} vs binário {}", json, binary);
    }

    #[test]
    fn test_signing_bytes_are_domain_separated_and_stable() {
        let a = signing_bytes("chat", &("geral", "oi", 1u64));
        assert_eq!(a, signing_bytes("chat", &("geral", "oi", 1u64)));
        assert_ne!(a, signing_bytes("manifest", &("geral", "oi", 1u64)));
        assert!(a.starts_with(b"anarchord/chat/v1\0"));
    }
}
