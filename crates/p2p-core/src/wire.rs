//! Motor de protocolo versionado, registro de adaptadores e negociação de capacidades (`wire.rs`).
//!
//! Toda mensagem publicada num tópico Gossipsub vai num envelope binário `[versão][tipo][corpo]`:
//! - `versão` (`u8`): versão do envelope wire (`v1 = 1`, `v2 = 2`).
//! - `tipo` (`u8`): discriminador [`Kind`] (nada de tentar desserializar em sequência).
//! - `corpo`: bytes serializados pelo adaptador de `(Kind, versão)` correspondente (postcard compacto e
//!   determinístico). Bytes de mídia (áudio, vídeo, assinaturas) viajam como bytes crus, sem base64/JSON.
//!
//! ## Arquitetura de Evolução e Compatibilidade (`N` e `N-1`)
//! - **Um único modelo interno:** o restante do core (`chat`, `dm`, `voice`, `screen`, `servers`, `files`)
//!   opera apenas sobre as estruturas canônicas atuais (`ChatMessage`, `DmWireMessage`, `MailboxMessage`, etc.).
//! - **Adaptadores por `(Kind, versão)`:** cada par `(Kind, u8)` no intervalo `[MIN_VERSION..=CURRENT_VERSION]`
//!   converte entre os bytes do fio daquela versão e o modelo interno único.
//! - **Assinaturas sobre os bytes da versão que foi assinada:** [`signing_bytes`] e [`signing_bytes_versioned`]
//!   mantêm o domínio canônico exato para que uma mensagem assinada em `v1` continue verificando em `v2`.
//! - **Compatibilidade para a frente (Forward Compatibility):** tipos de mensagem desconhecidos (`Kind` ainda
//!   não existente nesta versão do binário, ex.: enviado por um par `N+1`) numa versão de envelope suportada
//!   produzem [`Incoming::Unknown`] em [`decode`] e são ignorados sem erro nem queda do nó.
//! - **Proteção contra downgrade:** versões abaixo de [`MIN_VERSION`] (`0` ou legados obsoletos) são recusadas
//!   tanto na negociação do Identify quanto na decodificação do envelope.

use crate::api::ChatMessage;
use crate::community::ServerMessage;
use crate::dm::{DmWireMessage, MailboxMessage};
use crate::files::SwarmMessage;
use crate::runtime::discovery::PeerList;
use crate::screen::{ScreenAnnounce, ScreenPacket};
use crate::voice::VoicePacket;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Versão `v1` do protocolo de envelope binário (`N-1`).
pub const VERSION_V1: u8 = 1;
/// Versão `v2` atual do protocolo de envelope binário (`N`, com negociação de capacidades e forward-compat).
pub const VERSION_V2: u8 = 2;

/// Menor versão do protocolo aceita por este nó (política `N-1` + proteção contra downgrade).
pub const MIN_VERSION: u8 = VERSION_V1;
/// Maior versão do protocolo suportada e preferida por este nó (`N`).
pub const CURRENT_VERSION: u8 = VERSION_V2;
/// Alias para a versão padrão de codificação atual (`CURRENT_VERSION`).
pub const VERSION: u8 = CURRENT_VERSION;

/// Versão do aplicativo anunciada no Identify.
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Capacidades negociáveis anunciadas por cada nó no `agent_version` do Identify.
pub mod caps {
    pub const OPUS: &str = "opus";
    pub const PCM16: &str = "pcm16";
    pub const H264: &str = "h264";
    pub const JPEG: &str = "jpeg";
    pub const MLS: &str = "mls";
    pub const DM_E2EE: &str = "dm-e2ee";
    pub const MAILBOX_V1: &str = "mailbox-v1";
    pub const FILES_V2: &str = "files-v2";
}

/// Capacidades de protocolo e intervalo de versões `[wire_min..=wire_max]` anunciados por um par.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolCapabilities {
    /// Menor versão de envelope `wire` suportada pelo par
    pub wire_min: u8,
    /// Maior versão de envelope `wire` suportada pelo par
    pub wire_max: u8,
    /// Versão do aplicativo (ex.: `"0.1.0"`)
    pub app_version: String,
    /// Lista ordenada de capacidades suportadas (codecs, cifragem, extensões)
    pub capabilities: BTreeSet<String>,
}

impl Default for ProtocolCapabilities {
    fn default() -> Self {
        Self::local()
    }
}

impl ProtocolCapabilities {
    /// Capacidades nativas deste nó (`v1..=v2` + codecs e subsistemas suportados).
    pub fn local() -> Self {
        let capabilities = [
            caps::OPUS,
            caps::PCM16,
            caps::H264,
            caps::JPEG,
            caps::MLS,
            caps::DM_E2EE,
            caps::MAILBOX_V1,
            caps::FILES_V2,
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        Self {
            wire_min: MIN_VERSION,
            wire_max: CURRENT_VERSION,
            app_version: APP_VERSION.to_string(),
            capabilities,
        }
    }

    /// Perfil de um nó legado `v1` (que não enviava sufixo `:v=...` no Identify).
    pub fn legacy_v1() -> Self {
        let capabilities = [
            caps::OPUS,
            caps::PCM16,
            caps::H264,
            caps::JPEG,
            caps::MLS,
            caps::DM_E2EE,
            caps::MAILBOX_V1,
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        Self {
            wire_min: VERSION_V1,
            wire_max: VERSION_V1,
            app_version: "0.1.0-v1".to_string(),
            capabilities,
        }
    }

    /// Constrói capacidades customizadas para testes de negociação (`N`, `N-1`, incompatível).
    pub fn with_versions(wire_min: u8, wire_max: u8) -> Self {
        let mut caps = Self::local();
        caps.wire_min = wire_min;
        caps.wire_max = wire_max;
        caps
    }

    /// Formata o segmento compacto anunciado no final do `agent_version`:
    /// `v=1-2;app=0.1.0;caps=dm-e2ee,files-v2,h264,jpeg,mailbox-v1,mls,opus,pcm16`
    pub fn to_agent_suffix(&self) -> String {
        let caps_list: Vec<&str> = self.capabilities.iter().map(String::as_str).collect();
        format!(
            "v={}-{};app={};caps={}",
            self.wire_min,
            self.wire_max,
            self.app_version,
            caps_list.join(",")
        )
    }

    /// Analisa o sufixo `v=<min>-<max>;app=<ver>;caps=<c1>,<c2>` do Identify.
    pub fn parse_agent_suffix(suffix: &str) -> Option<Self> {
        if !suffix.contains("v=") {
            return None;
        }
        let mut wire_min = None;
        let mut wire_max = None;
        let mut app_version = "desconhecida".to_string();
        let mut capabilities = BTreeSet::new();

        for part in suffix.split(';') {
            let Some((k, v)) = part.split_once('=') else { continue };
            match k.trim() {
                "v" => {
                    if let Some((min_s, max_s)) = v.split_once('-') {
                        wire_min = min_s.trim().parse::<u8>().ok();
                        wire_max = max_s.trim().parse::<u8>().ok();
                    } else if let Ok(single) = v.trim().parse::<u8>() {
                        wire_min = Some(single);
                        wire_max = Some(single);
                    }
                }
                "app" => {
                    if !v.trim().is_empty() {
                        app_version = v.trim().to_string();
                    }
                }
                "caps" => {
                    for c in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                        capabilities.insert(c.to_string());
                    }
                }
                _ => {}
            }
        }

        let (min_v, max_v) = (wire_min?, wire_max?);
        if min_v == 0 || min_v > max_v {
            // Versão 0 ou intervalo invertido é inválido (proteção contra downgrade/malformação)
            return Some(Self {
                wire_min: min_v,
                wire_max: max_v,
                app_version,
                capabilities,
            });
        }
        Some(Self {
            wire_min: min_v,
            wire_max: max_v,
            app_version,
            capabilities,
        })
    }

    /// Negocia a **maior versão de protocolo em comum** entre `self` (local) e `remote` (par).
    /// Aplica proteção contra downgrade: nunca aceita versão menor que `self.wire_min` (`MIN_VERSION`)
    /// ou versão `0`. Retorna `None` se os intervalos `[wire_min..=wire_max]` forem disjuntos.
    pub fn negotiate_version(&self, remote: &ProtocolCapabilities) -> Option<u8> {
        if self.wire_min == 0 || remote.wire_min == 0 || self.wire_min > self.wire_max || remote.wire_min > remote.wire_max {
            return None;
        }
        let floor = self.wire_min.max(MIN_VERSION).max(remote.wire_min);
        let ceiling = self.wire_max.min(remote.wire_max);
        (floor <= ceiling).then_some(ceiling)
    }

    /// Interseção de capacidades suportadas por ambos os nós.
    pub fn negotiate_capabilities(&self, remote: &ProtocolCapabilities) -> BTreeSet<String> {
        self.capabilities.intersection(&remote.capabilities).cloned().collect()
    }

    /// Escolhe o melhor codec de vídeo comum por ordem de preferência (`h264` > `jpeg`).
    pub fn negotiate_video_codec(&self, remote: &ProtocolCapabilities) -> Option<&'static str> {
        let common = self.negotiate_capabilities(remote);
        if common.contains(caps::H264) {
            Some(caps::H264)
        } else if common.contains(caps::JPEG) {
            Some(caps::JPEG)
        } else {
            None
        }
    }

    /// Escolhe o melhor codec de áudio comum por ordem de preferência (`opus` > `pcm16`).
    pub fn negotiate_audio_codec(&self, remote: &ProtocolCapabilities) -> Option<&'static str> {
        let common = self.negotiate_capabilities(remote);
        if common.contains(caps::OPUS) {
            Some(caps::OPUS)
        } else if common.contains(caps::PCM16) {
            Some(caps::PCM16)
        } else {
            None
        }
    }

    /// Calcula a versão de envelope `wire` para publicar numa sala/tópico Gossipsub:
    /// usa a **menor versão máxima negociada** entre os pares compatíveis presentes na sala,
    /// garantindo que todos os membros (`N` e `N-1`) entendam o pacote sem partir a sala em duas.
    /// Quando não há pares `N-1` na sala, publica em `CURRENT_VERSION` (`v2`).
    pub fn room_wire_version<'a>(
        &self,
        room_peers: impl IntoIterator<Item = &'a ProtocolCapabilities>,
    ) -> u8 {
        let mut selected = self.wire_max;
        for peer in room_peers {
            if let Some(neg) = self.negotiate_version(peer) {
                selected = selected.min(neg);
            }
        }
        selected.clamp(self.wire_min.max(MIN_VERSION), self.wire_max)
    }

    /// Descrição curta da faixa de versões anunciada pelo par (ex.: `"v1-v2"` ou `"v1"`).
    pub fn version_range_label(&self) -> String {
        if self.wire_min == self.wire_max {
            format!("v{}", self.wire_max)
        } else {
            format!("v{}-v{}", self.wire_min, self.wire_max)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Chat = 1,
    Voice = 2,
    Swarm = 3,
    ScreenFrame = 4,
    ScreenAnnounce = 5,
    Server = 6,
    Peers = 7,
    DirectMessage = 8,
    Mailbox = 9,
}

impl Kind {
    pub fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            1 => Kind::Chat,
            2 => Kind::Voice,
            3 => Kind::Swarm,
            4 => Kind::ScreenFrame,
            5 => Kind::ScreenAnnounce,
            6 => Kind::Server,
            7 => Kind::Peers,
            8 => Kind::DirectMessage,
            9 => Kind::Mailbox,
            _ => return None,
        })
    }
}

/// Verifica se a versão do envelope está dentro da janela suportada `[MIN_VERSION..=CURRENT_VERSION]`.
pub const fn is_supported_version(version: u8) -> bool {
    version >= MIN_VERSION && version <= CURRENT_VERSION
}

/// Mensagem que pode ir num tópico Gossipsub.
///
/// O adaptador de versão `encode_body_for_version` / `decode_body_for_version` permite que um tipo
/// mantenha um único modelo interno em Rust enquanto lê/escreve o formato binário exato de `v1` ou `v2`.
pub trait WireMessage: Serialize + DeserializeOwned {
    const KIND: Kind;

    /// Serializa o corpo para a versão `version` solicitada.
    fn encode_body_for_version(&self, _version: u8, out: Vec<u8>) -> Vec<u8> {
        postcard::to_extend(self, out).expect("mensagem serializável")
    }

    /// Desserializa o corpo vindo de um pacote na versão `version` para o modelo interno único.
    fn decode_body_for_version(version: u8, body: &[u8]) -> Result<Self, WireError> {
        if !is_supported_version(version) {
            return Err(WireError::Version(version));
        }
        postcard::from_bytes(body).map_err(|_| WireError::Body)
    }
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

/// Mensagem recebida, já convertida pelo adaptador `(Kind, versão)` para o modelo interno único.
#[derive(Debug, Clone)]
pub enum Incoming {
    Chat(ChatMessage),
    Voice(VoicePacket),
    Swarm(SwarmMessage),
    ScreenFrame(ScreenPacket),
    ScreenAnnounce(ScreenAnnounce),
    Server(ServerMessage),
    Peers(PeerList),
    DirectMessage(DmWireMessage),
    Mailbox(MailboxMessage),
    /// Tipo de mensagem desconhecido (`Kind` de versão futura `N+1`), ignorado com segurança
    /// sem derrubar ou desconectar o nó (Forward Compatibility).
    Unknown {
        version: u8,
        kind: u8,
        len: usize,
    },
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("mensagem vazia")]
    Empty,
    #[error("versão {0} do formato não suportada (suportado: v{MIN_VERSION}..=v{CURRENT_VERSION})")]
    Version(u8),
    #[error("tipo de mensagem desconhecido: {0}")]
    UnknownKind(u8),
    #[error("corpo ilegível")]
    Body,
}

/// Codifica `message` usando a versão atual do protocolo ([`CURRENT_VERSION`]).
pub fn encode<T: WireMessage>(message: &T) -> Vec<u8> {
    encode_versioned(message, CURRENT_VERSION)
}

/// Codifica `message` usando explicitamente a versão `version` do envelope (`v1` ou `v2`).
/// Faz clamp seguro para `[MIN_VERSION..=CURRENT_VERSION]` (proteção contra downgrade).
pub fn encode_versioned<T: WireMessage>(message: &T, version: u8) -> Vec<u8> {
    let v = version.clamp(MIN_VERSION, CURRENT_VERSION);
    let prefix = vec![v, T::KIND as u8];
    message.encode_body_for_version(v, prefix)
}

/// Lê o envelope esperando um tipo específico (ex.: tópico de controle de servidor).
/// Aceita qualquer versão suportada `[MIN_VERSION..=CURRENT_VERSION]`.
pub fn decode_as<T: WireMessage>(bytes: &[u8]) -> Result<T, WireError> {
    let (version, kind_byte, body) = raw_header(bytes)?;
    let kind = Kind::from_byte(kind_byte).ok_or(WireError::UnknownKind(kind_byte))?;
    if kind != T::KIND {
        return Err(WireError::UnknownKind(kind as u8));
    }
    T::decode_body_for_version(version, body)
}

/// Decodifica um envelope binário e devolve `(versão_do_envelope, Incoming)`.
///
/// - Se a versão estiver fora de `[MIN_VERSION..=CURRENT_VERSION]`, retorna `Err(WireError::Version(v))`.
/// - Se a versão for suportada mas o `Kind` for desconhecido (ex.: novo recurso de um nó mais novo),
///   retorna `Ok((version, Incoming::Unknown { version, kind, len }))` para ser ignorado sem quebrar o nó.
pub fn decode_versioned(bytes: &[u8]) -> Result<(u8, Incoming), WireError> {
    let (version, kind_byte, body) = raw_header(bytes)?;
    let Some(kind) = Kind::from_byte(kind_byte) else {
        return Ok((
            version,
            Incoming::Unknown {
                version,
                kind: kind_byte,
                len: body.len(),
            },
        ));
    };
    let incoming = match kind {
        Kind::Chat => Incoming::Chat(ChatMessage::decode_body_for_version(version, body)?),
        Kind::Voice => Incoming::Voice(VoicePacket::decode_body_for_version(version, body)?),
        Kind::Swarm => Incoming::Swarm(SwarmMessage::decode_body_for_version(version, body)?),
        Kind::ScreenFrame => Incoming::ScreenFrame(ScreenPacket::decode_body_for_version(version, body)?),
        Kind::ScreenAnnounce => Incoming::ScreenAnnounce(ScreenAnnounce::decode_body_for_version(version, body)?),
        Kind::Server => Incoming::Server(ServerMessage::decode_body_for_version(version, body)?),
        Kind::Peers => Incoming::Peers(PeerList::decode_body_for_version(version, body)?),
        Kind::DirectMessage => Incoming::DirectMessage(DmWireMessage::decode_body_for_version(version, body)?),
        Kind::Mailbox => Incoming::Mailbox(MailboxMessage::decode_body_for_version(version, body)?),
    };
    Ok((version, incoming))
}

/// Decodifica um envelope binário em `[MIN_VERSION..=CURRENT_VERSION]` para [`Incoming`].
pub fn decode(bytes: &[u8]) -> Result<Incoming, WireError> {
    decode_versioned(bytes).map(|(_, incoming)| incoming)
}

fn raw_header(bytes: &[u8]) -> Result<(u8, u8, &[u8]), WireError> {
    let [version, kind_byte, body @ ..] = bytes else {
        return Err(WireError::Empty);
    };
    if !is_supported_version(*version) {
        return Err(WireError::Version(*version));
    }
    Ok((*version, *kind_byte, body))
}

/// Bytes assinados de uma estrutura: `anarchord/<domínio>/v1` + `0x00` + postcard do corpo.
pub fn signing_bytes<T: Serialize>(domain: &str, body: &T) -> Vec<u8> {
    signing_bytes_versioned(domain, 1, body)
}

/// Bytes assinados de uma estrutura para uma versão específica de domínio de assinatura (`anarchord/<domínio>/v<N>\0`).
/// Garante que a verificação da assinatura seja sempre executada sobre os bytes exatos da versão que a produziu.
pub fn signing_bytes_versioned<T: Serialize>(domain: &str, domain_version: u8, body: &T) -> Vec<u8> {
    let mut bytes = format!("anarchord/{}/v{}", domain, domain_version).into_bytes();
    bytes.push(0);
    postcard::to_extend(body, bytes).expect("corpo serializável")
}

/// Postcard puro (sem envelope), para estruturas guardadas ou comparadas por hash.
pub fn to_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    postcard::to_allocvec(value).expect("valor serializável")
}

pub fn from_bytes<T: DeserializeOwned>(bytes: &[u8]) -> Option<T> {
    postcard::from_bytes(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::{DirectMessageEnvelope, EphemeralKeyOffer, ReceiptAck, StoredEnvelope};
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
    fn test_n_and_n_minus_1_wire_compatibility_and_fixtures() {
        let alice = UserIdentity::generate_with_nick("Alice");
        let bob = UserIdentity::generate_with_nick("Bob");

        // 1. Mensagem de chat codificada na versão N-1 (v1) e lida pelo motor N (v2)
        let chat_v1 = ChatMessage::new_signed(&alice, "geral", "fixture v1 compatível", 1_700_000_000);
        let bytes_v1 = encode_versioned(&chat_v1, VERSION_V1);
        assert_eq!(&bytes_v1[..2], &[VERSION_V1, Kind::Chat as u8]);

        // Verifica fixture de bytes gravados da v1 (garante que o formato binário v1 nunca mude acidentalmente)
        let (ver, decoded) = decode_versioned(&bytes_v1).expect("motor v2 deve ler envelope v1");
        assert_eq!(ver, VERSION_V1);
        match decoded {
            Incoming::Chat(c) => {
                assert_eq!(c, chat_v1);
                assert!(c.verify_signature(), "assinatura Ed25519 gerada em v1 deve validar no modelo interno");
            }
            other => panic!("esperado Incoming::Chat, veio {:?}", other),
        }

        // 2. Envelope de DM e Mailbox gravados em v1 lidos pelo motor v2
        let offer_v1 = DmWireMessage::KeyOffer(EphemeralKeyOffer::new_signed(
            &alice,
            &bob.public_key_hex(),
            [0x33; 32],
            1_700_000_001,
        ));
        let offer_bytes_v1 = encode_versioned(&offer_v1, VERSION_V1);
        assert_eq!(offer_bytes_v1[0], VERSION_V1);
        assert!(matches!(
            decode(&offer_bytes_v1),
            Ok(Incoming::DirectMessage(DmWireMessage::KeyOffer(ref o))) if o.verify()
        ));

        let dm_env = DirectMessageEnvelope::seal(&alice, &bob.public_key_hex(), "oi v1", 1_700_000_002, None).unwrap();
        let dm_bytes_v1 = encode_versioned(&DmWireMessage::Message(dm_env), VERSION_V1);
        assert_eq!(dm_bytes_v1[0], VERSION_V1);
        if let Ok(Incoming::DirectMessage(DmWireMessage::Message(opened))) = decode(&dm_bytes_v1) {
            let payload = opened.open(&bob, None).expect("Bob em v2 deve abrir DM cifrada em v1");
            assert_eq!(payload.text, "oi v1");
        } else {
            panic!("falha ao decodificar DM v1");
        }

        // 3. Fixture binária gravada de uma ChatMessage v1 (garante estabilidade byte-a-byte de postcard + header v1)
        let fixed_chat = ChatMessage {
            channel_id: "geral".into(),
            author_pubkey: "aa".repeat(32),
            author_name: "Alice".into(),
            text: "oi".into(),
            timestamp: 42,
            signature: vec![1, 2, 3, 4],
        };
        let recorded_v1_fixture: Vec<u8> = vec![
            1, 1, // [version=1, kind=Chat(1)]
            5, b'g', b'e', b'r', b'a', b'l', // channel_id: "geral"
            64, // author_pubkey len = 64 ('a' * 64)
            b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a',
            b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a',
            b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a',
            b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a',
            5, b'A', b'l', b'i', b'c', b'e', // author_name: "Alice"
            2, b'o', b'i', // text: "oi"
            42, // timestamp: 42 (varint)
            4, 1, 2, 3, 4, // signature: [1, 2, 3, 4]
        ];
        assert_eq!(encode_versioned(&fixed_chat, VERSION_V1), recorded_v1_fixture);
        assert_eq!(decode_as::<ChatMessage>(&recorded_v1_fixture), Ok(fixed_chat));

        let stored = StoredEnvelope::create_signed_and_sealed(&alice, &bob.public_key_hex(), "offline v1", 1_700_000_003, Some(3600)).unwrap();
        let mb_bytes_v1 = encode_versioned(&MailboxMessage::Store(stored), VERSION_V1);
        assert_eq!(mb_bytes_v1[0], VERSION_V1);
        if let Ok(Incoming::Mailbox(MailboxMessage::Store(s))) = decode(&mb_bytes_v1) {
            assert!(s.verify_outer());
            assert_eq!(s.unseal_and_verify(&bob).unwrap().text, "offline v1");
        } else {
            panic!("falha ao decodificar Mailbox v1");
        }

        let ack = ReceiptAck::new_signed(&bob, "0123456789abcdef0123456789abcdef", 1_700_000_004);
        let ack_bytes_v2 = encode_versioned(&MailboxMessage::Ack(ack), VERSION_V2);
        assert_eq!(ack_bytes_v2[0], VERSION_V2);
        assert!(matches!(
            decode(&ack_bytes_v2),
            Ok(Incoming::Mailbox(MailboxMessage::Ack(ref a))) if a.verify()
        ));
    }

    #[test]
    fn test_unknown_kind_is_ignored_gracefully_for_forward_compatibility() {
        // Um nó na versão N+1 publica um novo tipo de mensagem (ex.: Kind = 200 ou 250) num envelope v1 ou v2:
        // decode() devolve Incoming::Unknown sem quebrar o nó, enquanto decode_as<T>() recusa pois esperava T.
        let future_packet = [VERSION_V2, 200, 0xde, 0xad, 0xbe, 0xef];
        assert!(matches!(
            decode(&future_packet),
            Ok(Incoming::Unknown { version: VERSION_V2, kind: 200, len: 4 })
        ));
        assert_eq!(
            decode_as::<ChatMessage>(&future_packet).err(),
            Some(WireError::UnknownKind(200))
        );
    }

    #[test]
    fn test_rejects_unsupported_versions_downgrade_and_garbage() {
        assert_eq!(decode(&[]).err(), Some(WireError::Empty));
        // Proteção contra downgrade: versão 0 é rejeitada
        assert_eq!(decode(&[0, 1, 0]).err(), Some(WireError::Version(0)));
        // Versão incompatível futura fora da janela [MIN_VERSION..=CURRENT_VERSION]
        assert_eq!(decode(&[9, 1, 0]).err(), Some(WireError::Version(9)));
        assert_eq!(decode(&[VERSION, Kind::Chat as u8, 0xff]).err(), Some(WireError::Body));
        assert!(decode(br#"{"channel_id":"geral"}"#).is_err(), "JSON antigo é descartado");
    }

    #[test]
    fn test_version_and_capability_negotiation_and_downgrade_protection() {
        let node_v2 = ProtocolCapabilities::local(); // v1..=v2
        let node_v1 = ProtocolCapabilities::legacy_v1(); // v1..=v1
        let node_v2_only = ProtocolCapabilities::with_versions(2, 2);
        let node_v3_only = ProtocolCapabilities::with_versions(3, 4);
        let node_downgrade_v0 = ProtocolCapabilities::with_versions(0, 0);

        // Par v2 + Par v2 -> negocia v2 (maior comum)
        assert_eq!(node_v2.negotiate_version(&node_v2), Some(VERSION_V2));
        // Par v2 (N) + Par v1 (N-1) -> negocia v1
        assert_eq!(node_v2.negotiate_version(&node_v1), Some(VERSION_V1));
        assert_eq!(node_v1.negotiate_version(&node_v2), Some(VERSION_V1));
        // Par v2-only + Par v1-only -> incompatível (None)
        assert_eq!(node_v2_only.negotiate_version(&node_v1), None);
        // Par v2 + Par v3..=v4 -> incompatível (None)
        assert_eq!(node_v2.negotiate_version(&node_v3_only), None);
        // Proteção contra downgrade para v0 -> recusado (None)
        assert_eq!(node_v2.negotiate_version(&node_downgrade_v0), None);

        // Sala Gossipsub: se todos falam v2, usa v2; se entrar um par v1 (N-1), desce para v1 na sala
        assert_eq!(node_v2.room_wire_version([&node_v2]), VERSION_V2);
        assert_eq!(node_v2.room_wire_version([&node_v2, &node_v1]), VERSION_V1);

        // Negociação de codecs e sufixo do Identify
        let suffix = node_v2.to_agent_suffix();
        let parsed = ProtocolCapabilities::parse_agent_suffix(&suffix).expect("sufixo válido");
        assert_eq!(parsed, node_v2);
        assert_eq!(node_v2.negotiate_video_codec(&node_v1), Some(caps::H264));
        assert_eq!(node_v2.negotiate_audio_codec(&node_v1), Some(caps::OPUS));
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
