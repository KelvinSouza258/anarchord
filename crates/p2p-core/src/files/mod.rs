//! Compartilhamento de arquivos em enxame.
//!
//! Na sala (Gossipsub) só trafegam mensagens pequenas: a oferta (CID do manifesto) e o mapa de
//! pedaços de cada par. Quem quer o arquivo pede o manifesto e os pedaços direto aos pares que os
//! têm, pelo protocolo `/anarchord/files/1`, e passa a servir o que já baixou (efeito torrent).
//! Pedaços e manifesto são identificados por CID (formato do IPFS) e conferidos ao chegar.

pub mod cid;
pub mod crypto;
pub mod engine;
pub mod manifest;
pub mod protocol;
pub mod store;

pub use cid::Cid;
pub use crypto::FileKey;
pub use engine::{FileAction, FileEngine, FileEvent, FileSummary, FileState, ShareTarget};
pub use manifest::{Manifest, ManifestError};
pub use protocol::{FileCodec, FileRequest, FileResponse, PROTOCOL, PROTOCOL_V1, PROTOCOL_V2, SUPPORTED_PROTOCOLS};
pub use store::{Bitfield, Origin, PieceError, PieceStore};

use serde::{Deserialize, Serialize};

/// Tamanho de cada pedaço (256 KB): paralelismo bom sem manifestos enormes
pub const PIECE_SIZE: u32 = 256 * 1024;

/// Tamanho máximo de um arquivo do enxame. O arquivo nunca fica inteiro na memória;
/// o limite vem do manifesto (~1 MB em 4 GB)
pub const MAX_FILE_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Chave do registro de provedor na DHT: o multihash do CID, como o IPFS usa para blocos `raw`
pub fn dht_key(cid: &Cid) -> libp2p::kad::RecordKey {
    let mut multihash = Vec::with_capacity(34);
    multihash.extend_from_slice(&[0x12, 0x20]);
    multihash.extend_from_slice(cid.digest());
    libp2p::kad::RecordKey::new(&multihash)
}

/// Tópico dedicado do enxame Gossipsub para troca de Have e Want de um arquivo específico (`anarchord/file/<cid>`)
pub fn file_swarm_topic(cid: &Cid) -> String {
    format!("anarchord/file/{}", cid)
}

/// Arquivo oferecido: o suficiente para listar e começar a baixar (o resto vem do manifesto)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OfferInfo {
    pub manifest: Cid,
    pub name: String,
    pub size: u64,
    /// Pubkey de quem publicou (o manifesto é assinado por ela)
    pub publisher: String,
    pub publisher_name: String,
    /// Chave dos pedaços. Só em servidor, onde a oferta vai cifrada com MLS
    pub key: Option<FileKey>,
}

/// Mensagens do enxame que vão no tópico da sala (cifradas com MLS em servidor)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum SwarmMessage {
    /// "Compartilhei este arquivo"
    Offer(OfferInfo),
    /// Pedaços que quem publicou a mensagem tem de um arquivo
    Have { manifest: Cid, have: Bitfield },
    /// "Estou baixando este arquivo": quem tem pedaços responde com `Have`
    Want { manifest: Cid },
}

impl SwarmMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::wire::encode(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::wire::WireError> {
        crate::wire::decode_as(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_swarm_message_roundtrip_and_distinct_from_other_messages() {
        let offer = SwarmMessage::Offer(OfferInfo {
            manifest: Cid::of(b"m"),
            name: "a.txt".into(),
            size: 3,
            publisher: "pk".into(),
            publisher_name: "Alice".into(),
            key: Some(FileKey::generate()),
        });
        assert_eq!(SwarmMessage::from_bytes(&offer.to_bytes()).unwrap(), offer);
        let have = SwarmMessage::Have { manifest: Cid::of(b"m"), have: Bitfield::new(3) };
        assert_eq!(SwarmMessage::from_bytes(&have.to_bytes()).unwrap(), have);
        let announce = crate::screen::ScreenAnnounce { stream_id: "s".into(), sender_pubkey: "p".into(), sender_name: "n".into(), width: 1, height: 1 };
        assert!(SwarmMessage::from_bytes(&crate::wire::encode(&announce)).is_err());
    }
}
