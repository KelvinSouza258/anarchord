//! Protocolo ponto a ponto `/anarchord/files/1` (request-response do libp2p).
//!
//! Cada pedido abre um stream na conexão já existente (direta ou por relay, cifrada pelo
//! transporte). Quadros com tamanho (u32 big-endian) e, na resposta, os bytes crus do pedaço,
//! sem JSON.

use super::cid::Cid;
use super::OfferInfo;
use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::StreamProtocol;
use serde::{Deserialize, Serialize};
use std::io;

pub const PROTOCOL: StreamProtocol = StreamProtocol::new("/anarchord/files/1");

const MAX_REQUEST: usize = 4 * 1024;
/// Um pedaço (256 KB + tag) ou um manifesto de arquivo grande (~1 MB em 4 GB)
const MAX_RESPONSE: usize = 2 * 1024 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum FileRequest {
    GetManifest { cid: Cid },
    GetBitfield { cid: Cid },
    GetPiece { cid: Cid, index: u32 },
    /// Oferta direta a um par (`/send`): não passa por tópico nenhum
    Offer(OfferInfo),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileResponse {
    Manifest(Vec<u8>),
    Bitfield(Vec<u8>),
    Piece(Vec<u8>),
    /// Muitos envios em andamento: tente outro par ou mais tarde
    Busy,
    NotFound,
    /// Oferta direta recebida
    Ok,
}

impl FileResponse {
    fn tag(&self) -> u8 {
        match self {
            FileResponse::Manifest(_) => 0,
            FileResponse::Bitfield(_) => 1,
            FileResponse::Piece(_) => 2,
            FileResponse::Busy => 3,
            FileResponse::NotFound => 4,
            FileResponse::Ok => 5,
        }
    }

    fn data(&self) -> &[u8] {
        match self {
            FileResponse::Manifest(d) | FileResponse::Bitfield(d) | FileResponse::Piece(d) => d,
            FileResponse::Busy | FileResponse::NotFound | FileResponse::Ok => &[],
        }
    }

    fn from_frame(mut frame: Vec<u8>) -> io::Result<Self> {
        if frame.is_empty() {
            return Err(invalid("resposta vazia"));
        }
        let data = frame.split_off(1);
        Ok(match frame[0] {
            0 => FileResponse::Manifest(data),
            1 => FileResponse::Bitfield(data),
            2 => FileResponse::Piece(data),
            3 => FileResponse::Busy,
            4 => FileResponse::NotFound,
            5 => FileResponse::Ok,
            _ => return Err(invalid("tipo de resposta desconhecido")),
        })
    }
}

#[derive(Clone, Default)]
pub struct FileCodec;

#[async_trait]
impl libp2p::request_response::Codec for FileCodec {
    type Protocol = StreamProtocol;
    type Request = FileRequest;
    type Response = FileResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let frame = read_frame(io, MAX_REQUEST).await?;
        serde_json::from_slice(&frame).map_err(|_| invalid("pedido ilegível"))
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        FileResponse::from_frame(read_frame(io, MAX_RESPONSE).await?)
    }

    async fn write_request<T>(&mut self, _: &Self::Protocol, io: &mut T, req: Self::Request) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = serde_json::to_vec(&req).map_err(|_| invalid("pedido não serializável"))?;
        write_frame(io, &[&bytes]).await
    }

    async fn write_response<T>(&mut self, _: &Self::Protocol, io: &mut T, res: Self::Response) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &[&[res.tag()], res.data()]).await
    }
}

async fn read_frame<T: AsyncRead + Unpin + Send>(io: &mut T, max: usize) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    io.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        return Err(invalid("quadro grande demais"));
    }
    let mut frame = vec![0u8; len];
    io.read_exact(&mut frame).await?;
    Ok(frame)
}

async fn write_frame<T: AsyncWrite + Unpin + Send>(io: &mut T, parts: &[&[u8]]) -> io::Result<()> {
    let len: usize = parts.iter().map(|p| p.len()).sum();
    io.write_all(&(len as u32).to_be_bytes()).await?;
    for part in parts {
        io.write_all(part).await?;
    }
    io.flush().await
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::Cursor;
    use libp2p::request_response::Codec;

    #[tokio::test]
    async fn test_codec_roundtrip() {
        let mut codec = FileCodec;
        let cid = Cid::of(b"x");
        for request in [FileRequest::GetManifest { cid }, FileRequest::GetBitfield { cid }, FileRequest::GetPiece { cid, index: 9 }] {
            let mut buffer = Cursor::new(Vec::new());
            codec.write_request(&PROTOCOL, &mut buffer, request.clone()).await.unwrap();
            buffer.set_position(0);
            assert_eq!(codec.read_request(&PROTOCOL, &mut buffer).await.unwrap(), request);
        }
        let piece = vec![7u8; 256 * 1024 + 16];
        for response in [FileResponse::Piece(piece), FileResponse::Manifest(b"{}".to_vec()), FileResponse::Busy, FileResponse::NotFound, FileResponse::Ok] {
            let mut buffer = Cursor::new(Vec::new());
            codec.write_response(&PROTOCOL, &mut buffer, response.clone()).await.unwrap();
            // Pedaço vai cru: só 4 bytes de tamanho + 1 de tipo a mais
            assert_eq!(buffer.get_ref().len(), 5 + response.data().len());
            buffer.set_position(0);
            assert_eq!(codec.read_response(&PROTOCOL, &mut buffer).await.unwrap(), response);
        }
    }

    #[tokio::test]
    async fn test_codec_rejects_oversized_frames() {
        let mut codec = FileCodec;
        let mut frame = (MAX_RESPONSE as u32 + 1).to_be_bytes().to_vec();
        frame.push(2);
        assert!(codec.read_response(&PROTOCOL, &mut Cursor::new(frame)).await.is_err());
        let frame = (MAX_REQUEST as u32 + 1).to_be_bytes().to_vec();
        assert!(codec.read_request(&PROTOCOL, &mut Cursor::new(frame)).await.is_err());
    }
}
