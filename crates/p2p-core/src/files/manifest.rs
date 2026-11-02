//! Manifesto de um arquivo do enxame: nome, tamanho e o CID de cada pedaço, assinado por quem
//! publicou. O CID do manifesto é o identificador do arquivo: quem tem o CID confere o manifesto,
//! e o manifesto confere cada pedaço.

use super::cid::Cid;
use super::crypto::{FileKey, TAG_SIZE};
use super::{MAX_FILE_SIZE, PIECE_SIZE};
use crate::file_transfer::sanitize_file_name;
use crate::identity::{verify_signature_hex, UserIdentity};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ManifestBody {
    pub name: String,
    pub size: u64,
    pub piece_size: u32,
    /// CID de cada pedaço como trafega na rede (cifrado, se `encrypted`)
    pub pieces: Vec<Cid>,
    /// Pubkey de quem publicou
    pub publisher: String,
    pub created_at: u64,
    /// Pedaços cifrados com a chave do arquivo (arquivos de servidor)
    pub encrypted: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Manifest {
    pub body: ManifestBody,
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("assinatura do manifesto inválida")]
    BadSignature,
    #[error("número de pedaços não bate com o tamanho")]
    BadLayout,
    #[error("arquivo maior que o limite")]
    TooLarge,
    #[error("manifesto não corresponde ao CID")]
    WrongCid,
    #[error("manifesto ilegível")]
    Malformed,
}

impl Manifest {
    /// Lê o arquivo pedaço a pedaço (sem carregar tudo na memória) e monta o manifesto assinado.
    /// Com `key`, os CIDs são dos pedaços cifrados.
    pub fn from_file(path: &Path, publisher: &UserIdentity, key: Option<&FileKey>, now: u64) -> std::io::Result<Self> {
        let mut file = std::fs::File::open(path)?;
        let size = file.metadata()?.len();
        if size > MAX_FILE_SIZE {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "arquivo maior que o limite"));
        }
        let mut pieces = Vec::with_capacity(piece_count(size, PIECE_SIZE) as usize);
        let mut buffer = vec![0u8; PIECE_SIZE as usize];
        for index in 0..piece_count(size, PIECE_SIZE) {
            let len = piece_len(size, PIECE_SIZE, index) as usize;
            file.read_exact(&mut buffer[..len])?;
            let wire = match key {
                Some(key) => key
                    .encrypt_piece(index, &buffer[..len])
                    .ok_or_else(|| std::io::Error::other("falha ao cifrar pedaço"))?,
                None => buffer[..len].to_vec(),
            };
            pieces.push(Cid::of(&wire));
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        let body = ManifestBody {
            name: sanitize_file_name(name),
            size,
            piece_size: PIECE_SIZE,
            pieces,
            publisher: publisher.public_key_hex(),
            created_at: now,
            encrypted: key.is_some(),
        };
        let signature = publisher.sign(&serde_json::to_vec(&body).expect("manifesto serializável"));
        Ok(Self { body, signature })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("manifesto serializável")
    }

    /// Lê e valida um manifesto recebido, conferindo que ele é o conteúdo de `expected`
    pub fn from_bytes(bytes: &[u8], expected: &Cid) -> Result<Self, ManifestError> {
        if !expected.matches(bytes) {
            return Err(ManifestError::WrongCid);
        }
        let manifest: Self = serde_json::from_slice(bytes).map_err(|_| ManifestError::Malformed)?;
        manifest.verify()?;
        Ok(manifest)
    }

    pub fn cid(&self) -> Cid {
        Cid::of(&self.to_bytes())
    }

    pub fn verify(&self) -> Result<(), ManifestError> {
        let body = &self.body;
        if body.size > MAX_FILE_SIZE {
            return Err(ManifestError::TooLarge);
        }
        if body.piece_size == 0 || body.pieces.len() as u64 != piece_count(body.size, body.piece_size) as u64 {
            return Err(ManifestError::BadLayout);
        }
        let bytes = serde_json::to_vec(body).map_err(|_| ManifestError::Malformed)?;
        if !verify_signature_hex(&body.publisher, &bytes, &self.signature) {
            return Err(ManifestError::BadSignature);
        }
        Ok(())
    }

    pub fn piece_count(&self) -> u32 {
        self.body.pieces.len() as u32
    }

    /// Tamanho do pedaço em texto claro
    pub fn piece_len(&self, index: u32) -> u64 {
        piece_len(self.body.size, self.body.piece_size, index)
    }

    /// Tamanho do pedaço como trafega na rede
    pub fn wire_len(&self, index: u32) -> u64 {
        self.piece_len(index) + if self.body.encrypted { TAG_SIZE as u64 } else { 0 }
    }

    pub fn piece_offset(&self, index: u32) -> u64 {
        index as u64 * self.body.piece_size as u64
    }
}

pub fn piece_count(size: u64, piece_size: u32) -> u32 {
    size.div_ceil(piece_size as u64) as u32
}

fn piece_len(size: u64, piece_size: u32, index: u32) -> u64 {
    let start = index as u64 * piece_size as u64;
    size.saturating_sub(start).min(piece_size as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn temp_file(name: &str, len: usize) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("anarchord_manifest_{}_{}", std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, data).unwrap();
        path
    }

    #[test]
    fn test_manifest_layout_and_cid() {
        let alice = UserIdentity::generate();
        let path = temp_file("video.mp4", PIECE_SIZE as usize * 2 + 10);
        let manifest = Manifest::from_file(&path, &alice, None, 100).unwrap();
        assert_eq!(manifest.piece_count(), 3);
        assert_eq!((manifest.piece_len(0), manifest.piece_len(2)), (PIECE_SIZE as u64, 10));
        assert_eq!(manifest.body.name, "video.mp4");
        let data = std::fs::read(&path).unwrap();
        assert!(manifest.body.pieces[2].matches(&data[PIECE_SIZE as usize * 2..]));

        let bytes = manifest.to_bytes();
        assert_eq!(Manifest::from_bytes(&bytes, &manifest.cid()).unwrap(), manifest);
        assert_eq!(Manifest::from_bytes(&bytes, &Cid::of(b"outro")), Err(ManifestError::WrongCid));
    }

    #[test]
    fn test_tampered_manifest_rejected() {
        let alice = UserIdentity::generate();
        let path = temp_file("a.txt", 1000);
        let mut manifest = Manifest::from_file(&path, &alice, None, 0).unwrap();
        manifest.body.name = "virus.exe".into();
        assert_eq!(manifest.verify(), Err(ManifestError::BadSignature));

        let mut manifest = Manifest::from_file(&path, &alice, None, 0).unwrap();
        manifest.body.pieces.push(Cid::of(b"x"));
        assert_eq!(manifest.verify(), Err(ManifestError::BadLayout));
    }

    #[test]
    fn test_encrypted_manifest_hashes_ciphertext() {
        let alice = UserIdentity::generate();
        let key = FileKey::generate();
        let path = temp_file("b.bin", 500);
        let manifest = Manifest::from_file(&path, &alice, Some(&key), 0).unwrap();
        let data = std::fs::read(&path).unwrap();
        assert!(!manifest.body.pieces[0].matches(&data));
        assert!(manifest.body.pieces[0].matches(&key.encrypt_piece(0, &data).unwrap()));
        assert_eq!(manifest.wire_len(0), 500 + TAG_SIZE as u64);
    }

    #[test]
    fn test_empty_file_has_no_pieces() {
        let alice = UserIdentity::generate();
        let manifest = Manifest::from_file(&temp_file("vazio", 0), &alice, None, 0).unwrap();
        assert_eq!(manifest.piece_count(), 0);
        assert!(manifest.verify().is_ok());
    }
}
