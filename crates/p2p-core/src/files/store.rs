//! Armazenamento de um arquivo do enxame em disco, pedaço a pedaço.
//!
//! Quem publica serve direto do arquivo original. Quem baixa grava em `<pasta parcial>/<cid>.part`
//! (já com o tamanho final), com `<cid>.json` (manifesto e chave) e `<cid>.have` (bitfield),
//! o que permite retomar depois de fechar o app. O texto claro fica no disco; a cifragem é aplicada
//! só na rede.

use super::cid::Cid;
use super::crypto::FileKey;
use super::manifest::Manifest;
use crate::file_transfer::create_unique_file;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Um bit por pedaço
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bitfield {
    len: u32,
    #[serde(with = "crate::b64")]
    bits: Vec<u8>,
}

impl Bitfield {
    pub fn new(len: u32) -> Self {
        Self { len, bits: vec![0; (len as usize).div_ceil(8)] }
    }

    pub fn full(len: u32) -> Self {
        let mut field = Self::new(len);
        (0..len).for_each(|i| field.set(i));
        field
    }

    pub fn len(&self) -> u32 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn get(&self, index: u32) -> bool {
        index < self.len && self.bits[index as usize / 8] & (1 << (index % 8)) != 0
    }

    pub fn set(&mut self, index: u32) {
        if index < self.len {
            self.bits[index as usize / 8] |= 1 << (index % 8);
        }
    }

    pub fn count(&self) -> u32 {
        (0..self.len).filter(|&i| self.get(i)).count() as u32
    }

    pub fn is_complete(&self) -> bool {
        self.count() == self.len
    }

    pub fn missing(&self) -> impl Iterator<Item = u32> + '_ {
        (0..self.len).filter(|&i| !self.get(i))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }

    /// Lê um bitfield recebido de outro par, conferindo o tamanho esperado
    pub fn from_bytes(len: u32, bytes: &[u8]) -> Option<Self> {
        (bytes.len() == (len as usize).div_ceil(8)).then(|| Self { len, bits: bytes.to_vec() })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PieceError {
    #[error("pedaço fora do arquivo")]
    OutOfRange,
    #[error("pedaço não confere com o manifesto")]
    WrongHash,
    #[error("falha ao decifrar pedaço")]
    Decrypt,
    #[error("erro de disco: {0}")]
    Io(#[from] std::io::Error),
}

/// De onde veio a oferta: para saber a quem perguntar e a quem servir ao retomar
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Origin {
    /// Tópico da sala
    Topic(String),
    /// PeerId de quem mandou direto
    Peer(String),
}

/// Manifesto, chave e origem gravados ao iniciar o download (para retomar)
#[derive(Serialize, Deserialize)]
struct SavedState {
    manifest: Manifest,
    key: Option<FileKey>,
    #[serde(default)]
    origin: Option<Origin>,
}

pub struct PieceStore {
    manifest: Manifest,
    cid: Cid,
    key: Option<FileKey>,
    origin: Option<Origin>,
    data_path: PathBuf,
    have: Bitfield,
    /// Pasta parcial e arquivos de estado enquanto o download não terminou
    partial: Option<PathBuf>,
}

impl PieceStore {
    /// Quem publicou (ou já tem o arquivo completo) serve direto do arquivo
    pub fn seed(manifest: Manifest, path: PathBuf, key: Option<FileKey>) -> Self {
        let have = Bitfield::full(manifest.piece_count());
        let cid = manifest.cid();
        Self { manifest, cid, key, origin: None, data_path: path, have, partial: None }
    }

    /// Começa um download em `partial_dir` (ou retoma, se já existir)
    pub fn create(partial_dir: &Path, manifest: Manifest, key: Option<FileKey>, origin: Option<Origin>) -> std::io::Result<Self> {
        let cid = manifest.cid();
        if let Ok(existing) = Self::open(partial_dir, &cid) {
            return Ok(existing);
        }
        std::fs::create_dir_all(partial_dir)?;
        let data_path = partial_dir.join(format!("{}.part", cid));
        File::create(&data_path)?.set_len(manifest.body.size)?;
        let state = SavedState { manifest, key, origin };
        std::fs::write(partial_dir.join(format!("{}.json", cid)), serde_json::to_vec(&state)?)?;
        let have = Bitfield::new(state.manifest.piece_count());
        let store = Self {
            manifest: state.manifest,
            cid,
            key: state.key,
            origin: state.origin,
            data_path,
            have,
            partial: Some(partial_dir.into()),
        };
        store.save_have()?;
        Ok(store)
    }

    /// Retoma um download salvo
    pub fn open(partial_dir: &Path, cid: &Cid) -> std::io::Result<Self> {
        let state: SavedState = serde_json::from_slice(&std::fs::read(partial_dir.join(format!("{}.json", cid)))?)?;
        if state.manifest.cid() != *cid || state.manifest.verify().is_err() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "estado do download corrompido"));
        }
        let count = state.manifest.piece_count();
        let have = std::fs::read(partial_dir.join(format!("{}.have", cid)))
            .ok()
            .and_then(|bytes| Bitfield::from_bytes(count, &bytes))
            .unwrap_or_else(|| Bitfield::new(count));
        let data_path = partial_dir.join(format!("{}.part", cid));
        if !data_path.exists() {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "arquivo parcial sumiu"));
        }
        Ok(Self {
            manifest: state.manifest,
            cid: *cid,
            key: state.key,
            origin: state.origin,
            data_path,
            have,
            partial: Some(partial_dir.into()),
        })
    }

    /// CIDs dos downloads pendentes numa pasta parcial
    pub fn pending(partial_dir: &Path) -> Vec<Cid> {
        let Ok(entries) = std::fs::read_dir(partial_dir) else { return Vec::new() };
        entries
            .filter_map(|e| e.ok()?.file_name().to_str()?.strip_suffix(".json")?.parse().ok())
            .collect()
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn cid(&self) -> &Cid {
        &self.cid
    }

    pub fn key(&self) -> Option<&FileKey> {
        self.key.as_ref()
    }

    pub fn origin(&self) -> Option<&Origin> {
        self.origin.as_ref()
    }

    pub fn have(&self) -> &Bitfield {
        &self.have
    }

    pub fn is_complete(&self) -> bool {
        self.have.is_complete()
    }

    pub fn path(&self) -> &Path {
        &self.data_path
    }

    /// Fração baixada (0.0 a 1.0) em bytes
    pub fn progress(&self) -> f32 {
        if self.manifest.body.size == 0 {
            return 1.0;
        }
        let done: u64 = (0..self.manifest.piece_count()).filter(|&i| self.have.get(i)).map(|i| self.manifest.piece_len(i)).sum();
        done as f32 / self.manifest.body.size as f32
    }

    /// Confere um pedaço recebido (como veio da rede) e grava o texto claro na posição dele
    pub fn accept_piece(&mut self, index: u32, wire: &[u8]) -> Result<(), PieceError> {
        let expected = self.manifest.body.pieces.get(index as usize).ok_or(PieceError::OutOfRange)?;
        if wire.len() as u64 != self.manifest.wire_len(index) || !expected.matches(wire) {
            return Err(PieceError::WrongHash);
        }
        if self.have.get(index) {
            return Ok(());
        }
        let plain = match &self.key {
            Some(key) => key.decrypt_piece(index, wire).ok_or(PieceError::Decrypt)?,
            None => wire.to_vec(),
        };
        let mut file = OpenOptions::new().write(true).open(&self.data_path)?;
        file.seek(SeekFrom::Start(self.manifest.piece_offset(index)))?;
        file.write_all(&plain)?;
        self.have.set(index);
        self.save_have()?;
        Ok(())
    }

    /// Bytes do pedaço como vão para a rede, se o temos
    pub fn serve_piece(&self, index: u32) -> Option<Vec<u8>> {
        if !self.have.get(index) {
            return None;
        }
        let mut file = File::open(&self.data_path).ok()?;
        file.seek(SeekFrom::Start(self.manifest.piece_offset(index))).ok()?;
        let mut plain = vec![0u8; self.manifest.piece_len(index) as usize];
        file.read_exact(&mut plain).ok()?;
        match &self.key {
            Some(key) => key.encrypt_piece(index, &plain),
            None => Some(plain),
        }
    }

    /// Download completo: move para `dest_dir` com nome sanitizado e sem sobrescrever nada,
    /// apaga o estado e passa a semear do arquivo final
    pub fn finish(&mut self, dest_dir: &Path) -> std::io::Result<PathBuf> {
        if !self.is_complete() {
            return Err(std::io::Error::other("download incompleto"));
        }
        let Some(partial) = self.partial.take() else { return Ok(self.data_path.clone()) };
        let (target, reserved) = create_unique_file(dest_dir, &self.manifest.body.name)?;
        drop(reserved);
        std::fs::rename(&self.data_path, &target)?;
        let _ = std::fs::remove_file(partial.join(format!("{}.json", self.cid)));
        let _ = std::fs::remove_file(partial.join(format!("{}.have", self.cid)));
        self.data_path = target.clone();
        Ok(target)
    }

    /// Cancela o download e apaga os arquivos parciais
    pub fn discard(self) {
        if let Some(partial) = self.partial {
            for ext in ["part", "json", "have"] {
                let _ = std::fs::remove_file(partial.join(format!("{}.{}", self.cid, ext)));
            }
        }
    }

    fn save_have(&self) -> std::io::Result<()> {
        match &self.partial {
            Some(partial) => std::fs::write(partial.join(format!("{}.have", self.cid)), self.have.as_bytes()),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::PIECE_SIZE;
    use crate::identity::UserIdentity;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("anarchord_store_{}_{}_{}", tag, std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn published(len: usize, key: Option<FileKey>) -> (PieceStore, Vec<u8>) {
        let dir = temp_dir("src");
        let path = dir.join("foto.png");
        let data: Vec<u8> = (0..len).map(|i| (i * 7 % 256) as u8).collect();
        std::fs::write(&path, &data).unwrap();
        let manifest = Manifest::from_file(&path, &UserIdentity::generate(), key.as_ref(), 0).unwrap();
        (PieceStore::seed(manifest, path, key), data)
    }

    #[test]
    fn test_bitfield() {
        let mut field = Bitfield::new(10);
        field.set(0);
        field.set(9);
        field.set(42);
        assert!(field.get(0) && field.get(9) && !field.get(5) && !field.get(42));
        assert_eq!(field.count(), 2);
        assert_eq!(field.missing().count(), 8);
        assert_eq!(Bitfield::from_bytes(10, field.as_bytes()), Some(field.clone()));
        assert!(Bitfield::from_bytes(10, &[0]).is_none());
        assert!(Bitfield::full(10).is_complete());
    }

    #[test]
    fn test_download_out_of_order_and_finish() {
        let (seed, data) = published(PIECE_SIZE as usize * 2 + 123, None);
        let partial = temp_dir("part");
        let downloads = temp_dir("down");
        let mut store = PieceStore::create(&partial, seed.manifest().clone(), None, None).unwrap();
        for index in [2, 0, 1] {
            store.accept_piece(index, &seed.serve_piece(index).unwrap()).unwrap();
            assert_eq!(store.serve_piece(index), seed.serve_piece(index), "já serve o que tem");
        }
        assert!(store.is_complete());
        assert_eq!(store.progress(), 1.0);
        let path = store.finish(&downloads).unwrap();
        assert_eq!(path.file_name().unwrap(), "foto.png");
        assert_eq!(std::fs::read(&path).unwrap(), data);
        assert!(PieceStore::pending(&partial).is_empty());
        assert_eq!(store.serve_piece(1), seed.serve_piece(1), "continua semeando do arquivo final");
    }

    #[test]
    fn test_wrong_piece_rejected() {
        let (seed, _) = published(1000, None);
        let mut store = PieceStore::create(&temp_dir("bad"), seed.manifest().clone(), None, None).unwrap();
        let mut piece = seed.serve_piece(0).unwrap();
        piece[0] ^= 1;
        assert!(matches!(store.accept_piece(0, &piece), Err(PieceError::WrongHash)));
        assert!(matches!(store.accept_piece(7, &piece), Err(PieceError::OutOfRange)));
        assert!(!store.have().get(0));
    }

    #[test]
    fn test_resume_after_restart() {
        let (seed, _) = published(PIECE_SIZE as usize * 3, None);
        let partial = temp_dir("resume");
        let cid = seed.cid().to_owned();
        {
            let mut store = PieceStore::create(&partial, seed.manifest().clone(), None, None).unwrap();
            store.accept_piece(1, &seed.serve_piece(1).unwrap()).unwrap();
        }
        assert_eq!(PieceStore::pending(&partial), vec![cid]);
        let store = PieceStore::open(&partial, &cid).unwrap();
        assert_eq!(store.have().missing().collect::<Vec<_>>(), vec![0, 2]);
        store.discard();
        assert!(PieceStore::pending(&partial).is_empty());
    }

    #[test]
    fn test_encrypted_pieces_roundtrip() {
        let key = FileKey::generate();
        let (seed, data) = published(PIECE_SIZE as usize + 50, Some(key.clone()));
        let wire = seed.serve_piece(0).unwrap();
        assert_ne!(&wire[..16], &data[..16], "na rede vai cifrado");

        // Sem a chave certa, o pedaço passa no hash mas não decifra
        let mut outsider = PieceStore::create(&temp_dir("enc_bad"), seed.manifest().clone(), Some(FileKey::generate()), None).unwrap();
        assert!(matches!(outsider.accept_piece(0, &wire), Err(PieceError::Decrypt)));

        let mut store = PieceStore::create(&temp_dir("enc"), seed.manifest().clone(), Some(key), None).unwrap();
        for index in 0..2 {
            store.accept_piece(index, &seed.serve_piece(index).unwrap()).unwrap();
        }
        let path = store.finish(&temp_dir("enc_down")).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), data);
    }
}
