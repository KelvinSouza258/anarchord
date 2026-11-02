//! Cifragem de pedaços para arquivos de servidor.
//!
//! A chave do arquivo é aleatória e só viaja dentro da oferta, que no servidor vai cifrada com MLS.
//! O nonce é o índice do pedaço: a chave é única por arquivo, então nunca se repete, e a cifragem
//! fica determinística. Assim qualquer semeador (que guarda o texto claro) gera exatamente os bytes
//! cujo CID está no manifesto.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};

/// Bytes extras que a cifragem acrescenta a cada pedaço (tag Poly1305)
pub const TAG_SIZE: usize = 16;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileKey(#[serde(with = "crate::b64")] Vec<u8>);

impl std::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileKey(..)")
    }
}

impl FileKey {
    pub fn generate() -> Self {
        Self(rand::random::<[u8; 32]>().to_vec())
    }

    fn cipher(&self) -> Option<ChaCha20Poly1305> {
        (self.0.len() == 32).then(|| ChaCha20Poly1305::new(Key::from_slice(&self.0)))
    }

    pub fn encrypt_piece(&self, index: u32, plaintext: &[u8]) -> Option<Vec<u8>> {
        self.cipher()?.encrypt(&nonce(index), plaintext).ok()
    }

    pub fn decrypt_piece(&self, index: u32, ciphertext: &[u8]) -> Option<Vec<u8>> {
        self.cipher()?.decrypt(&nonce(index), ciphertext).ok()
    }
}

fn nonce(index: u32) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[..4].copy_from_slice(&index.to_le_bytes());
    *Nonce::from_slice(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_piece_roundtrip_is_deterministic_and_bound_to_index() {
        let key = FileKey::generate();
        let a = key.encrypt_piece(3, b"conteudo").unwrap();
        assert_eq!(a, key.encrypt_piece(3, b"conteudo").unwrap(), "mesmo CID em qualquer semeador");
        assert_eq!(a.len(), 8 + TAG_SIZE);
        assert_eq!(key.decrypt_piece(3, &a).unwrap(), b"conteudo");
        assert!(key.decrypt_piece(4, &a).is_none(), "pedaço trocado de posição");
        assert!(FileKey::generate().decrypt_piece(3, &a).is_none(), "outra chave");
    }
}
