//! CID (Content Identifier) no formato do IPFS: CIDv1, codec `raw`, multihash SHA-256.
//!
//! Texto em base32 minúsculo com prefixo `b` (ex.: `bafkrei...`), o mesmo que `ipfs add --cid-version 1
//! --raw-leaves` gera para um bloco. Implementado à mão porque só precisamos deste formato.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

/// Versão 1, codec raw (0x55), multihash sha2-256 (0x12) com 32 bytes (0x20)
const PREFIX: [u8; 4] = [0x01, 0x55, 0x12, 0x20];
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cid([u8; 32]);

impl Cid {
    /// CID dos bytes (SHA-256)
    pub fn of(data: &[u8]) -> Self {
        Self(Sha256::digest(data).into())
    }

    /// Confere se `data` é o conteúdo deste CID
    pub fn matches(&self, data: &[u8]) -> bool {
        Self::of(data) == *self
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.0
    }

    /// Bytes binários do CID (prefixo + digest)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = PREFIX.to_vec();
        bytes.extend_from_slice(&self.0);
        bytes
    }

    /// Prefixo curto para exibir e para comandos (`/get bafkrei4f`)
    pub fn short(&self) -> String {
        self.to_string().chars().skip(8).take(8).collect()
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "b{}", base32_encode(&self.to_bytes()))
    }
}

impl fmt::Debug for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cid({})", self)
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("CID inválido")]
pub struct InvalidCid;

impl FromStr for Cid {
    type Err = InvalidCid;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let body = text.strip_prefix('b').ok_or(InvalidCid)?;
        let bytes = base32_decode(body).ok_or(InvalidCid)?;
        if bytes.len() != 36 || bytes[..4] != PREFIX {
            return Err(InvalidCid);
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[4..]);
        Ok(Self(digest))
    }
}

impl Serialize for Cid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Cid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let value = BASE32.iter().position(|&b| b == c)? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_ipfs_raw_cid() {
        // `echo -n "hello world" | ipfs add --cid-version 1 --raw-leaves -n -q`
        let cid = Cid::of(b"hello world");
        assert_eq!(cid.to_string(), "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e");
    }

    #[test]
    fn test_roundtrip_and_rejects_garbage() {
        let cid = Cid::of(b"pedaco");
        assert_eq!(cid.to_string().parse::<Cid>(), Ok(cid));
        assert!(cid.matches(b"pedaco") && !cid.matches(b"outro"));
        assert_eq!("bafkrei".parse::<Cid>(), Err(InvalidCid));
        assert_eq!("Qmabc".parse::<Cid>(), Err(InvalidCid));
        let json = serde_json::to_string(&cid).unwrap();
        assert_eq!(serde_json::from_str::<Cid>(&json).unwrap(), cid);
        assert_eq!(cid.short().len(), 8);
    }
}
