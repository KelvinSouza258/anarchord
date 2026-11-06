//! Serialização de bytes como texto base64 em JSON (em vez de um array de números, que
//! ocupa ~4x mais e é ilegível). A leitura também aceita o formato antigo (array).
//!
//! Uso: `#[serde(with = "crate::b64")] pub signature: Vec<u8>`

use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        serializer.serialize_str(&ENGINE.encode(bytes))
    } else {
        // Formato binário (rede): bytes crus
        serializer.serialize_bytes(bytes)
    }
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    if !deserializer.is_human_readable() {
        return serde_bytes::deserialize(deserializer);
    }
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Base64(String),
        Legacy(Vec<u8>),
    }
    match Repr::deserialize(deserializer)? {
        Repr::Base64(text) => ENGINE.decode(text).map_err(serde::de::Error::custom),
        Repr::Legacy(bytes) => Ok(bytes),
    }
}

pub mod arr32 {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&ENGINE.encode(bytes))
        } else {
            bytes.serialize(serializer)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        if !deserializer.is_human_readable() {
            return <[u8; 32]>::deserialize(deserializer);
        }
        let v = super::deserialize(deserializer)?;
        v.try_into().map_err(|vec: Vec<u8>| {
            serde::de::Error::custom(format!("esperava array de 32 bytes, obteve {}", vec.len()))
        })
    }
}

pub mod arr12 {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8; 12], serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&ENGINE.encode(bytes))
        } else {
            bytes.serialize(serializer)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 12], D::Error> {
        if !deserializer.is_human_readable() {
            return <[u8; 12]>::deserialize(deserializer);
        }
        let v = super::deserialize(deserializer)?;
        v.try_into().map_err(|vec: Vec<u8>| {
            serde::de::Error::custom(format!("esperava array de 12 bytes, obteve {}", vec.len()))
        })
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Signed {
        #[serde(with = "crate::b64")]
        signature: Vec<u8>,
        #[serde(with = "crate::b64::arr32")]
        key32: [u8; 32],
        #[serde(with = "crate::b64::arr12")]
        nonce12: [u8; 12],
    }

    #[test]
    fn test_bytes_as_base64_and_legacy_arrays_still_load() {
        let value = Signed {
            signature: vec![0, 1, 2, 250, 255],
            key32: [42u8; 32],
            nonce12: [7u8; 12],
        };
        let json = serde_json::to_string(&value).unwrap();
        assert!(json.contains("\"signature\":\"AAEC+v8=\""));
        assert_eq!(serde_json::from_str::<Signed>(&json).unwrap(), value);

        // Teste formato binário (postcard)
        let bin = postcard::to_allocvec(&value).unwrap();
        let decoded_bin: Signed = postcard::from_bytes(&bin).unwrap();
        assert_eq!(decoded_bin, value);

        // Teste retrocompatibilidade: JSON com arrays numéricos legados
        let legacy = format!(
            r#"{{"signature":[0,1,2,250,255],"key32":{:?},"nonce12":{:?}}}"#,
            vec![42u8; 32],
            vec![7u8; 12]
        );
        assert_eq!(serde_json::from_str::<Signed>(&legacy).unwrap(), value, "formato antigo continua legível");
        assert!(serde_json::from_str::<Signed>(r#"{"signature":"não é base64!","key32":[0],"nonce12":[0]}"#).is_err());
    }
}
