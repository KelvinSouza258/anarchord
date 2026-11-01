use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("Erro de I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("Chave inválida")]
    InvalidKey,
}

/// Identidade Permanente do Usuário (Sem TTL)
#[derive(Clone)]
pub struct UserIdentity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl UserIdentity {
    /// Gera uma nova identidade criptográfica aleatória usando RNG do SO
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Carrega do disco ou cria uma nova se não existir (Persistência permanente)
    pub fn load_or_create<P: AsRef<Path>>(path: P) -> Result<Self, IdentityError> {
        let path = path.as_ref();
        if path.exists() {
            let bytes = fs::read(path)?;
            if bytes.len() != 32 {
                return Err(IdentityError::InvalidKey);
            }
            let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| IdentityError::InvalidKey)?;
            let signing_key = SigningKey::from_bytes(&key_bytes);
            let verifying_key = signing_key.verifying_key();
            Ok(Self {
                signing_key,
                verifying_key,
            })
        } else {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let id = Self::generate();
            fs::write(path, id.signing_key.to_bytes())?;
            Ok(id)
        }
    }

    /// Retorna a chave pública (UserID) em formato Hexadecimal legível
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    /// Assina digitalmente qualquer mensagem ou comando
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        self.signing_key.sign(message).to_vec()
    }

    /// Converte para o par de chaves oficial do libp2p
    pub fn to_libp2p_keypair(&self) -> libp2p::identity::Keypair {
        let mut bytes = self.signing_key.to_bytes();
        let ed25519_key = libp2p::identity::ed25519::SecretKey::try_from_bytes(&mut bytes)
            .expect("Chave Ed25519 de tamanho válido");
        libp2p::identity::Keypair::from(libp2p::identity::ed25519::Keypair::from(ed25519_key))
    }
}

// Helper para converter hex sem adicionar crate externa agora
mod hex {
    pub fn encode(data: [u8; 32]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generate_and_sign() {
        use ed25519_dalek::{Signature, Verifier};
        let id = UserIdentity::generate();
        let msg = b"Mensagem secreta no chat";
        let sig_bytes = id.sign(msg);

        let sig = Signature::from_slice(&sig_bytes).unwrap();
        assert!(id.verifying_key.verify(msg, &sig).is_ok());
    }

    #[test]
    fn test_identity_persistence() {
        let temp_dir = std::env::temp_dir().join("p2p_test_identity");
        let key_file = temp_dir.join("id.key");
        let _ = fs::remove_file(&key_file);

        let id1 = UserIdentity::load_or_create(&key_file).unwrap();
        let id2 = UserIdentity::load_or_create(&key_file).unwrap();

        assert_eq!(id1.public_key_hex(), id2.public_key_hex());
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
