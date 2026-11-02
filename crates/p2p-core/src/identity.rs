use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("Erro de I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("Chave inválida: {0}")]
    InvalidKey(String),
    #[error("Erro de serialização JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Erro de formato PKCS8/PEM: {0}")]
    Pkcs8(String),
}

/// Perfil público do usuário armazenado junto com a identidade
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserProfile {
    pub display_name: String,
    pub bio: Option<String>,
    pub avatar_base64: Option<String>,
    pub banner_color: Option<String>,
}

impl Default for UserProfile {
    fn default() -> Self {
        Self {
            display_name: "Anonymous Peer".to_string(),
            bio: None,
            avatar_base64: None,
            banner_color: Some("#5865F2".to_string()),
        }
    }
}

/// Representação das chaves criptográficas em formato PEM / PKCS#8
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityKeys {
    pub algorithm: String,
    pub private_key_pem: String,
    pub public_key_pem: String,
}

/// Documento JSON persistido da Identidade do Usuário
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityDocument {
    pub version: u32,
    pub created_at: u64,
    pub user_id: String,
    pub profile: UserProfile,
    pub keys: IdentityKeys,
}

/// Identidade Permanente do Usuário em memória
#[derive(Clone)]
pub struct UserIdentity {
    pub profile: UserProfile,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl UserIdentity {
    /// Gera uma nova identidade criptográfica aleatória com perfil padrão
    pub fn generate() -> Self {
        Self::generate_with_nick("Anonymous Peer")
    }

    /// Gera uma nova identidade com apelido inicial
    pub fn generate_with_nick(nick: &str) -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        Self {
            profile: UserProfile {
                display_name: nick.to_string(),
                ..Default::default()
            },
            signing_key,
            verifying_key,
        }
    }

    /// Carrega do disco ou cria uma nova se não existir (Persistência permanente em JSON/PEM).
    /// Suporta retrocompatibilidade transparente com arquivos de 32 bytes binários antigos.
    pub fn load_or_create<P: AsRef<Path>>(path: P) -> Result<Self, IdentityError> {
        let path = path.as_ref();
        if path.exists() {
            let data = fs::read(path)?;

            // 1. Tentar ler como JSON estruturado moderno
            if let Ok(doc) = serde_json::from_slice::<IdentityDocument>(&data) {
                return Self::from_document(&doc);
            }

            // 2. Retrocompatibilidade: Se for arquivo binário de 32 bytes brutos (versão legada)
            if data.len() == 32 {
                let key_bytes: [u8; 32] = data
                    .try_into()
                    .map_err(|_| IdentityError::InvalidKey("Tamanho incorreto".into()))?;
                let signing_key = SigningKey::from_bytes(&key_bytes);
                let verifying_key = signing_key.verifying_key();
                let identity = Self {
                    profile: UserProfile::default(),
                    signing_key,
                    verifying_key,
                };

                // Migra automaticamente para o novo formato JSON
                let _ = identity.save_to(path);
                return Ok(identity);
            }

            // 3. Tentar ler como PEM bruto puro direto no arquivo
            if let Ok(pem_str) = std::str::from_utf8(&data) {
                if pem_str.contains("BEGIN PRIVATE KEY") {
                    let signing_key = SigningKey::from_pkcs8_pem(pem_str)
                        .map_err(|e| IdentityError::Pkcs8(e.to_string()))?;
                    let verifying_key = signing_key.verifying_key();
                    let identity = Self {
                        profile: UserProfile::default(),
                        signing_key,
                        verifying_key,
                    };
                    let _ = identity.save_to(path);
                    return Ok(identity);
                }
            }

            Err(IdentityError::InvalidKey(
                "Formato de chave não reconhecido (esperado JSON ou PEM)".into(),
            ))
        } else {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            let id = Self::generate();
            id.save_to(path)?;
            Ok(id)
        }
    }

    /// Reconstrói a identidade a partir do documento JSON
    pub fn from_document(doc: &IdentityDocument) -> Result<Self, IdentityError> {
        let signing_key = SigningKey::from_pkcs8_pem(&doc.keys.private_key_pem)
            .map_err(|e| IdentityError::Pkcs8(e.to_string()))?;
        let verifying_key = signing_key.verifying_key();

        // Validar se o user_id bate com a chave pública
        let calculated_user_id = hex::encode(verifying_key.to_bytes());
        if calculated_user_id != doc.user_id {
            return Err(IdentityError::InvalidKey(
                "UserID divergente da chave pública informada".into(),
            ));
        }

        Ok(Self {
            profile: doc.profile.clone(),
            signing_key,
            verifying_key,
        })
    }

    /// Converte a identidade em um documento JSON serializável
    pub fn to_document(&self) -> Result<IdentityDocument, IdentityError> {
        let priv_pem = self
            .signing_key
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .map_err(|e| IdentityError::Pkcs8(e.to_string()))?;

        let pub_pem = self
            .verifying_key
            .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .map_err(|e| IdentityError::Pkcs8(e.to_string()))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(IdentityDocument {
            version: 1,
            created_at: now,
            user_id: self.public_key_hex(),
            profile: self.profile.clone(),
            keys: IdentityKeys {
                algorithm: "Ed25519".to_string(),
                private_key_pem: priv_pem.to_string(),
                public_key_pem: pub_pem,
            },
        })
    }

    /// Salva a identidade no disco em formato JSON legível e formatado
    pub fn save_to<P: AsRef<Path>>(&self, path: P) -> Result<(), IdentityError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let doc = self.to_document()?;
        let json_text = serde_json::to_string_pretty(&doc)?;
        fs::write(path, json_text)?;
        Ok(())
    }

    /// Atualiza o apelido do perfil
    pub fn set_nick(&mut self, nick: &str) {
        self.profile.display_name = nick.to_string();
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

/// Decodifica uma chave de 32 bytes em hexadecimal (pubkey Ed25519 / User ID)
pub(crate) fn hex_decode_32(s: &str) -> Result<[u8; 32], ()> {
    if s.len() != 64 || !s.is_ascii() {
        return Err(());
    }
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(bytes)
}

/// Verifica uma assinatura Ed25519 feita pela pubkey em hexadecimal
pub(crate) fn verify_signature_hex(pubkey_hex: &str, message: &[u8], signature: &[u8]) -> bool {
    use ed25519_dalek::{Signature, Verifier};
    let Ok(key_bytes) = hex_decode_32(pubkey_hex) else { return false };
    let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else { return false };
    let Ok(signature) = Signature::from_slice(signature) else { return false };
    key.verify(message, &signature).is_ok()
}

// Helper para converter hex sem adicionar crate externa
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
        let id = UserIdentity::generate_with_nick("Victor-PC");
        assert_eq!(id.profile.display_name, "Victor-PC");

        let msg = b"Mensagem secreta no chat";
        let sig_bytes = id.sign(msg);

        let sig = Signature::from_slice(&sig_bytes).unwrap();
        assert!(id.verifying_key.verify(msg, &sig).is_ok());
    }

    #[test]
    fn test_identity_json_pem_persistence() {
        let temp_dir = std::env::temp_dir().join("p2p_test_identity_json");
        let key_file = temp_dir.join("identity.json");
        let _ = fs::remove_file(&key_file);

        let mut id1 = UserIdentity::generate_with_nick("Victor");
        id1.profile.bio = Some("Testando identidade P2P".to_string());
        id1.save_to(&key_file).unwrap();

        // Verificar que o arquivo é JSON válido e tem PEM dentro
        let content = fs::read_to_string(&key_file).unwrap();
        assert!(content.contains("BEGIN PRIVATE KEY"));
        assert!(content.contains("BEGIN PUBLIC KEY"));
        assert!(content.contains("\"display_name\": \"Victor\""));

        // Carregar novamente do arquivo JSON
        let id2 = UserIdentity::load_or_create(&key_file).unwrap();

        assert_eq!(id1.public_key_hex(), id2.public_key_hex());
        assert_eq!(id2.profile.display_name, "Victor");
        assert_eq!(id2.profile.bio.as_deref(), Some("Testando identidade P2P"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_legacy_binary_key_migration() {
        let temp_dir = std::env::temp_dir().join("p2p_test_legacy_migration");
        let key_file = temp_dir.join("legacy.key");
        let _ = fs::create_dir_all(&temp_dir);

        // Criar chave legada de 32 bytes puros
        let mut csprng = OsRng;
        let old_signing_key = SigningKey::generate(&mut csprng);
        fs::write(&key_file, old_signing_key.to_bytes()).unwrap();

        // O load_or_create deve carregar sem erro e migrar automaticamente para JSON
        let migrated_id = UserIdentity::load_or_create(&key_file).unwrap();
        assert_eq!(
            migrated_id.public_key_hex(),
            hex::encode(old_signing_key.verifying_key().to_bytes())
        );

        // Verificar que agora o arquivo virou JSON com PEM
        let updated_content = fs::read_to_string(&key_file).unwrap();
        assert!(updated_content.contains("BEGIN PRIVATE KEY"));
        assert!(updated_content.contains("\"version\": 1"));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
