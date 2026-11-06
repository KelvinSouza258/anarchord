use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

pub const ENC_KEY_ADV_DOMAIN: &[u8] = b"anarchord-enc-key-adv-v1\0";

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

/// Informações de um par de chaves assimétricas persistidas
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyPairInfo {
    pub algorithm: String,
    pub public_key: String,
    pub private_key: String,
}

/// Representação das chaves criptográficas desacopladas:
/// - `signing`: Chave raiz Ed25519 fixa para identidade e assinaturas
/// - `encryption`: Chave X25519 dedicada para criptografia E2EE (suporta rotação)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityKeys {
    pub signing: KeyPairInfo,
    pub encryption: KeyPairInfo,
}

/// Estrutura legada v1 para deserialização e migração transparente
#[derive(Clone, Debug, Serialize, Deserialize)]
struct LegacyIdentityKeys {
    pub algorithm: String,
    pub private_key_pem: String,
    pub public_key_pem: String,
}

/// Registro de amigo / contato na lista de amigos local
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FriendEntry {
    /// Chave pública Ed25519 em hexadecimal (64 caracteres)
    pub public_key: String,
    /// Apelido customizado definido localmente pelo usuário
    #[serde(default)]
    pub alias: Option<String>,
    /// Timestamp Unix (segundos) de quando foi adicionado
    pub added_at: u64,
    /// Chave pública X25519 dedicada para criptografia E2EE (hex de 64 caracteres)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_public_key: Option<String>,
    /// Época da chave de criptografia conhecida
    #[serde(default)]
    pub encryption_epoch: u64,
}

/// Registro serializável de uma chave de criptografia anterior arquivada no histórico
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoricalKey {
    pub epoch: u64,
    pub algorithm: String,
    pub public_key: String,
    pub private_key: String,
    pub retired_at: u64,
}

/// Chave de criptografia anterior em memória mantida para decifragem de mensagens em voo
#[derive(Clone)]
pub struct HistoricalEncryptionKey {
    pub epoch: u64,
    pub secret: StaticSecret,
    pub public: X25519PublicKey,
    pub retired_at: u64,
}

/// Documento JSON persistido da Identidade do Usuário (v2 com chaves separadas e histórico)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityDocument {
    pub version: u32,
    pub created_at: u64,
    pub user_id: String,
    pub profile: UserProfile,
    pub keys: IdentityKeys,
    #[serde(default)]
    pub previous_encryption_keys: Vec<HistoricalKey>,
    #[serde(default)]
    pub friends: Vec<FriendEntry>,
    #[serde(default)]
    pub encryption_epoch: u64,
}

/// Estrutura legada v1 para deserialização e migração transparente
#[derive(Clone, Debug, Serialize, Deserialize)]
struct LegacyIdentityDocument {
    pub version: u32,
    pub created_at: u64,
    pub user_id: String,
    pub profile: UserProfile,
    pub keys: LegacyIdentityKeys,
    #[serde(default)]
    pub friends: Vec<FriendEntry>,
}

/// Anúncio de chave pública de criptografia X25519 para rotação
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EncryptionKeyAdvertisement {
    /// Identidade imutável (User ID / chave pública Ed25519 em hex de 64 caracteres)
    pub user_id: String,
    /// Chave pública X25519 dedicada para criptografia E2EE (hex de 64 caracteres)
    pub encryption_public_key: String,
    /// Época da chave (contador monotônico incremental de rotação: 0, 1, 2...)
    pub epoch: u64,
    /// Timestamp Unix (segundos) em que o anúncio foi gerado
    pub timestamp: u64,
}

/// Anúncio de chave assinado digitalmente pela chave de assinatura raiz (Ed25519)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SignedEncryptionKeyAdvertisement {
    pub advertisement: EncryptionKeyAdvertisement,
    /// Assinatura Ed25519 sobre os bytes de `advertisement`
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl SignedEncryptionKeyAdvertisement {
    pub fn signing_bytes(adv: &EncryptionKeyAdvertisement) -> Vec<u8> {
        let tuple = (&adv.user_id, &adv.encryption_public_key, adv.epoch, adv.timestamp);
        postcard::to_extend(&tuple, ENC_KEY_ADV_DOMAIN.to_vec()).expect("serializável")
    }

    pub fn verify(&self) -> bool {
        if hex_decode_32(&self.advertisement.user_id).is_err() {
            return false;
        }
        if hex_decode_32(&self.advertisement.encryption_public_key).is_err() {
            return false;
        }
        let bytes = Self::signing_bytes(&self.advertisement);
        verify_signature_hex(&self.advertisement.user_id, &bytes, &self.signature)
    }
}

/// Identidade Permanente do Usuário em memória com chaves desacopladas
#[derive(Clone)]
pub struct UserIdentity {
    pub profile: UserProfile,
    pub friends: Vec<FriendEntry>,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    encryption_secret: StaticSecret,
    encryption_public: X25519PublicKey,
    encryption_epoch: u64,
    previous_encryption_keys: Vec<HistoricalEncryptionKey>,
}

impl UserIdentity {
    /// Gera uma nova identidade criptográfica aleatória com perfil padrão
    pub fn generate() -> Self {
        Self::generate_with_nick("Anonymous Peer")
    }

    /// Gera uma nova identidade com apelido inicial e chaves desacopladas (Ed25519 + X25519)
    pub fn generate_with_nick(nick: &str) -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let encryption_secret = ed25519_priv_to_x25519(&signing_key.to_bytes());
        let encryption_public = X25519PublicKey::from(&encryption_secret);

        Self {
            profile: UserProfile {
                display_name: nick.to_string(),
                ..Default::default()
            },
            friends: Vec::new(),
            signing_key,
            verifying_key,
            encryption_secret,
            encryption_public,
            encryption_epoch: 0,
            previous_encryption_keys: Vec::new(),
        }
    }

    /// Carrega do disco ou cria uma nova se não existir (Persistência permanente em JSON/PEM).
    /// Suporta retrocompatibilidade transparente com arquivos de versão v1 e binários de 32 bytes antigos.
    pub fn load_or_create<P: AsRef<Path>>(path: P) -> Result<Self, IdentityError> {
        let path = path.as_ref();
        if path.exists() {
            let data = fs::read(path)?;

            // 1. Tentar ler como JSON estruturado moderno (v2 com chaves separadas)
            if let Ok(doc) = serde_json::from_slice::<IdentityDocument>(&data) {
                return Self::from_document(&doc);
            }

            // 2. Retrocompatibilidade: ler como JSON v1 (chave única Ed25519) e migrar automaticamente para v2
            if let Ok(legacy_doc) = serde_json::from_slice::<LegacyIdentityDocument>(&data) {
                let identity = Self::from_legacy_document(&legacy_doc)?;
                let _ = identity.save_to(path);
                return Ok(identity);
            }

            // 3. Retrocompatibilidade: Se for arquivo binário de 32 bytes brutos (versão legada)
            if data.len() == 32 {
                let key_bytes: [u8; 32] = data
                    .try_into()
                    .map_err(|_| IdentityError::InvalidKey("Tamanho incorreto".into()))?;
                let signing_key = SigningKey::from_bytes(&key_bytes);
                let verifying_key = signing_key.verifying_key();
                let encryption_secret = ed25519_priv_to_x25519(&signing_key.to_bytes());
                let encryption_public = X25519PublicKey::from(&encryption_secret);
                let identity = Self {
                    profile: UserProfile::default(),
                    friends: Vec::new(),
                    signing_key,
                    verifying_key,
                    encryption_secret,
                    encryption_public,
                    encryption_epoch: 0,
                    previous_encryption_keys: Vec::new(),
                };

                // Migra automaticamente para o novo formato JSON v2
                let _ = identity.save_to(path);
                return Ok(identity);
            }

            // 4. Retrocompatibilidade: Tentar ler como PEM bruto puro direto no arquivo
            if let Ok(pem_str) = std::str::from_utf8(&data) {
                if pem_str.contains("BEGIN PRIVATE KEY") {
                    let signing_key = SigningKey::from_pkcs8_pem(pem_str)
                        .map_err(|e| IdentityError::Pkcs8(e.to_string()))?;
                    let verifying_key = signing_key.verifying_key();
                    let encryption_secret = ed25519_priv_to_x25519(&signing_key.to_bytes());
                    let encryption_public = X25519PublicKey::from(&encryption_secret);
                    let identity = Self {
                        profile: UserProfile::default(),
                        friends: Vec::new(),
                        signing_key,
                        verifying_key,
                        encryption_secret,
                        encryption_public,
                        encryption_epoch: 0,
                        previous_encryption_keys: Vec::new(),
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

    /// Reconstrói a identidade a partir do documento JSON v2
    pub fn from_document(doc: &IdentityDocument) -> Result<Self, IdentityError> {
        let signing_key = SigningKey::from_pkcs8_pem(&doc.keys.signing.private_key)
            .map_err(|e| IdentityError::Pkcs8(e.to_string()))?;
        let verifying_key = signing_key.verifying_key();

        // Validar se o user_id bate com a chave pública
        let calculated_user_id = hex::encode(verifying_key.to_bytes());
        if calculated_user_id != doc.user_id {
            return Err(IdentityError::InvalidKey(
                "UserID divergente da chave pública informada".into(),
            ));
        }

        let enc_bytes = hex_decode_32(&doc.keys.encryption.private_key)
            .map_err(|_| IdentityError::InvalidKey("Chave privada X25519 inválida (esperado 32 bytes hex)".into()))?;
        let encryption_secret = StaticSecret::from(enc_bytes);
        let encryption_public = X25519PublicKey::from(&encryption_secret);

        let mut previous_encryption_keys = Vec::new();
        for hk in &doc.previous_encryption_keys {
            if let Ok(bytes) = hex_decode_32(&hk.private_key) {
                let secret = StaticSecret::from(bytes);
                let public = X25519PublicKey::from(&secret);
                previous_encryption_keys.push(HistoricalEncryptionKey {
                    epoch: hk.epoch,
                    secret,
                    public,
                    retired_at: hk.retired_at,
                });
            }
        }

        Ok(Self {
            profile: doc.profile.clone(),
            friends: doc.friends.clone(),
            signing_key,
            verifying_key,
            encryption_secret,
            encryption_public,
            encryption_epoch: doc.encryption_epoch,
            previous_encryption_keys,
        })
    }

    /// Migra a identidade a partir de um documento legado v1
    fn from_legacy_document(doc: &LegacyIdentityDocument) -> Result<Self, IdentityError> {
        let signing_key = SigningKey::from_pkcs8_pem(&doc.keys.private_key_pem)
            .map_err(|e| IdentityError::Pkcs8(e.to_string()))?;
        let verifying_key = signing_key.verifying_key();

        let calculated_user_id = hex::encode(verifying_key.to_bytes());
        if calculated_user_id != doc.user_id {
            return Err(IdentityError::InvalidKey(
                "UserID divergente da chave pública informada".into(),
            ));
        }

        // Deriva a chave X25519 inicial a partir do seed Ed25519 para continuidade e compatibilidade retroativa
        let encryption_secret = ed25519_priv_to_x25519(&signing_key.to_bytes());
        let encryption_public = X25519PublicKey::from(&encryption_secret);

        Ok(Self {
            profile: doc.profile.clone(),
            friends: doc.friends.clone(),
            signing_key,
            verifying_key,
            encryption_secret,
            encryption_public,
            encryption_epoch: 0,
            previous_encryption_keys: Vec::new(),
        })
    }

    /// Converte a identidade em um documento JSON v2 serializável
    pub fn to_document(&self) -> Result<IdentityDocument, IdentityError> {
        let priv_pem = self
            .signing_key
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .map_err(|e| IdentityError::Pkcs8(e.to_string()))?;

        let pub_pem = self
            .verifying_key
            .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .map_err(|e| IdentityError::Pkcs8(e.to_string()))?;

        let enc_priv_hex = hex::encode(self.encryption_secret.to_bytes());
        let enc_pub_hex = self.encryption_public_key_hex();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let previous_encryption_keys = self
            .previous_encryption_keys
            .iter()
            .map(|k| HistoricalKey {
                epoch: k.epoch,
                algorithm: "X25519".to_string(),
                public_key: hex::encode(k.public.to_bytes()),
                private_key: hex::encode(k.secret.to_bytes()),
                retired_at: k.retired_at,
            })
            .collect();

        Ok(IdentityDocument {
            version: 2,
            created_at: now,
            user_id: self.public_key_hex(),
            profile: self.profile.clone(),
            keys: IdentityKeys {
                signing: KeyPairInfo {
                    algorithm: "Ed25519".to_string(),
                    private_key: priv_pem.to_string(),
                    public_key: pub_pem,
                },
                encryption: KeyPairInfo {
                    algorithm: "X25519".to_string(),
                    private_key: enc_priv_hex,
                    public_key: enc_pub_hex,
                },
            },
            previous_encryption_keys,
            friends: self.friends.clone(),
            encryption_epoch: self.encryption_epoch,
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

    /// Adiciona ou atualiza um amigo na lista local
    pub fn add_friend(&mut self, pubkey_hex: &str, alias: Option<&str>) -> Result<(), IdentityError> {
        let pubkey_clean = pubkey_hex.trim().to_lowercase();
        if hex_decode_32(&pubkey_clean).is_err() {
            return Err(IdentityError::InvalidKey("A chave pública deve ter exatamente 64 caracteres hexadecimais (32 bytes)".into()));
        }
        if pubkey_clean == self.public_key_hex().to_lowercase() {
            return Err(IdentityError::InvalidKey("Você não pode adicionar a si mesmo como amigo".into()));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Some(existing) = self.friends.iter_mut().find(|f| f.public_key.eq_ignore_ascii_case(&pubkey_clean)) {
            existing.alias = alias.map(|a| a.trim().to_string());
        } else {
            self.friends.push(FriendEntry {
                public_key: pubkey_clean,
                alias: alias.map(|a| a.trim().to_string()),
                added_at: now,
                encryption_public_key: None,
                encryption_epoch: 0,
            });
        }
        Ok(())
    }

    /// Remove um amigo da lista local pelo pubkey_hex. Retorna `true` se encontrou e removeu.
    pub fn remove_friend(&mut self, pubkey_hex: &str) -> bool {
        let pubkey_clean = pubkey_hex.trim().to_lowercase();
        let initial_len = self.friends.len();
        self.friends.retain(|f| !f.public_key.eq_ignore_ascii_case(&pubkey_clean));
        self.friends.len() < initial_len
    }

    /// Retorna a lista de amigos cadastrados
    pub fn get_friends(&self) -> &[FriendEntry] {
        &self.friends
    }

    /// Retorna a chave pública (UserID) em formato Hexadecimal legível
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    /// Retorna a chave pública X25519 de criptografia
    pub fn encryption_public_key(&self) -> X25519PublicKey {
        self.encryption_public
    }

    /// Retorna a chave pública X25519 de criptografia em hexadecimal (64 caracteres)
    pub fn encryption_public_key_hex(&self) -> String {
        hex::encode(self.encryption_public.to_bytes())
    }

    /// Referência ao segredo estático X25519 de criptografia
    pub fn encryption_secret(&self) -> &StaticSecret {
        &self.encryption_secret
    }

    /// Histórico de chaves de criptografia anteriores mantidas para decifrar mensagens em voo
    pub fn previous_encryption_keys(&self) -> &[HistoricalEncryptionKey] {
        &self.previous_encryption_keys
    }

    /// Contador monotônico / época atual da chave de criptografia
    pub fn encryption_epoch(&self) -> u64 {
        self.encryption_epoch
    }

    /// Gera um anúncio assinado pela chave de identidade Ed25519 com a chave de cifra X25519 atual
    pub fn create_key_advertisement(&self) -> SignedEncryptionKeyAdvertisement {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let adv = EncryptionKeyAdvertisement {
            user_id: self.public_key_hex(),
            encryption_public_key: self.encryption_public_key_hex(),
            epoch: self.encryption_epoch,
            timestamp: now,
        };
        let sig_bytes = SignedEncryptionKeyAdvertisement::signing_bytes(&adv);
        let signature = self.sign(&sig_bytes);
        SignedEncryptionKeyAdvertisement {
            advertisement: adv,
            signature,
        }
    }

    /// Rotaciona a chave de criptografia X25519, guardando a chave anterior no histórico,
    /// incrementando a época e mantendo a identidade intacta.
    /// Retorna o anúncio assinado da nova chave pronto para ser transmitido aos amigos.
    pub fn rotate_encryption_key(&mut self) -> SignedEncryptionKeyAdvertisement {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 1. Arquiva a chave atual no histórico antes de substituí-la
        self.previous_encryption_keys.push(HistoricalEncryptionKey {
            epoch: self.encryption_epoch,
            secret: StaticSecret::from(self.encryption_secret.to_bytes()),
            public: self.encryption_public,
            retired_at: now,
        });

        // 2. Gera novo par independente com OsRng
        let mut enc_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut enc_bytes);
        let new_secret = StaticSecret::from(enc_bytes);
        let new_public = X25519PublicKey::from(&new_secret);
        self.encryption_secret = new_secret;
        self.encryption_public = new_public;
        self.encryption_epoch = self.encryption_epoch.saturating_add(1);
        self.create_key_advertisement()
    }

    /// Atualiza a chave de criptografia de um amigo a partir de um anúncio assinado validado
    pub fn update_friend_encryption_key(
        &mut self,
        ad: &SignedEncryptionKeyAdvertisement,
    ) -> Result<bool, IdentityError> {
        if !ad.verify() {
            return Err(IdentityError::InvalidKey(
                "Assinatura do anúncio de chave de criptografia inválida".into(),
            ));
        }
        let peer_pk = ad.advertisement.user_id.trim().to_lowercase();
        if peer_pk == self.public_key_hex().to_lowercase() {
            return Ok(false);
        }
        if let Some(friend) = self.friends.iter_mut().find(|f| f.public_key.eq_ignore_ascii_case(&peer_pk)) {
            if ad.advertisement.epoch >= friend.encryption_epoch {
                friend.encryption_public_key = Some(ad.advertisement.encryption_public_key.to_lowercase());
                friend.encryption_epoch = ad.advertisement.epoch;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Retorna a chave pública de criptografia X25519 de um amigo se cadastrada
    pub fn friend_encryption_public_key(&self, pubkey_hex: &str) -> Option<X25519PublicKey> {
        let clean = pubkey_hex.trim().to_lowercase();
        let friend = self.friends.iter().find(|f| f.public_key.eq_ignore_ascii_case(&clean))?;
        let enc_hex = friend.encryption_public_key.as_ref()?;
        let bytes = hex_decode_32(enc_hex).ok()?;
        Some(X25519PublicKey::from(bytes))
    }

    /// Resolve a chave pública de criptografia X25519 de um par:
    /// 1. Se estiver na lista de amigos com chave X25519 dedicada, usa-a diretamente.
    /// 2. Fallback de retrocompatibilidade: deriva do ponto Montgomery da chave Ed25519.
    pub fn resolve_encryption_public_key(&self, pubkey_hex: &str) -> Result<X25519PublicKey, IdentityError> {
        if let Some(key) = self.friend_encryption_public_key(pubkey_hex) {
            return Ok(key);
        }
        ed25519_pub_hex_to_x25519(pubkey_hex)
    }

    /// Assina digitalmente qualquer mensagem ou comando
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        self.signing_key.sign(message).to_vec()
    }

    /// Bytes da chave privada Ed25519 (usada também como chave de assinatura MLS)
    pub(crate) fn signing_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Bytes da chave pública Ed25519
    pub(crate) fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Converte para o par de chaves oficial do libp2p
    pub fn to_libp2p_keypair(&self) -> libp2p::identity::Keypair {
        let mut bytes = self.signing_key.to_bytes();
        let ed25519_key = libp2p::identity::ed25519::SecretKey::try_from_bytes(&mut bytes)
            .expect("Chave Ed25519 de tamanho válido");
        libp2p::identity::Keypair::from(libp2p::identity::ed25519::Keypair::from(ed25519_key))
    }
}

/// Converte uma chave privada Ed25519 (seed de 32 bytes) para um `StaticSecret` X25519 (RFC 8032)
pub fn ed25519_priv_to_x25519(ed_secret_bytes: &[u8; 32]) -> StaticSecret {
    let hash = Sha512::digest(ed_secret_bytes);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    StaticSecret::from(scalar)
}

/// Converte uma chave pública Ed25519 (hex de 64 chars) para `X25519PublicKey` (ponto Montgomery biracionalmente equivalente)
pub fn ed25519_pub_hex_to_x25519(pubkey_hex: &str) -> Result<X25519PublicKey, IdentityError> {
    let bytes = hex_decode_32(pubkey_hex).map_err(|_| IdentityError::InvalidKey("Hex inválido".into()))?;
    let compressed = CompressedEdwardsY(bytes);
    let edwards_point = compressed.decompress().ok_or_else(|| IdentityError::InvalidKey("Ponto Edwards inválido".into()))?;
    let montgomery = edwards_point.to_montgomery();
    Ok(X25519PublicKey::from(montgomery.to_bytes()))
}

/// Decodifica uma chave de 32 bytes em hexadecimal (pubkey Ed25519 / User ID / chave X25519)
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

        // Chave pública de criptografia X25519 deve ter 64 chars hex (32 bytes)
        assert_eq!(id.encryption_public_key_hex().len(), 64);
        assert_eq!(id.encryption_epoch(), 0);
    }

    #[test]
    fn test_identity_json_pem_persistence_v2() {
        let temp_dir = std::env::temp_dir().join("p2p_test_identity_json_v2");
        let key_file = temp_dir.join("identity.json");
        let _ = fs::remove_file(&key_file);

        let mut id1 = UserIdentity::generate_with_nick("Victor");
        id1.profile.bio = Some("Testando identidade P2P v2".to_string());
        id1.save_to(&key_file).unwrap();

        // Verificar que o arquivo é JSON válido e tem chaves separadas v2
        let content = fs::read_to_string(&key_file).unwrap();
        assert!(content.contains("BEGIN PRIVATE KEY"));
        assert!(content.contains("BEGIN PUBLIC KEY"));
        assert!(content.contains("\"algorithm\": \"Ed25519\""));
        assert!(content.contains("\"algorithm\": \"X25519\""));
        assert!(content.contains("\"version\": 2"));
        assert!(content.contains("\"display_name\": \"Victor\""));

        // Carregar novamente do arquivo JSON
        let id2 = UserIdentity::load_or_create(&key_file).unwrap();

        assert_eq!(id1.public_key_hex(), id2.public_key_hex());
        assert_eq!(id1.encryption_public_key_hex(), id2.encryption_public_key_hex());
        assert_eq!(id2.profile.display_name, "Victor");
        assert_eq!(id2.profile.bio.as_deref(), Some("Testando identidade P2P v2"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_legacy_v1_identity_json_migration() {
        let temp_dir = std::env::temp_dir().join("p2p_test_legacy_v1_migration");
        let key_file = temp_dir.join("identity.json");
        let _ = fs::create_dir_all(&temp_dir);

        // Simula um identity.json v1 legado (onde havia apenas keys.algorithm/private_key_pem/public_key_pem)
        let mut csprng = OsRng;
        let old_signing = SigningKey::generate(&mut csprng);
        let old_verifying = old_signing.verifying_key();
        let priv_pem = old_signing
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .unwrap();
        let pub_pem = old_verifying
            .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .unwrap();
        let old_uid = hex::encode(old_verifying.to_bytes());

        let legacy_json = serde_json::json!({
            "version": 1,
            "created_at": 1700000000u64,
            "user_id": old_uid,
            "profile": {
                "display_name": "OldUser",
                "bio": null,
                "avatar_base64": null,
                "banner_color": "#5865F2"
            },
            "keys": {
                "algorithm": "Ed25519",
                "private_key_pem": priv_pem.to_string(),
                "public_key_pem": pub_pem
            },
            "friends": []
        });
        fs::write(&key_file, serde_json::to_string_pretty(&legacy_json).unwrap()).unwrap();

        // O load_or_create deve carregar sem erro e migrar automaticamente para v2
        let migrated_id = UserIdentity::load_or_create(&key_file).unwrap();
        assert_eq!(migrated_id.public_key_hex(), old_uid);
        assert_eq!(migrated_id.profile.display_name, "OldUser");

        // A chave X25519 derivada inicialmente deve bater com a conversão Montgomery da chave Ed25519
        let montgomery_expected = ed25519_pub_hex_to_x25519(&old_uid).unwrap();
        assert_eq!(migrated_id.encryption_public_key().to_bytes(), montgomery_expected.to_bytes());

        // Verificar que agora o arquivo foi reescrito no formato v2 com as duas chaves
        let updated_content = fs::read_to_string(&key_file).unwrap();
        assert!(updated_content.contains("\"version\": 2"));
        assert!(updated_content.contains("\"algorithm\": \"X25519\""));

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

        // O load_or_create deve carregar sem erro e migrar automaticamente para JSON v2
        let migrated_id = UserIdentity::load_or_create(&key_file).unwrap();
        assert_eq!(
            migrated_id.public_key_hex(),
            hex::encode(old_signing_key.verifying_key().to_bytes())
        );

        // Verificar que agora o arquivo virou JSON com PEM e X25519 v2
        let updated_content = fs::read_to_string(&key_file).unwrap();
        assert!(updated_content.contains("BEGIN PRIVATE KEY"));
        assert!(updated_content.contains("\"version\": 2"));
        assert!(updated_content.contains("\"algorithm\": \"X25519\""));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_encryption_key_rotation_and_advertisement() {
        let mut alice = UserIdentity::generate_with_nick("Alice");
        let mut bob = UserIdentity::generate_with_nick("Bob");

        let alice_uid = alice.public_key_hex();
        let initial_enc_key = alice.encryption_public_key_hex();
        assert_eq!(alice.encryption_epoch(), 0);

        // Bob adiciona Alice como amiga
        bob.add_friend(&alice_uid, Some("Alice")).unwrap();

        // Alice cria anúncio da sua chave inicial
        let ad0 = alice.create_key_advertisement();
        assert!(ad0.verify());
        assert_eq!(ad0.advertisement.user_id, alice_uid);
        assert_eq!(ad0.advertisement.encryption_public_key, initial_enc_key);
        assert_eq!(ad0.advertisement.epoch, 0);

        // Bob processa anúncio da Alice
        assert!(bob.update_friend_encryption_key(&ad0).unwrap());
        assert_eq!(
            bob.friend_encryption_public_key(&alice_uid).unwrap().to_bytes(),
            alice.encryption_public_key().to_bytes()
        );

        // Alice rotaciona a chave de criptografia
        let ad1 = alice.rotate_encryption_key();
        assert!(ad1.verify());
        assert_eq!(alice.encryption_epoch(), 1);
        assert_eq!(ad1.advertisement.epoch, 1);
        // O user_id de Alice PERMANECE IDÊNTICO (separação de chaves)
        assert_eq!(alice.public_key_hex(), alice_uid);
        // A chave de criptografia MUDOU
        assert_ne!(alice.encryption_public_key_hex(), initial_enc_key);

        // Bob atualiza a chave de Alice a partir do novo anúncio
        assert!(bob.update_friend_encryption_key(&ad1).unwrap());
        assert_eq!(
            bob.friend_encryption_public_key(&alice_uid).unwrap().to_bytes(),
            alice.encryption_public_key().to_bytes()
        );

        // Proteção contra replay: tentar reaplicar o anúncio antigo ad0 deve ser ignorado
        assert!(!bob.update_friend_encryption_key(&ad0).unwrap());
        // Chave do Bob permanece a nova (ad1)
        assert_eq!(
            bob.friend_encryption_public_key(&alice_uid).unwrap().to_bytes(),
            alice.encryption_public_key().to_bytes()
        );

        // Mallory tenta falsificar um anúncio com o user_id da Alice
        let mallory = UserIdentity::generate_with_nick("Mallory");
        let forged_adv = EncryptionKeyAdvertisement {
            user_id: alice_uid.clone(),
            encryption_public_key: mallory.encryption_public_key_hex(),
            epoch: 99,
            timestamp: 2000000000,
        };
        // Mallory assina com a própria chave dela (não a da Alice)
        let forged_sig = mallory.sign(&SignedEncryptionKeyAdvertisement::signing_bytes(&forged_adv));
        let forged_ad = SignedEncryptionKeyAdvertisement {
            advertisement: forged_adv,
            signature: forged_sig,
        };
        assert!(!forged_ad.verify());
        assert!(bob.update_friend_encryption_key(&forged_ad).is_err());
    }

    #[test]
    fn test_friends_management_and_persistence() {
        let temp_dir = std::env::temp_dir().join(format!("p2p_test_friends_{}", std::process::id()));
        let key_file = temp_dir.join("identity.json");
        let _ = fs::create_dir_all(&temp_dir);

        let mut user = UserIdentity::generate_with_nick("Alice");
        let friend_id = UserIdentity::generate_with_nick("Bob");
        let friend_pk = friend_id.public_key_hex();

        // Adicionar a si mesmo deve falhar
        assert!(user.add_friend(&user.public_key_hex(), None).is_err());
        // Chave inválida deve falhar
        assert!(user.add_friend("chave_invalida", None).is_err());

        // Adicionar Bob
        assert!(user.add_friend(&friend_pk, Some("Bobby")).is_ok());
        assert_eq!(user.get_friends().len(), 1);
        assert_eq!(user.get_friends()[0].public_key, friend_pk);
        assert_eq!(user.get_friends()[0].alias.as_deref(), Some("Bobby"));

        // Persistir e recarregar
        user.save_to(&key_file).unwrap();
        let loaded = UserIdentity::load_or_create(&key_file).unwrap();
        assert_eq!(loaded.get_friends().len(), 1);
        assert_eq!(loaded.get_friends()[0].public_key, friend_pk);
        assert_eq!(loaded.get_friends()[0].alias.as_deref(), Some("Bobby"));

        // Remover amigo
        let mut loaded = loaded;
        assert!(loaded.remove_friend(&friend_pk));
        assert_eq!(loaded.get_friends().len(), 0);
        assert!(!loaded.remove_friend(&friend_pk)); // já removido

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
