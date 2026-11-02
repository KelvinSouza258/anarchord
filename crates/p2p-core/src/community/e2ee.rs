//! Criptografia de ponta a ponta dos servidores com MLS (RFC 9420, via `openmls`).
//!
//! - Cada servidor é um grupo MLS (group id = id do servidor). Chat, voz e tela do servidor
//!   trafegam cifrados com a chave do grupo; quem não está no grupo vê só bytes ilegíveis.
//! - A chave de assinatura MLS de cada pessoa é a própria chave Ed25519 da identidade, e a
//!   credencial é a pubkey em hex: quem está no grupo é exatamente quem diz ser.
//! - **Só o nó do dono faz Commits** (adicionar e remover), como na cadeia de configuração:
//!   as épocas ficam lineares e não há fork. Remover alguém troca a chave do grupo, e o
//!   removido não decifra mais nada dali em diante.
//! - Um membro que perde um Commit (estava offline) descarta o grupo e pede para entrar de
//!   novo; o dono troca a folha antiga pela nova.

use crate::identity::UserIdentity;
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use thiserror::Error;

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[derive(Error, Debug)]
pub enum E2eeError {
    #[error("sem chave do grupo deste servidor (ainda não admitido)")]
    NotInGroup,
    #[error("quem pediu não tem direito de entrar (banido ou fora da allow-list)")]
    NotAllowed,
    #[error("só o nó do dono administra o grupo cifrado")]
    NotOwner,
    #[error("pacote de chave inválido: {0}")]
    BadKeyPackage(String),
    #[error("o pacote de chave não pertence a quem o publicou")]
    KeyPackageMismatch,
    #[error("mensagem MLS inválida: {0}")]
    BadMessage(String),
    #[error("erro MLS: {0}")]
    Mls(String),
    #[error("erro de E/S: {0}")]
    Io(#[from] std::io::Error),
}

fn mls<E: std::fmt::Debug>(e: E) -> E2eeError {
    E2eeError::Mls(format!("{:?}", e))
}

/// Resultado de processar um Commit recebido
#[derive(Debug, PartialEq)]
pub enum CommitOutcome {
    /// Aplicado: nova época, chave do grupo trocada
    Applied { epoch: u64 },
    /// Este nó foi removido do grupo
    Removed,
    /// Commit de outra época (perdemos algum): é preciso pedir para entrar de novo
    OutOfSync,
    /// Commit que já vimos ou de época antiga
    Ignored,
}

/// Mensagem decifrada
#[derive(Debug)]
pub struct Decrypted {
    /// Pubkey (hex) de quem enviou, autenticada pelo MLS
    pub sender: String,
    pub plaintext: Vec<u8>,
}

#[derive(Serialize, Deserialize, Default)]
struct StoredState {
    /// Conteúdo do armazenamento do openmls (chave e valor em hex)
    storage: Vec<(String, String)>,
    groups: Vec<String>,
}

/// Grupos MLS dos servidores em que este nó está
pub struct ServerGroups {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    me: String,
    groups: HashMap<String, MlsGroup>,
    path: Option<PathBuf>,
    /// Quando o dono admitiu cada (servidor, pubkey): pedidos repetidos logo depois são ignorados
    recently_added: HashMap<(String, String), std::time::Instant>,
}

/// Janela em que pedidos de entrada repetidos de quem acabou de ser admitido são ignorados
/// (o Welcome pode ainda estar a caminho)
const READMIT_GRACE: std::time::Duration = std::time::Duration::from_secs(60);

impl ServerGroups {
    /// `path`: arquivo onde salvar o estado (None = só memória)
    pub fn new(identity: &UserIdentity, path: Option<PathBuf>) -> Self {
        let provider = OpenMlsRustCrypto::default();
        let me = identity.public_key_hex();
        let signer = SignatureKeyPair::from_raw(
            CIPHERSUITE.signature_algorithm(),
            identity.signing_key_bytes().to_vec(),
            identity.verifying_key_bytes().to_vec(),
        );
        let credential = CredentialWithKey {
            credential: BasicCredential::new(me.as_bytes().to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        let mut this = Self { provider, signer, credential, me, groups: HashMap::new(), path, recently_added: HashMap::new() };
        this.load();
        this
    }

    fn join_config() -> MlsGroupJoinConfig {
        MlsGroupJoinConfig::builder().use_ratchet_tree_extension(true).build()
    }

    pub fn has_group(&self, server_id: &str) -> bool {
        self.groups.get(server_id).is_some_and(|g| g.is_active())
    }

    pub fn epoch(&self, server_id: &str) -> Option<u64> {
        self.groups.get(server_id).map(|g| g.epoch().as_u64())
    }

    /// Cria o grupo de um servidor novo (nó do dono)
    pub fn create_group(&mut self, server_id: &str) -> Result<(), E2eeError> {
        let config = MlsGroupCreateConfig::builder().ciphersuite(CIPHERSUITE).use_ratchet_tree_extension(true).build();
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(server_id.as_bytes()),
            self.credential.clone(),
        )
        .map_err(mls)?;
        self.groups.insert(server_id.to_string(), group);
        self.save();
        Ok(())
    }

    /// Pubkeys dos membros do grupo
    pub fn members(&self, server_id: &str) -> BTreeSet<String> {
        self.groups
            .get(server_id)
            .map(|g| g.members().map(|m| String::from_utf8_lossy(m.credential.serialized_content()).to_string()).collect())
            .unwrap_or_default()
    }

    /// Pacote de chave para pedir entrada no grupo (publicado no tópico de controle)
    pub fn key_package(&mut self) -> Result<Vec<u8>, E2eeError> {
        let bundle = KeyPackage::builder()
            .build(CIPHERSUITE, &self.provider, &self.signer, self.credential.clone())
            .map_err(mls)?;
        self.save();
        bundle.key_package().tls_serialize_detached().map_err(mls)
    }

    /// Valida um pacote de chave e confere que ele é de `expected_pubkey`
    /// (credencial e chave de assinatura iguais à pubkey de quem publicou)
    fn validate_key_package(&self, bytes: &[u8], expected_pubkey: &str) -> Result<KeyPackage, E2eeError> {
        let kp = KeyPackageIn::tls_deserialize_exact(bytes)
            .map_err(|e| E2eeError::BadKeyPackage(format!("{:?}", e)))?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| E2eeError::BadKeyPackage(format!("{:?}", e)))?;
        let leaf = kp.leaf_node();
        let identity = String::from_utf8_lossy(leaf.credential().serialized_content()).to_string();
        let key_hex: String = leaf.signature_key().as_slice().iter().map(|b| format!("{:02x}", b)).collect();
        if identity != expected_pubkey || key_hex != expected_pubkey {
            return Err(E2eeError::KeyPackageMismatch);
        }
        Ok(kp)
    }

    /// Adiciona quem publicou o pacote de chave (nó do dono). Se a pessoa já estava no grupo
    /// (perdeu algum Commit), a folha antiga sai no mesmo passo.
    /// Retorna os Commits a publicar (para os membros) e o Welcome (para quem entrou).
    pub fn add_member(&mut self, server_id: &str, key_package: &[u8], pubkey: &str) -> Result<(Vec<Vec<u8>>, Vec<u8>), E2eeError> {
        let kp = self.validate_key_package(key_package, pubkey)?;
        let mut commits = Vec::new();
        if self.members(server_id).contains(pubkey) {
            if let Some(commit) = self.remove_members(server_id, &[pubkey.to_string()])? {
                commits.push(commit);
            }
        }
        let group = self.groups.get_mut(server_id).ok_or(E2eeError::NotInGroup)?;
        let (commit, welcome, _info) = group.add_members(&self.provider, &self.signer, &[kp]).map_err(mls)?;
        group.merge_pending_commit(&self.provider).map_err(mls)?;
        commits.push(commit.to_bytes().map_err(mls)?);
        let welcome = welcome.to_bytes().map_err(mls)?;
        self.save();
        Ok((commits, welcome))
    }

    /// Remove pessoas do grupo (nó do dono): a chave do grupo é trocada.
    /// Retorna o Commit a publicar, ou None se ninguém da lista estava no grupo.
    pub fn remove_members(&mut self, server_id: &str, pubkeys: &[String]) -> Result<Option<Vec<u8>>, E2eeError> {
        let group = self.groups.get_mut(server_id).ok_or(E2eeError::NotInGroup)?;
        let leaves: Vec<LeafNodeIndex> = group
            .members()
            .filter(|m| pubkeys.iter().any(|pk| pk.as_bytes() == m.credential.serialized_content()))
            .map(|m| m.index)
            .filter(|i| *i != group.own_leaf_index())
            .collect();
        if leaves.is_empty() {
            return Ok(None);
        }
        let (commit, _welcome, _info) = group.remove_members(&self.provider, &self.signer, &leaves).map_err(mls)?;
        group.merge_pending_commit(&self.provider).map_err(mls)?;
        self.save();
        Ok(Some(commit.to_bytes().map_err(mls)?))
    }

    /// Entra no grupo com um Welcome. Falha se o Welcome não é para este nó.
    /// Entra no grupo pelo Welcome. Só vale Welcome enviado pelo `owner` (identidade pessoal do
    /// dono, registrada na cadeia): o ID do servidor é público, então qualquer um poderia criar um
    /// grupo com o mesmo `group_id` e atrair membros para ele, lendo o que mandassem.
    pub fn join(&mut self, server_id: &str, welcome: &[u8], owner: &str) -> Result<(), E2eeError> {
        let message = MlsMessageIn::tls_deserialize_exact(welcome).map_err(|e| E2eeError::BadMessage(format!("{:?}", e)))?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(E2eeError::BadMessage("não é um Welcome".into()));
        };
        let staged = StagedWelcome::new_from_welcome(&self.provider, &Self::join_config(), welcome, None).map_err(mls)?;
        // A assinatura do GroupInfo já foi verificada pelo openmls contra a folha de quem enviou
        let sender = staged.welcome_sender().map_err(mls)?;
        // Credencial básica não amarra a chave: confere também a chave de assinatura (é a identidade)
        let key_hex: String = sender.signature_key().as_slice().iter().map(|b| format!("{:02x}", b)).collect();
        if sender.credential().serialized_content() != owner.as_bytes() || key_hex != owner {
            return Err(E2eeError::NotOwner);
        }
        let group = staged.into_group(&self.provider).map_err(mls)?;
        if group.group_id().as_slice() != server_id.as_bytes() {
            return Err(E2eeError::BadMessage("Welcome de outro grupo".into()));
        }
        self.groups.insert(server_id.to_string(), group);
        self.save();
        Ok(())
    }

    /// Aplica um Commit. Só Commits de `owner` (a identidade pessoal do dono, registrada na
    /// cadeia) são aceitos: no MLS qualquer membro poderia fazer Commits, mas aqui só o dono
    /// administra o grupo.
    pub fn process_commit(&mut self, server_id: &str, commit: &[u8], owner: &str) -> Result<CommitOutcome, E2eeError> {
        let Some(group) = self.groups.get_mut(server_id) else { return Ok(CommitOutcome::Ignored) };
        let message = MlsMessageIn::tls_deserialize_exact(commit).map_err(|e| E2eeError::BadMessage(format!("{:?}", e)))?;
        let protocol = message.try_into_protocol_message().map_err(|e| E2eeError::BadMessage(format!("{:?}", e)))?;
        let incoming = protocol.epoch().as_u64();
        let current = group.epoch().as_u64();
        if incoming < current {
            return Ok(CommitOutcome::Ignored);
        }
        if incoming > current {
            return Ok(CommitOutcome::OutOfSync);
        }
        let processed = match group.process_message(&self.provider, protocol) {
            Ok(p) => p,
            Err(_) => return Ok(CommitOutcome::OutOfSync),
        };
        if processed.credential().serialized_content() != owner.as_bytes() {
            return Ok(CommitOutcome::Ignored);
        }
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Ok(CommitOutcome::Ignored);
        };
        group.merge_staged_commit(&self.provider, *staged).map_err(mls)?;
        let outcome = if group.is_active() { CommitOutcome::Applied { epoch: group.epoch().as_u64() } } else { CommitOutcome::Removed };
        if outcome == CommitOutcome::Removed {
            self.forget(server_id);
        }
        self.save();
        Ok(outcome)
    }

    /// Descarta o grupo local (para pedir entrada de novo)
    pub fn drop_group(&mut self, server_id: &str) {
        self.forget(server_id);
        self.save();
    }

    /// Apaga o grupo da memória e do armazenamento do openmls (para poder entrar de novo)
    fn forget(&mut self, server_id: &str) {
        if let Some(mut group) = self.groups.remove(server_id) {
            let _ = group.delete(self.provider.storage());
        }
    }

    /// Cifra conteúdo para o grupo do servidor
    pub fn encrypt(&mut self, server_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, E2eeError> {
        let group = self.groups.get_mut(server_id).filter(|g| g.is_active()).ok_or(E2eeError::NotInGroup)?;
        let message = group.create_message(&self.provider, &self.signer, plaintext).map_err(mls)?;
        message.to_bytes().map_err(mls)
    }

    /// Decifra conteúdo do grupo e devolve quem enviou (autenticado pelo MLS)
    pub fn decrypt(&mut self, server_id: &str, ciphertext: &[u8]) -> Result<Decrypted, E2eeError> {
        let group = self.groups.get_mut(server_id).ok_or(E2eeError::NotInGroup)?;
        let message = MlsMessageIn::tls_deserialize_exact(ciphertext).map_err(|e| E2eeError::BadMessage(format!("{:?}", e)))?;
        let protocol = message.try_into_protocol_message().map_err(|e| E2eeError::BadMessage(format!("{:?}", e)))?;
        let processed = group.process_message(&self.provider, protocol).map_err(|e| E2eeError::BadMessage(format!("{:?}", e)))?;
        let sender = String::from_utf8_lossy(processed.credential().serialized_content()).to_string();
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(Decrypted { sender, plaintext: app.into_bytes() }),
            _ => Err(E2eeError::BadMessage("não é mensagem de aplicação".into())),
        }
    }

    pub fn me(&self) -> &str {
        &self.me
    }

    fn save(&self) {
        let Some(path) = &self.path else { return };
        let hex = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
        let storage = self.provider.storage().values.read().map(|v| v.iter().map(|(k, val)| (hex(k), hex(val))).collect()).unwrap_or_default();
        let state = StoredState { storage, groups: self.groups.keys().cloned().collect() };
        if let Ok(bytes) = serde_json::to_vec(&state) {
            let _ = std::fs::write(path, bytes);
        }
    }

    fn load(&mut self) {
        let Some(path) = &self.path else { return };
        let Ok(bytes) = std::fs::read(path) else { return };
        let Ok(state) = serde_json::from_slice::<StoredState>(&bytes) else { return };
        let unhex = |s: &str| (0..s.len()).step_by(2).filter_map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect::<Vec<u8>>();
        if let Ok(mut values) = self.provider.storage().values.write() {
            for (k, v) in &state.storage {
                values.insert(unhex(k), unhex(v));
            }
        }
        for id in state.groups {
            if let Ok(Some(group)) = MlsGroup::load(self.provider.storage(), &GroupId::from_slice(id.as_bytes())) {
                self.groups.insert(id, group);
            }
        }
    }
}

/// Nó do dono: admite no grupo cifrado quem publicou o pacote de chave, se tiver direito
/// (não banido e, em servidor fechado, na allow-list). Devolve as mensagens a publicar.
pub fn admit_from_key_package(
    groups: &mut ServerGroups,
    registry: &super::ServerRegistry,
    server_id: &str,
    from_pubkey: &str,
    key_package: &[u8],
    now: u64,
) -> Result<Vec<super::ServerMessage>, E2eeError> {
    let server = registry.get(server_id).filter(|s| s.is_owner()).ok_or(E2eeError::NotOwner)?;
    if !groups.has_group(server_id) {
        return Err(E2eeError::NotInGroup);
    }
    if server.is_banned(from_pubkey, now) || !server.is_allowed(from_pubkey, now) {
        return Err(E2eeError::NotAllowed);
    }
    let key = (server_id.to_string(), from_pubkey.to_string());
    if groups.members(server_id).contains(from_pubkey)
        && groups.recently_added.get(&key).is_some_and(|t| t.elapsed() < READMIT_GRACE)
    {
        return Ok(Vec::new());
    }
    let (commits, welcome) = groups.add_member(server_id, key_package, from_pubkey)?;
    groups.recently_added.insert(key, std::time::Instant::now());
    let mut out: Vec<super::ServerMessage> =
        commits.into_iter().map(|commit| super::ServerMessage::Commit { server_id: server_id.to_string(), commit }).collect();
    out.push(super::ServerMessage::Welcome { server_id: server_id.to_string(), target: from_pubkey.to_string(), welcome });
    Ok(out)
}

/// Nó do dono: remove do grupo cifrado quem não deveria estar (banido ou fora da allow-list).
/// Devolve o Commit a publicar, se alguém saiu.
pub fn enforce_membership(
    groups: &mut ServerGroups,
    registry: &super::ServerRegistry,
    server_id: &str,
    now: u64,
) -> Result<Option<super::ServerMessage>, E2eeError> {
    let Some(server) = registry.get(server_id).filter(|s| s.is_owner()) else { return Ok(None) };
    if !groups.has_group(server_id) {
        return Ok(None);
    }
    let me = groups.me().to_string();
    let out: Vec<String> = groups
        .members(server_id)
        .into_iter()
        .filter(|pk| *pk != me && (server.is_banned(pk, now) || !server.is_allowed(pk, now)))
        .collect();
    if out.is_empty() {
        return Ok(None);
    }
    Ok(groups.remove_members(server_id, &out)?.map(|commit| super::ServerMessage::Commit { server_id: server_id.to_string(), commit }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: &str = "abababababababababababababababababababababababababababababababab";

    fn node(nick: &str) -> (UserIdentity, ServerGroups) {
        let id = UserIdentity::generate_with_nick(nick);
        let groups = ServerGroups::new(&id, None);
        (id, groups)
    }

    /// Dono adiciona alguém; todos os membros atuais aplicam os Commits
    fn admit(owner: &mut ServerGroups, newcomer: &mut ServerGroups, members: &mut [&mut ServerGroups]) {
        let kp = newcomer.key_package().unwrap();
        let me = newcomer.me().to_string();
        let (commits, welcome) = owner.add_member(SERVER, &kp, &me).unwrap();
        for m in members.iter_mut() {
            for c in &commits {
                assert!(matches!(m.process_commit(SERVER, c, owner.me()).unwrap(), CommitOutcome::Applied { .. }));
            }
        }
        newcomer.join(SERVER, &welcome, owner.me()).unwrap();
    }

    #[test]
    fn test_members_exchange_encrypted_messages() {
        let (_a, mut alice) = node("Alice");
        let (bob_id, mut bob) = node("Bob");
        alice.create_group(SERVER).unwrap();
        admit(&mut alice, &mut bob, &mut []);

        let ciphertext = alice.encrypt(SERVER, b"segredo").unwrap();
        assert!(!ciphertext.windows(7).any(|w| w == b"segredo"), "texto não aparece em claro");
        let got = bob.decrypt(SERVER, &ciphertext).unwrap();
        assert_eq!(got.plaintext, b"segredo");
        assert_eq!(got.sender, alice.me());

        let reply = bob.encrypt(SERVER, b"oi").unwrap();
        assert_eq!(alice.decrypt(SERVER, &reply).unwrap().sender, bob_id.public_key_hex());
        assert_eq!(alice.members(SERVER).len(), 2);
    }

    #[test]
    fn test_outsider_cannot_decrypt() {
        let (_a, mut alice) = node("Alice");
        let (_e, mut eve) = node("Eve");
        alice.create_group(SERVER).unwrap();
        let ciphertext = alice.encrypt(SERVER, b"segredo").unwrap();
        assert!(eve.decrypt(SERVER, &ciphertext).is_err());
    }

    /// Ban: o removido não decifra nada depois do Commit de remoção
    #[test]
    fn test_removed_member_loses_access() {
        let (_a, mut alice) = node("Alice");
        let (_b, mut bob) = node("Bob");
        let (carol_id, mut carol) = node("Carol");
        alice.create_group(SERVER).unwrap();
        admit(&mut alice, &mut bob, &mut []);
        admit(&mut alice, &mut carol, &mut [&mut bob]);

        let commit = alice.remove_members(SERVER, &[carol_id.public_key_hex()]).unwrap().expect("Carol estava no grupo");
        assert!(matches!(bob.process_commit(SERVER, &commit, alice.me()).unwrap(), CommitOutcome::Applied { .. }));
        assert_eq!(carol.process_commit(SERVER, &commit, alice.me()).unwrap(), CommitOutcome::Removed);
        assert!(!carol.has_group(SERVER));

        let after = alice.encrypt(SERVER, b"depois do ban").unwrap();
        assert_eq!(bob.decrypt(SERVER, &after).unwrap().plaintext, b"depois do ban");
        assert!(carol.decrypt(SERVER, &after).is_err(), "removida não lê");
        assert!(!alice.members(SERVER).contains(&carol_id.public_key_hex()));
    }

    /// Commit de um membro que não é o dono é ignorado
    #[test]
    fn test_commits_from_non_owner_are_ignored() {
        let (_a, mut alice) = node("Alice");
        let (_b, mut bob) = node("Bob");
        let (carol_id, mut carol) = node("Carol");
        alice.create_group(SERVER).unwrap();
        admit(&mut alice, &mut bob, &mut []);
        admit(&mut alice, &mut carol, &mut [&mut bob]);
        // Bob (membro comum) tenta remover a Carol
        let rogue = bob.remove_members(SERVER, &[carol_id.public_key_hex()]).unwrap().unwrap();
        assert_eq!(carol.process_commit(SERVER, &rogue, alice.me()).unwrap(), CommitOutcome::Ignored);
        assert!(carol.has_group(SERVER));
        let msg = alice.encrypt(SERVER, b"Carol continua").unwrap();
        assert_eq!(carol.decrypt(SERVER, &msg).unwrap().plaintext, b"Carol continua");
    }

    /// Alguém cria um grupo com o mesmo ID do servidor e manda um Welcome: é recusado
    #[test]
    fn test_welcome_from_non_owner_is_rejected() {
        let (_a, mut alice) = node("Alice");
        let (_e, mut eve) = node("Eve");
        let (_b, mut bob) = node("Bob");
        alice.create_group(SERVER).unwrap();
        eve.create_group(SERVER).unwrap();
        let kp = bob.key_package().unwrap();
        let me = bob.me().to_string();
        let (_commits, fake) = eve.add_member(SERVER, &kp, &me).unwrap();
        assert!(matches!(bob.join(SERVER, &fake, alice.me()), Err(E2eeError::NotOwner)));
        assert!(!bob.has_group(SERVER));
        // O Welcome verdadeiro continua funcionando
        admit(&mut alice, &mut bob, &mut []);
        let msg = alice.encrypt(SERVER, b"grupo certo").unwrap();
        assert_eq!(bob.decrypt(SERVER, &msg).unwrap().plaintext, b"grupo certo");
    }

    #[test]
    fn test_key_package_must_belong_to_publisher() {
        let (_a, mut alice) = node("Alice");
        let (_b, mut bob) = node("Bob");
        let (eve_id, _eve) = node("Eve");
        alice.create_group(SERVER).unwrap();
        let kp = bob.key_package().unwrap();
        // Eve tenta entrar usando o pacote de chave do Bob
        assert!(matches!(alice.add_member(SERVER, &kp, &eve_id.public_key_hex()), Err(E2eeError::KeyPackageMismatch)));
    }

    /// Membro que perdeu um Commit pede para entrar de novo; o dono troca a folha
    #[test]
    fn test_member_out_of_sync_rejoins() {
        let (_a, mut alice) = node("Alice");
        let (_b, mut bob) = node("Bob");
        let (_c, mut carol) = node("Carol");
        alice.create_group(SERVER).unwrap();
        admit(&mut alice, &mut bob, &mut []);
        // Bob estava offline quando Carol entrou
        let kp = carol.key_package().unwrap();
        let me = carol.me().to_string();
        let (_missed, welcome) = alice.add_member(SERVER, &kp, &me).unwrap();
        carol.join(SERVER, &welcome, alice.me()).unwrap();

        let (_c2, mut dave) = node("Dave");
        let kp = dave.key_package().unwrap();
        let me = dave.me().to_string();
        let (commits, dave_welcome) = alice.add_member(SERVER, &kp, &me).unwrap();
        assert!(matches!(carol.process_commit(SERVER, &commits[0], alice.me()).unwrap(), CommitOutcome::Applied { .. }));
        dave.join(SERVER, &dave_welcome, alice.me()).unwrap();
        assert_eq!(bob.process_commit(SERVER, &commits[0], alice.me()).unwrap(), CommitOutcome::OutOfSync);

        bob.drop_group(SERVER);
        admit(&mut alice, &mut bob, &mut [&mut carol, &mut dave]);
        let msg = alice.encrypt(SERVER, b"de volta").unwrap();
        assert_eq!(bob.decrypt(SERVER, &msg).unwrap().plaintext, b"de volta");
        assert_eq!(alice.members(SERVER).iter().filter(|m| m.as_str() == bob.me()).count(), 1, "folha antiga substituída");
    }

    /// Desbanido pode entrar de novo depois de ter sido removido
    #[test]
    fn test_removed_member_can_be_readmitted() {
        let (_a, mut alice) = node("Alice");
        let (bob_id, mut bob) = node("Bob");
        alice.create_group(SERVER).unwrap();
        admit(&mut alice, &mut bob, &mut []);
        let commit = alice.remove_members(SERVER, &[bob_id.public_key_hex()]).unwrap().unwrap();
        assert_eq!(bob.process_commit(SERVER, &commit, alice.me()).unwrap(), CommitOutcome::Removed);
        admit(&mut alice, &mut bob, &mut []);
        let msg = alice.encrypt(SERVER, b"bem-vindo de volta").unwrap();
        assert_eq!(bob.decrypt(SERVER, &msg).unwrap().plaintext, b"bem-vindo de volta");
    }

    /// Regras de entrada aplicadas pelo dono a partir do estado do servidor
    #[test]
    fn test_owner_admits_and_enforces_with_server_rules() {
        use crate::community::{ModKind, ServerMessage, ServerRegistry};
        const T0: u64 = 1_800_000_000;
        let alice_id = UserIdentity::generate_with_nick("Alice");
        let mut alice = ServerGroups::new(&alice_id, None);
        let mut registry = ServerRegistry::in_memory();
        let server = registry.create("Guild", &alice_id.public_key_hex(), T0).unwrap();
        alice.create_group(&server).unwrap();

        let (bob_id, mut bob) = node("Bob");
        let bob_pk = bob_id.public_key_hex();
        let kp = bob.key_package().unwrap();
        let msgs = admit_from_key_package(&mut alice, &registry, &server, &bob_pk, &kp, T0).unwrap();
        assert!(matches!(msgs.last(), Some(ServerMessage::Welcome { target, .. }) if *target == bob_pk));
        assert!(alice.members(&server).contains(&bob_pk));

        // Pedido repetido logo depois de admitido: ignorado (sem nova troca de chave)
        let kp_again = bob.key_package().unwrap();
        assert!(admit_from_key_package(&mut alice, &registry, &server, &bob_pk, &kp_again, T0).unwrap().is_empty());

        // Ban: a manutenção tira Bob do grupo
        registry.moderate(&server, &alice_id, ModKind::Ban { until: None }, &bob_pk, "", T0 + 1).unwrap();
        assert!(enforce_membership(&mut alice, &registry, &server, T0 + 2).unwrap().is_some());
        assert!(!alice.members(&server).contains(&bob_pk));
        assert!(enforce_membership(&mut alice, &registry, &server, T0 + 3).unwrap().is_none(), "nada mais a fazer");

        // Banido não é readmitido
        let kp = bob.key_package().unwrap();
        assert!(matches!(admit_from_key_package(&mut alice, &registry, &server, &bob_pk, &kp, T0 + 4), Err(E2eeError::NotAllowed)));
    }

    #[test]
    fn test_state_persists_across_restart() {
        let path = std::env::temp_dir().join(format!("anarchord_mls_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let alice_id = UserIdentity::generate_with_nick("Alice");
        let (_b, mut bob) = node("Bob");
        {
            let mut alice = ServerGroups::new(&alice_id, Some(path.clone()));
            alice.create_group(SERVER).unwrap();
            admit(&mut alice, &mut bob, &mut []);
        }
        let mut alice = ServerGroups::new(&alice_id, Some(path.clone()));
        assert!(alice.has_group(SERVER));
        let msg = alice.encrypt(SERVER, b"depois de reiniciar").unwrap();
        assert_eq!(bob.decrypt(SERVER, &msg).unwrap().plaintext, b"depois de reiniciar");
        let _ = std::fs::remove_file(&path);
    }
}
