//! Criptografia de ponta a ponta dos servidores com MLS (RFC 9420, via `openmls`).
//!
//! - **100% Efêmero em Memória (Sem `mls-state.json` em disco):** o estado do grupo MLS vive
//!   exclusivamente em RAM. Se o processo encerrar, as chaves de época da sessão são destruídas.
//! - **Chave do Servidor = Apenas Assinatura/Governança:** a chave de dono (`owner-key.json`) e a
//!   cadeia de blocos (`ServerChain`) servem exclusivamente para governança (certificados de
//!   moderador, allow-list, bans e canais). O dono **não precisa estar online** para que os membros
//!   conversem com criptografia E2EE.
//! - **Eleição Determinística de Líder (`menor pubkey`):** dentro de qualquer grupo MLS ativo,
//!   o líder (committer responsável por adicionar/remover membros e rotacionar chaves) é sempre o
//!   membro presente no grupo com a **menor `pubkey` lexicográfica** (`members.iter().min()`).
//!   Se um membro com `pubkey` menor entrar, ele assume a liderança na época seguinte. Se o líder
//!   atual sair ou desconectar, o próximo menor assume imediatamente e remove a folha antiga.
//! - **Convergência Determinística de Grupos (`maior grupo vence`):** se dois subgrupos MLS se
//!   formarem simultaneamente (ex.: entrada simultânea em canal vazio ou partição de rede), vence
//!   o grupo com **mais membros válidos** (desempate: menor `pubkey` de líder). O grupo menor
//!   descarta seu estado local e pede entrada (`KeyPackage`) ao grupo vencedor.
//! - **Rotação Periódica de Chaves (`self_update`):** o líder atual rotaciona periodicamente o
//!   segredo de época do grupo via `self_update`, invalidando estados antigos (Forward Secrecy /
//!   Post-Compromise Security).

use crate::identity::UserIdentity;
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
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
    #[error("apenas o líder determinístico atual do grupo pode administrar commits")]
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
    /// Commit que já vimos, de época antiga ou de quem não é o líder
    Ignored,
}

/// Mensagem decifrada
#[derive(Debug)]
pub struct Decrypted {
    /// Pubkey (hex) de quem enviou, autenticada pelo MLS
    pub sender: String,
    pub plaintext: Vec<u8>,
}

/// Regra determinística de convergência entre dois grupos MLS:
/// Retorna `true` se o grupo candidato (`candidate_members`) deve vencer e substituir
/// o grupo atual (`current_members`).
/// - Grupo com **mais membros** vence;
/// - Em caso de empate no número de membros, vence o grupo cujo líder (`min(pubkey)`) é lexicograficamente menor.
pub fn should_adopt_group(current_members: &BTreeSet<String>, candidate_members: &BTreeSet<String>) -> bool {
    if candidate_members.is_empty() {
        return false;
    }
    if current_members.is_empty() {
        return true;
    }
    match candidate_members.len().cmp(&current_members.len()) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => {
            let candidate_leader = candidate_members.iter().min();
            let current_leader = current_members.iter().min();
            candidate_leader < current_leader
        }
    }
}

/// Grupos MLS efêmeros (100% em RAM) dos servidores em que este nó está
pub struct ServerGroups {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    me: String,
    groups: HashMap<String, MlsGroup>,
    /// Quando o líder admitiu cada (servidor, pubkey): pedidos repetidos logo depois são ignorados
    recently_added: HashMap<(String, String), std::time::Instant>,
    /// Última rotação periódica de chave (ou criação) de cada grupo
    last_rotation: HashMap<String, std::time::Instant>,
}

/// Janela em que pedidos de entrada repetidos de quem acabou de ser admitido são ignorados
/// (o Welcome pode ainda estar a caminho)
const READMIT_GRACE: std::time::Duration = std::time::Duration::from_secs(15);

/// Intervalo padrão de rotação periódica da chave MLS pelo líder (5 minutos em produção)
pub const DEFAULT_KEY_ROTATION_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

impl ServerGroups {
    /// Inicializa o gerenciador de grupos MLS efêmeros (100% em memória; `_path` é ignorado
    /// e qualquer arquivo legado `mls-state.json` é removido por segurança).
    pub fn new(identity: &UserIdentity, legacy_path: Option<PathBuf>) -> Self {
        if let Some(p) = legacy_path {
            let _ = std::fs::remove_file(p);
        }
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
        Self {
            provider,
            signer,
            credential,
            me,
            groups: HashMap::new(),
            recently_added: HashMap::new(),
            last_rotation: HashMap::new(),
        }
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

    /// Retorna a pubkey (hex) do líder determinístico atual do grupo (a menor `pubkey` presente no grupo).
    pub fn leader(&self, server_id: &str) -> Option<String> {
        self.members(server_id).into_iter().min()
    }

    /// Retorna `true` se este nó é o líder determinístico atual do grupo (`min(pubkey)`).
    pub fn is_leader(&self, server_id: &str) -> bool {
        self.leader(server_id).as_deref() == Some(self.me.as_str())
    }

    /// Cria um grupo efêmero em memória para o servidor (quando somos o primeiro membro presente)
    pub fn create_group(&mut self, server_id: &str) -> Result<(), E2eeError> {
        self.forget(server_id);
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(server_id.as_bytes()),
            self.credential.clone(),
        )
        .map_err(mls)?;
        self.groups.insert(server_id.to_string(), group);
        self.last_rotation.insert(server_id.to_string(), std::time::Instant::now());
        Ok(())
    }

    /// Pubkeys dos membros atuais do grupo (ordenadas lexicograficamente no `BTreeSet`)
    pub fn members(&self, server_id: &str) -> BTreeSet<String> {
        self.groups
            .get(server_id)
            .filter(|g| g.is_active())
            .map(|g| {
                g.members()
                    .map(|m| String::from_utf8_lossy(m.credential.serialized_content()).to_string())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Pacote de chave para pedir entrada no grupo (publicado no tópico de controle)
    pub fn key_package(&mut self) -> Result<Vec<u8>, E2eeError> {
        let bundle = KeyPackage::builder()
            .build(CIPHERSUITE, &self.provider, &self.signer, self.credential.clone())
            .map_err(mls)?;
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

    /// Adiciona quem publicou o pacote de chave (executado pelo líder atual do grupo).
    /// Se a pessoa já estava no grupo (perdeu algum Commit), a folha antiga sai antes.
    /// Retorna os Commits a publicar (para os membros) e o Welcome (para quem entrou).
    pub fn add_member(&mut self, server_id: &str, key_package: &[u8], pubkey: &str) -> Result<(Vec<Vec<u8>>, Vec<u8>), E2eeError> {
        if !self.has_group(server_id) {
            return Err(E2eeError::NotInGroup);
        }
        if !self.is_leader(server_id) {
            return Err(E2eeError::NotOwner);
        }
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
        self.last_rotation.insert(server_id.to_string(), std::time::Instant::now());
        Ok((commits, welcome))
    }

    /// Remove pessoas do grupo (executado pelo líder atual): a chave do grupo é trocada.
    /// Retorna o Commit a publicar, ou None se ninguém da lista estava no grupo.
    pub fn remove_members(&mut self, server_id: &str, pubkeys: &[String]) -> Result<Option<Vec<u8>>, E2eeError> {
        if !self.has_group(server_id) {
            return Err(E2eeError::NotInGroup);
        }
        if !self.is_leader(server_id) {
            return Err(E2eeError::NotOwner);
        }
        self.remove_members_unchecked(server_id, pubkeys)
    }

    /// Remove folhas do grupo e avança a época sem checar se o nó já era o menor antes da remoção
    /// (usado quando o líder antigo desconectou/caiu e o próximo menor membro assume a liderança removendo-o).
    pub fn remove_members_unchecked(&mut self, server_id: &str, pubkeys: &[String]) -> Result<Option<Vec<u8>>, E2eeError> {
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
        self.last_rotation.insert(server_id.to_string(), std::time::Instant::now());
        Ok(Some(commit.to_bytes().map_err(mls)?))
    }

    /// Rotaciona o segredo de época do grupo MLS (`self_update`) sem alterar a lista de membros.
    /// Apenas o líder determinístico atual (`min(pubkey)`) pode emitir a rotação periódica.
    pub fn rotate_key(&mut self, server_id: &str) -> Result<Vec<u8>, E2eeError> {
        if !self.has_group(server_id) {
            return Err(E2eeError::NotInGroup);
        }
        if !self.is_leader(server_id) {
            return Err(E2eeError::NotOwner);
        }
        let group = self.groups.get_mut(server_id).ok_or(E2eeError::NotInGroup)?;
        let commit_bundle = group
            .self_update(&self.provider, &self.signer, LeafNodeParameters::default())
            .map_err(mls)?;
        group.merge_pending_commit(&self.provider).map_err(mls)?;
        self.last_rotation.insert(server_id.to_string(), std::time::Instant::now());
        commit_bundle.into_commit().to_bytes().map_err(mls)
    }

    /// Verifica se o grupo precisa de rotação periódica de chave (quando este nó é o líder e há >= 1 membro)
    pub fn needs_periodic_rotation(&self, server_id: &str, interval: std::time::Duration) -> bool {
        if !self.is_leader(server_id) || self.members(server_id).len() < 2 {
            return false;
        }
        self.last_rotation
            .get(server_id)
            .is_none_or(|t| t.elapsed() >= interval)
    }

    /// Entra no grupo com um Welcome validando quem o enviou e aplicando a regra de convergência:
    /// - Se `expected_sender_or_owner` não for vazio, exige que o remetente do Welcome seja essa pubkey
    ///   OU que passe na validação de membro autorizado;
    /// - Verifica que todas as folhas do grupo recebido possuem `credential == signature_key` (anti-spoofing);
    /// - Se já estivermos num grupo ativo para `server_id`, só substitui o grupo atual se o grupo do
    ///   Welcome vencer pela regra determinística (`should_adopt_group`: mais membros, ou empate com menor líder).
    pub fn join(&mut self, server_id: &str, welcome: &[u8], expected_sender: &str) -> Result<(), E2eeError> {
        self.join_with_validator(server_id, welcome, |sender_pk, members| {
            expected_sender.is_empty() || sender_pk == expected_sender || members.contains(expected_sender)
        })
    }

    /// Entra no grupo com um Welcome usando um validador customizado das regras do servidor (`ServerChain`).
    pub fn join_with_validator<F>(
        &mut self,
        server_id: &str,
        welcome: &[u8],
         mut is_valid_group: F,
    ) -> Result<(), E2eeError>
    where
        F: FnMut(&str, &BTreeSet<String>) -> bool,
    {
        let message = MlsMessageIn::tls_deserialize_exact(welcome).map_err(|e| E2eeError::BadMessage(format!("{:?}", e)))?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(E2eeError::BadMessage("não é um Welcome".into()));
        };
        let staged = StagedWelcome::new_from_welcome(&self.provider, &Self::join_config(), welcome, None).map_err(mls)?;
        let sender = staged.welcome_sender().map_err(mls)?;
        let sender_cred = String::from_utf8_lossy(sender.credential().serialized_content()).to_string();
        let sender_key_hex: String = sender.signature_key().as_slice().iter().map(|b| format!("{:02x}", b)).collect();
        if sender_cred != sender_key_hex {
            return Err(E2eeError::NotOwner);
        }

        // Verifica a integridade de todas as folhas do grupo anunciado no Welcome ANTES de chamar into_group
        let mut candidate_members = BTreeSet::new();
        for m in staged.members() {
            let cred_pk = String::from_utf8_lossy(m.credential.serialized_content()).to_string();
            let sig_pk: String = m.signature_key.iter().map(|b| format!("{:02x}", b)).collect();
            if cred_pk != sig_pk {
                return Err(E2eeError::KeyPackageMismatch);
            }
            candidate_members.insert(cred_pk);
        }

        if !is_valid_group(&sender_key_hex, &candidate_members) {
            return Err(E2eeError::NotOwner);
        }

        // Se já temos um grupo ativo para este servidor, só trocamos se o grupo do Welcome for vencedor,
        // limpando o grupo anterior do storage do OpenMLS ANTES de chamar `staged.into_group`!
        if self.has_group(server_id) {
            let current_members = self.members(server_id);
            if !should_adopt_group(&current_members, &candidate_members) {
                return Err(E2eeError::BadMessage("grupo atual tem prioridade na convergência".into()));
            }
            self.forget(server_id);
        }

        let group = staged.into_group(&self.provider).map_err(mls)?;
        if group.group_id().as_slice() != server_id.as_bytes() {
            let mut g = group;
            let _ = g.delete(self.provider.storage());
            return Err(E2eeError::BadMessage("Welcome de outro grupo".into()));
        }

        self.groups.insert(server_id.to_string(), group);
        self.last_rotation.insert(server_id.to_string(), std::time::Instant::now());
        Ok(())
    }

    /// Aplica um Commit.
    /// Só aceita Commits assinados pelo **líder determinístico atual do grupo** (`self.leader(server_id)`)
    /// ou pelo `fallback_leader` informado (quando aplicável).
    pub fn process_commit(&mut self, server_id: &str, commit: &[u8], fallback_leader: &str) -> Result<CommitOutcome, E2eeError> {
        self.process_commit_with_validator(server_id, commit, fallback_leader, |_pk| true)
    }

    /// Aplica um Commit validando que o autor é o líder atual do grupo e que qualquer membro
    /// existente/novo no grupo resultante respeita `is_member_allowed`.
    pub fn process_commit_with_validator<F>(
        &mut self,
        server_id: &str,
        commit: &[u8],
        fallback_leader: &str,
        mut is_member_allowed: F,
    ) -> Result<CommitOutcome, E2eeError>
    where
        F: FnMut(&str) -> bool,
    {
        let current_leader = self.leader(server_id);
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
        let sender_pk = String::from_utf8_lossy(processed.credential().serialized_content()).to_string();
        if !is_member_allowed(&sender_pk) {
            return Ok(CommitOutcome::Ignored);
        }
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Ok(CommitOutcome::Ignored);
        };
        // Valida propostas de Add dentro do Commit: nenhuma folha ilegítima ou banida pode ser adicionada
        for add_prop in staged.add_proposals() {
            let kp = add_prop.add_proposal().key_package();
            let leaf = kp.leaf_node();
            let cred_pk = String::from_utf8_lossy(leaf.credential().serialized_content()).to_string();
            let sig_pk: String = leaf.signature_key().as_slice().iter().map(|b| format!("{:02x}", b)).collect();
            if cred_pk != sig_pk || !is_member_allowed(&cred_pk) {
                return Ok(CommitOutcome::Ignored);
            }
        }
        // Quem pode assinar o Commit?
        // 1) O líder determinístico atual (`min(pubkey)` do grupo);
        // 2) `fallback_leader` (quando informado explícitamente);
        // 3) O próximo menor membro (`min` dos membros restantes) SE e SOMENTE SE o Commit estiver
        //    removendo o líder antigo (ex.: o líder antigo desconectou ou foi banido e o sucessor assumiu).
        // 4) O próximo menor membro permitido (`min` dos membros permitidos por `is_member_allowed`)
        //    quando o antigo líder de menor `pubkey` acabou de ser banido ou removido da allow-list!
        let is_expected_leader = if current_leader.as_deref() == Some(sender_pk.as_str())
            || (!fallback_leader.is_empty() && sender_pk == fallback_leader)
        {
            true
        } else {
            let allowed_leader = group
                .members()
                .map(|m| String::from_utf8_lossy(m.credential.serialized_content()).to_string())
                .filter(|pk| is_member_allowed(pk))
                .min();
            if allowed_leader.as_deref() == Some(sender_pk.as_str()) {
                true
            } else {
                let removed_indices: std::collections::HashSet<LeafNodeIndex> =
                    staged.remove_proposals().map(|r| r.remove_proposal().removed()).collect();
                if removed_indices.is_empty() {
                    false
                } else {
                    let remaining_leader = group
                        .members()
                        .filter(|m| !removed_indices.contains(&m.index))
                        .map(|m| String::from_utf8_lossy(m.credential.serialized_content()).to_string())
                        .min();
                    remaining_leader.as_deref() == Some(sender_pk.as_str())
                }
            }
        };
        if !is_expected_leader {
            return Ok(CommitOutcome::Ignored);
        }
        group.merge_staged_commit(&self.provider, *staged).map_err(mls)?;
        let outcome = if group.is_active() {
            CommitOutcome::Applied { epoch: group.epoch().as_u64() }
        } else {
            CommitOutcome::Removed
        };
        if outcome == CommitOutcome::Removed {
            self.forget(server_id);
        } else {
            self.last_rotation.insert(server_id.to_string(), std::time::Instant::now());
        }
        Ok(outcome)
    }

    /// Descarta o grupo local da memória (para pedir entrada de novo ou convergir para um grupo maior)
    pub fn drop_group(&mut self, server_id: &str) {
        self.forget(server_id);
    }

    /// Apaga o grupo da memória e do armazenamento em RAM do openmls
    fn forget(&mut self, server_id: &str) {
        self.last_rotation.remove(server_id);
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
}

/// Líder determinístico atual do grupo: admite no grupo cifrado quem publicou o pacote de chave,
/// se tiver direito pela cadeia de governança do servidor (não banido e, em servidor fechado, na allow-list).
/// O dono do servidor NÃO precisa estar online: qualquer membro legítimo que seja o líder atual (`min(pubkey)`)
/// processa o `KeyPackage` e emite o `Commit` + `Welcome`.
pub fn admit_from_key_package(
    groups: &mut ServerGroups,
    registry: &super::ServerRegistry,
    server_id: &str,
    from_pubkey: &str,
    key_package: &[u8],
    passport: Option<&super::ServerPassport>,
    signer_identity: Option<&crate::identity::UserIdentity>,
    now: u64,
) -> Result<Vec<super::ServerMessage>, E2eeError> {
    let server = registry.get(server_id).filter(|s| s.has_chain()).ok_or(E2eeError::NotOwner)?;
    if !groups.has_group(server_id) {
        return Err(E2eeError::NotInGroup);
    }
    if !groups.is_leader(server_id) {
        return Err(E2eeError::NotOwner);
    }
    let me = groups.me().to_string();
    if server.is_banned(&me, now) || !server.is_allowed_with_passport(&me, server.my_passport(), now) {
        return Err(E2eeError::NotAllowed);
    }
    if server.is_banned(from_pubkey, now) || !server.is_allowed_with_passport(from_pubkey, passport, now) {
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

    // Se o solicitante não possuía passaporte e o servidor é público/aberto,
    // o líder pode emitir automaticamente um passaporte inicial de membro para ele:
    let issued_passport = if passport.is_none() {
        if let Some(owner_key) = server.owner_key() {
            Some(super::ServerPassport::issue_root(
                owner_key,
                from_pubkey,
                super::MEMBER_LEVEL,
                super::passport::PassportPermission::member(),
                now,
                Some(now + super::chain::DEFAULT_CERT_VALIDITY_SECS),
            ))
        } else if let (Some(my_passport), Some(signer)) = (server.my_passport(), signer_identity) {
            my_passport.issue_subordinate(
                signer,
                from_pubkey,
                super::MEMBER_LEVEL,
                super::passport::PassportPermission::member(),
                now,
                now + super::chain::DEFAULT_CERT_VALIDITY_SECS,
            ).ok()
        } else {
            None
        }
    } else {
        None
    };

    let mut out: Vec<super::ServerMessage> =
        commits.into_iter().map(|commit| super::ServerMessage::Commit { server_id: server_id.to_string(), commit }).collect();
    out.push(super::ServerMessage::Welcome {
        server_id: server_id.to_string(),
        target: from_pubkey.to_string(),
        welcome,
        passport: issued_passport,
    });
    Ok(out)
}

/// Líder determinístico atual do grupo (ou sucessor imediato caso o líder anterior tenha sido banido):
/// remove do grupo cifrado quem não deveria estar (banido ou fora da allow-list segundo a cadeia do servidor).
/// Devolve o Commit a publicar, se alguém saiu.
pub fn enforce_membership(
    groups: &mut ServerGroups,
    registry: &super::ServerRegistry,
    server_id: &str,
    now: u64,
) -> Result<Option<super::ServerMessage>, E2eeError> {
    let Some(server) = registry.get(server_id).filter(|s| s.has_chain()) else { return Ok(None) };
    if !groups.has_group(server_id) {
        return Ok(None);
    }
    let me = groups.me().to_string();
    // Se nós mesmos fomos banidos, deixamos o líder legítimo emitir e publicar o Commit de remoção
    // (e quando esse Commit chegar em process_commit_with_validator, nossa folha será removida e
    // emitiremos ServerNotice::RemovedFromGroup).
    if server.is_banned(&me, now) || !server.is_allowed(&me, now) {
        return Ok(None);
    }
    // Quem deve executar a manutenção? O menor membro NÃO-banido e permitido que está no grupo!
    let effective_leader = groups
        .members(server_id)
        .into_iter()
        .filter(|pk| !server.is_banned(pk, now) && server.is_allowed(pk, now))
        .min();
    if effective_leader.as_deref() != Some(me.as_str()) {
        return Ok(None);
    }
    let out: Vec<String> = groups
        .members(server_id)
        .into_iter()
        .filter(|pk| *pk != me && (server.is_banned(pk, now) || !server.is_allowed(pk, now)))
        .collect();
    if out.is_empty() {
        return Ok(None);
    }
    Ok(groups.remove_members_unchecked(server_id, &out)?.map(|commit| super::ServerMessage::Commit { server_id: server_id.to_string(), commit }))
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

    /// Gera `n` nós e devolve-os ordenados pela `pubkey` lexicográfica crescente:
    /// `nodes[0]` terá sempre a menor `pubkey` (líder determinístico se estiver no grupo).
    fn sorted_nodes(n: usize) -> Vec<(UserIdentity, ServerGroups)> {
        let mut list: Vec<(UserIdentity, ServerGroups)> = (0..n).map(|i| node(&format!("Peer{}", i))).collect();
        list.sort_by(|a, b| a.1.me().cmp(b.1.me()));
        list
    }

    /// O líder atual (`leader`) adiciona `newcomer`; todos os membros atuais aplicam os Commits
    fn admit(leader: &mut ServerGroups, newcomer: &mut ServerGroups, members: &mut [&mut ServerGroups]) {
        let kp = newcomer.key_package().unwrap();
        let me = newcomer.me().to_string();
        let leader_pk = leader.me().to_string();
        let (commits, welcome) = leader.add_member(SERVER, &kp, &me).unwrap();
        for m in members.iter_mut() {
            for c in &commits {
                assert!(matches!(m.process_commit(SERVER, c, &leader_pk).unwrap(), CommitOutcome::Applied { .. }));
            }
        }
        newcomer.join(SERVER, &welcome, &leader_pk).unwrap();
    }

    #[test]
    fn test_members_exchange_encrypted_messages() {
        let mut nodes = sorted_nodes(2);
        let (_, mut bob) = nodes.pop().unwrap();
        let (_, mut alice) = nodes.pop().unwrap();
        alice.create_group(SERVER).unwrap();
        admit(&mut alice, &mut bob, &mut []);

        let ciphertext = alice.encrypt(SERVER, b"segredo").unwrap();
        assert!(!ciphertext.windows(7).any(|w| w == b"segredo"), "texto não aparece em claro");
        let got = bob.decrypt(SERVER, &ciphertext).unwrap();
        assert_eq!(got.plaintext, b"segredo");
        assert_eq!(got.sender, alice.me());

        let reply = bob.encrypt(SERVER, b"oi").unwrap();
        assert_eq!(alice.decrypt(SERVER, &reply).unwrap().sender, bob.me());
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

    /// Ban / Remoção: o membro removido não decifra nada depois do Commit de remoção
    #[test]
    fn test_removed_member_loses_access() {
        let mut nodes = sorted_nodes(3);
        let (carol_id, mut carol) = nodes.pop().unwrap();
        let (_, mut bob) = nodes.pop().unwrap();
        let (_, mut alice) = nodes.pop().unwrap();

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

    /// Commit de um membro que não é o líder determinístico (`min(pubkey)`) é recusado/ignorado
    #[test]
    fn test_commits_from_non_leader_are_rejected() {
        let mut nodes = sorted_nodes(3);
        let (carol_id, mut carol) = nodes.pop().unwrap();
        let (_, mut bob) = nodes.pop().unwrap();
        let (_, mut alice) = nodes.pop().unwrap(); // alice tem a menor pubkey = líder

        alice.create_group(SERVER).unwrap();
        admit(&mut alice, &mut bob, &mut []);
        admit(&mut alice, &mut carol, &mut [&mut bob]);
        assert!(alice.is_leader(SERVER));
        assert!(!bob.is_leader(SERVER));

        // 1. Bob tentar chamar remove_members pela API segura falha com NotOwner
        assert!(matches!(bob.remove_members(SERVER, &[carol_id.public_key_hex()]), Err(E2eeError::NotOwner)));

        // 2. Mesmo que Bob force um commit bruto com remove_members_unchecked (sem remover a líder Alice!),
        //    Carol ignora o commit porque Bob não é o líder nem o sucessor legítimo.
        let rogue = bob.remove_members_unchecked(SERVER, &[carol_id.public_key_hex()]).unwrap().unwrap();
        assert_eq!(carol.process_commit(SERVER, &rogue, "").unwrap(), CommitOutcome::Ignored);
        assert!(carol.has_group(SERVER));
        let msg = alice.encrypt(SERVER, b"Carol continua").unwrap();
        assert_eq!(carol.decrypt(SERVER, &msg).unwrap().plaintext, b"Carol continua");
    }

    /// Alguém não autorizado cria um grupo com o mesmo ID do servidor e manda um Welcome: é recusado
    #[test]
    fn test_welcome_from_unauthorized_sender_is_rejected() {
        let mut nodes = sorted_nodes(3);
        let (_, mut eve) = nodes.pop().unwrap();
        let (_, mut bob) = nodes.pop().unwrap();
        let (_, mut alice) = nodes.pop().unwrap();

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

    /// Eleição determinística de líder (`menor pubkey`):
    /// - Bob entra primeiro e é o líder inicial;
    /// - Alice (com pubkey menor que a de Bob!) entra depois: Bob a adiciona e, na nova época,
    ///   Alice passa automaticamente a ser a líder determinística;
    /// - Quando Alice sai/desconecta, Bob assume a liderança de volta removendo a folha de Alice.
    #[test]
    fn test_deterministic_leader_election_handoff_and_failover() {
        let mut nodes = sorted_nodes(3);
        let (_, mut carol) = nodes.pop().unwrap(); // maior pubkey
        let (_, mut bob) = nodes.pop().unwrap();   // pubkey intermediária
        let (_, mut alice) = nodes.pop().unwrap(); // menor pubkey

        // 1. Bob está sozinho na sala e cria o grupo -> Bob é o líder inicial
        bob.create_group(SERVER).unwrap();
        assert!(bob.is_leader(SERVER));
        assert_eq!(bob.leader(SERVER).as_deref(), Some(bob.me()));

        // 2. Alice (menor pubkey!) pede para entrar -> Bob (líder atual) admite Alice
        admit(&mut bob, &mut alice, &mut []);
        // Na nova época, ambos veem deterministicamente que ALICE agora é a líder!
        assert_eq!(bob.leader(SERVER).as_deref(), Some(alice.me()));
        assert_eq!(alice.leader(SERVER).as_deref(), Some(alice.me()));
        assert!(alice.is_leader(SERVER));
        assert!(!bob.is_leader(SERVER));

        // 3. Carol entra -> agora quem deve admitir Carol é a nova líder (Alice!), não Bob
        let kp_carol = carol.key_package().unwrap();
        let carol_pk = carol.me().to_string();
        assert!(matches!(bob.add_member(SERVER, &kp_carol, &carol_pk), Err(E2eeError::NotOwner)));
        admit(&mut alice, &mut carol, &mut [&mut bob]);
        assert_eq!(carol.leader(SERVER).as_deref(), Some(alice.me()));

        // 4. Alice desconecta abruptamente -> Bob (próximo menor!) remove Alice via remove_members_unchecked
        let alice_pk = alice.me().to_string();
        let commit = bob.remove_members_unchecked(SERVER, &[alice_pk.clone()]).unwrap().unwrap();
        assert!(matches!(carol.process_commit(SERVER, &commit, "").unwrap(), CommitOutcome::Applied { .. }));
        assert!(bob.is_leader(SERVER));
        assert_eq!(carol.leader(SERVER).as_deref(), Some(bob.me()));

        // Alice (desconectada/removida) não consegue decifrar as mensagens da nova época de Bob e Carol
        let secret = bob.encrypt(SERVER, b"sem alice").unwrap();
        assert_eq!(carol.decrypt(SERVER, &secret).unwrap().plaintext, b"sem alice");
        assert!(alice.decrypt(SERVER, &secret).is_err());
    }

    /// Convergência determinística de grupos (`maior grupo vence`, desempate `menor pubkey`):
    /// Se dois subgrupos se formarem ao mesmo tempo, o menor adota o Welcome do maior.
    #[test]
    fn test_group_convergence_largest_wins_and_tiebreaker_by_smallest_leader() {
        let mut nodes = sorted_nodes(3);
        let (_, mut carol) = nodes.pop().unwrap();
        let (_, mut bob) = nodes.pop().unwrap();
        let (_, mut alice) = nodes.pop().unwrap();

        // Subgrupo 1: Bob e Carol (2 membros)
        bob.create_group(SERVER).unwrap();
        admit(&mut bob, &mut carol, &mut []);
        assert_eq!(bob.members(SERVER).len(), 2);

        // Subgrupo 2: Alice criou um grupo sozinha (1 membro)
        alice.create_group(SERVER).unwrap();
        assert_eq!(alice.members(SERVER).len(), 1);

        // A regra should_adopt_group diz que Alice (1 membro) deve adotar o grupo de Bob+Carol (2 membros),
        // mesmo que a pubkey da Alice seja menor que a do Bob!
        assert!(should_adopt_group(&alice.members(SERVER), &bob.members(SERVER)));
        assert!(!should_adopt_group(&bob.members(SERVER), &alice.members(SERVER)));

        // Ao detectar o grupo maior (ex.: via GroupAnnounce), Alice descarta seu grupo unitário (`drop_group`)
        // e publica seu KeyPackage; Bob adiciona Alice ao grupo maior e envia o Welcome!
        alice.drop_group(SERVER);
        let kp_alice = alice.key_package().unwrap();
        let alice_pk = alice.me().to_string();
        let (commits, welcome) = bob.add_member(SERVER, &kp_alice, &alice_pk).unwrap();
        for c in &commits {
            assert!(matches!(carol.process_commit(SERVER, c, "").unwrap(), CommitOutcome::Applied { .. }));
        }
        alice.join(SERVER, &welcome, "").unwrap();
        assert_eq!(alice.members(SERVER).len(), 3);
        assert!(alice.is_leader(SERVER), "após convergir para o grupo de 3, Alice vira líder por ter menor pubkey");

        let msg = carol.encrypt(SERVER, b"convergimos!").unwrap();
        assert_eq!(alice.decrypt(SERVER, &msg).unwrap().plaintext, b"convergimos!");
        assert_eq!(bob.decrypt(SERVER, &msg).unwrap().plaintext, b"convergimos!");
    }

    /// Rotação periódica de chaves (`rotate_key` / `self_update`) avança a época e invalida estados antigos
    #[test]
    fn test_periodic_key_rotation_advances_epoch_and_invalidates_stale_state() {
        let mut nodes = sorted_nodes(3);
        let (_, mut carol) = nodes.pop().unwrap();
        let (_, mut bob) = nodes.pop().unwrap();
        let (_, mut alice) = nodes.pop().unwrap();

        alice.create_group(SERVER).unwrap();
        admit(&mut alice, &mut bob, &mut []);
        admit(&mut alice, &mut carol, &mut [&mut bob]);

        let epoch_before = alice.epoch(SERVER).unwrap();
        // Bob (não-líder) não pode rotacionar a chave
        assert!(matches!(bob.rotate_key(SERVER), Err(E2eeError::NotOwner)));

        // Alice (líder) rotaciona a chave de época (`self_update`)
        let commit = alice.rotate_key(SERVER).unwrap();
        let epoch_after = alice.epoch(SERVER).unwrap();
        assert_eq!(epoch_after, epoch_before + 1);

        // Bob aplica o Commit de rotação; Carol perde o Commit (fica com o estado da época antiga!)
        assert_eq!(
            bob.process_commit(SERVER, &commit, "").unwrap(),
            CommitOutcome::Applied { epoch: epoch_after }
        );

        let post_rotation_msg = alice.encrypt(SERVER, b"segredo da nova epoca").unwrap();
        assert_eq!(bob.decrypt(SERVER, &post_rotation_msg).unwrap().plaintext, b"segredo da nova epoca");
        assert!(
            carol.decrypt(SERVER, &post_rotation_msg).is_err(),
            "estado antigo de época anterior não deve decifrar mensagens após rotação de chave"
        );
    }

    /// Membro que perdeu um Commit pede para entrar de novo; o líder troca a folha
    #[test]
    fn test_member_out_of_sync_rejoins() {
        let mut nodes = sorted_nodes(4);
        let (_, mut dave) = nodes.pop().unwrap();
        let (_, mut carol) = nodes.pop().unwrap();
        let (_, mut bob) = nodes.pop().unwrap();
        let (_, mut alice) = nodes.pop().unwrap();

        alice.create_group(SERVER).unwrap();
        admit(&mut alice, &mut bob, &mut []);
        // Bob estava offline quando Carol entrou
        let kp = carol.key_package().unwrap();
        let me = carol.me().to_string();
        let (_missed, welcome) = alice.add_member(SERVER, &kp, &me).unwrap();
        carol.join(SERVER, &welcome, alice.me()).unwrap();

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
        let mut nodes = sorted_nodes(2);
        let (bob_id, mut bob) = nodes.pop().unwrap();
        let (_, mut alice) = nodes.pop().unwrap();

        alice.create_group(SERVER).unwrap();
        admit(&mut alice, &mut bob, &mut []);
        let commit = alice.remove_members(SERVER, &[bob_id.public_key_hex()]).unwrap().unwrap();
        assert_eq!(bob.process_commit(SERVER, &commit, alice.me()).unwrap(), CommitOutcome::Removed);
        admit(&mut alice, &mut bob, &mut []);
        let msg = alice.encrypt(SERVER, b"bem-vindo de volta").unwrap();
        assert_eq!(bob.decrypt(SERVER, &msg).unwrap().plaintext, b"bem-vindo de volta");
    }

    /// Regras de entrada aplicadas pelo líder atual a partir do estado do servidor (mesmo sem ser o dono!)
    #[test]
    fn test_leader_admits_and_enforces_with_server_rules_even_when_owner_offline() {
        use crate::community::{ModKind, ServerEvent, ServerMessage, ServerRegistry};
        const T0: u64 = 1_800_000_000;
        let owner_id = UserIdentity::generate_with_nick("Owner");
        let mut owner_registry = ServerRegistry::in_memory();
        let server = owner_registry.create("Guild", &owner_id.public_key_hex(), T0).unwrap();

        // Bob e Carol são membros comuns (o dono NÃO está no grupo MLS!)
        let mut nodes = sorted_nodes(2);
        let (carol_id, mut carol) = nodes.pop().unwrap();
        let (_bob_id, mut bob) = nodes.pop().unwrap(); // bob tem menor pubkey entre bob e carol

        // Bob sincroniza a cadeia do servidor
        let mut bob_registry = ServerRegistry::in_memory();
        bob_registry.join(&server).unwrap();
        let req = bob_registry.chain_request(&server).unwrap();
        let ServerEvent::Reply { messages, .. } = owner_registry.handle_message(req, None, T0).remove(0) else { panic!() };
        for m in messages {
            bob_registry.handle_message(m, None, T0);
        }

        // Bob cria o grupo efêmero da sala (sem o dono estar online!) e admite Carol
        bob.create_group(&server).unwrap();
        let carol_pk = carol_id.public_key_hex();
        let kp = carol.key_package().unwrap();
        let msgs = admit_from_key_package(&mut bob, &bob_registry, &server, &carol_pk, &kp, None, None, T0).unwrap();
        assert!(matches!(msgs.last(), Some(ServerMessage::Welcome { target, .. }) if *target == carol_pk));
        assert!(bob.members(&server).contains(&carol_pk));

        // Pedido repetido logo depois de admitida: ignorado (sem nova troca de chave)
        let kp_again = carol.key_package().unwrap();
        assert!(admit_from_key_package(&mut bob, &bob_registry, &server, &carol_pk, &kp_again, None, None, T0).unwrap().is_empty());

        // Dono bane Carol na cadeia e o bloco chega para Bob -> Bob (líder MLS) remove Carol do grupo!
        let ban_block = owner_registry.moderate(&server, &owner_id, ModKind::Ban { until: None }, &carol_pk, "", T0 + 1).unwrap();
        bob_registry.handle_message(ban_block, None, T0 + 1);
        assert!(enforce_membership(&mut bob, &bob_registry, &server, T0 + 2).unwrap().is_some());
        assert!(!bob.members(&server).contains(&carol_pk));
        assert!(enforce_membership(&mut bob, &bob_registry, &server, T0 + 3).unwrap().is_none(), "nada mais a fazer");

        // Banida não é readmitida pelo líder Bob
        let kp = carol.key_package().unwrap();
        assert!(matches!(admit_from_key_package(&mut bob, &bob_registry, &server, &carol_pk, &kp, None, None, T0 + 4), Err(E2eeError::NotAllowed)));
    }

    /// Garante que o grupo MLS é 100% efêmero em memória: nenhum arquivo `mls-state.json` é criado
    /// e qualquer arquivo legado é apagado ao inicializar `ServerGroups::new`.
    #[test]
    fn test_mls_state_is_strictly_ephemeral_in_memory_and_deletes_legacy_file() {
        let path = std::env::temp_dir().join(format!("anarchord_mls_ephemeral_{}.json", std::process::id()));
        std::fs::write(&path, b"legacy state").unwrap();
        assert!(path.exists());

        let alice_id = UserIdentity::generate_with_nick("Alice");
        let mut alice = ServerGroups::new(&alice_id, Some(path.clone()));
        assert!(!path.exists(), "arquivo legado mls-state.json deve ser apagado");
        alice.create_group(SERVER).unwrap();
        assert!(!path.exists(), "nenhum estado MLS deve ser persistido em disco");
    }
}
