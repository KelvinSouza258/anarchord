//! Espaços de conversa: o Lobby público e os servidores (comunidades com dono).
//!
//! - **Lobby**: sem dono e sem moderação; qualquer nome vira canal. É onde as pessoas se
//!   encontram pela primeira vez e trocam convites de servidor.
//! - **Servidor**: definido por uma cadeia de blocos assinada pela chave do servidor
//!   ([`chain`]), com moderadores certificados ([`cert`]). Os canais de cada servidor ficam num
//!   namespace próprio de tópicos.
//!
//! Este módulo contém só lógica (sem rede nem interface): o loop de eventos publica as
//! mensagens que ele devolve e repassa a ele as que chegam.

pub mod cert;
pub mod chain;
pub mod e2ee;

pub use cert::{format_duration, parse_duration, ModAction, ModKind, ModeratorCert, Permission, UtcSecs};
pub use chain::{AppendResult, BanState, Block, Channel, ChannelType, Entry, Rejection, ServerChain, ServerState};

use crate::identity::{hex_decode_32, UserIdentity};
use cert::default_permissions;
use chain::{DEFAULT_CERT_VALIDITY_SECS, DEFAULT_RENEWAL_WINDOW_SECS};
use libp2p::kad;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

const TOPIC_PREFIX: &str = "p2p-anarchord";
/// Blocos por mensagem ao responder um pedido de cadeia (mantém cada mensagem bem abaixo de 1 MB)
const BLOCKS_PER_MESSAGE: usize = 32;

/// Onde o usuário está conversando
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Space {
    Lobby,
    Server(String),
}

/// Tópico Gossipsub de um canal de texto. No Lobby mantém o formato original
/// (`p2p-anarchord/channel/<canal>`), compatível com nós anteriores.
pub fn channel_topic(space: &Space, channel: &str) -> String {
    match space {
        Space::Lobby => format!("{}/channel/{}", TOPIC_PREFIX, channel),
        Space::Server(id) => format!("{}/server/{}/channel/{}", TOPIC_PREFIX, id, channel),
    }
}

/// Tópico Gossipsub de uma sala de voz
pub fn voice_topic(space: &Space, channel: &str) -> String {
    match space {
        Space::Lobby => format!("{}/voice/{}", TOPIC_PREFIX, channel),
        Space::Server(id) => format!("{}/server/{}/voice/{}", TOPIC_PREFIX, id, channel),
    }
}

/// Tópico de compartilhamento de tela do espaço
pub fn screen_topic(space: &Space) -> String {
    match space {
        Space::Lobby => format!("{}/screens", TOPIC_PREFIX),
        Space::Server(id) => format!("{}/server/{}/screens", TOPIC_PREFIX, id),
    }
}

/// Tópico dos quadros de uma transmissão de tela: só quem assiste se inscreve
pub fn screen_stream_topic(space: &Space, stream_id: &str) -> String {
    format!("{}/{}", screen_topic(space), stream_id)
}

/// Se o tópico é de conteúdo de um servidor (canal, voz ou tela), devolve o id do servidor.
/// Esse conteúdo trafega cifrado com MLS.
pub fn parse_server_content_topic(topic: &str) -> Option<&str> {
    let rest = topic.strip_prefix(TOPIC_PREFIX)?.strip_prefix("/server/")?;
    let (id, tail) = rest.split_at(rest.find('/')?);
    let content = tail.starts_with("/channel/") || tail.starts_with("/voice/") || tail.starts_with("/screens");
    (content && is_valid_server_id(id)).then_some(id)
}

/// Tópico de controle de um servidor: blocos da cadeia, ações de moderação e pedidos de cadeia
pub fn server_control_topic(server_id: &str) -> String {
    format!("{}/server/{}", TOPIC_PREFIX, server_id)
}

/// Se o tópico é o de controle de um servidor, devolve o id do servidor
pub fn parse_server_control_topic(topic: &str) -> Option<&str> {
    let id = topic.strip_prefix(TOPIC_PREFIX)?.strip_prefix("/server/")?;
    is_valid_server_id(id).then_some(id)
}

/// Chave de descoberta do servidor na DHT: membros a anunciam, quem entra procura por ela
pub fn server_dht_key(server_id: &str) -> kad::RecordKey {
    let digest = Sha256::digest(format!("anarchord-server:{}", server_id).as_bytes());
    let mut multihash = Vec::with_capacity(34);
    multihash.extend_from_slice(&[0x12, 0x20]);
    multihash.extend_from_slice(&digest);
    kad::RecordKey::new(&multihash)
}

/// O id de um servidor é a pubkey Ed25519 dele em hex (64 caracteres)
pub fn is_valid_server_id(id: &str) -> bool {
    hex_decode_32(id).is_ok()
}

/// Início do id, para exibição
pub fn short_id(id: &str) -> &str {
    &id[..id.len().min(8)]
}

/// Canais criados junto com um servidor novo
pub fn default_channels() -> Vec<Channel> {
    vec![
        Channel { name: "geral".into(), channel_type: ChannelType::Text },
        Channel { name: "voz".into(), channel_type: ChannelType::Voice },
    ]
}

/// Mensagens trocadas no tópico de controle de um servidor
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ServerMessage {
    /// Blocos da cadeia (novos ou em resposta a um pedido)
    Blocks { server_id: String, blocks: Vec<Block> },
    /// Pedido dos blocos a partir de uma altura
    ChainRequest { server_id: String, from_height: u64 },
    /// Ação de moderador ainda não incluída na cadeia
    Action(ModAction),
    /// Pedido de entrada no grupo cifrado (MLS): pacote de chave de quem publicou
    KeyPackage {
        server_id: String,
        #[serde(with = "crate::b64")]
        key_package: Vec<u8>,
    },
    /// Commit MLS do líder (adiciona/remove membros ou rotaciona a chave do grupo)
    Commit {
        server_id: String,
        #[serde(with = "crate::b64")]
        commit: Vec<u8>,
    },
    /// Welcome MLS para quem foi admitido no grupo
    Welcome {
        server_id: String,
        target: String,
        #[serde(with = "crate::b64")]
        welcome: Vec<u8>,
    },
    /// Anúncio de presença do grupo MLS ativo (líder, época e membros) para convergência determinística
    GroupAnnounce {
        server_id: String,
        epoch: u64,
        leader: String,
        members: Vec<String>,
    },
}

impl ServerMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::wire::encode(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::wire::WireError> {
        crate::wire::decode_as(bytes)
    }
}

#[derive(Error, Debug)]
pub enum CommunityError {
    #[error("ID de servidor inválido (esperado: 64 caracteres hexadecimais)")]
    InvalidServerId,
    #[error("Você não está nesse servidor")]
    UnknownServer,
    #[error("A configuração desse servidor ainda não chegou; aguarde algum membro online")]
    NoChainYet,
    #[error("Só o dono do servidor pode fazer isso")]
    NotOwner,
    #[error("Você não tem certificado de moderador válido com essa permissão")]
    NotModerator,
    #[error("Ação recusada: {0}")]
    Rejected(Rejection),
    #[error("Já existe um canal com esse nome")]
    ChannelExists,
    #[error("Canal inexistente")]
    UnknownChannel,
    #[error("{0}")]
    Identity(#[from] crate::identity::IdentityError),
    #[error("Erro de E/S: {0}")]
    Io(#[from] std::io::Error),
    #[error("Erro de serialização: {0}")]
    Json(#[from] serde_json::Error),
}

/// Um servidor que este nó acompanha
pub struct KnownServer {
    pub server_id: String,
    chain: ServerChain,
    /// Presente só se este nó é o dono
    owner_key: Option<UserIdentity>,
    /// Ações de moderadores recebidas e ainda não incluídas na cadeia (por id)
    pending: BTreeMap<String, ModAction>,
}

impl KnownServer {
    fn new(server_id: &str) -> Self {
        Self { server_id: server_id.to_string(), chain: ServerChain::new(server_id), owner_key: None, pending: BTreeMap::new() }
    }

    pub fn has_chain(&self) -> bool {
        !self.chain.is_empty()
    }

    pub fn chain(&self) -> &ServerChain {
        &self.chain
    }

    pub fn name(&self) -> String {
        if self.has_chain() {
            self.chain.state().name.clone()
        } else {
            format!("(aguardando configuração) {}", short_id(&self.server_id))
        }
    }

    pub fn is_owner(&self) -> bool {
        self.owner_key.is_some()
    }

    pub fn channels(&self) -> Vec<Channel> {
        self.chain.state().channels.clone()
    }

    pub fn has_channel(&self, name: &str, kind: ChannelType) -> bool {
        self.chain.state().channels.iter().any(|c| c.name == name && c.channel_type == kind)
    }

    /// Verifica se existe qualquer canal (texto ou voz) com este nome no servidor
    pub fn has_any_channel(&self, name: &str) -> bool {
        self.chain.state().channels.iter().any(|c| c.name == name)
    }

    /// Primeiro canal de texto (onde o usuário cai ao entrar no servidor)
    pub fn default_text_channel(&self) -> Option<String> {
        self.channels()
            .into_iter()
            .find(|c| c.channel_type == ChannelType::Text)
            .or_else(|| self.channels().into_iter().next())
            .map(|c| c.name)
    }

    pub fn pending_actions(&self) -> impl Iterator<Item = &ModAction> {
        self.pending.values()
    }

    /// Estado efetivo agora: a cadeia mais as ações provisórias que continuam válidas,
    /// aplicadas na ordem das datas declaradas (desempate pelo id)
    pub fn effective_state(&self, now: UtcSecs) -> ServerState {
        let mut state = self.chain.state().clone();
        let mut pending: Vec<&ModAction> = self.pending.values().collect();
        pending.sort_by(|a, b| (a.body.created_at, a.id()).cmp(&(b.body.created_at, b.id())));
        for action in pending {
            let _ = state.apply_mod_action(action, now);
        }
        state
    }

    pub fn is_banned(&self, pubkey: &str, now: UtcSecs) -> bool {
        self.effective_state(now).is_banned(pubkey, now)
    }

    pub fn is_allowed(&self, pubkey: &str, now: UtcSecs) -> bool {
        self.effective_state(now).is_allowed(pubkey, now)
    }

    pub fn level_of(&self, pubkey: &str, now: UtcSecs) -> Option<u8> {
        self.chain.state().level_of(pubkey, now)
    }

    /// Descarta ações provisórias que já entraram na cadeia ou que a cadeia atual invalida
    /// (ex.: o certificado foi revogado). É assim que ações de um moderador bloqueado são desfeitas.
    fn prune_pending(&mut self, now: UtcSecs) {
        let state = self.chain.state();
        self.pending.retain(|_, action| state.check_mod_action(action, now).is_ok());
    }

    /// Mensagens com a cadeia a partir de `from_height` e as ações provisórias
    fn sync_messages(&self, from_height: u64) -> Vec<ServerMessage> {
        let blocks = self.chain.blocks().iter().skip(from_height as usize).cloned().collect::<Vec<_>>();
        let mut out: Vec<ServerMessage> = blocks
            .chunks(BLOCKS_PER_MESSAGE)
            .map(|chunk| ServerMessage::Blocks { server_id: self.server_id.clone(), blocks: chunk.to_vec() })
            .collect();
        out.extend(self.pending.values().cloned().map(ServerMessage::Action));
        out
    }
}

/// O que aconteceu ao processar uma mensagem de servidor recebida da rede
#[derive(Debug)]
pub enum ServerEvent {
    /// A cadeia avançou (ou foi trocada num fork)
    ChainUpdated { server_id: String, name: String, height: u64 },
    /// Fork detectado na altura `height`; `replaced` = este nó trocou de ramo
    Fork { server_id: String, height: u64, replaced: bool },
    /// Faltam blocos: publicar um `ChainRequest` a partir de `from_height`
    NeedBlocks { server_id: String, from_height: u64 },
    /// Ação de moderador válida aceita como provisória
    ActionAccepted { server_id: String, action: ModAction },
    /// Ações provisórias desfeitas porque a cadeia nova as invalidou
    ActionsUndone { server_id: String, count: usize },
    /// Responder publicando estas mensagens no tópico de controle
    Reply { server_id: String, messages: Vec<ServerMessage> },
    /// Mensagem descartada (inválida, antiga ou de servidor que não acompanhamos)
    Ignored(String),
}

#[derive(Serialize, Deserialize)]
struct StoredServer {
    server_id: String,
    blocks: Vec<Block>,
    pending: Vec<ModAction>,
}

/// Uma linha do histórico de alterações (para exibição)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub height: u64,
    pub timestamp: UtcSecs,
    pub description: String,
}

/// Servidores que este nó acompanha, com persistência opcional em disco:
/// - `<dir>/<id>.server.json`: blocos da cadeia e ações provisórias
/// - `<dir>/<id>.owner-key.json`: chave do servidor (só no nó do dono; nunca é apagada)
#[derive(Default)]
pub struct ServerRegistry {
    dir: Option<PathBuf>,
    servers: BTreeMap<String, KnownServer>,
}

impl ServerRegistry {
    /// Registro sem persistência (testes)
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Carrega os servidores salvos em `dir` (cria a pasta se não existir).
    /// Blocos são revalidados ao carregar: um arquivo adulterado perde a cadeia a partir do ponto alterado.
    pub fn load(dir: impl AsRef<Path>, now: UtcSecs) -> Result<Self, CommunityError> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        let mut registry = Self { dir: Some(dir.clone()), servers: BTreeMap::new() };

        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            let Some(file) = path.file_name().and_then(|n| n.to_str()) else { continue };
            let Some(id) = file.strip_suffix(".server.json") else { continue };
            if !is_valid_server_id(id) {
                continue;
            }
            let Ok(stored) = serde_json::from_slice::<StoredServer>(&std::fs::read(&path)?) else {
                tracing::warn!("Servidor salvo ilegível (formato antigo?): {:?}", path);
                continue;
            };
            let mut server = KnownServer::new(id);
            for block in stored.blocks {
                if server.chain.try_append(block) != AppendResult::Appended {
                    break;
                }
            }
            for action in stored.pending {
                server.pending.insert(action.id(), action);
            }
            server.prune_pending(now);
            let key_path = dir.join(format!("{}.owner-key.json", id));
            if key_path.exists() {
                let key = UserIdentity::load_or_create(&key_path)?;
                if key.public_key_hex() == id {
                    server.owner_key = Some(key);
                }
            }
            registry.servers.insert(id.to_string(), server);
        }
        Ok(registry)
    }

    pub fn get(&self, server_id: &str) -> Option<&KnownServer> {
        self.servers.get(server_id)
    }

    pub fn list(&self) -> impl Iterator<Item = &KnownServer> {
        self.servers.values()
    }

    /// Procura por id completo, prefixo do id (4+ caracteres) ou nome (sem diferenciar maiúsculas)
    pub fn find(&self, query: &str) -> Option<&KnownServer> {
        self.servers.get(query).or_else(|| {
            self.servers
                .values()
                .find(|s| (query.len() >= 4 && s.server_id.starts_with(query)) || s.name().eq_ignore_ascii_case(query))
        })
    }

    /// Cria um servidor com chave própria. Este nó vira o dono, e `owner_pubkey` (a identidade
    /// pessoal de quem cria) fica registrada com nível 0.
    pub fn create(&mut self, name: &str, owner_pubkey: &str, now: UtcSecs) -> Result<String, CommunityError> {
        let key = UserIdentity::generate_with_nick(name);
        let id = key.public_key_hex();
        if let Some(dir) = &self.dir {
            key.save_to(dir.join(format!("{}.owner-key.json", id)))?;
        }
        let mut server = KnownServer::new(&id);
        server.chain.append_own(
            &key,
            now,
            vec![Entry::Genesis {
                name: name.to_string(),
                owner: owner_pubkey.to_string(),
                channels: default_channels(),
                closed: false,
                cert_validity_secs: DEFAULT_CERT_VALIDITY_SECS,
                renewal_window_secs: DEFAULT_RENEWAL_WINDOW_SECS,
            }],
        );
        server.owner_key = Some(key);
        self.servers.insert(id.clone(), server);
        self.persist(&id)?;
        Ok(id)
    }

    /// Passa a acompanhar um servidor pelo id. Retorna `false` se já acompanhava.
    /// A cadeia chega depois, de algum membro online.
    pub fn join(&mut self, server_id: &str) -> Result<bool, CommunityError> {
        if !is_valid_server_id(server_id) {
            return Err(CommunityError::InvalidServerId);
        }
        if self.servers.contains_key(server_id) {
            return Ok(false);
        }
        self.servers.insert(server_id.to_string(), KnownServer::new(server_id));
        self.persist(server_id)?;
        Ok(true)
    }

    /// Deixa de acompanhar o servidor. A chave de dono, se existir, é mantida em disco.
    pub fn leave(&mut self, server_id: &str) -> bool {
        let removed = self.servers.remove(server_id).is_some();
        if let (true, Some(dir)) = (removed, &self.dir) {
            let _ = std::fs::remove_file(dir.join(format!("{}.server.json", server_id)));
        }
        removed
    }

    /// Processa uma mensagem do tópico de controle. `from_pubkey` é quem publicou (do PeerId),
    /// usado para não entregar a cadeia de um servidor fechado a quem está fora dele.
    pub fn handle_message(&mut self, message: ServerMessage, from_pubkey: Option<&str>, now: UtcSecs) -> Vec<ServerEvent> {
        match message {
            ServerMessage::Blocks { server_id, mut blocks } => {
                let Some(server) = self.servers.get_mut(&server_id) else {
                    return vec![ServerEvent::Ignored("servidor não acompanhado".into())];
                };
                blocks.sort_by_key(|b| b.body.height);
                let before = server.chain.head().map(Block::hash);
                let mut events = Vec::new();
                for block in blocks {
                    match server.chain.try_append(block) {
                        AppendResult::Appended | AppendResult::Duplicate => {}
                        AppendResult::Gap { need_from } => {
                            events.push(ServerEvent::NeedBlocks { server_id: server_id.clone(), from_height: need_from });
                            break;
                        }
                        AppendResult::Fork { height, replaced } => {
                            events.push(ServerEvent::Fork { server_id: server_id.clone(), height, replaced })
                        }
                        AppendResult::Invalid(reason) => {
                            events.push(ServerEvent::Ignored(format!("bloco recusado: {}", reason)));
                            break;
                        }
                    }
                }
                if server.chain.head().map(Block::hash) != before {
                    let pending_before = server.pending.len();
                    server.prune_pending(now);
                    let undone = pending_before - server.pending.len();
                    let height = server.chain.head().map_or(0, |b| b.body.height);
                    events.push(ServerEvent::ChainUpdated { server_id: server_id.clone(), name: server.name(), height });
                    if undone > 0 {
                        events.push(ServerEvent::ActionsUndone { server_id: server_id.clone(), count: undone });
                    }
                    let _ = self.persist(&server_id);
                }
                events
            }
            ServerMessage::ChainRequest { server_id, from_height } => {
                let Some(server) = self.servers.get(&server_id).filter(|s| s.has_chain()) else {
                    return vec![ServerEvent::Ignored("sem cadeia para responder".into())];
                };
                let state = server.effective_state(now);
                if state.closed && !from_pubkey.is_some_and(|pk| state.is_allowed(pk, now)) {
                    return vec![ServerEvent::Ignored("servidor fechado: pedido de quem está fora da allow-list".into())];
                }
                vec![ServerEvent::Reply { messages: server.sync_messages(from_height), server_id }]
            }
            ServerMessage::KeyPackage { .. }
            | ServerMessage::Commit { .. }
            | ServerMessage::Welcome { .. }
            | ServerMessage::GroupAnnounce { .. } => {
                vec![ServerEvent::Ignored("mensagem do grupo cifrado (tratada por e2ee)".into())]
            }
            ServerMessage::Action(action) => {
                let server_id = action.body.server_id.clone();
                let Some(server) = self.servers.get_mut(&server_id) else {
                    return vec![ServerEvent::Ignored("servidor não acompanhado".into())];
                };
                if !server.has_chain() {
                    return vec![ServerEvent::Ignored("cadeia ainda não sincronizada".into())];
                }
                if server.pending.contains_key(&action.id()) {
                    return vec![ServerEvent::Ignored("ação já conhecida".into())];
                }
                match server.effective_state(now).check_mod_action(&action, now) {
                    Ok(()) => {
                        server.pending.insert(action.id(), action.clone());
                        let _ = self.persist(&server_id);
                        vec![ServerEvent::ActionAccepted { server_id, action }]
                    }
                    Err(rejection) => vec![ServerEvent::Ignored(format!("ação recusada: {}", rejection))],
                }
            }
        }
    }

    /// Pedido da cadeia a partir do que este nó já tem
    pub fn chain_request(&self, server_id: &str) -> Option<ServerMessage> {
        let server = self.servers.get(server_id)?;
        Some(ServerMessage::ChainRequest { server_id: server_id.to_string(), from_height: server.chain.blocks().len() as u64 })
    }

    /// Tudo que este nó sabe do servidor, para entregar a quem acabou de entrar no tópico
    pub fn snapshot(&self, server_id: &str) -> Vec<ServerMessage> {
        self.servers.get(server_id).filter(|s| s.has_chain()).map(|s| s.sync_messages(0)).unwrap_or_default()
    }

    // ---------- Operações do dono (assinam blocos com a chave do servidor) ----------

    fn owner_append(&mut self, server_id: &str, now: UtcSecs, entries: Vec<Entry>) -> Result<ServerMessage, CommunityError> {
        let server = self.servers.get_mut(server_id).ok_or(CommunityError::UnknownServer)?;
        let key = server.owner_key.clone().ok_or(CommunityError::NotOwner)?;
        if !server.has_chain() {
            return Err(CommunityError::NoChainYet);
        }
        let block = server.chain.append_own(&key, now, entries);
        server.prune_pending(now);
        self.persist(server_id)?;
        Ok(ServerMessage::Blocks { server_id: server_id.to_string(), blocks: vec![block] })
    }

    pub fn add_channel(&mut self, server_id: &str, name: &str, kind: ChannelType, now: UtcSecs) -> Result<ServerMessage, CommunityError> {
        if self.get(server_id).is_some_and(|s| s.channels().iter().any(|c| c.name == name)) {
            return Err(CommunityError::ChannelExists);
        }
        self.owner_append(server_id, now, vec![Entry::AddChannel(Channel { name: name.to_string(), channel_type: kind })])
    }

    pub fn remove_channel(&mut self, server_id: &str, name: &str, now: UtcSecs) -> Result<ServerMessage, CommunityError> {
        if !self.get(server_id).is_some_and(|s| s.channels().iter().any(|c| c.name == name)) {
            return Err(CommunityError::UnknownChannel);
        }
        self.owner_append(server_id, now, vec![Entry::RemoveChannel(name.to_string())])
    }

    pub fn set_closed(&mut self, server_id: &str, closed: bool, now: UtcSecs) -> Result<ServerMessage, CommunityError> {
        self.owner_append(server_id, now, vec![Entry::SetClosed(closed)])
    }

    pub fn set_cert_policy(
        &mut self,
        server_id: &str,
        validity_secs: u64,
        renewal_window_secs: u64,
        now: UtcSecs,
    ) -> Result<ServerMessage, CommunityError> {
        self.owner_append(server_id, now, vec![Entry::SetCertPolicy { validity_secs, renewal_window_secs }])
    }

    /// Emite um certificado de moderador (nível ≥ 1) com a validade da política do servidor
    pub fn add_moderator(&mut self, server_id: &str, pubkey: &str, level: u8, now: UtcSecs) -> Result<ServerMessage, CommunityError> {
        let server = self.servers.get(server_id).ok_or(CommunityError::UnknownServer)?;
        let key = server.owner_key.as_ref().ok_or(CommunityError::NotOwner)?;
        let validity = server.chain.state().cert_validity_secs.max(3600);
        let cert = ModeratorCert::issue(key, pubkey, level, default_permissions(), now, validity);
        self.owner_append(server_id, now, vec![Entry::IssueCert(cert)])
    }

    /// Revoga todos os certificados ativos de uma pubkey
    pub fn remove_moderator(&mut self, server_id: &str, pubkey: &str, now: UtcSecs) -> Result<ServerMessage, CommunityError> {
        let server = self.servers.get(server_id).ok_or(CommunityError::UnknownServer)?;
        let serials: Vec<Entry> = server
            .chain
            .state()
            .certs
            .values()
            .filter(|c| c.body.subject == pubkey && !server.chain.state().revoked.contains(&c.body.serial))
            .map(|c| Entry::RevokeCert { serial: c.body.serial.clone() })
            .collect();
        if serials.is_empty() {
            return Err(CommunityError::NotModerator);
        }
        self.owner_append(server_id, now, serials)
    }

    /// Manutenção do dono, chamada periodicamente enquanto ele está online:
    /// - inclui na cadeia as ações provisórias válidas dos moderadores (consolidação);
    /// - renova os certificados que entraram na janela de renovação.
    ///
    /// Retorna o bloco a publicar, se houve algo a fazer.
    pub fn owner_maintenance(&mut self, server_id: &str, now: UtcSecs) -> Option<ServerMessage> {
        let server = self.servers.get(server_id)?;
        let key = server.owner_key.as_ref()?;
        if !server.has_chain() {
            return None;
        }
        let state = server.chain.state();
        let mut entries: Vec<Entry> = Vec::new();
        let mut pending: Vec<&ModAction> = server.pending.values().collect();
        pending.sort_by(|a, b| (a.body.created_at, a.id()).cmp(&(b.body.created_at, b.id())));
        let mut probe = state.clone();
        for action in pending {
            if probe.apply_mod_action(action, now).is_ok() {
                entries.push(Entry::IncludeModAction(action.clone()));
            }
        }
        for cert in state.certs_due_for_renewal(now) {
            entries.push(Entry::IssueCert(cert.renewed(key, now, state.cert_validity_secs.max(3600))));
        }
        if entries.is_empty() {
            return None;
        }
        self.owner_append(server_id, now, entries).ok()
    }

    // ---------- Moderação (dono assina blocos; moderador assina ações) ----------

    /// Bane, desbane, admite ou remove da allow-list. O dono grava direto num bloco; um moderador
    /// cria uma ação assinada com o próprio certificado, válida na hora como provisória.
    pub fn moderate(
        &mut self,
        server_id: &str,
        personal: &UserIdentity,
        kind: ModKind,
        target: &str,
        reason: &str,
        now: UtcSecs,
    ) -> Result<ServerMessage, CommunityError> {
        let server = self.servers.get(server_id).ok_or(CommunityError::UnknownServer)?;
        if !server.has_chain() {
            return Err(CommunityError::NoChainYet);
        }
        if server.is_owner() {
            let entry = match kind {
                ModKind::Ban { until } => Entry::Ban { target: target.to_string(), until, reason: reason.to_string() },
                ModKind::Unban => Entry::Unban { target: target.to_string() },
                ModKind::Admit => Entry::AllowAdd(target.to_string()),
                ModKind::Unadmit => Entry::AllowRemove(target.to_string()),
            };
            return self.owner_append(server_id, now, vec![entry]);
        }
        let state = server.effective_state(now);
        let cert = state
            .active_certs(now)
            .filter(|c| c.body.subject == personal.public_key_hex() && c.allows(kind.permission()))
            .min_by_key(|c| c.body.level)
            .cloned()
            .ok_or(CommunityError::NotModerator)?;
        let action = ModAction::create(personal, &cert, kind, target, reason, now);
        state.check_mod_action(&action, now).map_err(CommunityError::Rejected)?;
        let server = self.servers.get_mut(server_id).expect("verificado acima");
        server.pending.insert(action.id(), action.clone());
        self.persist(server_id)?;
        Ok(ServerMessage::Action(action))
    }

    /// Histórico de alterações da cadeia, do mais antigo ao mais novo
    pub fn history(&self, server_id: &str) -> Vec<HistoryEntry> {
        let Some(server) = self.servers.get(server_id) else { return Vec::new() };
        server
            .chain
            .blocks()
            .iter()
            .map(|block| HistoryEntry {
                height: block.body.height,
                timestamp: block.body.timestamp,
                description: block.body.entries.iter().map(describe_entry).collect::<Vec<_>>().join("; "),
            })
            .collect()
    }

    fn persist(&self, server_id: &str) -> Result<(), CommunityError> {
        let (Some(dir), Some(server)) = (&self.dir, self.servers.get(server_id)) else { return Ok(()) };
        let stored = StoredServer {
            server_id: server_id.to_string(),
            blocks: server.chain.blocks().to_vec(),
            pending: server.pending.values().cloned().collect(),
        };
        std::fs::write(dir.join(format!("{}.server.json", server_id)), serde_json::to_vec_pretty(&stored)?)?;
        Ok(())
    }
}

/// Descrição curta de uma alteração (pubkeys abreviadas)
fn describe_entry(entry: &Entry) -> String {
    match entry {
        Entry::Genesis { name, owner, closed, .. } => {
            format!("criado '{}' por {}{}", name, short_id(owner), if *closed { " (fechado)" } else { "" })
        }
        Entry::SetOwner(owner) => format!("posse transferida para {}", short_id(owner)),
        Entry::SetName(name) => format!("renomeado para '{}'", name),
        Entry::AddChannel(c) => format!("canal {}{} criado", if c.channel_type == ChannelType::Voice { "🔊 " } else { "#" }, c.name),
        Entry::RemoveChannel(name) => format!("canal {} removido", name),
        Entry::SetClosed(true) => "servidor fechado (allow-list)".into(),
        Entry::SetClosed(false) => "servidor aberto".into(),
        Entry::SetCertPolicy { validity_secs, renewal_window_secs } => format!(
            "certificados: validade {}, renovação nos últimos {}",
            format_duration(Some(*validity_secs)),
            format_duration(Some(*renewal_window_secs))
        ),
        Entry::AllowAdd(pk) => format!("{} admitido", short_id(pk)),
        Entry::AllowRemove(pk) => format!("{} removido da allow-list", short_id(pk)),
        Entry::IssueCert(cert) => format!(
            "certificado de moderador nível {} para {} (até {})",
            cert.body.level,
            short_id(&cert.body.subject),
            cert.body.expires_at
        ),
        Entry::RevokeCert { serial } => format!("certificado {} revogado", serial),
        Entry::Ban { target, until, .. } => format!(
            "dono baniu {} ({})",
            short_id(target),
            until.map_or("permanente".to_string(), |u| format!("até {}", u))
        ),
        Entry::Unban { target } => format!("dono desbaniu {}", short_id(target)),
        Entry::IncludeModAction(action) => {
            let verb = match action.body.kind {
                ModKind::Ban { .. } => "baniu",
                ModKind::Unban => "desbaniu",
                ModKind::Admit => "admitiu",
                ModKind::Unadmit => "removeu da allow-list",
            };
            format!("moderador {} {} {}", short_id(action.actor()), verb, short_id(&action.body.target))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_800_000_000;
    const DAY: u64 = 86_400;
    /// Identidade pessoal de quem cria os servidores nos testes
    const OWNER: &str = "0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e";

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("anarchord_test_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// Entrega mensagens de um registro a outro, como a rede faria
    fn deliver(to: &mut ServerRegistry, messages: Vec<ServerMessage>, from: Option<&str>, now: u64) -> Vec<ServerEvent> {
        messages.into_iter().flat_map(|m| to.handle_message(m, from, now)).collect()
    }

    /// Dono cria o servidor; membro entra e sincroniza a cadeia
    fn owner_and_member() -> (ServerRegistry, ServerRegistry, String) {
        let mut owner = ServerRegistry::in_memory();
        let id = owner.create("Rust Guild", OWNER, T0).unwrap();
        let mut member = ServerRegistry::in_memory();
        member.join(&id).unwrap();
        let request = member.chain_request(&id).unwrap();
        let reply = owner.handle_message(request, None, T0);
        let ServerEvent::Reply { messages, .. } = &reply[0] else { panic!("{:?}", reply) };
        deliver(&mut member, messages.clone(), None, T0);
        (owner, member, id)
    }

    fn pk(id: &UserIdentity) -> String {
        id.public_key_hex()
    }

    #[test]
    fn test_topics_keep_lobby_compatible_and_namespace_servers() {
        assert_eq!(channel_topic(&Space::Lobby, "geral"), "p2p-anarchord/channel/geral");
        assert_eq!(voice_topic(&Space::Lobby, "sala"), "p2p-anarchord/voice/sala");
        let id = "ab".repeat(32);
        let space = Space::Server(id.clone());
        assert_eq!(channel_topic(&space, "geral"), format!("p2p-anarchord/server/{}/channel/geral", id));
        assert_eq!(parse_server_control_topic(&server_control_topic(&id)), Some(id.as_str()));
        assert_eq!(parse_server_control_topic(&channel_topic(&space, "geral")), None);
        assert_eq!(parse_server_content_topic(&channel_topic(&space, "geral")), Some(id.as_str()));
        assert_eq!(parse_server_content_topic(&voice_topic(&space, "voz")), Some(id.as_str()));
        assert_eq!(parse_server_content_topic(&screen_topic(&space)), Some(id.as_str()));
        assert_eq!(parse_server_content_topic(&server_control_topic(&id)), None);
        assert_eq!(parse_server_content_topic(&channel_topic(&Space::Lobby, "geral")), None);
        assert_eq!(screen_topic(&Space::Lobby), "p2p-anarchord/screens");
        assert_eq!(screen_stream_topic(&Space::Lobby, "screen:ab12cd34"), "p2p-anarchord/screens/screen:ab12cd34");
        assert_eq!(parse_server_content_topic(&screen_stream_topic(&space, "screen:ab12cd34")), Some(id.as_str()), "quadros de servidor são cifrados");
    }

    #[test]
    fn test_member_syncs_chain_from_owner() {
        let (_owner, member, id) = owner_and_member();
        let server = member.get(&id).unwrap();
        assert!(server.has_chain());
        assert!(!server.is_owner());
        assert_eq!(server.name(), "Rust Guild");
        assert_eq!(server.default_text_channel().as_deref(), Some("geral"));
        assert_eq!(server.level_of(&id, T0), Some(0), "a chave do servidor é o nível 0");
    }

    #[test]
    fn test_gap_requests_missing_blocks() {
        let (mut owner, mut member, id) = owner_and_member();
        owner.add_channel(&id, "a", ChannelType::Text, T0 + 1).unwrap();
        let latest = owner.add_channel(&id, "b", ChannelType::Text, T0 + 2).unwrap();
        let events = deliver(&mut member, vec![latest], None, T0 + 3);
        assert!(matches!(events.as_slice(), [ServerEvent::NeedBlocks { from_height: 1, .. }]), "{:?}", events);

        let request = member.chain_request(&id).unwrap();
        let ServerEvent::Reply { messages, .. } = owner.handle_message(request, None, T0 + 3).remove(0) else { panic!() };
        deliver(&mut member, messages, None, T0 + 3);
        assert!(member.get(&id).unwrap().has_channel("b", ChannelType::Text));
    }

    #[test]
    fn test_moderator_action_is_provisional_then_consolidated() {
        let (mut owner, mut member, id) = owner_and_member();
        let moderator = UserIdentity::generate();
        let spammer = pk(&UserIdentity::generate());

        // O dono certifica o moderador; o bloco chega ao registro dele (aqui, `member`)
        deliver(&mut member, vec![owner.add_moderator(&id, &pk(&moderator), 1, T0 + 10).unwrap()], None, T0 + 10);

        let action = member.moderate(&id, &moderator, ModKind::Ban { until: None }, &spammer, "spam", T0 + 20).unwrap();
        assert!(member.get(&id).unwrap().is_banned(&spammer, T0 + 20), "vale na hora como provisória");

        let events = deliver(&mut owner, vec![action], None, T0 + 21);
        assert!(matches!(events.as_slice(), [ServerEvent::ActionAccepted { .. }]), "{:?}", events);
        assert!(owner.get(&id).unwrap().is_banned(&spammer, T0 + 21));

        // Dono online: consolida a ação na cadeia
        let block = owner.owner_maintenance(&id, T0 + 30).expect("deveria consolidar");
        assert!(owner.get(&id).unwrap().chain().state().is_banned(&spammer, T0 + 30), "agora definitivo");
        assert_eq!(owner.get(&id).unwrap().pending_actions().count(), 0);
        deliver(&mut member, vec![block], None, T0 + 31);
        assert_eq!(member.get(&id).unwrap().pending_actions().count(), 0, "incluída na cadeia: sai da fila");
        assert!(owner.owner_maintenance(&id, T0 + 40).is_none(), "nada mais a fazer");
    }

    /// Moderador revogado: ações provisórias dele são desfeitas quando a revogação chega
    #[test]
    fn test_revocation_undoes_provisional_actions() {
        let (mut owner, mut member, id) = owner_and_member();
        let rogue = UserIdentity::generate();
        let victim = pk(&UserIdentity::generate());
        deliver(&mut member, vec![owner.add_moderator(&id, &pk(&rogue), 1, T0 + 10).unwrap()], None, T0 + 10);

        let mut rogue_registry = ServerRegistry::in_memory();
        rogue_registry.join(&id).unwrap();
        deliver(&mut rogue_registry, owner.snapshot(&id), None, T0 + 11);
        let action = rogue_registry.moderate(&id, &rogue, ModKind::Ban { until: None }, &victim, "abuso", T0 + 20).unwrap();
        deliver(&mut member, vec![action], None, T0 + 21);
        assert!(member.get(&id).unwrap().is_banned(&victim, T0 + 21), "o membro foi influenciado");

        let revoke = owner.remove_moderator(&id, &pk(&rogue), T0 + 30).unwrap();
        let events = deliver(&mut member, vec![revoke], None, T0 + 31);
        assert!(events.iter().any(|e| matches!(e, ServerEvent::ActionsUndone { count: 1, .. })), "{:?}", events);
        assert!(!member.get(&id).unwrap().is_banned(&victim, T0 + 31), "ação desfeita");
        assert_eq!(member.get(&id).unwrap().level_of(&pk(&rogue), T0 + 31), None);
    }

    #[test]
    fn test_owner_maintenance_renews_certificates_in_window() {
        let (mut owner, _member, id) = owner_and_member();
        let moderator = UserIdentity::generate();
        owner.add_moderator(&id, &pk(&moderator), 1, T0).unwrap();
        assert!(owner.owner_maintenance(&id, T0 + 4 * DAY).is_none(), "fora da janela");
        assert!(owner.owner_maintenance(&id, T0 + 5 * DAY + 1).is_some(), "na janela: renova");
        let state = owner.get(&id).unwrap().chain().state().clone();
        assert_eq!(state.level_of(&pk(&moderator), T0 + 9 * DAY), Some(1), "válido além da data original");
        assert!(owner.owner_maintenance(&id, T0 + 5 * DAY + 2).is_none(), "não renova duas vezes");
    }

    #[test]
    fn test_certificate_policy_is_configurable() {
        let (mut owner, _member, id) = owner_and_member();
        owner.set_cert_policy(&id, 3 * DAY, DAY, T0 + 1).unwrap();
        let moderator = UserIdentity::generate();
        owner.add_moderator(&id, &pk(&moderator), 1, T0 + 2).unwrap();
        let state = owner.get(&id).unwrap().chain().state().clone();
        assert_eq!(state.level_of(&pk(&moderator), T0 + 2 + 3 * DAY - 1), Some(1));
        assert_eq!(state.level_of(&pk(&moderator), T0 + 2 + 3 * DAY), None, "validade de 3 dias");
        assert!(owner.owner_maintenance(&id, T0 + 2 + DAY).is_none(), "janela de 1 dia ainda não começou");
        assert!(owner.owner_maintenance(&id, T0 + 2 + 2 * DAY).is_some());
    }

    #[test]
    fn test_only_owner_changes_configuration_and_non_moderator_cannot_moderate() {
        let (_owner, mut member, id) = owner_and_member();
        assert!(matches!(member.add_channel(&id, "x", ChannelType::Text, T0), Err(CommunityError::NotOwner)));
        let nobody = UserIdentity::generate();
        let result = member.moderate(&id, &nobody, ModKind::Ban { until: None }, &"cd".repeat(32), "", T0);
        assert!(matches!(result, Err(CommunityError::NotModerator)));
    }

    #[test]
    fn test_moderator_rules_are_enforced_when_acting() {
        let (mut owner, mut member, id) = owner_and_member();
        let mod_a = UserIdentity::generate();
        let mod_b = UserIdentity::generate();
        deliver(&mut member, vec![owner.add_moderator(&id, &pk(&mod_a), 1, T0).unwrap()], None, T0);
        deliver(&mut member, vec![owner.add_moderator(&id, &pk(&mod_b), 1, T0).unwrap()], None, T0);
        let result = member.moderate(&id, &mod_a, ModKind::Ban { until: None }, &pk(&mod_b), "", T0 + 1);
        assert!(matches!(result, Err(CommunityError::Rejected(Rejection::TargetOutranks))));
    }

    #[test]
    fn test_closed_server_does_not_serve_outsiders() {
        let (mut owner, _member, id) = owner_and_member();
        let insider = UserIdentity::generate();
        owner.set_closed(&id, true, T0 + 1).unwrap();
        owner.moderate(&id, &UserIdentity::generate(), ModKind::Admit, &pk(&insider), "", T0 + 2).unwrap();

        let request = ServerMessage::ChainRequest { server_id: id.clone(), from_height: 0 };
        let outsider = pk(&UserIdentity::generate());
        assert!(matches!(owner.handle_message(request.clone(), Some(&outsider), T0 + 3)[0], ServerEvent::Ignored(_)));
        assert!(matches!(owner.handle_message(request.clone(), None, T0 + 3)[0], ServerEvent::Ignored(_)), "sem autor conhecido");
        assert!(matches!(owner.handle_message(request, Some(&pk(&insider)), T0 + 3)[0], ServerEvent::Reply { .. }));
    }

    #[test]
    fn test_owner_temporary_ban_from_registry() {
        let (mut owner, mut member, id) = owner_and_member();
        let target = pk(&UserIdentity::generate());
        let block = owner.moderate(&id, &UserIdentity::generate(), ModKind::Ban { until: Some(T0 + 3600) }, &target, "1h", T0).unwrap();
        deliver(&mut member, vec![block], None, T0 + 1);
        assert!(member.get(&id).unwrap().is_banned(&target, T0 + 10));
        assert!(!member.get(&id).unwrap().is_banned(&target, T0 + 3600));
    }

    #[test]
    fn test_history_lists_every_change() {
        let (mut owner, _member, id) = owner_and_member();
        owner.add_channel(&id, "jogos", ChannelType::Text, T0 + 1).unwrap();
        owner.set_closed(&id, true, T0 + 2).unwrap();
        let history = owner.history(&id);
        assert_eq!(history.len(), 3);
        assert!(history[0].description.contains("criado 'Rust Guild'"));
        assert!(history[1].description.contains("#jogos"));
        assert_eq!(history[2].description, "servidor fechado (allow-list)");
        assert!(history.windows(2).all(|w| w[0].timestamp <= w[1].timestamp));
    }

    #[test]
    fn test_persistence_restores_chain_ownership_and_pending() {
        let dir = temp_dir("chain_persist");
        let moderator = UserIdentity::generate();
        let target = pk(&UserIdentity::generate());
        let id = {
            let mut reg = ServerRegistry::load(&dir, T0).unwrap();
            let id = reg.create("Persistente", OWNER, T0).unwrap();
            reg.add_channel(&id, "jogos", ChannelType::Voice, T0 + 1).unwrap();
            reg.add_moderator(&id, &pk(&moderator), 1, T0 + 2).unwrap();
            id
        };
        {
            // Outro nó (o do moderador) com a mesma pasta: ação provisória fica salva
            let mut reg = ServerRegistry::load(&dir, T0 + 3).unwrap();
            let server = reg.servers.get_mut(&id).unwrap();
            server.owner_key = None; // simula o registro do moderador
            reg.moderate(&id, &moderator, ModKind::Ban { until: None }, &target, "", T0 + 4).unwrap();
        }
        let reg = ServerRegistry::load(&dir, T0 + 5).unwrap();
        let server = reg.get(&id).unwrap();
        assert!(server.is_owner(), "chave de dono continua no disco");
        assert!(server.has_channel("jogos", ChannelType::Voice));
        assert_eq!(server.pending_actions().count(), 1);
        assert!(server.is_banned(&target, T0 + 5));
        assert_eq!(reg.find("persistente").map(|s| s.server_id.clone()), Some(id.clone()));

        let mut reg = reg;
        assert!(reg.leave(&id));
        assert!(dir.join(format!("{}.owner-key.json", id)).exists(), "sair nunca apaga a chave");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tampered_file_loses_chain_from_altered_block() {
        let dir = temp_dir("chain_tamper");
        let id = {
            let mut reg = ServerRegistry::load(&dir, T0).unwrap();
            let id = reg.create("Original", OWNER, T0).unwrap();
            reg.add_channel(&id, "segredo", ChannelType::Text, T0 + 1).unwrap();
            id
        };
        let path = dir.join(format!("{}.server.json", id));
        let text = std::fs::read_to_string(&path).unwrap().replace("segredo", "alterado");
        std::fs::write(&path, text).unwrap();
        let reg = ServerRegistry::load(&dir, T0 + 2).unwrap();
        let server = reg.get(&id).unwrap();
        assert_eq!(server.chain().blocks().len(), 1, "bloco adulterado e seguintes descartados");
        assert!(!server.has_channel("alterado", ChannelType::Text));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
