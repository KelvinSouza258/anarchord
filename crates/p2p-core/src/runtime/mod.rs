//! Loop de eventos do nó Anarchord.
//!
//! A interface manda [`CoreCommand`]s e recebe [`CoreEvent`]s; todo o resto (rede, chat, voz,
//! tela, servidores, arquivos, descoberta) roda aqui, numa tarefa tokio. O CLI, uma GUI futura
//! ou um teste usam o mesmo core.
//!
//! O estado fica em [`Runtime`]; cada assunto tem seu arquivo com os métodos dele
//! (`network`, `chat`, `voice`, `screen`, `servers`, `files`).

mod chat;
pub mod discovery;
pub mod command;
pub mod event;
mod files;
mod network;
mod screen;
mod servers;
mod voice;

pub use chat::ActiveChannel;
pub use command::{CoreCommand, FrameSink, ServerCommand};
pub use event::*;
pub use servers::{invite_text, parse_invite};

use crate::community::{self, e2ee::ServerGroups, ServerRegistry, Space};
use crate::identity::UserIdentity;
use crate::node::P2PNode;
use crate::relay::RelayManager;
use libp2p::gossipsub::IdentTopic;
use libp2p::{Multiaddr, PeerId};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

/// Como o nó deve rodar
#[derive(Clone)]
pub struct CoreConfig {
    pub identity: UserIdentity,
    /// Porta TCP + QUIC (0 = escolhe uma livre)
    pub port: u16,
    /// Onde ficam os servidores acompanhados e o estado MLS
    pub servers_dir: PathBuf,
    /// Onde os downloads completos são salvos
    pub download_dir: PathBuf,
    /// Canal de texto inicial no Lobby
    pub channel: String,
    /// Endereço para discar ao iniciar
    pub connect: Option<Multiaddr>,
    /// Sala de voz do Lobby em que entra ao iniciar
    pub auto_voice: Option<String>,
    /// Abre microfone e alto-falante
    pub audio: bool,
    /// Transmite uma melodia sintética na sala de voz (bots e testes)
    pub synth_audio: bool,
    /// Transmite vídeo sintético no Lobby (bots e testes)
    pub synth_video: bool,
    /// Descoberta automática (DHT Amino e trackers BitTorrent)
    pub discovery: bool,
    /// Modo de teste: baixa todo arquivo oferecido e assiste toda tela anunciada
    pub test_mode: bool,
    /// Bootstrap da DHT (com `/p2p/<id>`), além dos públicos se `public_defaults`
    pub bootstrap: Vec<Multiaddr>,
    /// Trackers BitTorrent UDP (`host:porta`), além dos públicos se `public_defaults`
    pub trackers: Vec<String>,
    /// Usa também os nós de bootstrap do IPFS e os trackers públicos embutidos.
    /// Desligado, o nó só conhece o que foi informado (redes isoladas, laboratório).
    pub public_defaults: bool,
    /// Descoberta na rede local (mDNS)
    pub mdns: bool,
    /// Atende como servidor de relay (nós públicos)
    pub relay_server: bool,
    /// Rede de laboratório: IPs privados valem como públicos e as sondagens são rápidas
    pub lab: bool,
}

impl CoreConfig {
    /// Configuração padrão para uma identidade (sem áudio nem descoberta, útil em testes)
    pub fn new(identity: UserIdentity, servers_dir: PathBuf, download_dir: PathBuf) -> Self {
        Self {
            identity,
            port: 0,
            servers_dir,
            download_dir,
            channel: "geral".into(),
            connect: None,
            auto_voice: None,
            audio: false,
            synth_audio: false,
            synth_video: false,
            discovery: false,
            test_mode: false,
            bootstrap: Vec::new(),
            trackers: Vec::new(),
            public_defaults: false,
            mdns: true,
            relay_server: false,
            lab: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CoreStartError {
    #[error("rede: {0}")]
    Node(#[from] crate::node::NodeError),
    #[error("servidores: {0}")]
    Servers(#[from] crate::community::CommunityError),
    #[error("tópico: {0}")]
    Subscribe(String),
}

/// Ponta da interface: manda comandos e recebe eventos
pub struct CoreHandle {
    commands: UnboundedSender<CoreCommand>,
    events: UnboundedReceiver<CoreEvent>,
}

impl CoreHandle {
    pub fn send(&self, command: CoreCommand) {
        let _ = self.commands.send(command);
    }

    pub async fn next_event(&mut self) -> Option<CoreEvent> {
        self.events.recv().await
    }

    /// Separa as duas pontas (ex.: comandos numa tarefa, eventos em outra)
    pub fn split(self) -> (UnboundedSender<CoreCommand>, UnboundedReceiver<CoreEvent>) {
        (self.commands, self.events)
    }
}

pub struct Core;

impl Core {
    /// Prepara o nó e devolve a ponta da interface e o loop a executar.
    ///
    /// O loop não é `Send` (os fluxos de áudio do sistema ficam presos à thread), então ele roda
    /// com `.await` na tarefa principal (ou numa `LocalSet`), enquanto a interface roda em outra
    /// tarefa conversando pelo `CoreHandle`.
    pub fn start(config: CoreConfig) -> Result<(CoreHandle, CoreTask), CoreStartError> {
        let (tx_events, events) = unbounded_channel();
        let (commands, rx_commands) = unbounded_channel();
        let runtime = Runtime::new(config, tx_events)?;
        Ok((CoreHandle { commands, events }, CoreTask { runtime, commands: rx_commands }))
    }
}

/// O loop do nó, pronto para rodar
pub struct CoreTask {
    runtime: Runtime,
    commands: UnboundedReceiver<CoreCommand>,
}

impl CoreTask {
    /// Roda até `CoreCommand::Shutdown` (ou até a interface descartar o `CoreHandle`)
    pub async fn run(self) {
        self.runtime.run(self.commands).await
    }

    pub fn peer_id(&self) -> PeerId {
        self.runtime.node.peer_id
    }

    pub fn listen_port(&self) -> u16 {
        self.runtime.node.listen_port
    }
}

/// Agora, em segundos Unix (UTC)
pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default()
}

/// Estado do nó. Os campos são usados pelos módulos de cada assunto.
pub(crate) struct Runtime {
    config: CoreConfig,
    identity: UserIdentity,
    nick: String,
    events: UnboundedSender<CoreEvent>,
    node: P2PNode,

    // Rede
    connected_peers: HashSet<PeerId>,
    /// Melhor conexão conhecida com cada par: (endereço, relayed). O `Connected` só é emitido
    /// para pares Anarchord identificados (a maioria das conexões é com nós do IPFS na DHT)
    links: HashMap<PeerId, (String, bool)>,
    /// PeerId -> (nick, pubkey) dos pares Anarchord identificados
    peer_metadata: HashMap<PeerId, (String, String)>,
    /// Pares já anunciados na interface desde que conectaram
    identified: HashSet<PeerId>,
    /// Endereços discados com conexão aberta (o tracker repete os mesmos pares)
    dialed_open: HashSet<Multiaddr>,
    relay_manager: RelayManager,
    discovery: discovery::DiscoveryState,
    tracker_rx: Option<UnboundedReceiver<String>>,

    // Chat e servidores
    active: ActiveChannel,
    servers: ServerRegistry,
    mls: ServerGroups,
    last_key_package: HashMap<String, std::time::Instant>,
    /// Servidor em que entra assim que a configuração chegar
    pending_switch: Option<String>,
    last_invite: Option<String>,
    last_snapshot_reply: HashMap<String, std::time::Instant>,

    voice: voice::VoiceState,
    screen: screen::ScreenState,
    files: files::FilesState,
}

impl Runtime {
    fn new(config: CoreConfig, events: UnboundedSender<CoreEvent>) -> Result<Self, CoreStartError> {
        let identity = config.identity.clone();
        let nick = identity.profile.display_name.clone();
        let mut node = P2PNode::with_options(
            identity.clone(),
            crate::node::NodeOptions { port: config.port, relay_server: config.relay_server, lab: config.lab, mdns: config.mdns },
        )?;
        let mut relay_manager = RelayManager::new();
        relay_manager.allow_private(config.lab);
        let servers = ServerRegistry::load(config.servers_dir.clone(), now_secs())?;
        let mls = ServerGroups::new(&identity, Some(config.servers_dir.join("mls-state.json")));
        let active = ActiveChannel::new(Space::Lobby, config.channel.clone());
        node.swarm.behaviour_mut().gossipsub.subscribe(&active.topic).map_err(|e| CoreStartError::Subscribe(format!("{:?}", e)))?;
        let screen = screen::ScreenState::new(&mut node);
        let files = files::FilesState::new(&identity, config.download_dir.clone());
        Ok(Self {
            identity,
            nick,
            events,
            node,
            connected_peers: HashSet::new(),
            links: HashMap::new(),
            peer_metadata: HashMap::new(),
            identified: HashSet::new(),
            dialed_open: HashSet::new(),
            relay_manager,
            discovery: discovery::DiscoveryState::new(config.lab),
            tracker_rx: None,
            active,
            servers,
            mls,
            last_key_package: HashMap::new(),
            pending_switch: None,
            last_invite: None,
            last_snapshot_reply: HashMap::new(),
            voice: voice::VoiceState::default(),
            screen,
            files,
            config,
        })
    }

    fn emit(&self, event: CoreEvent) {
        let _ = self.events.send(event);
    }

    fn error(&self, error: CoreError) {
        self.emit(CoreEvent::Error(error));
    }

    fn my_pubkey(&self) -> String {
        self.identity.public_key_hex()
    }

    async fn run(mut self, mut commands: UnboundedReceiver<CoreCommand>) {
        self.emit(CoreEvent::Started {
            nick: self.nick.clone(),
            pubkey: self.my_pubkey(),
            peer_id: self.node.peer_id.to_string(),
            port: self.node.listen_port,
        });
        for id in self.servers.list().map(|s| s.server_id.clone()).collect::<Vec<_>>() {
            self.follow_server(&id);
        }
        if let Some(address) = self.config.connect.clone() {
            self.emit(CoreEvent::Network(NetworkEvent::Dialing(address.to_string())));
            if let Err(e) = self.node.swarm.dial(address) {
                self.error(CoreError::Network(e.to_string()));
            }
        }
        self.subscribe_peer_exchange();
        self.start_discovery();
        self.start_voice();
        self.start_synthetic_video();
        self.publish_servers();
        self.resume_files();

        let mut discovery_tick = tokio::time::interval(Duration::from_secs(1));
        let mut server_sync = tokio::time::interval(Duration::from_secs(5));
        let mut screen_announce = tokio::time::interval(Duration::from_secs(2));
        let mut speaker_check = tokio::time::interval(Duration::from_millis(200));
        let mut files_tick = tokio::time::interval(Duration::from_secs(1));
        let mut tracker_rx = self.tracker_rx.take();
        let mut voice_rx = self.voice.outgoing.take();
        let mut screen_rx = self.screen.outgoing.take();
        let mut manifest_rx = self.files.manifests.take();

        loop {
            tokio::select! {
                command = commands.recv() => match command {
                    Some(CoreCommand::Shutdown) | None => break,
                    Some(command) => self.handle_command(command),
                },
                event = self.node.swarm.next_event() => self.handle_swarm_event(event),
                _ = discovery_tick.tick() => self.discovery_tick(),
                _ = server_sync.tick() => self.server_sync_tick(),
                _ = screen_announce.tick() => self.screen_tick(),
                _ = speaker_check.tick() => self.speaker_tick(),
                _ = files_tick.tick() => self.files_tick(),
                Some(address) = recv(&mut tracker_rx) => self.dial_discovered(address),
                Some(packet) = recv(&mut voice_rx) => self.broadcast_voice(packet),
                Some(packet) = recv(&mut screen_rx) => self.broadcast_screen(packet),
                Some(job) = recv(&mut manifest_rx) => self.manifest_ready(job),
            }
        }

        self.stop_discovery();
        self.emit(CoreEvent::Stopped);
    }

    fn handle_command(&mut self, command: CoreCommand) {
        match command {
            CoreCommand::SendMessage(text) => self.send_chat(&text),
            CoreCommand::JoinChannel(channel) => self.join_text_channel(channel),
            CoreCommand::JoinVoice(channel) => self.join_voice(channel),
            CoreCommand::LeaveVoice => self.leave_voice(),
            CoreCommand::ToggleMute => self.toggle_mute(),
            CoreCommand::ListPeers => {
                let anarchord = self.peer_metadata.keys().filter(|p| self.connected_peers.contains(p)).count();
                self.emit(CoreEvent::Peers { anarchord, connections: self.connected_peers.len() });
            }
            CoreCommand::ListAudioDevices => self.emit(CoreEvent::AudioDevices {
                inputs: crate::voice::AudioDeviceManager::list_input_devices(),
                outputs: crate::voice::AudioDeviceManager::list_output_devices(),
            }),
            CoreCommand::ListScreens => {
                self.emit(CoreEvent::Screen(ScreenEvent::Monitors(crate::screen::ScreenCaptureEngine::list_screens())))
            }
            CoreCommand::StartScreenShare { monitor, quality } => self.start_screen_share(monitor, quality),
            CoreCommand::StopScreenShare => self.stop_screen_share(),
            CoreCommand::WatchScreen { query, sink } => self.watch_screen(&query, sink),
            CoreCommand::Dial(address) => match address.parse::<Multiaddr>() {
                Ok(address) => {
                    self.emit(CoreEvent::Network(NetworkEvent::Dialing(address.to_string())));
                    if let Err(e) = self.node.swarm.dial(address) {
                        self.error(CoreError::Network(e.to_string()));
                    }
                }
                Err(e) => self.error(CoreError::Network(e.to_string())),
            },
            CoreCommand::ShareFile(path) => self.share_file(path),
            CoreCommand::SendFile { to, path } => self.send_file(&to, path),
            CoreCommand::GetFile(query) => self.get_file(&query),
            CoreCommand::RejectFile(query) => self.reject_file(&query),
            CoreCommand::Unshare(query) => self.unshare_file(&query),
            CoreCommand::ListFiles => self.list_files(),
            CoreCommand::Server(command) => self.run_server_command(command),
            CoreCommand::Shutdown => {}
        }
    }

    /// Publica conteúdo (chat, voz, tela, enxame). Em tópicos de servidor, cifra antes com o grupo MLS.
    fn publish_content(&mut self, topic: &IdentTopic, bytes: Vec<u8>) -> Result<(), PublishError> {
        let topic_name = topic.hash().into_string();
        let payload = match community::parse_server_content_topic(&topic_name) {
            Some(server_id) => self.mls.encrypt(server_id, &bytes).map_err(|_| PublishError::NoGroupKey)?,
            None => bytes,
        };
        self.node.swarm.behaviour_mut().gossipsub.publish(topic.clone(), payload).map(|_| ()).map_err(|_| PublishError::Network)
    }

    /// Nick conhecido de uma pubkey, ou o início dela
    fn nick_for(&self, pubkey: &str) -> String {
        if pubkey == self.my_pubkey() {
            return self.nick.clone();
        }
        self.peer_metadata
            .values()
            .find(|(_, pk)| pk == pubkey)
            .map(|(nick, _)| nick.clone())
            .unwrap_or_else(|| community::short_id(pubkey).to_string())
    }

    /// PeerId de um par por nick, PeerId ou prefixo da pubkey
    fn find_peer(&self, query: &str) -> Option<PeerId> {
        self.peer_metadata.iter().find_map(|(peer, (nick, pubkey))| {
            (nick.eq_ignore_ascii_case(query) || peer.to_string().starts_with(query) || pubkey.starts_with(query)).then_some(*peer)
        })
    }
}

#[derive(Debug)]
enum PublishError {
    /// Conteúdo de servidor e este nó ainda não tem a chave do grupo
    NoGroupKey,
    Network,
}

/// `recv` de um receptor opcional (pendente para sempre se não houver)
async fn recv<T>(rx: &mut Option<UnboundedReceiver<T>>) -> Option<T> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Extensão para usar o swarm dentro do `select!`
trait NextEvent {
    async fn next_event(&mut self) -> libp2p::swarm::SwarmEvent<crate::protocol::AppBehaviourEvent>;
}

impl NextEvent for libp2p::Swarm<crate::protocol::AppBehaviour> {
    async fn next_event(&mut self) -> libp2p::swarm::SwarmEvent<crate::protocol::AppBehaviourEvent> {
        use futures::StreamExt;
        self.select_next_some().await
    }
}
