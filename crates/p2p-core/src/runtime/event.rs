//! Eventos que o core manda para a interface. Tudo tipado: o texto mostrado ao usuário é
//! escolhido pela interface (cada uma no seu idioma e estilo).

use crate::community::{HistoryEntry, ModKind, UtcSecs};
use crate::config::NodeConfig;
use crate::dm::FirewallBlockEntry;
use crate::files::{FileEvent, FileSummary};
use crate::screen::ScreenInfo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CoreEvent {
    /// Nó no ar
    Started { nick: String, pubkey: String, peer_id: String, port: u16 },
    Network(NetworkEvent),
    /// Par Anarchord identificado (primeira vez na conexão ou nick novo)
    PeerIdentified { peer_id: String, nick: String, pubkey: String },
    /// Par Anarchord desconectou
    PeerLeft { peer_id: String, nick: String },
    /// Resposta a `ListPeers` (`/peers`)
    Peers {
        anarchord: usize,
        connections: usize,
        #[serde(default)]
        peers: Vec<PeerProtocolInfo>,
    },
    /// Par usa uma versão incompatível do protocolo (emitido uma única vez por par na sessão)
    PeerIncompatible {
        peer_id: String,
        nick: String,
        pubkey: String,
        peer_version: String,
        supported_versions: String,
    },
    AudioDevices { inputs: Vec<String>, outputs: Vec<String> },
    /// Espaço atual (Lobby ou servidor) e os canais dele
    SpaceChanged { space: SpaceInfo, channels: Vec<ChannelInfo> },
    ServersChanged(Vec<ServerSummary>),
    ChannelEntered { space: SpaceInfo, channel: String },
    /// Pares Anarchord inscritos no canal de texto atual
    ChannelMembers { channel: String, members: Vec<String> },
    ChatMessage { channel: String, author: String, author_pubkey: String, text: String, timestamp: u64 },
    /// Convite de servidor recebido no chat (`/server accept`)
    InviteReceived { from: String, server_id: String, known: bool },
    Voice(VoiceEvent),
    Screen(ScreenEvent),
    File(FileEvent),
    /// Resposta a `ListFiles`
    Files(Vec<FileSummary>),
    /// Resposta a `ListFriends` e atualizações de presença de amigos
    Friends(Vec<FriendStatus>),
    /// Um amigo ficou online ou offline
    FriendPresence { public_key: String, alias: Option<String>, online: bool },
    /// Amigo adicionado ou removido com sucesso
    FriendUpdated { pubkey: String, alias: Option<String>, removed: bool },
    /// Canal de DM privado aberto na TUI (`@Amigo`)
    DmOpened { peer_pubkey: String, peer_name: String, channel: String },
    /// Mensagem Direta (DM 1:1 E2EE) enviada ou recebida (online ou entregue via Mailbox offline)
    DirectMessage {
        peer_pubkey: String,
        peer_name: String,
        author: String,
        author_pubkey: String,
        text: String,
        timestamp: u64,
        offline_delivery: bool,
    },
    /// Envelope de DM enfileirado para entrega offline via guardiões amigos
    MailboxQueued {
        recipient_pubkey: String,
        recipient_name: String,
        envelope_id: String,
        suggested_ttl: Option<u64>,
    },
    /// Este nó guardião aceitou armazenar um envelope offline para um amigo
    MailboxStoredForFriend {
        sender_name: String,
        recipient_short: String,
        envelope_id: String,
        effective_ttl_secs: u64,
    },
    /// Status da configuração local e uso de disco da Mailbox
    ConfigStatus {
        config: NodeConfig,
        mailbox_used_bytes: u64,
        mailbox_envelope_count: usize,
    },
    /// Parâmetro de configuração alterado
    ConfigUpdated { key: String, value: String },
    /// Chave de criptografia X25519 rotacionada com sucesso
    EncryptionKeyRotated {
        epoch: u64,
        public_key: String,
    },
    /// Um par foi bloqueado temporariamente pelo Firewall local (aviso único por bloqueio)
    PeerBlocked {
        pubkey: String,
        peer_name: String,
        is_friend: bool,
        reason: String,
        duration_secs: u64,
        blocked_until: u64,
        offense_level: u32,
        courtesy_sent: bool,
    },
    /// Um par foi desbloqueado no Firewall local
    PeerUnblocked {
        pubkey: String,
        peer_name: String,
    },
    /// Lista de bloqueios ativos no Firewall (`/firewall`)
    FirewallStatus(Vec<FirewallBlockEntry>),
    /// Lendo o arquivo para montar o manifesto
    FilePreparing { name: String },
    Server(ServerNotice),
    Error(CoreError),
    /// O nó encerrou (depois de `Shutdown`)
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FriendStatus {
    pub public_key: String,
    pub alias: Option<String>,
    pub added_at: u64,
    pub online: bool,
    pub current_nick: Option<String>,
    pub peer_id: Option<String>,
}

/// Resumo de versão do protocolo e capacidades de um par Anarchord conectado (`/peers`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerProtocolInfo {
    pub peer_id: String,
    pub nick: String,
    pub pubkey: String,
    /// Faixa de versões anunciada pelo par (ex.: `"v1-v2"` ou `"v1"`)
    pub announced_versions: String,
    /// Versão do envelope negociada com este par (`None` se incompatível)
    pub negotiated_version: Option<u8>,
    /// Versão da aplicação anunciada pelo par (ex.: `"0.1.0"`)
    pub app_version: String,
    /// Capacidades em comum negociadas com este par
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SpaceInfo {
    Lobby,
    /// `name` é `None` enquanto a configuração do servidor não chegou
    Server { id: String, name: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelInfo {
    pub name: String,
    pub voice: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerSummary {
    pub id: String,
    pub name: String,
    pub current: bool,
    pub owner: bool,
    /// Configuração ainda não chegou
    pub pending: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NetworkEvent {
    Listening(String),
    ExternalAddress(String),
    DhtBootstrap { nodes: usize },
    Dialing(String),
    TrackerPeer(String),
    BehindNat,
    RelayRequested { relay: String, address: String },
    RelayReserved(String),
    HolePunched(String),
    /// Tentativa de hole punching falhou (a conexão segue pelo relay)
    HolePunchFailed { peer_id: String, error: String },
    /// Primeira conexão com um par Anarchord, ou a primeira direta depois de uma relayada
    Connected { peer_id: String, address: String, relayed: bool },
    ConnectionClosed { peer_id: String, cause: String },
    /// Pares novos recebidos na troca de pares e discados
    PeerExchange { from: String, dialed: usize },
    AudioUnavailable(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VoiceEvent {
    Joined(String),
    Left(String),
    Members(Vec<String>),
    Speaking { nick: String, speaking: bool },
    Muted(bool),
    AudioReady,
    SynthStarted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScreenEvent {
    Monitors(Vec<ScreenInfo>),
    ShareStarted { stream_id: String, quality: u32, synthetic: bool },
    ShareStopped,
    /// A cada 60 quadros enviados
    FrameSent { seq: u64, bytes: usize },
    StreamAvailable { stream_id: String, nick: String },
    /// A cada 60 quadros recebidos de uma stream assistida
    FrameReceived { nick: String, seq: u64, bytes: usize, width: u32, height: u32 },
    Watching { stream_id: String, nick: String },
    /// A janela fechou: o core saiu da transmissão
    WatchEnded,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ServerNotice {
    Created { id: String, name: String },
    /// Procurando membros online para receber a configuração
    Searching { id: String },
    /// `/server switch` para um servidor cuja configuração ainda não chegou
    WaitingConfig { id: String },
    Left { name: String, was_owner: bool },
    Synced { id: String, name: String, height: u64 },
    Fork { id: String, height: u64, replaced: bool },
    /// Alteração feita por este nó e já publicada
    Changed { server: String, change: ServerChange },
    /// Ação de moderação feita por este nó
    Moderated { server: String, target: String, kind: ModKind, at: UtcSecs, recorded_by_owner: bool },
    /// Ação de moderação de outro moderador
    ModerationReceived { server: String, by: String, target: String, kind: ModKind, at: UtcSecs, reason: String },
    ActionsUndone { server: String, count: usize },
    /// Ban deste usuário começou ou acabou
    BanStatus { server: String, banned: bool },
    /// Nível de moderador deste usuário mudou
    Role { server: String, level: Option<u8> },
    /// (dono) entregou a chave do grupo cifrado a alguém
    KeyGranted { to: String },
    KeyReceived { server: String },
    RemovedFromGroup { server: String },
    InviteSent { server: String },
    /// Ninguém no Lobby para receber o convite: id para mandar à mão
    InviteManual { id: String },
    /// Servidor fechado: quem foi convidado precisa estar na allow-list
    InviteNeedsAllow,
    List { lobby_current: bool, servers: Vec<ServerListEntry> },
    Info(ServerInfo),
    History(Vec<HistoryEntry>),
    Help,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ServerChange {
    ChannelAdded { name: String, voice: bool },
    ChannelRemoved(String),
    ModeratorAdded { who: String, level: u8, validity_secs: u64 },
    ModeratorRemoved { who: String },
    Closed,
    Opened,
    Policy { validity_secs: u64, renewal_window_secs: u64 },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerListEntry {
    pub id: String,
    pub name: String,
    pub current: bool,
    pub owner: bool,
    pub moderator_level: Option<u8>,
    pub pending: bool,
    pub closed: bool,
    pub banned: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Role {
    Owner,
    Moderator(u8),
    Member,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerInfo {
    pub id: String,
    pub name: String,
    pub height: u64,
    pub updated_at: Option<UtcSecs>,
    pub channels: Vec<ChannelInfo>,
    pub role: Role,
    pub closed: bool,
    pub allow_list: usize,
    /// (nick, nível, validade do certificado)
    pub moderators: Vec<(String, u8, UtcSecs)>,
    /// (nick, até quando, nível de quem baniu)
    pub bans: Vec<(String, Option<UtcSecs>, u8)>,
    pub cert_validity_secs: u64,
    pub renewal_window_secs: u64,
    pub pending_actions: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CoreError {
    PeerNotFound(String),
    NoStream(String),
    AlreadyStreaming,
    NotStreaming,
    NotInVoice,
    NoSuchChannel { name: String, voice: bool },
    /// Servidor e este nó ainda não tem a chave do grupo cifrado
    NoGroupKey,
    BannedHere,
    NotOnAllowList,
    /// Comando de servidor usado no Lobby
    InLobby,
    SelfModeration,
    NoInvite,
    ServerNotFound(String),
    /// Erro de regra de servidor (permissão, nível, canal...)
    Server(String),
    File(String),
    Friend(String),
    Config(String),
    Io { context: String, message: String },
    Network(String),
}
