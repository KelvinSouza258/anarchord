mod render;
mod screen_viewer;
mod spaces;
mod ui;

use clap::Parser;
use p2p_core::files::FileEvent;
use p2p_core::runtime::{Core, CoreCommand, CoreConfig, CoreError, CoreEvent, ScreenEvent, ServerCommand, SpaceInfo, VoiceEvent};
use p2p_core::screen::VideoCodec;
use p2p_core::UserIdentity;
use screen_viewer::ScreenViewer;
use spaces::parse_server_command;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use ui::menu::{FriendUiEntry, ServerEntry};
use ui::{TerminalUi, UiAction, UiEvent};

#[derive(Parser, Debug, PartialEq)]
#[command(author = "Victor Gerin", version = "0.1.0", about = "Anarchord P2P Daemon & CLI")]
pub struct Args {
    /// Nome de exibição (apelido no chat)
    #[arg(short, long, default_value = "Peer")]
    pub nick: String,

    /// Porta local para escutar conexões UDP/QUIC e TCP (0 = porta dinâmica aleatória)
    #[arg(short, long, default_value_t = 0)]
    pub port: u16,

    /// Caminho do arquivo de identidade e perfil do usuário (JSON com chaves PEM)
    #[arg(long, default_value = "identity.json")]
    pub identity_file: PathBuf,

    /// Conectar diretamente a um endereço multiaddr conhecido (opcional)
    #[arg(long)]
    pub connect: Option<String>,

    /// Sala inicial de chat
    #[arg(long, default_value = "geral")]
    pub channel: String,

    /// Entrar automaticamente em uma sala de voz P2P ao iniciar (útil para nós bots/rádio)
    #[arg(long)]
    pub auto_voice: Option<String>,

    /// Desativar descoberta automática via IPFS Amino DHT e Open Trackers BitTorrent
    #[arg(long, default_value_t = false)]
    pub no_auto_bootstrap: bool,

    /// Gravar logs de telemetria e diagnóstico em arquivo (ex: anarchord.log)
    #[arg(long)]
    pub log_file: Option<PathBuf>,

    /// Caminho customizado para o arquivo de configuração `config.json` (opcional)
    #[arg(long)]
    pub config: Option<PathBuf>,
}

/// Quadros de vídeo aguardando a janela do viewer. Fila curta: se a janela atrasar, os quadros
/// excedentes são descartados em vez de acumular segundos de atraso.
const VIEWER_QUEUE_FRAMES: usize = 3;

/// Ação interpretada a partir de uma linha digitada no chat
#[derive(Debug, PartialEq, Clone)]
pub enum ChatAction {
    Quit,
    ListPeers,
    ListDevices,
    ToggleMute,
    JoinVoice(String),
    LeaveVoice,
    JoinTextChannel(String),
    /// Compartilha um arquivo na sala atual
    ShareFile(String),
    /// Oferece um arquivo só a um par
    SendFile { recipient_query: String, file_path: String },
    GetFile(String),
    RejectFile(String),
    ListFiles,
    Unshare(String),
    AddFriend { pubkey: String, alias: Option<String> },
    RemoveFriend(String),
    ListFriends,
    OpenDm(String),
    SendDm { target: String, text: String, suggested_ttl: Option<u64> },
    ShowConfig,
    SetConfig { key: String, value: String },
    ListFirewall,
    UnblockPeer(String),
    ScreenStart { monitor_idx: usize, quality: u32 },
    ScreenStop,
    ScreenWatch(String),
    ScreenList,
    SendTextMessage(String),
    Server(ServerCommand),
    Empty,
}

/// Analisa a linha digitada pelo usuário e extrai a ação correspondente
pub fn parse_user_input(input: &str) -> ChatAction {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return ChatAction::Empty;
    }
    if trimmed == "/quit" {
        return ChatAction::Quit;
    }
    if trimmed == "/peers" {
        return ChatAction::ListPeers;
    }
    if trimmed == "/devices" {
        return ChatAction::ListDevices;
    }
    if trimmed == "/mute" {
        return ChatAction::ToggleMute;
    }
    if trimmed == "/screen start" {
        return ChatAction::ScreenStart { monitor_idx: 0, quality: 720 };
    }
    if trimmed.starts_with("/screen start ") {
        let remainder = trimmed.trim_start_matches("/screen start ").trim();
        let parts: Vec<&str> = remainder.split_whitespace().collect();
        let monitor_idx = parts.first().and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
        let quality = parts.get(1).and_then(|s| s.parse::<u32>().ok()).unwrap_or(720);
        return ChatAction::ScreenStart { monitor_idx, quality };
    }
    if trimmed == "/screen stop" {
        return ChatAction::ScreenStop;
    }
    if trimmed == "/screen list" {
        return ChatAction::ScreenList;
    }
    if trimmed.starts_with("/screen watch ") {
        let target = trimmed.trim_start_matches("/screen watch ").trim();
        if !target.is_empty() {
            return ChatAction::ScreenWatch(target.to_string());
        }
    }
    if trimmed.starts_with("/voice join ") {
        let v_channel = trimmed.trim_start_matches("/voice join ").trim();
        if !v_channel.is_empty() {
            return ChatAction::JoinVoice(v_channel.to_string());
        }
    }
    if trimmed == "/voice leave" {
        return ChatAction::LeaveVoice;
    }
    if trimmed == "/lobby" {
        return ChatAction::Server(ServerCommand::Switch("lobby".to_string()));
    }
    if trimmed == "/server" || trimmed.starts_with("/server ") {
        return ChatAction::Server(parse_server_command(trimmed.trim_start_matches("/server")));
    }
    if trimmed.starts_with("/join ") {
        let new_channel = trimmed.trim_start_matches("/join ").trim();
        if !new_channel.is_empty() {
            return ChatAction::JoinTextChannel(new_channel.to_string());
        }
    }
    if trimmed.starts_with("/send ") {
        let remainder = trimmed.trim_start_matches("/send ").trim();
        if let Some((recipient, path_part)) = remainder.split_once(' ') {
            let clean_path = path_part.trim().trim_matches('"').trim_matches('\'').to_string();
            if !recipient.is_empty() && !clean_path.is_empty() {
                return ChatAction::SendFile {
                    recipient_query: recipient.to_string(),
                    file_path: clean_path,
                };
            }
        }
    }
    if let Some(path) = trimmed.strip_prefix("/share ") {
        let clean_path = path.trim().trim_matches('"').trim_matches('\'');
        if !clean_path.is_empty() {
            return ChatAction::ShareFile(clean_path.to_string());
        }
    }
    // /accept continua funcionando como sinônimo de /get
    for prefix in ["/get ", "/accept "] {
        if let Some(id) = trimmed.strip_prefix(prefix).map(str::trim).filter(|id| !id.is_empty()) {
            return ChatAction::GetFile(id.to_string());
        }
    }
    if let Some(id) = trimmed.strip_prefix("/reject ").map(str::trim).filter(|id| !id.is_empty()) {
        return ChatAction::RejectFile(id.to_string());
    }
    if let Some(id) = trimmed.strip_prefix("/unshare ").map(str::trim).filter(|id| !id.is_empty()) {
        return ChatAction::Unshare(id.to_string());
    }
    if trimmed == "/files" {
        return ChatAction::ListFiles;
    }
    if trimmed == "/friends" || trimmed == "/amigos" || trimmed == "/friend" {
        return ChatAction::ListFriends;
    }
    for prefix in ["/friend ", "/amigo "] {
        if let Some(rest) = trimmed.strip_prefix(prefix).map(str::trim) {
            let mut parts = rest.splitn(3, char::is_whitespace);
            match (parts.next(), parts.next().map(str::trim), parts.next().map(str::trim)) {
                (Some("add"), Some(pubkey), alias) if !pubkey.is_empty() => {
                    return ChatAction::AddFriend { pubkey: pubkey.to_string(), alias: alias.filter(|a| !a.is_empty()).map(str::to_string) };
                }
                (Some("remove" | "rm"), Some(pubkey), _) if !pubkey.is_empty() => return ChatAction::RemoveFriend(pubkey.to_string()),
                (Some("list"), _, _) => return ChatAction::ListFriends,
                _ => {}
            }
        }
    }
    if let Some(rest) = trimmed.strip_prefix("/dm ").map(str::trim) {
        if let Some(open_target) = rest.strip_prefix("open ").map(str::trim).filter(|t| !t.is_empty()) {
            return ChatAction::OpenDm(open_target.to_string());
        }
        if let Some((target, mut msg_part)) = rest.split_once(char::is_whitespace) {
            let target = target.trim();
            msg_part = msg_part.trim();
            let mut suggested_ttl = None;
            if let Some((before_ttl, ttl_str)) = msg_part.rsplit_once("--ttl ") {
                if let Some(secs) = p2p_core::config::parse_ttl_arg(ttl_str.trim()) {
                    suggested_ttl = Some(secs);
                    msg_part = before_ttl.trim();
                }
            }
            if !target.is_empty() && !msg_part.is_empty() {
                return ChatAction::SendDm {
                    target: target.to_string(),
                    text: msg_part.to_string(),
                    suggested_ttl,
                };
            }
        }
    }
    if trimmed == "/config" || trimmed == "/config show" {
        return ChatAction::ShowConfig;
    }
    if let Some(rest) = trimmed.strip_prefix("/config set ").map(str::trim) {
        if let Some((key, value)) = rest.split_once(char::is_whitespace) {
            let (key, value) = (key.trim(), value.trim());
            if !key.is_empty() && !value.is_empty() {
                return ChatAction::SetConfig { key: key.to_string(), value: value.to_string() };
            }
        }
    }
    if trimmed == "/firewall" || trimmed == "/firewall list" {
        return ChatAction::ListFirewall;
    }
    if let Some(target) = trimmed.strip_prefix("/firewall unblock ").map(str::trim).filter(|t| !t.is_empty()) {
        return ChatAction::UnblockPeer(target.to_string());
    }
    ChatAction::SendTextMessage(trimmed.to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    setup_logging(&args)?;

    // Identidade permanente do usuário (JSON com chaves PEM e perfil)
    let mut identity = UserIdentity::load_or_create(&args.identity_file)?;
    if args.nick != "Peer" || identity.profile.display_name == "Anonymous Peer" {
        identity.set_nick(&args.nick);
        let _ = identity.save_to(&args.identity_file);
    }

    let config = CoreConfig {
        identity_path: Some(args.identity_file.clone()),
        config_path: args.config.clone(),
        identity: identity.clone(),
        port: args.port,
        servers_dir: servers_dir_for(&args.identity_file),
        download_dir: download_dir(),
        channel: args.channel.clone(),
        connect: args.connect.as_deref().map(str::parse).transpose()?,
        auto_voice: args.auto_voice.clone(),
        audio: true,
        synth_audio: false,
        synth_video: false,
        discovery: !args.no_auto_bootstrap,
        test_mode: false,
        bootstrap: Vec::new(),
        trackers: Vec::new(),
        // Rede pública: nós de bootstrap do IPFS e trackers BitTorrent embutidos
        public_defaults: true,
        mdns: true,
        relay_server: false,
        lab: false,
    };
    let (core, task) = Core::start(config)?;
    let (commands, events) = core.split();

    // Configura panic hook para garantir que o terminal seja sempre restaurado
    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        TerminalUi::restore_terminal();
        default_panic(info);
    }));

    // Ctrl+C encerra com calma (desanuncia o nó nos trackers)
    let on_ctrl_c = commands.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = on_ctrl_c.send(CoreCommand::Shutdown);
        }
    });

    let ui_handle = {
        let (tx_ui_event, rx_ui_event) = tokio::sync::mpsc::unbounded_channel::<UiEvent>();
        let (tx_ui_action, rx_ui_action) = tokio::sync::mpsc::unbounded_channel::<UiAction>();
        let muted = Arc::new(AtomicBool::new(false));
        let ui = TerminalUi::new(
            identity.profile.display_name.clone(),
            identity.public_key_hex(),
            Arc::clone(&muted),
            Some(args.identity_file.with_extension("history")),
        );
        let ui_handle = tokio::spawn(async move {
            let _ = ui.run(rx_ui_event, tx_ui_action).await;
        });
        tokio::spawn(bridge(events, rx_ui_action, commands, tx_ui_event, muted));
        ui_handle
    };

    // O loop do core roda nesta tarefa enquanto a UI estiver aberta
    let run = task.run();
    tokio::pin!(run);
    tokio::select! {
        _ = &mut run => {},
        // A UI fechou (o Shutdown já foi enviado): o core termina de desanunciar o nó
        _ = ui_handle => { let _ = tokio::time::timeout(std::time::Duration::from_secs(5), &mut run).await; }
    }
    TerminalUi::restore_terminal();
    // Encerra na hora: threads de áudio, captura e rede não seguram o processo
    std::process::exit(0)
}

fn setup_logging(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(ref log_path) = args.log_file {
        let file = std::fs::OpenOptions::new().create(true).append(true).open(log_path)?;
        let subscriber = FmtSubscriber::builder().with_max_level(Level::DEBUG).with_writer(file).finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    } else {
        // Na TUI, logs no stdout distorceriam a tela
        let subscriber = FmtSubscriber::builder().with_writer(std::io::sink).finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }
    Ok(())
}

/// Liga a TUI ao core: eventos viram atualizações de tela; o que o usuário digita vira comando
async fn bridge(
    mut events: UnboundedReceiver<CoreEvent>,
    mut actions: UnboundedReceiver<UiAction>,
    commands: UnboundedSender<CoreCommand>,
    ui: UnboundedSender<UiEvent>,
    muted: Arc<AtomicBool>,
) {
    // Janela de vídeo esperando o core confirmar a transmissão
    let mut pending_viewer: Option<std::sync::mpsc::Receiver<(VideoCodec, Vec<u8>)>> = None;
    loop {
        tokio::select! {
            event = events.recv() => {
                let Some(event) = event else { break };
                if let CoreEvent::Screen(ScreenEvent::Watching { nick, .. }) = &event {
                    if let Some(rx) = pending_viewer.take() {
                        ScreenViewer::spawn_window(nick.clone(), 1280, 720, Arc::new(std::sync::Mutex::new(rx)), Arc::new(AtomicBool::new(true)));
                    }
                }
                if let CoreEvent::Error(CoreError::NoStream(_)) = &event {
                    pending_viewer = None;
                }
                if let CoreEvent::Voice(VoiceEvent::Muted(on)) = &event {
                    muted.store(*on, Ordering::Relaxed);
                }
                for ui_event in ui_events(&event) {
                    let _ = ui.send(ui_event);
                }
            }
            action = actions.recv() => {
                let Some(action) = action else { break };
                let command = match action {
                    UiAction::Quit => Some(CoreCommand::Shutdown),
                    UiAction::ToggleMute => Some(CoreCommand::ToggleMute),
                    UiAction::SendMessage(text) => match parse_user_input(&text) {
                        ChatAction::ScreenWatch(query) => {
                            let (sink, rx) = std::sync::mpsc::sync_channel(VIEWER_QUEUE_FRAMES);
                            pending_viewer = Some(rx);
                            Some(CoreCommand::WatchScreen { query, sink: Some(sink) })
                        }
                        action => action.into_command(),
                    },
                };
                if let Some(command) = command {
                    let _ = commands.send(command);
                }
            }
        }
    }
}

/// O que a TUI mostra para cada evento do core
fn ui_events(event: &CoreEvent) -> Vec<UiEvent> {
    let mut out = Vec::new();
    match event {
        CoreEvent::PeerIdentified { peer_id, nick, pubkey } => {
            out.push(UiEvent::PeerConnected { peer_id: peer_id.clone(), nick: nick.clone(), pubkey: pubkey.clone() })
        }
        CoreEvent::PeerLeft { peer_id, .. } => out.push(UiEvent::PeerDisconnected(peer_id.clone())),
        CoreEvent::SpaceChanged { space, channels } => out.push(UiEvent::SpaceChanged {
            space_name: render::space_label(space),
            channels: channels.iter().map(|c| (c.name.clone(), c.voice)).collect(),
            is_server: matches!(space, SpaceInfo::Server { .. }),
        }),
        CoreEvent::ServersChanged(servers) => out.push(UiEvent::ServersChanged(
            servers
                .iter()
                .map(|s| ServerEntry { name: s.name.clone(), id: s.id.clone(), current: s.current, owner: s.owner, pending: s.pending })
                .collect(),
        )),
        CoreEvent::Friends(list) => out.push(UiEvent::FriendsChanged(
            list.iter()
                .map(|f| {
                    let display_name = f
                        .alias
                        .clone()
                        .or_else(|| f.current_nick.clone())
                        .unwrap_or_else(|| p2p_core::community::short_id(&f.public_key).to_string());
                    FriendUiEntry {
                        public_key: f.public_key.clone(),
                        display_name,
                        online: f.online,
                    }
                })
                .collect(),
        )),
        CoreEvent::DmOpened { peer_name, channel, .. } => {
            out.push(UiEvent::DmOpened { peer_name: peer_name.clone(), channel: channel.clone() })
        }
        CoreEvent::DirectMessage { peer_name, author, text, offline_delivery, .. } => out.push(UiEvent::DirectMessage {
            peer_name: peer_name.clone(),
            author: author.clone(),
            text: text.clone(),
            offline_delivery: *offline_delivery,
        }),
        CoreEvent::ChannelEntered { channel, .. } => out.push(UiEvent::ChannelChanged(channel.clone())),
        CoreEvent::ChannelMembers { channel, members } => {
            out.push(UiEvent::ChannelMembers { channel: channel.clone(), members: members.clone() })
        }
        CoreEvent::ChatMessage { channel, author, text, .. } => {
            out.push(UiEvent::ChatMessage { channel: channel.clone(), author: author.clone(), text: text.clone() })
        }
        CoreEvent::Voice(VoiceEvent::Joined(room)) => out.push(UiEvent::VoiceChannelChanged(Some(room.clone()))),
        CoreEvent::Voice(VoiceEvent::Left(_)) => out.push(UiEvent::VoiceChannelChanged(None)),
        CoreEvent::Voice(VoiceEvent::Members(members)) => out.push(UiEvent::VoiceRoomMembers(members.clone())),
        CoreEvent::Voice(VoiceEvent::Speaking { nick, speaking }) => {
            // Falar/parar de falar aparece no painel de voz, não como texto
            out.push(UiEvent::VoiceActivity { nick: nick.clone(), speaking: *speaking });
            return out;
        }
        CoreEvent::File(event) => {
            let progress = |name: &String, percentage: f32| UiEvent::FileTransferProgress { file_name: name.clone(), percentage, is_download: true };
            match event {
                FileEvent::Started { name, .. } => out.push(progress(name, 0.0)),
                FileEvent::Progress { name, progress: p, .. } => out.push(progress(name, (p * 100.0).min(99.9))),
                FileEvent::Completed { name, .. } => out.push(progress(name, 100.0)),
                FileEvent::Failed { name, .. } => out.push(progress(name, -1.0)),
                _ => {}
            }
        }
        _ => {}
    }
    out.extend(render::describe(event).into_iter().map(UiEvent::SystemLog));
    out
}

impl ChatAction {
    /// Comando do core correspondente (assistir tela é tratado à parte: precisa da janela)
    fn into_command(self) -> Option<CoreCommand> {
        Some(match self {
            ChatAction::Empty | ChatAction::ScreenWatch(_) => return None,
            ChatAction::Quit => CoreCommand::Shutdown,
            ChatAction::ListPeers => CoreCommand::ListPeers,
            ChatAction::ListDevices => CoreCommand::ListAudioDevices,
            ChatAction::ToggleMute => CoreCommand::ToggleMute,
            ChatAction::JoinVoice(room) => CoreCommand::JoinVoice(room),
            ChatAction::LeaveVoice => CoreCommand::LeaveVoice,
            ChatAction::JoinTextChannel(channel) => CoreCommand::JoinChannel(channel),
            ChatAction::ShareFile(path) => CoreCommand::ShareFile(PathBuf::from(path)),
            ChatAction::SendFile { recipient_query, file_path } => CoreCommand::SendFile { to: recipient_query, path: PathBuf::from(file_path) },
            ChatAction::GetFile(query) => CoreCommand::GetFile(query),
            ChatAction::RejectFile(query) => CoreCommand::RejectFile(query),
            ChatAction::ListFiles => CoreCommand::ListFiles,
            ChatAction::Unshare(query) => CoreCommand::Unshare(query),
            ChatAction::AddFriend { pubkey, alias } => CoreCommand::AddFriend { pubkey, alias },
            ChatAction::RemoveFriend(pubkey) => CoreCommand::RemoveFriend { pubkey },
            ChatAction::ListFriends => CoreCommand::ListFriends,
            ChatAction::OpenDm(target) => CoreCommand::OpenDm { target },
            ChatAction::SendDm { target, text, suggested_ttl } => CoreCommand::SendDm { target, text, suggested_ttl },
            ChatAction::ShowConfig => CoreCommand::ShowConfig,
            ChatAction::SetConfig { key, value } => CoreCommand::SetConfig { key, value },
            ChatAction::ListFirewall => CoreCommand::ListFirewall,
            ChatAction::UnblockPeer(target) => CoreCommand::UnblockPeer { target },
            ChatAction::ScreenStart { monitor_idx, quality } => CoreCommand::StartScreenShare { monitor: monitor_idx, quality },
            ChatAction::ScreenStop => CoreCommand::StopScreenShare,
            ChatAction::ScreenList => CoreCommand::ListScreens,
            ChatAction::SendTextMessage(text) => CoreCommand::SendMessage(text),
            ChatAction::Server(command) => CoreCommand::Server(command),
        })
    }
}

/// Pasta dos servidores acompanhados: `<identidade>.servers/`, ao lado do arquivo de identidade.
/// Cada identidade tem a sua (ex.: alice.json -> alice.servers/), para nós na mesma pasta não
/// compartilharem chaves de dono.
fn servers_dir_for(identity_file: &Path) -> PathBuf {
    let stem = identity_file.file_stem().and_then(|s| s.to_str()).unwrap_or("identity");
    identity_file.with_file_name(format!("{}.servers", stem))
}

/// `$HOME/downloads`, ou `./downloads` sem `HOME` (comum no Windows)
fn download_dir() -> PathBuf {
    std::env::var("HOME").ok().map(PathBuf::from).map(|h| h.join("downloads")).unwrap_or_else(|| PathBuf::from("downloads"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::PeerId;

    #[test]
    fn test_parse_user_input_commands() {
        assert_eq!(parse_user_input(""), ChatAction::Empty);
        assert_eq!(parse_user_input("   "), ChatAction::Empty);
        assert_eq!(parse_user_input("/quit"), ChatAction::Quit);
        assert_eq!(parse_user_input("  /quit  "), ChatAction::Quit);
        assert_eq!(parse_user_input("/peers"), ChatAction::ListPeers);
        assert_eq!(parse_user_input("/devices"), ChatAction::ListDevices);
        assert_eq!(parse_user_input("/mute"), ChatAction::ToggleMute);
        assert_eq!(parse_user_input("/voice leave"), ChatAction::LeaveVoice);
    }

    #[test]
    fn test_parse_user_input_file_commands() {
        assert_eq!(
            parse_user_input("/send Alice foto.png"),
            ChatAction::SendFile {
                recipient_query: "Alice".to_string(),
                file_path: "foto.png".to_string(),
            }
        );
        assert_eq!(
            parse_user_input("/send Bob C:\\fotos\\ferias 2026.png"),
            ChatAction::SendFile {
                recipient_query: "Bob".to_string(),
                file_path: "C:\\fotos\\ferias 2026.png".to_string(),
            }
        );
        assert_eq!(
            parse_user_input("/accept 8f4a123b"),
            ChatAction::GetFile("8f4a123b".to_string())
        );
        assert_eq!(parse_user_input("/get bafk1234"), ChatAction::GetFile("bafk1234".to_string()));
        assert_eq!(parse_user_input(r#"/share "C:\fotos\a b.png""#), ChatAction::ShareFile(r"C:\fotos\a b.png".to_string()));
        assert_eq!(parse_user_input("/files"), ChatAction::ListFiles);
        assert_eq!(parse_user_input("/unshare filme.mkv"), ChatAction::Unshare("filme.mkv".to_string()));
        assert_eq!(
            parse_user_input("/reject 8f4a123b"),
            ChatAction::RejectFile("8f4a123b".to_string())
        );
    }

    #[test]
    fn test_parse_friend_commands() {
        let pk = "a".repeat(64);
        assert_eq!(parse_user_input("/friends"), ChatAction::ListFriends);
        assert_eq!(
            parse_user_input(&format!("/friend add {} Bob da Silva", pk)),
            ChatAction::AddFriend { pubkey: pk.clone(), alias: Some("Bob da Silva".into()) }
        );
        assert_eq!(parse_user_input(&format!("/friend add {}", pk)), ChatAction::AddFriend { pubkey: pk.clone(), alias: None });
        assert_eq!(parse_user_input(&format!("/friend remove {}", pk)), ChatAction::RemoveFriend(pk));
    }

    #[test]
    fn test_parse_dm_and_config_commands() {
        assert_eq!(parse_user_input("/dm open Bob"), ChatAction::OpenDm("Bob".into()));
        assert_eq!(
            parse_user_input("/dm Bob olá mundo privado!"),
            ChatAction::SendDm {
                target: "Bob".into(),
                text: "olá mundo privado!".into(),
                suggested_ttl: None,
            }
        );
        assert_eq!(
            parse_user_input("/dm Bob urgente --ttl 2h"),
            ChatAction::SendDm {
                target: "Bob".into(),
                text: "urgente".into(),
                suggested_ttl: Some(7200),
            }
        );
        assert_eq!(parse_user_input("/config"), ChatAction::ShowConfig);
        assert_eq!(parse_user_input("/config show"), ChatAction::ShowConfig);
        assert_eq!(
            parse_user_input("/config set mailbox.max_ttl_days 14"),
            ChatAction::SetConfig { key: "mailbox.max_ttl_days".into(), value: "14".into() }
        );
        assert_eq!(parse_user_input("/firewall"), ChatAction::ListFirewall);
        assert_eq!(parse_user_input("/firewall unblock Alice"), ChatAction::UnblockPeer("Alice".into()));
    }

    /// Amigo adicionado pela TUI aparece offline e passa a online quando o par conecta
    #[tokio::test]
    async fn test_friend_presence_typed_in_the_tui() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let (mut alice, port) = FakeUi::start("Alice", None);
                alice.type_line("/friend add nao-e-chave");
                alice.wait_log("nick desconhecido recusado", "'nao-e-chave' não encontrado").await;
                alice.type_line(&format!("/friend add {}", alice.pubkey));
                alice.wait_log("adicionar a si mesmo recusado", "Amigos:").await;

                let (bob, _) = FakeUi::start("Bob", Some(port));
                let bob_key = bob.pubkey.clone();
                alice.wait("Alice identificar Bob", move |e| matches!(e, UiEvent::PeerConnected { pubkey, .. } if *pubkey == bob_key)).await;

                alice.type_line(&format!("/friend add {} Bobby", bob.pubkey));
                alice.wait_log("amigo adicionado", "Bobby adicionado").await;
                alice.wait_log("lista com Bob online", "🟢 Bobby").await;

                // Pelo nick (como o menu de contexto faz): remove pelo apelido e readiciona
                alice.type_line("/friend remove Bobby");
                alice.wait_log("amigo removido", "Bobby removido").await;
                alice.type_line("/friend add Bob");
                alice.wait_log("adicionado pelo nick", "Bob adicionado").await;
                alice.type_line("/friend add Fantasma");
                alice.wait_log("nick desconhecido", "'Fantasma' não encontrado").await;
            })
            .await;
    }

    #[test]
    fn test_parse_user_input_channels() {
        assert_eq!(
            parse_user_input("/join dev-chat"),
            ChatAction::JoinTextChannel("dev-chat".to_string())
        );
        assert_eq!(
            parse_user_input("/voice join musica"),
            ChatAction::JoinVoice("musica".to_string())
        );
        // Texto comum
        assert_eq!(
            parse_user_input("Olá mundo descentralizado!"),
            ChatAction::SendTextMessage("Olá mundo descentralizado!".to_string())
        );
    }

    #[test]
    fn test_clap_cli_args_parsing() {
        // Testa flags padrão
        let args = Args::parse_from(["p2p-cli"]);
        assert_eq!(args.nick, "Peer");
        assert_eq!(args.port, 0);
        assert_eq!(args.channel, "geral");
        assert!(!args.no_auto_bootstrap);
        assert_eq!(args.auto_voice, None);

        // Testa flags customizadas
        let custom_args = Args::parse_from([
            "p2p-cli",
            "--nick", "Satoshi",
            "--port", "4001",
            "--channel", "crypto",
            "--auto-voice", "geral",
            "--no-auto-bootstrap",
        ]);
        assert_eq!(custom_args.nick, "Satoshi");
        assert_eq!(custom_args.port, 4001);
        assert_eq!(custom_args.channel, "crypto");
        assert_eq!(custom_args.auto_voice, Some("geral".to_string()));
        assert!(custom_args.no_auto_bootstrap);
    }

    #[test]
    fn test_server_commands_are_parsed_from_chat_input() {
        assert_eq!(parse_user_input("/lobby"), ChatAction::Server(ServerCommand::Switch("lobby".into())));
        assert_eq!(parse_user_input("/server"), ChatAction::Server(ServerCommand::Help));
        assert_eq!(parse_user_input("/server create Rust Guild"), ChatAction::Server(ServerCommand::Create("Rust Guild".into())));
        assert_eq!(parse_user_input("/serverx"), ChatAction::SendTextMessage("/serverx".into()));
    }

    #[test]
    fn test_servers_dir_is_per_identity() {
        assert_eq!(servers_dir_for(Path::new("alice.json")), PathBuf::from("alice.servers"));
        assert_eq!(servers_dir_for(Path::new("dados/bob.json")), PathBuf::from("dados/bob.servers"));
        assert_ne!(servers_dir_for(Path::new("alice.json")), servers_dir_for(Path::new("bob.json")));
    }

    #[test]
    fn test_text_commands_become_core_commands() {
        let command = |text: &str| parse_user_input(text).into_command();
        assert!(matches!(command("/share \"C:\\a b.txt\""), Some(CoreCommand::ShareFile(p)) if p == Path::new("C:\\a b.txt")));
        assert!(matches!(command("/send Bob foto.png"), Some(CoreCommand::SendFile { to, path }) if to == "Bob" && path == Path::new("foto.png")));
        assert!(matches!(command("/get bafk1234"), Some(CoreCommand::GetFile(q)) if q == "bafk1234"));
        assert!(matches!(command("/accept bafk1234"), Some(CoreCommand::GetFile(q)) if q == "bafk1234"));
        assert!(matches!(command("/reject bafk1234"), Some(CoreCommand::RejectFile(q)) if q == "bafk1234"));
        assert!(matches!(command("/unshare notas.txt"), Some(CoreCommand::Unshare(q)) if q == "notas.txt"));
        assert!(matches!(command("/files"), Some(CoreCommand::ListFiles)));
        assert!(matches!(command("/screen start 1 1080"), Some(CoreCommand::StartScreenShare { monitor: 1, quality: 1080 })));
        assert!(matches!(command("/voice join papo"), Some(CoreCommand::JoinVoice(r)) if r == "papo"));
        assert!(matches!(command("/server create Guilda"), Some(CoreCommand::Server(ServerCommand::Create(n))) if n == "Guilda"));
        assert!(matches!(command("olá"), Some(CoreCommand::SendMessage(t)) if t == "olá"));
        assert!(command("/screen watch Alice").is_none(), "assistir precisa da janela: tratado pela ponte");
        assert!(command("").is_none());
    }

    /// Uma TUI de mentira ligada a um core de verdade pela mesma ponte do app
    struct FakeUi {
        actions: UnboundedSender<UiAction>,
        events: UnboundedReceiver<UiEvent>,
        seen: Vec<UiEvent>,
        downloads: PathBuf,
        pubkey: String,
    }

    impl FakeUi {
        fn start_with_identity(identity: UserIdentity, connect_to: Option<u16>) -> (Self, u16) {
            let nick = identity.profile.display_name.clone();
            let base = std::env::temp_dir().join(format!("anarchord_cli_{}_{}_{}", nick, std::process::id(), PeerId::random()));
            let pubkey = identity.public_key_hex();
            let mut config = CoreConfig::new(identity, base.join("servers"), base.join("downloads"));
            config.config_path = Some(base.join("config.json"));
            config.connect = connect_to.map(|port| format!("/ip4/127.0.0.1/tcp/{}", port).parse().unwrap());
            let (core, task) = Core::start(config).unwrap();
            let port = task.listen_port();
            let (commands, core_events) = core.split();
            let (tx_ui, events) = tokio::sync::mpsc::unbounded_channel();
            let (actions, rx_actions) = tokio::sync::mpsc::unbounded_channel();
            tokio::task::spawn_local(task.run());
            tokio::task::spawn_local(bridge(core_events, rx_actions, commands, tx_ui, Arc::new(AtomicBool::new(false))));
            (Self { actions, events, seen: Vec::new(), downloads: base.join("downloads"), pubkey }, port)
        }

        fn start(nick: &str, connect_to: Option<u16>) -> (Self, u16) {
            Self::start_with_identity(UserIdentity::generate_with_nick(nick), connect_to)
        }

        /// Digita uma linha na caixa de texto
        fn type_line(&self, text: &str) {
            self.actions.send(UiAction::SendMessage(text.to_string())).unwrap();
        }

        async fn wait(&mut self, what: &str, pred: impl Fn(&UiEvent) -> bool) -> UiEvent {
            if let Some(found) = self.seen.iter().find(|e| pred(e)) {
                return found.clone();
            }
            tokio::time::timeout(std::time::Duration::from_secs(30), async {
                loop {
                    let event = self.events.recv().await.expect("ponte encerrou");
                    self.seen.push(event.clone());
                    if pred(&event) {
                        return event;
                    }
                }
            })
            .await
            .unwrap_or_else(|_| panic!("tempo esgotado esperando: {}", what))
        }

        async fn wait_log(&mut self, what: &str, needle: &str) -> String {
            let needle = needle.to_string();
            match self.wait(what, move |e| matches!(e, UiEvent::SystemLog(t) if t.contains(&needle))).await {
                UiEvent::SystemLog(text) => text,
                _ => unreachable!(),
            }
        }
    }

    /// `/share`, `/get`, `/files`, `/unshare` e `/reject` digitados na TUI, passando pela ponte,
    /// por dois cores reais e pela rede, até o que a TUI mostra
    #[tokio::test]
    async fn test_share_and_get_typed_in_the_tui() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let (mut alice, port) = FakeUi::start("Alice", None);
                let (mut bob, _) = FakeUi::start("Bob", Some(port));
                // Sala exclusiva do teste, para não misturar com nós reais na LAN (mDNS)
                let room = format!("arquivos-{}", PeerId::random());
                alice.type_line(&format!("/join {}", room));
                bob.type_line(&format!("/join {}", room));
                let r = room.clone();
                alice
                    .wait("Alice ver Bob na sala", move |e| {
                        matches!(e, UiEvent::ChannelMembers { channel, members } if *channel == r && members.iter().any(|m| m == "Bob"))
                    })
                    .await;

                let dir = std::env::temp_dir().join(format!("anarchord_cli_share_{}", PeerId::random()));
                std::fs::create_dir_all(&dir).unwrap();
                let path = dir.join("notas.txt");
                let data: Vec<u8> = (0..600_000).map(|i| (i % 251) as u8).collect();
                std::fs::write(&path, &data).unwrap();

                alice.type_line(&format!("/share \"{}\"", path.display()));
                alice.wait_log("Alice compartilhar", "compartilhado (id").await;
                let offer = bob.wait_log("oferta aparecer para Bob", "compartilhou 'notas.txt'").await;
                let id = offer.rsplit("/get ").next().unwrap().trim().to_string();

                bob.type_line("/reject zzzz");
                bob.wait_log("id inexistente", "nenhum arquivo com id ou nome 'zzzz'").await;
                bob.type_line(&format!("/get {}", id));
                bob.wait("barra de progresso chegar a 100%", |e| matches!(e, UiEvent::FileTransferProgress { percentage, .. } if *percentage >= 100.0))
                    .await;
                let saved = bob.wait_log("arquivo salvo", "salvo em").await;
                assert!(saved.contains("notas.txt"), "{}", saved);
                assert_eq!(std::fs::read(bob.downloads.join("notas.txt")).unwrap(), data);

                bob.type_line("/files");
                bob.wait_log("Bob listar e já estar compartilhando", "notas.txt (586 KB) — compartilhando").await;
                alice.type_line("/unshare notas.txt");
                alice.wait_log("Alice parar de compartilhar", "não está mais sendo compartilhado").await;
                alice.type_line("/files");
                alice.wait_log("lista vazia", "Nenhum arquivo").await;
            })
            .await;
    }

    /// Testa que o runtime do app permanece ativo e não encerra prematuramente
    /// até que a UI ou o comando de encerramento seja emitido.
    #[tokio::test]
    async fn test_app_runtime_does_not_exit_prematurely() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let (app, _) = FakeUi::start("Dave", None);
                // Espera 3.5 segundos (tempo superior ao antigo timeout de 3s)
                tokio::time::sleep(std::time::Duration::from_millis(3500)).await;

                // Envia comando para garantir que o runtime e a ponte ainda estão vivos e operantes
                app.type_line("/peers");
                // Se o runtime tivesse encerrado, o canal estaria fechado e não receberíamos nada
                let mut app = app;
                let log = app.wait_log("resposta ao comando /peers após tempo de espera", "Pares Anarchord conectados").await;
                assert!(log.contains("Pares Anarchord conectados"));
            })
            .await;
    }

    /// Testa DMs 1:1 E2EE online (/dm e /dm open @Amigo), entrega offline via guardiã Carol
    /// (mesmo sem Bob conhecer Carol) e comandos /config show e /config set.
    #[tokio::test]
    async fn test_dm_online_and_offline_via_guardian_and_config_in_the_tui() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                // Prepara a identidade do Bob de antemão (mas ele ainda NÃO está online!)
                let bob_identity = UserIdentity::generate_with_nick("Bob");
                let bob_pubkey = bob_identity.public_key_hex();

                // Alice e sua amiga Carol ficam online
                let (mut alice, alice_port) = FakeUi::start("Alice", None);
                let (mut carol, carol_port) = FakeUi::start("Carol", Some(alice_port));

                let alice_pk = alice.pubkey.clone();
                let carol_pk = carol.pubkey.clone();
                alice
                    .wait("Alice identificar Carol", move |e| matches!(e, UiEvent::PeerConnected { pubkey, .. } if *pubkey == carol_pk))
                    .await;
                carol
                    .wait("Carol identificar Alice", move |e| matches!(e, UiEvent::PeerConnected { pubkey, .. } if *pubkey == alice_pk))
                    .await;

                // Carol adiciona Alice como amiga (para atuar como guardiã da mailbox de Alice)
                carol.type_line(&format!("/friend add {} Alice", alice.pubkey));
                carol.wait_log("Carol adicionar Alice", "Alice adicionado").await;

                // Alice adiciona Carol e Bob (que ainda está offline!) aos amigos
                alice.type_line(&format!("/friend add {} Carol", carol.pubkey));
                alice.wait_log("Alice adicionar Carol", "Carol adicionado").await;
                alice.type_line(&format!("/friend add {} Bobby", bob_pubkey));
                alice.wait_log("Alice adicionar Bobby offline", "Bobby adicionado").await;

                // Testa /config show e /config set na Carol
                carol.type_line("/config set mailbox.max_message_ttl_days 10");
                carol.wait_log("Carol atualizar config", "mailbox.max_message_ttl_days").await;
                carol.wait_log("Carol exibir status da config", "mailbox.max_message_ttl_days = 10").await;

                // 1) DM Online E2EE entre Alice e Carol (usando /dm open Carol + mensagem direta)
                alice.type_line("/dm open Carol");
                alice
                    .wait("Alice abrir canal @Carol", |e| matches!(e, UiEvent::DmOpened { channel, .. } if channel == "@Carol"))
                    .await;
                alice.type_line("segredo online para Carol");
                carol
                    .wait("Carol receber DM E2EE online de Alice", |e| {
                        matches!(e, UiEvent::DirectMessage { author, text, offline_delivery: false, .. } if author == "Alice" && text == "segredo online para Carol")
                    })
                    .await;

                // 2) DM Offline (Sign-then-Seal): Alice envia DM para Bobby enquanto Bob está OFFLINE!
                alice.type_line("/dm Bobby mensagem guardada na malha --ttl 2h");
                alice.wait_log("Alice enfileirar DM offline", "Bobby está offline: DM assinada e lacrada").await;
                carol.wait_log("Carol guardar envelope para a amiga Alice", "Guardando envelope offline de Alice").await;

                // 3) Agora Bob entra online conectando APENAS na Carol (Bob nem tem Carol nos amigos!)
                let (mut bob, _) = FakeUi::start_with_identity(bob_identity, Some(carol_port));
                bob.wait("Bob receber DM offline assinada por Alice via Carol", |e| {
                    matches!(
                        e,
                        UiEvent::DirectMessage { author, text, offline_delivery: true, .. }
                        if author == "Alice" && text == "mensagem guardada na malha"
                    )
                })
                .await;

                // 4) Teste do Firewall Assimétrico + Mensagem de Cortesia:
                // Bob NÃO está na lista de amigos da Carol. Se Bob tentar inundar Carol (> 3 msg/min para desconhecido),
                // Carol bloqueia Bob na 4ª mensagem e envia 1 aviso automático de cortesia para o Bob!
                for i in 1..=4 {
                    bob.type_line(&format!("/dm Carol oi spam {}", i));
                }
                carol
                    .wait_log("Carol registrar bloqueio de Bob no Firewall", "Firewall: Bob")
                    .await;
                bob.wait("Bob receber mensagem de cortesia do Firewall da Carol", |e| {
                    matches!(
                        e,
                        UiEvent::DirectMessage { author, text, .. }
                        if author == "Carol" && text.contains("Aviso Automático do Firewall de Carol")
                    )
                })
                .await;

                // Carol pode listar no /firewall e desbloquear o Bob
                carol.type_line("/firewall");
                carol.wait_log("Carol listar bloqueio ativo", "Pares bloqueados (1)").await;
                carol.type_line("/firewall unblock Bob");
                carol.wait_log("Carol desbloquear Bob", "foi desbloqueado").await;
            })
            .await;
    }
}
