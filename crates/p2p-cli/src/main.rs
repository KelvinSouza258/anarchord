mod render;
mod screen_viewer;
mod spaces;
mod ui;

use clap::Parser;
use libp2p::PeerId;
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
use ui::menu::ServerEntry;
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

    /// Executar como Daemon sem ler stdin do terminal
    #[arg(long, default_value_t = false)]
    pub daemon: bool,

    /// Transmitir tom sintético de teste de áudio (440Hz / 880Hz) continuamente na sala de voz
    #[arg(long, default_value_t = false)]
    pub synth_audio: bool,

    /// Transmitir vídeo sintético/fake em loop na malha P2P (útil para bots/servidores de teste de tela)
    #[arg(long, default_value_t = false)]
    pub synth_video: bool,

    /// Desativar descoberta automática via IPFS Amino DHT e Open Trackers BitTorrent
    #[arg(long, default_value_t = false)]
    pub no_auto_bootstrap: bool,

    /// Gravar logs de telemetria e diagnóstico em arquivo (ex: anarchord.log)
    #[arg(long)]
    pub log_file: Option<PathBuf>,
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
        identity: identity.clone(),
        port: args.port,
        servers_dir: servers_dir_for(&args.identity_file),
        download_dir: download_dir(),
        channel: args.channel.clone(),
        connect: args.connect.as_deref().map(str::parse).transpose()?,
        auto_voice: args.auto_voice.clone(),
        // Daemon sem sintetizador nem sala de voz não precisa (nem costuma ter) microfone
        audio: !(args.daemon && !args.synth_audio && args.auto_voice.is_none()),
        synth_audio: args.synth_audio,
        synth_video: args.synth_video,
        discovery: !args.no_auto_bootstrap,
        // O daemon só existe para testes: baixa todo arquivo e assiste toda tela anunciada
        test_mode: args.daemon,
    };
    let (core, task) = Core::start(config)?;
    let (commands, events) = core.split();

    // Ctrl+C encerra com calma (desanuncia o nó nos trackers)
    let on_ctrl_c = commands.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = on_ctrl_c.send(CoreCommand::Shutdown);
        }
    });

    if args.daemon {
        print_banner(&identity, &args, task.peer_id(), task.listen_port());
        tokio::spawn(daemon_output(events));
    } else {
        let (tx_ui_event, rx_ui_event) = tokio::sync::mpsc::unbounded_channel::<UiEvent>();
        let (tx_ui_action, rx_ui_action) = tokio::sync::mpsc::unbounded_channel::<UiAction>();
        let muted = Arc::new(AtomicBool::new(false));
        let ui = TerminalUi::new(
            identity.profile.display_name.clone(),
            identity.public_key_hex(),
            Arc::clone(&muted),
            Some(args.identity_file.with_extension("history")),
        );
        tokio::spawn(async move {
            let _ = ui.run(rx_ui_event, tx_ui_action).await;
        });
        tokio::spawn(bridge(events, rx_ui_action, commands, tx_ui_event, muted));
    }

    // O loop do core roda nesta tarefa (o áudio do sistema não pode trocar de thread)
    task.run().await;
    Ok(())
}

fn setup_logging(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(ref log_path) = args.log_file {
        let file = std::fs::OpenOptions::new().create(true).append(true).open(log_path)?;
        let subscriber = FmtSubscriber::builder().with_max_level(Level::DEBUG).with_writer(file).finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    } else if args.daemon {
        let subscriber = FmtSubscriber::builder().with_max_level(Level::INFO).finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    } else {
        // Na TUI, logs no stdout distorceriam a tela
        let subscriber = FmtSubscriber::builder().with_writer(std::io::sink).finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }
    Ok(())
}

fn print_banner(identity: &UserIdentity, args: &Args, peer_id: PeerId, port: u16) {
    println!("============================================================");
    println!(" 🚀 Anarchord P2P Daemon / CLI (100% Descentralizado)");
    println!("============================================================");
    println!("👤 Apelido     : {}", identity.profile.display_name);
    println!("🔑 User ID     : {}", identity.public_key_hex());
    println!("🌐 Peer ID P2P : {}", peer_id);
    println!("🚪 Porta Local : {} (TCP + QUIC)", port);
    println!("💬 Sala Ativa  : #{}", args.channel);
    println!("============================================================");
    println!("🤖 Modo daemon: só exibe eventos (sem entrada de comandos). Ctrl+C encerra.");
    println!("============================================================\n");
}

/// Daemon: imprime os eventos no terminal
async fn daemon_output(mut events: UnboundedReceiver<CoreEvent>) {
    while let Some(event) = events.recv().await {
        match &event {
            CoreEvent::PeerIdentified { peer_id, nick, pubkey } => {
                println!("✨ Identidade confirmada: {} é '{}' (User ID: {})", peer_id, nick, pubkey)
            }
            CoreEvent::ChatMessage { channel, author, text, .. } => println!("\n📩 [#{}] {}: {}", channel, author, text),
            CoreEvent::File(FileEvent::Completed { name, path, .. }) => {
                println!("📁 [DAEMON ARQUIVO] '{}' recebido e conferido: {}", name, path.display())
            }
            _ => {}
        }
        for line in render::describe(&event) {
            println!("{}", line);
        }
    }
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
                            Some(CoreCommand::WatchScreen { query, sink })
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
        assert!(!args.daemon);
        assert!(!args.synth_audio);
        assert!(!args.no_auto_bootstrap);
        assert_eq!(args.auto_voice, None);

        // Testa flags customizadas
        let custom_args = Args::parse_from([
            "p2p-cli",
            "--nick", "Satoshi",
            "--port", "4001",
            "--channel", "crypto",
            "--auto-voice", "geral",
            "--daemon",
            "--synth-audio",
            "--no-auto-bootstrap",
        ]);
        assert_eq!(custom_args.nick, "Satoshi");
        assert_eq!(custom_args.port, 4001);
        assert_eq!(custom_args.channel, "crypto");
        assert_eq!(custom_args.auto_voice, Some("geral".to_string()));
        assert!(custom_args.daemon);
        assert!(custom_args.synth_audio);
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
}
