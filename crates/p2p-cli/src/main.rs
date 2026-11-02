mod presence;
mod spaces;
mod ui;
mod screen_viewer;

use clap::Parser;
use futures::StreamExt;
use libp2p::gossipsub::IdentTopic;
use libp2p::PeerId;
use opus1::{Application, Channels, OpusDecoder, OpusEncoder, SampleRate};
use p2p_core::{
    api::{pubkey_hex_from_peer_id, ChatMessage},
    bootstrap::OPENTRACKER_SERVERS,
    community::{
        self,
        e2ee::{self, CommitOutcome, E2eeError, ServerGroups},
        format_duration, server_control_topic, server_dht_key, short_id, ChannelType, ModKind, ServerEvent, ServerMessage,
        ServerRegistry, Space,
    },
    files::{self as swarm_files, FileAction, FileEngine, FileEvent, FileKey, FileRequest, FileState, Manifest, ShareTarget, SwarmMessage},
    identity::UserIdentity,
    node::{parse_agent_version, P2PNode, DHT_DISCOVERY_NAMESPACE},
    protocol::AppBehaviourEvent,
    relay::RelayManager,
    screen::{max_width_for_quality, KeyframeGate, ScreenAnnounce, ScreenCaptureEngine, ScreenPacket},
    tracker::{make_info_hash, TorrentTrackerClient},
    voice::{AudioCodec, AudioDeviceManager, JitterBuffer, VoiceEngine, VoicePacket},
};
use screen_viewer::ScreenViewer;
use spaces::{invite_text, parse_invite, parse_server_command, ActiveChannel, ServerCommand, SERVER_HELP};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use tokio::sync::mpsc::UnboundedSender;
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

    if let Some(ref log_path) = args.log_file {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;
        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::DEBUG)
            .with_writer(file)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    } else if args.daemon {
        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::INFO)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    } else {
        // No modo TUI do Ratatui, desativa logs para stdout para não distorcer a tela
        let subscriber = FmtSubscriber::builder()
            .with_writer(|| std::io::sink())
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }

    if args.daemon {
        println!("============================================================");
        println!(" 🚀 Anarchord P2P Daemon / CLI (100% Descentralizado)");
        println!("============================================================");
    }

    // 1. Carrega ou gera a identidade permanente do usuário (JSON/PEM com perfil)
    let mut identity = UserIdentity::load_or_create(&args.identity_file)?;
    if args.nick != "Peer" || identity.profile.display_name == "Anonymous Peer" {
        identity.set_nick(&args.nick);
        let _ = identity.save_to(&args.identity_file);
    }
    // Nick efetivo: o salvo na identidade (atualizado acima quando --nick é informado)
    let my_nick = identity.profile.display_name.clone();
    if args.daemon {
        println!("👤 Apelido     : {}", identity.profile.display_name);
        println!("🔑 User ID     : {}", identity.public_key_hex());
    }

    // 2. Inicializa o Nó P2P (Swarm com Kademlia, QUIC, GossipSub, DCUtR)
    let mut node = P2PNode::new(identity.clone(), args.port)?;
    if args.daemon {
        println!("🌐 Peer ID P2P : {}", node.peer_id);
        if args.port > 0 {
            println!("🚪 Porta Local : {} (TCP + QUIC)", node.listen_port);
        } else {
            println!("🚪 Porta Local : {} (TCP + QUIC, escolhida automaticamente)", node.listen_port);
        }
        println!("💬 Sala Ativa  : #{}", args.channel);
        println!("============================================================");
        println!("🤖 Modo daemon: só exibe eventos (sem entrada de comandos). Ctrl+C encerra.");
        println!("============================================================\n");
    }

    // Servidores acompanhados (cadeias de configuração e chaves de dono), ao lado do arquivo de identidade
    let mut servers = ServerRegistry::load(servers_dir_for(&args.identity_file), now_secs())?;
    // Grupos MLS (criptografia de ponta a ponta) dos servidores, salvos junto dos servidores
    let mut mls = ServerGroups::new(&identity, Some(servers_dir_for(&args.identity_file).join("mls-state.json")));
    // Último pedido de entrada no grupo cifrado por servidor (evita repetir a cada tick)
    let mut last_key_package: HashMap<String, std::time::Instant> = HashMap::new();
    for id in servers.list().map(|s| s.server_id.clone()).collect::<Vec<_>>() {
        follow_server(&mut node, &id);
    }
    // Servidor em que o usuário entra assim que a configuração chegar (/server join sem cadeia ainda)
    let mut pending_switch: Option<String> = None;
    // Último convite de servidor recebido no chat (/server accept)
    let mut last_invite: Option<String> = None;
    // Quando cada servidor teve a cadeia reenviada pela última vez (evita rajadas de respostas)
    let mut last_snapshot_reply: HashMap<String, std::time::Instant> = HashMap::new();

    // Canal ativo inicial: sempre no Lobby
    let mut active = ActiveChannel::new(Space::Lobby, args.channel.clone());
    node.swarm.behaviour_mut().gossipsub.subscribe(&active.topic)?;

    // Conexão direta explícita se fornecida
    if let Some(remote_addr) = args.connect {
        let multiaddr: libp2p::Multiaddr = remote_addr.parse()?;
        if args.daemon {
            println!("⏳ Conectando ao par remoto: {}", multiaddr);
        }
        node.swarm.dial(multiaddr)?;
    }

    // Descoberta Automática Híbrida: 1) IPFS Amino DHT + 2) BitTorrent Open Trackers
    let (tx_peer_discovery, mut rx_peer_discovery) = tokio::sync::mpsc::unbounded_channel::<String>();

    // TCP e QUIC escutam na mesma porta, então a porta anunciada nos trackers vale para os dois
    let listen_port = node.listen_port;
    let is_daemon = args.daemon;

    if !args.no_auto_bootstrap {
        // 1. Entra na DHT Amino do IPFS; a busca por outros nós Anarchord roda no loop principal
        let bootstrap_count = node.bootstrap_dht();
        if args.daemon {
            println!("🌍 DHT Amino: {} nós de bootstrap registrados", bootstrap_count);
        }

        // 2. Fallback: Consulta os Open Trackers BitTorrent em background
        let p2p_id_bytes = node.peer_id.to_bytes();
        let mut bt_peer_id = [0u8; 20];
        let copy_len = p2p_id_bytes.len().min(20);
        bt_peer_id[0..copy_len].copy_from_slice(&p2p_id_bytes[0..copy_len]);

        tokio::spawn(async move {
            let info_hash = make_info_hash(DHT_DISCOVERY_NAMESPACE);

            // Loop contínuo de reanúncio e redescoberta periódica (a cada 10 segundos)
            loop {
                for tracker in OPENTRACKER_SERVERS {
                    match TorrentTrackerClient::discover_peers(tracker, &info_hash, &bt_peer_id, listen_port) {
                        Ok(peers) => {
                            for peer in peers {
                                if is_daemon {
                                    println!("📡 Par descoberto via BitTorrent Tracker: {}", peer);
                                }
                                let tcp_addr = format!("/ip4/{}/tcp/{}", peer.ip(), peer.port());
                                let quic_addr = format!("/ip4/{}/udp/{}/quic-v1", peer.ip(), peer.port());
                                let _ = tx_peer_discovery.send(tcp_addr);
                                let _ = tx_peer_discovery.send(quic_addr);
                            }
                            break;
                        }
                        Err(_) => {}
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }
        });
    }

    // Inicialização do Subsistema de Áudio P2P (somente se não estiver em modo daemon headless sem sintetizador)
    let voice_engine_res = if args.daemon && !args.synth_audio && args.auto_voice.is_none() {
        Err(p2p_core::voice::AudioEngineError::DeviceNotFound("Modo daemon headless sem captura de microfone".to_string()))
    } else {
        VoiceEngine::start()
    };
    let (voice_engine, mut voice_mic_rx) = match voice_engine_res {
        Ok((engine, rx)) => {
            if args.daemon {
                println!("🎤 Subsistema de Áudio ativado com sucesso.");
            }
            (Some(engine), Some(rx))
        }
        Err(e) => {
            if args.daemon {
                println!("⚠️ Áudio nativo indisponível neste terminal: {}", e);
            }
            (None, None)
        }
    };

    let mut current_voice_channel: Option<String> = None;
    let mut current_voice_topic: Option<IdentTopic> = None;

    if let Some(v_chan) = &args.auto_voice {
        let v_topic = IdentTopic::new(community::voice_topic(&Space::Lobby, v_chan));
        if let Err(e) = node.swarm.behaviour_mut().gossipsub.subscribe(&v_topic) {
            if args.daemon {
                println!("❌ Falha ao entrar no canal de voz automático: {:?}", e);
            }
        } else {
            current_voice_channel = Some(v_chan.clone());
            current_voice_topic = Some(v_topic);
            if args.daemon {
                println!("🔊 Conectado automaticamente à sala de voz [🔊 {}]!", v_chan);
            }
        }
    }
    let voice_seq = Arc::new(AtomicU64::new(1));
    let (tx_voice_to_broadcast, mut rx_voice_to_broadcast) = tokio::sync::mpsc::unbounded_channel::<VoicePacket>();

    // Jitter Buffers e Decoders Opus para pares remotos (um por PeerId/chave pública)
    let mut remote_jitter_buffers: HashMap<String, JitterBuffer> = HashMap::new();
    let mut remote_opus_decoders: HashMap<String, OpusDecoder> = HashMap::new();

    // Se a flag --synth-audio estiver ativada, transmite melodia chiptune retrô de 8-bits comprimida em Opus
    if args.synth_audio {
        let voice_seq_synth = Arc::clone(&voice_seq);
        let my_pubkey_synth = identity.public_key_hex();
        let my_nick_synth = identity.profile.display_name.clone();
        let tx_synth = tx_voice_to_broadcast.clone();

        println!("📻 Modo Sintetizador 8-Bits ativado: tocando melodia chiptune comprimida em Opus...");
        std::thread::spawn(move || {
            let mut encoder = OpusEncoder::new(SampleRate::Hz48000, Channels::Mono, Application::Voip)
                .expect("Falha ao inicializar encoder Opus");
            let sample_rate = p2p_core::SAMPLE_RATE as f32; // 48000 Hz
            let frame_size = p2p_core::FRAME_SIZE; // 960 amostras (20ms)

            // Frequências das notas musicais em Hz
            const REST: f32 = 0.0;
            const C4: f32 = 261.63;
            const _D4: f32 = 293.66;
            const E4: f32 = 329.63;
            const F4: f32 = 349.23;
            const G4: f32 = 392.00;
            const A4: f32 = 440.00;
            const B4: f32 = 493.88;
            const C5: f32 = 523.25;
            const D5: f32 = 587.33;
            const E5: f32 = 659.25;
            const G5: f32 = 783.99;

            // Melodia estilo Chiptune / Super Mario: (lead, bass, duração_em_frames_de_20ms)
            let score: [(f32, f32, u32); 43] = [
                // Intro Mario
                (E5, C4, 6), (REST, REST, 2), (E5, C4, 6), (REST, REST, 4), (E5, C4, 6), (REST, REST, 4),
                (C5, G4, 6), (REST, REST, 2), (E5, C4, 6), (REST, REST, 4), (G5, G4, 12), (REST, REST, 6),
                (G4, G4, 12), (REST, REST, 8),

                // Frase A (Korobeiniki / Aventura 8-bit)
                (E4, C4, 8), (B4, G4, 4), (C5, E4, 4), (D5, G4, 8), (C5, E4, 4), (B4, G4, 4),
                (A4, F4, 8), (A4, F4, 4), (C5, A4, 4), (E5, C4, 8), (D5, G4, 4), (C5, E4, 4),
                (B4, G4, 10), (C5, E4, 4), (D5, G4, 8), (E5, C4, 8),
                (C5, A4, 8), (A4, F4, 8), (A4, F4, 10), (REST, REST, 6),

                // Arpeggio de fechamento
                (C4, C4, 4), (E4, C4, 4), (G4, E4, 4), (C5, G4, 4), (E5, C5, 6), (REST, REST, 4),
                (D5, B4, 6), (C5, C4, 12), (REST, REST, 10),
            ];

            let mut note_idx = 0;
            let mut frames_left_in_note = score[0].2;
            let mut lead_phase: f32 = 0.0;
            let mut bass_phase: f32 = 0.0;

            loop {
                let start_time = std::time::Instant::now();
                let (lead_freq, bass_freq, _) = score[note_idx];

                let lead_step = if lead_freq > 0.0 {
                    (2.0 * std::f32::consts::PI * lead_freq) / sample_rate
                } else {
                    0.0
                };

                let bass_step = if bass_freq > 0.0 {
                    (2.0 * std::f32::consts::PI * bass_freq) / sample_rate
                } else {
                    0.0
                };

                let mut samples = Vec::with_capacity(frame_size);

                for _ in 0..frame_size {
                    // Onda quadrada com duty-cycle de 50% para Lead (Canal de pulso NES)
                    let lead_sample = if lead_freq > 0.0 {
                        if lead_phase < std::f32::consts::PI { 0.25 } else { -0.25 }
                    } else {
                        0.0
                    };

                    // Onda quadrada com duty-cycle de 25% para Bass (Canal de baixo)
                    let bass_sample = if bass_freq > 0.0 {
                        if bass_phase < (std::f32::consts::PI * 0.5) { 0.15 } else { -0.15 }
                    } else {
                        0.0
                    };

                    samples.push(lead_sample + bass_sample);

                    lead_phase = (lead_phase + lead_step) % (2.0 * std::f32::consts::PI);
                    bass_phase = (bass_phase + bass_step) % (2.0 * std::f32::consts::PI);
                }

                // Avança na partitura de notas
                frames_left_in_note -= 1;
                if frames_left_in_note == 0 {
                    note_idx = (note_idx + 1) % score.len();
                    frames_left_in_note = score[note_idx].2;
                }

                let seq = voice_seq_synth.fetch_add(1, Ordering::SeqCst);
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                let packet = VoicePacket::from_pcm_samples_opus(
                    "active_voice".to_string(),
                    my_pubkey_synth.clone(),
                    my_nick_synth.clone(),
                    seq,
                    now_ms,
                    &samples,
                    &mut encoder,
                ).unwrap_or_else(|_| VoicePacket::from_pcm_samples(
                    "active_voice".to_string(),
                    my_pubkey_synth.clone(),
                    my_nick_synth.clone(),
                    seq,
                    now_ms,
                    &samples,
                ));

                let _ = tx_synth.send(packet);

                // Espera exatamente 20ms para sincronizar o fluxo de áudio em tempo real
                let elapsed = start_time.elapsed();
                if elapsed < std::time::Duration::from_millis(20) {
                    std::thread::sleep(std::time::Duration::from_millis(20) - elapsed);
                }
            }
        });
    }
    if let (Some(engine), Some(mic_rx)) = (&voice_engine, voice_mic_rx.take()) {
        let is_muted_flag = engine.is_muted_handle();
        let voice_seq_clone = Arc::clone(&voice_seq);
        let my_pubkey = identity.public_key_hex();
        let my_nick = identity.profile.display_name.clone();

        std::thread::spawn(move || {
            let mut encoder = OpusEncoder::new(SampleRate::Hz48000, Channels::Mono, Application::Voip).ok();
            while let Ok(frame_samples) = mic_rx.recv() {
                if is_muted_flag.load(Ordering::Relaxed) {
                    continue;
                }

                let energy = p2p_core::calculate_vad_energy(&frame_samples);
                // VAD: Envia somente se houver energia perceptível (fala ativa)
                if energy >= 8 {
                    let seq = voice_seq_clone.fetch_add(1, Ordering::SeqCst);
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;

                    let packet = if let Some(enc) = encoder.as_mut() {
                        VoicePacket::from_pcm_samples_opus(
                            "active_voice".to_string(),
                            my_pubkey.clone(),
                            my_nick.clone(),
                            seq,
                            now_ms,
                            &frame_samples,
                            enc,
                        ).unwrap_or_else(|_| VoicePacket::from_pcm_samples(
                            "active_voice".to_string(),
                            my_pubkey.clone(),
                            my_nick.clone(),
                            seq,
                            now_ms,
                            &frame_samples,
                        ))
                    } else {
                        VoicePacket::from_pcm_samples(
                            "active_voice".to_string(),
                            my_pubkey.clone(),
                            my_nick.clone(),
                            seq,
                            now_ms,
                            &frame_samples,
                        )
                    };

                    let _ = tx_voice_to_broadcast.send(packet);
                }
            }
        });
    }


    // Canais de comunicação com a TUI do Ratatui
    let (tx_ui_event, rx_ui_event) = tokio::sync::mpsc::unbounded_channel::<UiEvent>();
    let (tx_ui_action, mut rx_ui_action) = tokio::sync::mpsc::unbounded_channel::<UiAction>();

    let is_muted_flag = voice_engine
        .as_ref()
        .map(|e| e.is_muted_handle())
        .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));

    if !args.daemon {
        let ui = TerminalUi::new(
            identity.profile.display_name.clone(),
            identity.public_key_hex(),
            Arc::clone(&is_muted_flag),
            Some(args.identity_file.with_extension("history")),
        );
        tokio::spawn(async move {
            let _ = ui.run(rx_ui_event, tx_ui_action).await;
        });
        publish_servers(&servers, &active, &tx_ui_event);
    }

    // Rastreamento de nós conectados para desduplicação e metadados de identificação
    let mut connected_peers: HashSet<libp2p::PeerId> = HashSet::new();
    let mut peer_metadata: HashMap<libp2p::PeerId, (String, String)> = HashMap::new(); // PeerId -> (Nick, PubKey)
    // Pares Anarchord já anunciados na interface desde que conectaram (o Identify se repete a cada
    // conexão; só a primeira identificação é notificada)
    let mut identified: HashSet<libp2p::PeerId> = HashSet::new();
    // Endereços discados que já têm conexão aberta (o tracker devolve os mesmos pares a cada ciclo)
    let mut dialed_open: HashSet<libp2p::Multiaddr> = HashSet::new();

    // Busca periódica de outros nós Anarchord na DHT (registros de provedor)
    let mut dht_search_interval = tokio::time::interval(std::time::Duration::from_secs(30));

    // Sincronização periódica: pede a cadeia de quem ainda não tem e faz a manutenção dos servidores próprios
    let mut server_sync_interval = tokio::time::interval(std::time::Duration::from_secs(5));

    // Reservas em relays públicos quando o AutoNAT detecta NAT (habilita DCUtR / hole punching)
    let mut relay_manager = RelayManager::new();

    // Arquivos em enxame: ofertas na sala, pedaços pedidos direto a quem tem (protocolo /anarchord/files/1)
    let download_dir = std::env::var("HOME").ok().map(PathBuf::from).map(|h| h.join("downloads")).unwrap_or_else(|| PathBuf::from("downloads"));
    // Parciais separados por identidade: vários nós na mesma máquina não se misturam
    let partial_dir = download_dir.join(".parcial").join(&identity.public_key_hex()[..8]);
    let mut file_engine = FileEngine::new(partial_dir, download_dir);
    let mut file_requests: HashMap<libp2p::request_response::OutboundRequestId, (PeerId, FileRequest)> = HashMap::new();
    // Manifestos montados fora do loop (ler e calcular o hash de um arquivo grande leva tempo)
    let (tx_manifest, mut rx_manifest) = tokio::sync::mpsc::unbounded_channel::<ManifestJob>();
    let mut files_tick = tokio::time::interval(std::time::Duration::from_secs(1));
    let resumed = file_engine.resume(std::time::Instant::now());
    apply_file_actions(resumed, &mut file_engine, &mut node, &mut mls, &mut file_requests, &tx_ui_event, args.daemon);

    // Rastreamento de pares ativos falando/transmitindo áudio (pubkey -> (nome, Instant da última recepção))
    let mut active_speakers: HashMap<String, (String, std::time::Instant)> = HashMap::new();
    let mut speaker_check_interval = tokio::time::interval(std::time::Duration::from_millis(200));

    // Rastreamento de participantes conhecidos no canal de voz ativo
    let mut current_voice_peers: HashSet<String> = HashSet::new();

    // Subsistema de Compartilhamento de Tela P2P (Screen Share H.264)
    let screen_topic = IdentTopic::new(community::screen_topic(&Space::Lobby));
    let _ = node.swarm.behaviour_mut().gossipsub.subscribe(&screen_topic);
    // Minha transmissão: quadros vão no tópico da stream (só quem assiste se inscreve) e um anúncio
    // leve vai a cada 2 s no tópico de telas do espaço
    let mut screen_publish_topic = screen_topic.clone();
    let mut my_stream: Option<(IdentTopic, ScreenAnnounce)> = None;
    let mut screen_announce_interval = tokio::time::interval(std::time::Duration::from_secs(2));
    // Streams anunciadas: stream_id -> tópico dos quadros; e o tópico que estou assistindo
    let mut stream_topics: HashMap<String, IdentTopic> = HashMap::new();
    let mut watching_topic: Option<IdentTopic> = None;
    let screen_capture_engine = Arc::new(ScreenCaptureEngine::new());
    let (tx_screen_out, mut rx_screen_out) = tokio::sync::mpsc::unbounded_channel::<ScreenPacket>();
    let mut tx_viewer_frame_opt: Option<std::sync::mpsc::SyncSender<(p2p_core::screen::VideoCodec, Vec<u8>)>> = None;
    let screen_viewer_active = Arc::new(AtomicBool::new(false));
    let mut current_watching_stream: Option<String> = None;
    let mut viewer_gate = KeyframeGate::new();
    let mut active_screen_streams: HashMap<String, (String, String, u32, u32, std::time::Instant)> = HashMap::new(); // stream_id -> (nick, pubkey, w, h, last_seen)

    // Se o argumento --synth-video foi informado (útil para bots como Oracle-Bot), inicia transmissão automática
    if args.synth_video {
        let stream_id = format!("screen:{}", &identity.public_key_hex()[..8]);
        screen_publish_topic = IdentTopic::new(community::screen_stream_topic(&Space::Lobby, &stream_id));
        my_stream = Some((
            screen_topic.clone(),
            ScreenAnnounce { stream_id: stream_id.clone(), sender_pubkey: identity.public_key_hex(), sender_name: my_nick.clone(), width: 0, height: 0 },
        ));
        let tx_frame = tx_screen_out.clone();
        screen_capture_engine.start_synthetic_video_stream(
            stream_id.clone(),
            identity.public_key_hex(),
            my_nick.clone(),
            30, // 30 FPS fluido com H.264
            move |pkt| {
                let _ = tx_frame.send(pkt);
            },
        );
        if args.daemon {
            println!("📺 [VÍDEO H.264] Transmissão animada P2P iniciada automaticamente a 30 FPS (Stream ID: {})", stream_id);
        }
    }

    // Loop de eventos da malha P2P + Teclado + Auto-Discovery
    loop {
        tokio::select! {
            // Procura na DHT os nós Anarchord que anunciaram a chave de descoberta
            _ = dht_search_interval.tick(), if !args.no_auto_bootstrap => {
                node.dht_find_peers();
                // Membros online dos servidores acompanhados
                for id in servers.list().map(|s| s.server_id.clone()).collect::<Vec<_>>() {
                    node.dht_find(server_dht_key(&id));
                }
            }
            _ = server_sync_interval.tick() => {
                // Cadeia ainda não chegou: pede de novo a quem estiver no tópico
                for id in servers.list().filter(|s| !s.has_chain()).map(|s| s.server_id.clone()).collect::<Vec<_>>() {
                    if let Some(request) = servers.chain_request(&id) {
                        publish_server_message(&mut node, &id, &request);
                    }
                }
                // Grupo cifrado: pedir entrada / dono cria, admite e remove
                server_sync_tick(&mut node, &servers, &mut mls, &mut last_key_package);
                // Dono online: consolida ações de moderadores e renova certificados na janela
                let now = now_secs();
                for id in servers.list().filter(|s| s.is_owner()).map(|s| s.server_id.clone()).collect::<Vec<_>>() {
                    if let Some(block) = servers.owner_maintenance(&id, now) {
                        publish_server_message(&mut node, &id, &block);
                        if active.server_id() == Some(id.as_str()) {
                            refresh_space(&node, &servers, &active, &peer_metadata, &tx_ui_event);
                        }
                    }
                }
            }
            // Monitora quando pares pararam de falar/transmitir (inatividade > 600ms)
            // Anuncia a minha transmissão; expira streams sem anúncio; larga a stream se a janela fechou
            _ = screen_announce_interval.tick() => {
                if let Some((topic, announce)) = &my_stream {
                    if let Ok(bytes) = announce.to_bytes() {
                        let _ = publish_content(&mut node, &mut mls, topic, bytes);
                    }
                }
                active_screen_streams.retain(|sid, (_, _, _, _, last_seen)| {
                    let alive = last_seen.elapsed() < std::time::Duration::from_secs(6);
                    if !alive {
                        stream_topics.remove(sid);
                    }
                    alive
                });
                if !screen_viewer_active.load(Ordering::Relaxed) && !args.daemon {
                    if let Some(topic) = watching_topic.take() {
                        let _ = node.swarm.behaviour_mut().gossipsub.unsubscribe(&topic);
                        current_watching_stream = None;
                    }
                }
            }
            _ = speaker_check_interval.tick() => {
                let now = std::time::Instant::now();
                active_speakers.retain(|_pubkey, (name, last_seen)| {
                    if now.duration_since(*last_seen).as_millis() > 600 {
                        let _ = tx_ui_event.send(UiEvent::VoiceActivity { nick: name.clone(), speaking: false });
                        if args.daemon {
                            println!("🔇 [VOZ] {} parou de falar.", name);
                        }
                        false
                    } else {
                        true
                    }
                });
            }
            // Publicação de quadros de vídeo da tela capturada para a malha P2P
            // Manifesto pronto: passa a semear e publica a oferta
            Some(job) = rx_manifest.recv() => {
                match job.manifest {
                    Ok(manifest) => {
                        let (_, actions) = file_engine.share(manifest, job.path, job.key, job.target, &my_nick);
                        apply_file_actions(actions, &mut file_engine, &mut node, &mut mls, &mut file_requests, &tx_ui_event, args.daemon);
                    }
                    Err(e) => ui_log(&tx_ui_event, format!("❌ Erro ao ler '{}': {}", job.path.display(), e)),
                }
            }
            _ = files_tick.tick() => {
                let actions = file_engine.tick(std::time::Instant::now());
                apply_file_actions(actions, &mut file_engine, &mut node, &mut mls, &mut file_requests, &tx_ui_event, args.daemon);
            }
            Some(screen_pkt) = rx_screen_out.recv() => {
                if let Some((_, announce)) = my_stream.as_mut() {
                    announce.width = screen_pkt.width;
                    announce.height = screen_pkt.height;
                }
                if let Ok(pkt_bytes) = screen_pkt.to_bytes() {
                    match publish_content(&mut node, &mut mls, &screen_publish_topic, pkt_bytes) {
                        Ok(()) => {
                            if screen_pkt.frame_seq % 60 == 0 {
                                let _ = tx_ui_event.send(UiEvent::SystemLog(format!("📺 [VÍDEO ENVIADO] Quadro #{} transmitido na malha ({:.1} KB)", screen_pkt.frame_seq, screen_pkt.video_data.len() as f32 / 1024.0)));
                            }
                        }
                        Err(e) => {
                            let _ = tx_ui_event.send(UiEvent::SystemLog(format!("⚠️ Erro ao publicar quadro de vídeo: {:?}", e)));
                        }
                    }
                }
            }

            // Auto-conexão com nós descobertos via Tracker / DHT
            Some(discovered_addr) = rx_peer_discovery.recv() => {
                if let Ok(multiaddr) = discovered_addr.parse::<libp2p::Multiaddr>() {
                    // O tracker repete os mesmos pares a cada 10 s: não redisca quem já está conectado
                    if !dialed_open.contains(&multiaddr) {
                        let _ = node.swarm.dial(multiaddr);
                    }
                }
            }

            // Transmissão de áudio do microfone para a sala de voz ativa
            Some(mut voice_pkt) = rx_voice_to_broadcast.recv() => {
                if let Some(v_topic) = &current_voice_topic {
                    if let Some(ch) = &current_voice_channel {
                        voice_pkt.channel_id = ch.clone();
                        if let Ok(pkt_bytes) = voice_pkt.to_bytes() {
                            if let Err(e) = publish_content(&mut node, &mut mls, v_topic, pkt_bytes) {
                                // Exibe apenas em caso de erro incomum
                                tracing::debug!("Erro ao publicar pacote de voz: {:?}", e);
                            }
                        }
                    }
                }
            }

            // Captura de encerramento via CTRL+C (Graceful Shutdown)
            _ = tokio::signal::ctrl_c() => {
                println!("\n🛑 Interrupção detectada (CTRL+C). Notificando saída aos Trackers...");
                break;
            }

            // Ações disparadas pela UI do Ratatui
            Some(action) = rx_ui_action.recv(), if !args.daemon => {
                match action {
                    UiAction::Quit => {
                        println!("Encerrando nó P2P...");
                        break;
                    }
                    UiAction::ToggleMute => {
                        if let Some(engine) = &voice_engine {
                            let muted = engine.toggle_mute();
                            let _ = tx_ui_event.send(UiEvent::SystemLog(if muted {
                                "Microfone MUTADO.".to_string()
                            } else {
                                "Microfone ATIVADO.".to_string()
                            }));
                        }
                    }
                    UiAction::SendMessage(text) => {
                        let parsed = parse_user_input(&text);
                        match parsed {
                            ChatAction::Empty => {}
                            ChatAction::Quit => break,
                            ChatAction::ListPeers => {
                                let anarchord_peers = peer_metadata.keys().filter(|p| connected_peers.contains(p)).count();
                                let _ = tx_ui_event.send(UiEvent::SystemLog(format!("Pares Anarchord conectados: {} (conexões totais, incluindo DHT: {})", anarchord_peers, connected_peers.len())));
                            }
                            ChatAction::ListDevices => {
                                ui_log(&tx_ui_event, format!("🎤 Entradas: {}", AudioDeviceManager::list_input_devices().join(" | ")));
                                ui_log(&tx_ui_event, format!("🔊 Saídas: {}", AudioDeviceManager::list_output_devices().join(" | ")));
                            }
                            ChatAction::Server(cmd) => {
                                run_server_command(
                                    cmd,
                                    &mut node,
                                    &mut servers,
                                    &mut mls,
                                    &mut active,
                                    &mut pending_switch,
                                    &last_invite,
                                    &identity,
                                    &peer_metadata,
                                    &tx_ui_event,
                                );
                            }
                            ChatAction::ToggleMute => {
                                if let Some(engine) = &voice_engine {
                                    let muted = engine.toggle_mute();
                                    let _ = tx_ui_event.send(UiEvent::SystemLog(if muted { "Microfone MUTADO.".to_string() } else { "Microfone ATIVADO.".to_string() }));
                                }
                            }
                            ChatAction::ScreenList => {
                                let screens = ScreenCaptureEngine::list_screens();
                                let mut msg = format!("Telas locais detectadas ({}): ", screens.len());
                                for (i, s) in screens.iter().enumerate() {
                                    msg.push_str(&format!("[{}] {} ({}x{}){} | ", i, s.name, s.width, s.height, if s.is_primary { " (Primária)" } else { "" }));
                                }
                                let _ = tx_ui_event.send(UiEvent::SystemLog(msg));
                            }
                            ChatAction::ScreenStart { monitor_idx, quality } => {
                                if screen_capture_engine.is_streaming() {
                                    let _ = tx_ui_event.send(UiEvent::SystemLog("Você já está transmitindo sua tela. Use /screen stop para parar.".to_string()));
                                } else {
                                    let max_width = max_width_for_quality(quality);
                                    let stream_id = format!("screen:{}", &identity.public_key_hex()[..8]);
                                    screen_publish_topic = IdentTopic::new(community::screen_stream_topic(&active.space, &stream_id));
                                    my_stream = Some((
                                        IdentTopic::new(community::screen_topic(&active.space)),
                                        ScreenAnnounce { stream_id: stream_id.clone(), sender_pubkey: identity.public_key_hex(), sender_name: my_nick.clone(), width: 0, height: 0 },
                                    ));
                                    let tx_frame = tx_screen_out.clone();
                                    screen_capture_engine.start_capture(
                                        stream_id.clone(),
                                        identity.public_key_hex(),
                                        my_nick.clone(),
                                        monitor_idx,
                                        30, // 30 FPS com H.264
                                        max_width,
                                        move |pkt| {
                                            let _ = tx_frame.send(pkt);
                                        },
                                    );
                                    let _ = tx_ui_event.send(UiEvent::SystemLog(format!("📺 Transmissão H.264 (30 FPS, {}p) INICIADA (Stream ID: {}). Use /screen stop para encerrar.", quality, stream_id)));
                                }
                            }
                            ChatAction::ScreenStop => {
                                if screen_capture_engine.is_streaming() {
                                    screen_capture_engine.stop_capture();
                                    my_stream = None;
                                    let _ = tx_ui_event.send(UiEvent::SystemLog("📺 Transmissão de tela ENCERRADA.".to_string()));
                                } else {
                                    let _ = tx_ui_event.send(UiEvent::SystemLog("Nenhuma transmissão de tela em andamento.".to_string()));
                                }
                            }
                            ChatAction::ScreenWatch(target_query) => {
                                let target_stream = active_screen_streams.iter().find_map(|(sid, (nick, pubkey, _, _, _))| {
                                    if nick.eq_ignore_ascii_case(&target_query) || sid.starts_with(&target_query) || pubkey.starts_with(&target_query) {
                                        Some((sid.clone(), nick.clone()))
                                    } else {
                                        None
                                    }
                                });

                                if let Some((sid, presenter_nick)) = target_stream {
                                    // Só agora passa a receber os quadros dessa stream
                                    if let Some(previous) = watching_topic.take() {
                                        let _ = node.swarm.behaviour_mut().gossipsub.unsubscribe(&previous);
                                    }
                                    if let Some(topic) = stream_topics.get(&sid) {
                                        let _ = node.swarm.behaviour_mut().gossipsub.subscribe(topic);
                                        watching_topic = Some(topic.clone());
                                    }
                                    // Cria ou recria o canal com capacidade para que quadros antigos sejam descartados se a janela travar
                                    let (tx_vf, rx_vf) = std::sync::mpsc::sync_channel::<(p2p_core::screen::VideoCodec, Vec<u8>)>(VIEWER_QUEUE_FRAMES);
                                    let rx_vf_arc = Arc::new(std::sync::Mutex::new(rx_vf));
                                    tx_viewer_frame_opt = Some(tx_vf);

                                    current_watching_stream = Some(sid.clone());
                                    viewer_gate = KeyframeGate::new();
                                    screen_viewer_active.store(true, Ordering::SeqCst);
                                    ScreenViewer::spawn_window(
                                        presenter_nick.clone(),
                                        1280,
                                        720,
                                        rx_vf_arc,
                                        Arc::clone(&screen_viewer_active),
                                    );
                                    let _ = tx_ui_event.send(UiEvent::SystemLog(format!("📺 Assistindo transmissão de '{}'. Pressione ESC na janela para fechar.", presenter_nick)));
                                } else {
                                    let _ = tx_ui_event.send(UiEvent::SystemLog(format!("⚠️ Nenhuma tela ativa encontrada para '{}'. Verifique os pares ou aguarde.", target_query)));
                                }
                            }
                            ChatAction::JoinVoice(channel_id) => {
                                if let Some(server) = active.server_id().and_then(|id| servers.get(id)) {
                                    if !server.has_channel(&channel_id, ChannelType::Voice) {
                                        ui_log(&tx_ui_event, format!("❌ Não há sala de voz '{}' neste servidor. Veja o painel de canais.", channel_id));
                                        continue;
                                    }
                                }
                                if let Some(prev) = &current_voice_topic {
                                    let _ = node.swarm.behaviour_mut().gossipsub.unsubscribe(prev);
                                }
                                current_voice_peers.clear();
                                current_voice_peers.insert(my_nick.clone());
                                let v_topic = IdentTopic::new(community::voice_topic(&active.space, &channel_id));
                                if let Err(e) = node.swarm.behaviour_mut().gossipsub.subscribe(&v_topic) {
                                    let _ = tx_ui_event.send(UiEvent::SystemLog(format!("❌ Falha ao entrar no canal de voz: {:?}", e)));
                                } else {
                                    current_voice_channel = Some(channel_id.clone());
                                    current_voice_topic = Some(v_topic);
                                    let _ = tx_ui_event.send(UiEvent::VoiceChannelChanged(Some(channel_id.clone())));
                                    let _ = tx_ui_event.send(UiEvent::VoiceRoomMembers(current_voice_peers.iter().cloned().collect()));
                                    let _ = tx_ui_event.send(UiEvent::SystemLog(format!("🔊 Conectado à sala de voz [🔊 {}]", channel_id)));
                                }
                            }
                            ChatAction::LeaveVoice => {
                                if let Some(prev) = current_voice_topic.take() {
                                    let _ = node.swarm.behaviour_mut().gossipsub.unsubscribe(&prev);
                                    let prev_name = current_voice_channel.take().unwrap_or_default();
                                    current_voice_peers.clear();
                                    let _ = tx_ui_event.send(UiEvent::VoiceChannelChanged(None));
                                    let _ = tx_ui_event.send(UiEvent::VoiceRoomMembers(Vec::new()));
                                    let _ = tx_ui_event.send(UiEvent::SystemLog(format!("🔇 Saiu da sala de voz [{}].", prev_name)));
                                } else {
                                    let _ = tx_ui_event.send(UiEvent::SystemLog("⚠️ Você não está conectado a nenhuma sala de voz.".to_string()));
                                }
                            }
                            ChatAction::JoinTextChannel(new_channel) => {
                                // No Lobby qualquer nome vira canal; num servidor, só os canais do manifesto
                                if let Some(server) = active.server_id().and_then(|id| servers.get(id)) {
                                    if !server.has_channel(&new_channel, ChannelType::Text) {
                                        ui_log(&tx_ui_event, format!("❌ #{} não existe neste servidor. Veja o painel de canais.", new_channel));
                                        continue;
                                    }
                                }
                                let space = active.space.clone();
                                enter_channel(&mut node, &servers, &mut active, space, new_channel, &peer_metadata, &tx_ui_event);
                            }
                            ChatAction::ShareFile(file_path) => {
                                // Em servidor, os pedaços vão cifrados com uma chave que só viaja na oferta (MLS)
                                let key = match active.server_id() {
                                    Some(id) if !mls.has_group(id) => {
                                        ui_log(&tx_ui_event, "🔐 Ainda sem a chave do grupo cifrado deste servidor: espere o dono te admitir.".to_string());
                                        continue;
                                    }
                                    Some(_) => Some(FileKey::generate()),
                                    None => None,
                                };
                                let target = ShareTarget::Topic(active.topic.hash().into_string());
                                build_manifest(&tx_manifest, &tx_ui_event, &identity, &my_nick, &file_path, key, target);
                            }
                            ChatAction::SendFile { recipient_query, file_path } => {
                                let target = peer_metadata.iter().find_map(|(pid, (nick, pubkey))| {
                                    (nick.eq_ignore_ascii_case(&recipient_query) || pid.to_string().starts_with(&recipient_query) || pubkey.starts_with(&recipient_query))
                                        .then_some(*pid)
                                });
                                match target {
                                    Some(peer) => build_manifest(&tx_manifest, &tx_ui_event, &identity, &my_nick, &file_path, None, ShareTarget::Peer(peer)),
                                    None => ui_log(&tx_ui_event, format!("❌ Destinatário '{}' não encontrado.", recipient_query)),
                                }
                            }
                            ChatAction::GetFile(query) => match file_engine.get(&query, std::time::Instant::now()) {
                                Ok(actions) => apply_file_actions(actions, &mut file_engine, &mut node, &mut mls, &mut file_requests, &tx_ui_event, args.daemon),
                                Err(e) => ui_log(&tx_ui_event, format!("❌ {}", e)),
                            },
                            ChatAction::RejectFile(query) => match file_engine.dismiss(&query) {
                                Ok(name) => ui_log(&tx_ui_event, format!("Oferta de '{}' recusada.", name)),
                                Err(e) => ui_log(&tx_ui_event, format!("❌ {}", e)),
                            },
                            ChatAction::Unshare(query) => match file_engine.unshare(&query) {
                                Ok(name) => ui_log(&tx_ui_event, format!("📁 '{}' não está mais sendo compartilhado nem baixado.", name)),
                                Err(e) => ui_log(&tx_ui_event, format!("❌ {}", e)),
                            },
                            ChatAction::ListFiles => {
                                let list = file_engine.list(std::time::Instant::now());
                                if list.is_empty() {
                                    ui_log(&tx_ui_event, "📁 Nenhum arquivo. Compartilhe com /share <arquivo>.".to_string());
                                }
                                for file in list {
                                    let state = match file.state {
                                        FileState::Offered => format!("oferecido por {} · /get {}", file.from, file.cid.short()),
                                        FileState::Downloading { progress, peers } => format!("baixando {:.0}% de {} par(es)", progress * 100.0, peers),
                                        FileState::Seeding => "compartilhando".to_string(),
                                    };
                                    ui_log(&tx_ui_event, format!("📁 [{}] {} ({}) — {}", file.cid.short(), file.name, human_size(file.size), state));
                                }
                            }
                            ChatAction::SendTextMessage(trimmed) => {
                                if let Some(server) = active.server_id().and_then(|id| servers.get(id)) {
                                    let me = identity.public_key_hex();
                                    if server.is_banned(&me, now_secs()) {
                                        ui_log(&tx_ui_event, "⛔ Você está banido deste servidor: os outros membros ignoram suas mensagens.");
                                        continue;
                                    }
                                    if !server.is_allowed(&me, now_secs()) {
                                        ui_log(&tx_ui_event, "🔒 Servidor fechado e você não está na allow-list: suas mensagens são ignoradas.");
                                        continue;
                                    }
                                }
                                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                                let msg = ChatMessage::new_signed(&identity, &active.channel, &trimmed, now);
                                if let Ok(json_bytes) = serde_json::to_vec(&msg) {
                                    if let Err(PublishError::NoGroupKey) = publish_content(&mut node, &mut mls, &active.topic, json_bytes) {
                                        ui_log(&tx_ui_event, "🔐 Aguardando a chave do grupo deste servidor (o dono precisa estar online para admitir você). Mensagem não enviada.");
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Eventos de rede P2P
            event = node.swarm.select_next_some() => {
                match event {
                    libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                        let _ = tx_ui_event.send(UiEvent::SystemLog(format!("Endereço de escuta: {}", address)));
                        if args.daemon {
                            println!("📡 Endereço de escuta ativo: {}", address);
                        }
                    }
                    libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        connected_peers.insert(peer_id);
                        if let libp2p::core::ConnectedPoint::Dialer { address, .. } = &endpoint {
                            dialed_open.insert(address.clone());
                        }
                        // Com a DHT ativa, a maioria das conexões é com nós do IPFS; os pares Anarchord
                        // aparecem na UI quando o Identify confirma a identidade
                        tracing::debug!("Conexão P2P com {} via {:?}", peer_id, endpoint.get_remote_address());
                    }
                    libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, cause, num_established, endpoint, .. } => {
                        if let libp2p::core::ConnectedPoint::Dialer { address, .. } = &endpoint {
                            dialed_open.remove(address);
                        }
                        if num_established == 0 {
                            connected_peers.remove(&peer_id);
                            identified.remove(&peer_id);
                            relay_manager.remove_peer(&peer_id);
                            if peer_metadata.contains_key(&peer_id) {
                                let _ = tx_ui_event.send(UiEvent::PeerDisconnected(peer_id.to_string()));
                                publish_channel_members(&node, &peer_metadata, &active.channel, &active.topic, &tx_ui_event);
                            }
                            if args.daemon && peer_metadata.contains_key(&peer_id) {
                                println!("👋 Conexão fechada com: {} (Motivo: {:?})", peer_id, cause);
                            } else {
                                tracing::debug!("Conexão fechada com {}: {:?}", peer_id, cause);
                            }
                        }
                    }
                    libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Identify(
                        libp2p::identify::Event::Received { peer_id, info, .. }
                    )) => {
                        // Alimenta a tabela de roteamento da DHT com os endereços de quem fala Kademlia
                        if info.protocols.contains(&libp2p::kad::PROTOCOL_NAME) {
                            for addr in &info.listen_addrs {
                                node.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                            }
                        }
                        // Pares que oferecem Circuit Relay v2 (HOP) viram candidatos a reserva
                        if info.protocols.contains(&libp2p::relay::HOP_PROTOCOL_NAME) {
                            relay_manager.add_candidate(peer_id, &info.listen_addrs);
                            request_relay_reservations(&mut node, &mut relay_manager, &tx_ui_event, args.daemon);
                        }

                        // Extrai Nickname e PubKey do agent_version ("anarchord:nick:pubkey")
                        if let Some((nick, pubkey)) = parse_agent_version(&info.agent_version) {
                            // O Identify se repete a cada conexão com o mesmo par: só notifica a
                            // primeira identificação (ou se o nick mudou)
                            let changed = peer_metadata.insert(peer_id, (nick.clone(), pubkey.clone())) != Some((nick.clone(), pubkey.clone()));
                            if !identified.insert(peer_id) && !changed {
                                continue;
                            }
                            let _ = tx_ui_event.send(UiEvent::PeerConnected {
                                peer_id: peer_id.to_string(),
                                nick: nick.clone(),
                                pubkey: pubkey.clone(),
                            });
                            if args.daemon {
                                println!("✨ Identidade confirmada: {} é '{}' (User ID: {})", peer_id, nick, pubkey);
                            }
                            publish_channel_members(&node, &peer_metadata, &active.channel, &active.topic, &tx_ui_event);
                        }
                    }
                    // Presença na sala: um par entrou ou saiu de algum tópico Gossipsub
                    libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(
                        libp2p::gossipsub::Event::Subscribed { peer_id, topic }
                    )) => {
                        if topic == active.topic.hash() {
                            publish_channel_members(&node, &peer_metadata, &active.channel, &active.topic, &tx_ui_event);
                        }
                        if my_stream.is_some() && topic == screen_publish_topic.hash() {
                            screen_capture_engine.request_keyframe();
                        }
                        // Alguém entrou no tópico de controle de um servidor que conhecemos: entrega a cadeia
                        // (servidor fechado: só para quem está na allow-list)
                        if let Some(server_id) = community::parse_server_control_topic(topic.as_str()).map(str::to_string) {
                            let recently = last_snapshot_reply.get(&server_id).is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(2));
                            let peer_pubkey = pubkey_hex_from_peer_id(&peer_id);
                            let allowed = servers
                                .get(&server_id)
                                .is_some_and(|s| peer_pubkey.as_deref().is_some_and(|pk| s.is_allowed(pk, now_secs())));
                            if !recently && allowed {
                                let snapshot = servers.snapshot(&server_id);
                                if !snapshot.is_empty() {
                                    for m in &snapshot {
                                        publish_server_message(&mut node, &server_id, m);
                                    }
                                    last_snapshot_reply.insert(server_id, std::time::Instant::now());
                                }
                            }
                        }
                    }
                    libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(
                        libp2p::gossipsub::Event::Unsubscribed { topic, .. }
                    )) => {
                        if topic == active.topic.hash() {
                            publish_channel_members(&node, &peer_metadata, &active.channel, &active.topic, &tx_ui_event);
                        }
                    }
                    libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(
                        libp2p::gossipsub::Event::Message { message, .. }
                    )) => {
                        // Conteúdo de servidor (chat, voz, tela) chega cifrado com MLS: decifra antes.
                        // O MLS autentica quem enviou; quem não está no grupo (banido, fora da
                        // allow-list) não consegue produzir nada que decifre.
                        let mut data = message.data.clone();
                        let mut mls_sender: Option<String> = None;
                        let mut undecryptable = false;
                        if let Some(server_id) = community::parse_server_content_topic(message.topic.as_str()) {
                            match mls.decrypt(server_id, &message.data) {
                                Ok(decrypted) => {
                                    data = decrypted.plaintext;
                                    mls_sender = Some(decrypted.sender);
                                }
                                Err(e) => {
                                    tracing::debug!("Conteúdo de servidor não decifrado: {}", e);
                                    undecryptable = true;
                                }
                            }
                        }
                        // Autor declarado no pacote precisa ser quem o MLS diz que enviou
                        let sender_matches = |author: &str| mls_sender.as_deref().map_or(true, |s| s == author);
                        if undecryptable {}
                        // 0. Tópico de controle de servidor: blocos da cadeia, ações de moderadores e pedidos
                        else if let Some(server_id) = community::parse_server_control_topic(message.topic.as_str()).map(str::to_string) {
                            let from_pubkey = message.source.as_ref().and_then(pubkey_hex_from_peer_id);
                            handle_server_network_message(
                                &server_id,
                                &message.data,
                                from_pubkey.as_deref(),
                                &mut node,
                                &mut servers,
                                &mut mls,
                                &mut active,
                                &mut pending_switch,
                                &identity,
                                &peer_metadata,
                                &tx_ui_event,
                            );
                        }
                        // 1. Tenta decodificar como mensagem de chat de texto
                        else if let Ok(chat_msg) = serde_json::from_slice::<ChatMessage>(&data) {
                            if chat_msg.author_pubkey != identity.public_key_hex() && sender_matches(&chat_msg.author_pubkey) {
                                let server = active.server_id().and_then(|id| servers.get(id));
                                let banned = server.is_some_and(|s| s.is_banned(&chat_msg.author_pubkey, now_secs()));
                                let outside = server.is_some_and(|s| !s.is_allowed(&chat_msg.author_pubkey, now_secs()));
                                if !chat_msg.verify(message.source.as_ref()) {
                                    // Assinatura inválida ou publicada por outro par que não o autor
                                    tracing::debug!("Mensagem de chat não autêntica descartada (autor alegado: {})", chat_msg.author_name);
                                } else if banned {
                                    tracing::debug!("Mensagem de usuário banido descartada: {}", chat_msg.author_name);
                                } else if outside {
                                    tracing::debug!("Mensagem de quem está fora da allow-list descartada: {}", chat_msg.author_name);
                                } else {
                                    let _ = tx_ui_event.send(UiEvent::ChatMessage {
                                        channel: chat_msg.channel_id.clone(),
                                        author: chat_msg.author_name.clone(),
                                        text: chat_msg.text.clone(),
                                    });
                                    if args.daemon {
                                        println!("\n📩 [#{}] {}: {}", chat_msg.channel_id, chat_msg.author_name, chat_msg.text);
                                    }
                                    if let Some(invite) = parse_invite(&chat_msg.text) {
                                        if servers.get(&invite).is_none() {
                                            ui_log(&tx_ui_event, format!("💡 Convite de {}: digite /server accept para entrar", chat_msg.author_name));
                                        }
                                        last_invite = Some(invite);
                                    }
                                }
                            }
                        }
                        // 2. Tenta decodificar como pacote de voz P2P
                        else if let Ok(voice_pkt) = VoicePacket::from_bytes(&data) {
                            if voice_pkt.sender_pubkey != identity.public_key_hex() && sender_matches(&voice_pkt.sender_pubkey) {
                                let now = std::time::Instant::now();
                                if current_voice_peers.insert(voice_pkt.sender_name.clone()) {
                                    let _ = tx_ui_event.send(UiEvent::VoiceRoomMembers(current_voice_peers.iter().cloned().collect()));
                                }
                                if let std::collections::hash_map::Entry::Vacant(e) = active_speakers.entry(voice_pkt.sender_pubkey.clone()) {
                                    let _ = tx_ui_event.send(UiEvent::VoiceActivity {
                                        nick: voice_pkt.sender_name.clone(),
                                        speaking: true,
                                    });
                                    if args.daemon {
                                        println!("🔊 [VOZ] {} começou a falar...", voice_pkt.sender_name);
                                    }
                                    e.insert((voice_pkt.sender_name.clone(), now));
                                } else if let Some(speaker) = active_speakers.get_mut(&voice_pkt.sender_pubkey) {
                                    speaker.1 = now;
                                }

                                // Insere no JitterBuffer do remetente
                                let jb = remote_jitter_buffers
                                    .entry(voice_pkt.sender_pubkey.clone())
                                    .or_insert_with(|| JitterBuffer::new(10));
                                
                                jb.push(voice_pkt);

                                // Se tiver pacote ordenado pronto para reprodução, envia ao alto-falante
                                if let Some(ready_pkt) = jb.pop_next() {
                                    if let Some(engine) = &voice_engine {
                                        let samples = match ready_pkt.codec {
                                            AudioCodec::Opus => {
                                                let dec = remote_opus_decoders
                                                    .entry(ready_pkt.sender_pubkey.clone())
                                                    .or_insert_with(|| {
                                                        OpusDecoder::new(SampleRate::Hz48000, Channels::Mono)
                                                            .expect("Falha ao criar OpusDecoder")
                                                    });
                                                ready_pkt.to_pcm_samples_opus(dec).unwrap_or_else(|_| ready_pkt.to_pcm_samples())
                                            }
                                            AudioCodec::Pcm16 => ready_pkt.to_pcm_samples(),
                                        };
                                        engine.play_remote_samples(samples);
                                    }
                                }
                            }
                        }
                        // 3. Enxame de arquivos: oferta, mapa de pedaços ou pedido de quem tem
                        else if let Ok(swarm_msg) = SwarmMessage::from_bytes(&data) {
                            let authentic = match &swarm_msg {
                                SwarmMessage::Offer(offer) => {
                                    offer.publisher != identity.public_key_hex()
                                        && sender_matches(&offer.publisher)
                                        && message.source.as_ref().and_then(pubkey_hex_from_peer_id).as_deref() == Some(offer.publisher.as_str())
                                }
                                _ => true,
                            };
                            if let (true, Some(source)) = (authentic, message.source) {
                                let actions = file_engine.on_gossip(source, message.topic.as_str(), swarm_msg, std::time::Instant::now());
                                apply_file_actions(actions, &mut file_engine, &mut node, &mut mls, &mut file_requests, &tx_ui_event, args.daemon);
                            }
                        }
                        // 4. Tenta decodificar como quadro de compartilhamento de tela P2P (ScreenPacket)
                        else if let Ok(screen_pkt) = ScreenPacket::from_bytes(&data) {
                            if screen_pkt.sender_pubkey != identity.public_key_hex() && sender_matches(&screen_pkt.sender_pubkey) {
                                let stream_id = screen_pkt.stream_id.clone();
                                let is_new = !active_screen_streams.contains_key(&stream_id);
                                active_screen_streams.insert(
                                    stream_id.clone(),
                                    (
                                        screen_pkt.sender_name.clone(),
                                        screen_pkt.sender_pubkey.clone(),
                                        screen_pkt.width,
                                        screen_pkt.height,
                                        std::time::Instant::now(),
                                    ),
                                );

                                if is_new {
                                    let notif = format!("📺 Nova tela compartilhada por '{}' (Stream ID: {}). Digite /screen watch {}", screen_pkt.sender_name, &stream_id[..stream_id.len().min(15)], screen_pkt.sender_name);
                                    let _ = tx_ui_event.send(UiEvent::SystemLog(notif.clone()));
                                    if args.daemon {
                                        println!("\n{}", notif);
                                    }
                                } else if args.daemon && screen_pkt.frame_seq % 60 == 0 {
                                    println!("📺 [DAEMON VÍDEO] Recebendo transmissão de '{}': quadro #{} ({:.1} KB, {}x{})", screen_pkt.sender_name, screen_pkt.frame_seq, screen_pkt.video_data.len() as f32 / 1024.0, screen_pkt.width, screen_pkt.height);
                                }

                                // Se estivermos assistindo este fluxo, repassa o quadro para o exibidor da janela
                                if let Some(watching_id) = &current_watching_stream {
                                    if watching_id == &stream_id && screen_viewer_active.load(Ordering::Relaxed) {
                                        if let Some(tx_vf) = &tx_viewer_frame_opt {
                                            // Fila cheia descarta o quadro sem travar a malha; o gate segura os P-frames
                                            // seguintes até o próximo keyframe para não corromper a imagem
                                            let (codec, data) = (screen_pkt.codec, screen_pkt.video_data);
                                            viewer_gate.forward(screen_pkt.is_keyframe, || tx_vf.try_send((codec, data)).is_ok());
                                        }
                                    }
                                }
                            }
                        }
                        // 5. Anúncio de transmissão de tela: lista a stream; quadros só para quem assistir
                        else if let Ok(announce) = ScreenAnnounce::from_bytes(&data) {
                            if announce.sender_pubkey != identity.public_key_hex() && sender_matches(&announce.sender_pubkey) {
                                let stream_id = announce.stream_id.clone();
                                let is_new = !active_screen_streams.contains_key(&stream_id);
                                active_screen_streams.insert(
                                    stream_id.clone(),
                                    (announce.sender_name.clone(), announce.sender_pubkey.clone(), announce.width, announce.height, std::time::Instant::now()),
                                );
                                let topic = IdentTopic::new(format!("{}/{}", message.topic.as_str(), stream_id));
                                stream_topics.insert(stream_id.clone(), topic.clone());
                                if is_new {
                                    let notif = format!("📺 Nova tela compartilhada por '{}'. Digite /screen watch {}", announce.sender_name, announce.sender_name);
                                    let _ = tx_ui_event.send(UiEvent::SystemLog(notif.clone()));
                                    if args.daemon {
                                        // O daemon só existe para testes: assiste automaticamente para validar o vídeo
                                        println!("\n{}", notif);
                                        let _ = node.swarm.behaviour_mut().gossipsub.subscribe(&topic);
                                    }
                                }
                            }
                        }
                    }
                    libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Mdns(
                        libp2p::mdns::Event::Discovered(list)
                    )) => {
                        // Um par anuncia vários endereços (interfaces × TCP/QUIC): disca uma vez por par,
                        // com todos os endereços, e só se não houver conexão nem discagem em andamento.
                        // Descoberta não é notificada: o aviso útil é "Par conectado" (Identify).
                        let mut by_peer: HashMap<libp2p::PeerId, Vec<libp2p::Multiaddr>> = HashMap::new();
                        for (peer_id, multiaddr) in list {
                            if peer_id != node.peer_id && !connected_peers.contains(&peer_id) {
                                by_peer.entry(peer_id).or_default().push(multiaddr);
                            }
                        }
                        for (peer_id, addresses) in by_peer {
                            tracing::debug!("Par local descoberto via mDNS: {} ({} endereços)", peer_id, addresses.len());
                            let opts = libp2p::swarm::dial_opts::DialOpts::peer_id(peer_id)
                                .addresses(addresses)
                                .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
                                .build();
                            let _ = node.swarm.dial(opts);
                        }
                    }
                    libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Mdns(
                        libp2p::mdns::Event::Expired(list)
                    )) => {
                        for (peer_id, multiaddr) in list {
                            tracing::debug!("mDNS expired: {} em {}", peer_id, multiaddr);
                        }
                    }
                    // Protocolo de arquivos: pedidos de outros pares e respostas aos nossos
                    libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Files(event)) => {
                        let now = std::time::Instant::now();
                        let actions = match event {
                            libp2p::request_response::Event::Message { peer, message, .. } => match message {
                                libp2p::request_response::Message::Request { request, channel, .. } => {
                                    // Arquivo de servidor: só responde a membros do grupo cifrado
                                    let requester = pubkey_hex_from_peer_id(&peer);
                                    let allow = |topic: &str| match community::parse_server_content_topic(topic) {
                                        Some(server_id) => requester.as_ref().is_some_and(|pk| mls.members(server_id).contains(pk)),
                                        None => true,
                                    };
                                    let (response, actions) = file_engine.handle_request(peer, request, &allow, now);
                                    let _ = node.swarm.behaviour_mut().files.send_response(channel, response);
                                    actions
                                }
                                libp2p::request_response::Message::Response { request_id, response } => match file_requests.remove(&request_id) {
                                    Some((peer, request)) => file_engine.on_response(peer, request, response, now),
                                    None => Vec::new(),
                                },
                            },
                            libp2p::request_response::Event::OutboundFailure { request_id, error, .. } => match file_requests.remove(&request_id) {
                                Some((peer, request)) => {
                                    tracing::debug!("Pedido de arquivo para {} falhou: {}", peer, error);
                                    file_engine.on_failure(peer, request, now)
                                }
                                None => Vec::new(),
                            },
                            _ => Vec::new(),
                        };
                        apply_file_actions(actions, &mut file_engine, &mut node, &mut mls, &mut file_requests, &tx_ui_event, args.daemon);
                    }
                    // Outros nós Anarchord encontrados na DHT: os endereços deles ficam disponíveis
                    // para o Kademlia enquanto a consulta está ativa, então discamos pelo PeerId
                    libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Kademlia(
                        libp2p::kad::Event::OutboundQueryProgressed {
                            result: libp2p::kad::QueryResult::GetProviders(Ok(
                                libp2p::kad::GetProvidersOk::FoundProviders { key, providers }
                            )),
                            ..
                        }
                    )) => {
                        // Provedores de um arquivo que estamos baixando
                        let file_cid = file_engine.downloading().find(|cid| swarm_files::dht_key(cid) == key).copied();
                        if let Some(cid) = file_cid {
                            let found: Vec<PeerId> = providers.iter().filter(|p| **p != node.peer_id).copied().collect();
                            let actions = file_engine.add_providers(&cid, found, std::time::Instant::now());
                            apply_file_actions(actions, &mut file_engine, &mut node, &mut mls, &mut file_requests, &tx_ui_event, args.daemon);
                        }
                        for provider in providers {
                            if provider != node.peer_id && !connected_peers.contains(&provider) {
                                tracing::debug!("Par Anarchord encontrado via DHT: {}", provider);
                                let opts = libp2p::swarm::dial_opts::DialOpts::peer_id(provider)
                                    .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
                                    .build();
                                let _ = node.swarm.dial(opts);
                            }
                        }
                    }
                    // Endereço externo confirmado (AutoNAT público ou reserva em relay aceita):
                    // (re)anuncia o nó na DHT para que o registro de provedor carregue esse endereço
                    libp2p::swarm::SwarmEvent::ExternalAddrConfirmed { address } => {
                        let _ = tx_ui_event.send(UiEvent::SystemLog(format!("🌐 Endereço externo confirmado: {}", address)));
                        if args.daemon {
                            println!("🌐 Endereço externo confirmado: {}", address);
                        }
                        if !args.no_auto_bootstrap {
                            node.dht_start_providing();
                            // Anuncia também os servidores acompanhados, para novos membros nos acharem pela DHT
                            for id in servers.list().filter(|s| s.has_chain()).map(|s| s.server_id.clone()).collect::<Vec<_>>() {
                                node.dht_provide(server_dht_key(&id));
                            }
                            // E os arquivos públicos que estamos semeando
                            for cid in file_engine.providing() {
                                node.dht_provide(swarm_files::dht_key(&cid));
                            }
                        }
                    }
                    libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Autonat(
                        libp2p::autonat::Event::StatusChanged { new, .. }
                    )) => {
                        match new {
                            libp2p::autonat::NatStatus::Private => {
                                let _ = tx_ui_event.send(UiEvent::SystemLog("🧱 AutoNAT: nó atrás de NAT. Buscando relays públicos...".to_string()));
                                if args.daemon {
                                    println!("🧱 AutoNAT: nó atrás de NAT. Buscando relays públicos...");
                                }
                                relay_manager.set_behind_nat(true);
                                request_relay_reservations(&mut node, &mut relay_manager, &tx_ui_event, args.daemon);
                            }
                            libp2p::autonat::NatStatus::Public(addr) => {
                                tracing::info!("AutoNAT: nó publicamente acessível em {}", addr);
                                relay_manager.set_behind_nat(false);
                            }
                            libp2p::autonat::NatStatus::Unknown => {}
                        }
                    }
                    libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::RelayClient(
                        libp2p::relay::client::Event::ReservationReqAccepted { relay_peer_id, renewal, .. }
                    )) => {
                        if !renewal {
                            let _ = tx_ui_event.send(UiEvent::SystemLog(format!("🛰️ Reserva aceita no relay {}", relay_peer_id)));
                            if args.daemon {
                                println!("🛰️ Reserva aceita no relay {}", relay_peer_id);
                            }
                        }
                    }
                    libp2p::swarm::SwarmEvent::ListenerClosed { listener_id, reason, .. } => {
                        if let Some(relay) = relay_manager.listener_closed(listener_id) {
                            tracing::info!("Reserva no relay {} encerrada: {:?}", relay, reason);
                            request_relay_reservations(&mut node, &mut relay_manager, &tx_ui_event, args.daemon);
                        }
                    }
                    libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Dcutr(
                        libp2p::dcutr::Event { remote_peer_id, result }
                    )) => {
                        match result {
                            Ok(_) => {
                                let _ = tx_ui_event.send(UiEvent::SystemLog(format!("🕳️ Hole punching OK: conexão direta com {}", remote_peer_id)));
                                if args.daemon {
                                    println!("🕳️ Hole punching OK: conexão direta com {}", remote_peer_id);
                                }
                            }
                            Err(e) => {
                                tracing::info!("Hole punching com {} falhou (segue via relay): {}", remote_peer_id, e);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Graceful Shutdown: Desanuncia o par do BitTorrent Tracker com event = stopped
    if !args.no_auto_bootstrap {
        println!("📡 Removendo nó da lista de pares dos Open Trackers (event = stopped)...");
        let p2p_id_bytes = node.peer_id.to_bytes();
        let mut bt_peer_id = [0u8; 20];
        let copy_len = p2p_id_bytes.len().min(20);
        bt_peer_id[0..copy_len].copy_from_slice(&p2p_id_bytes[0..copy_len]);
        let info_hash = make_info_hash(DHT_DISCOVERY_NAMESPACE);

        for tracker in OPENTRACKER_SERVERS {
            let _ = TorrentTrackerClient::announce_stopped(tracker, &info_hash, &bt_peer_id, listen_port);
        }
    }

    println!("👋 Anarchord encerrado com sucesso.");
    Ok(())
}

/// Envia à UI os pares Anarchord inscritos no tópico do canal de texto atual (presença na sala)
fn publish_channel_members(
    node: &P2PNode,
    peer_metadata: &HashMap<libp2p::PeerId, (String, String)>,
    channel: &str,
    topic: &IdentTopic,
    tx_ui_event: &tokio::sync::mpsc::UnboundedSender<UiEvent>,
) {
    let members = presence::channel_members(&node.swarm.behaviour().gossipsub, peer_metadata, topic);
    let _ = tx_ui_event.send(UiEvent::ChannelMembers {
        channel: channel.to_string(),
        members,
    });
}

/// Pasta dos servidores acompanhados: `<identidade>.servers/`, ao lado do arquivo de identidade.
/// Cada identidade tem a sua (ex.: alice.json -> alice.servers/), para nós na mesma pasta não
/// compartilharem chaves de dono.
fn servers_dir_for(identity_file: &Path) -> PathBuf {
    let stem = identity_file.file_stem().and_then(|s| s.to_str()).unwrap_or("identity");
    identity_file.with_file_name(format!("{}.servers", stem))
}

/// Agora, em segundos Unix (UTC)
fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default()
}

/// Data UTC legível ("2026-11-02 18:20 UTC"), sem depender de biblioteca de datas
fn fmt_utc(secs: u64) -> String {
    // Algoritmo de datas civis de Howard Hinnant (dias desde 1970-01-01 -> ano/mês/dia)
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    format!("{:04}-{:02}-{:02} {:02}:{:02} UTC", year, month, day, rem / 3600, rem % 3600 / 60)
}

fn ui_log(tx_ui_event: &UnboundedSender<UiEvent>, message: impl Into<String>) {
    let _ = tx_ui_event.send(UiEvent::SystemLog(message.into()));
}

/// Passa a ouvir o tópico de controle do servidor (cadeia e moderação) e o de tela dele
fn follow_server(node: &mut P2PNode, server_id: &str) {
    let _ = node.swarm.behaviour_mut().gossipsub.subscribe(&IdentTopic::new(server_control_topic(server_id)));
    let _ = node.swarm.behaviour_mut().gossipsub.subscribe(&IdentTopic::new(community::screen_topic(&Space::Server(server_id.to_string()))));
}

#[derive(Debug)]
enum PublishError {
    /// Conteúdo de servidor e este nó ainda não tem a chave do grupo
    NoGroupKey,
    Network,
}

/// Publica conteúdo (chat, voz, tela). Em tópicos de servidor, cifra antes com o grupo MLS.
/// Manifesto montado em segundo plano, pronto para compartilhar
struct ManifestJob {
    manifest: std::io::Result<Manifest>,
    path: PathBuf,
    key: Option<FileKey>,
    target: ShareTarget,
}

/// Lê o arquivo e monta o manifesto numa thread de bloqueio, sem travar o loop
fn build_manifest(
    tx: &UnboundedSender<ManifestJob>,
    tx_ui_event: &UnboundedSender<UiEvent>,
    identity: &UserIdentity,
    nick: &str,
    file_path: &str,
    key: Option<FileKey>,
    target: ShareTarget,
) {
    let path = std::fs::canonicalize(file_path).unwrap_or_else(|_| PathBuf::from(file_path));
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or(file_path).to_string();
    ui_log(tx_ui_event, format!("📁 Preparando '{}' para compartilhar ({})...", name, nick));
    let (tx, identity) = (tx.clone(), identity.clone());
    tokio::task::spawn_blocking(move || {
        let manifest = Manifest::from_file(&path, &identity, key.as_ref(), now_secs());
        let _ = tx.send(ManifestJob { manifest, path, key, target });
    });
}

/// Executa o que o motor do enxame pediu: pedidos, publicações, DHT e avisos na interface
fn apply_file_actions(
    actions: Vec<FileAction>,
    engine: &mut FileEngine,
    node: &mut P2PNode,
    mls: &mut ServerGroups,
    requests: &mut HashMap<libp2p::request_response::OutboundRequestId, (PeerId, FileRequest)>,
    tx_ui_event: &UnboundedSender<UiEvent>,
    daemon: bool,
) {
    let mut queue: std::collections::VecDeque<FileAction> = actions.into();
    while let Some(action) = queue.pop_front() {
        match action {
            FileAction::Request { peer, request } => {
                let id = node.swarm.behaviour_mut().files.send_request(&peer, request.clone());
                requests.insert(id, (peer, request));
            }
            FileAction::Publish { topic, message } => {
                if publish_content(node, mls, &IdentTopic::new(topic), message.to_bytes()).is_err() {
                    tracing::debug!("Mensagem do enxame não publicada (sem pares no tópico ou sem chave do grupo)");
                }
            }
            FileAction::Provide(cid) => node.dht_provide(swarm_files::dht_key(&cid)),
            FileAction::FindProviders(cid) => node.dht_find(swarm_files::dht_key(&cid)),
            FileAction::Event(event) => match event {
                FileEvent::Offered { cid, name, size, from, direct } => {
                    let how = if direct { "te enviou" } else { "compartilhou" };
                    let text = format!("📎 {} {} '{}' ({}). Baixe com /get {}", from, how, name, human_size(size), cid.short());
                    ui_log(tx_ui_event, text.clone());
                    if daemon {
                        // O daemon só existe para testes: baixa tudo o que for oferecido
                        println!("{}", text);
                        if let Ok(more) = engine.get(&cid.short(), std::time::Instant::now()) {
                            queue.extend(more);
                        }
                    }
                }
                FileEvent::Shared { cid, name } => ui_log(
                    tx_ui_event,
                    format!("📤 '{}' compartilhado (id {}). Fica disponível enquanto o app estiver aberto.", name, cid.short()),
                ),
                FileEvent::Started { name, .. } => {
                    ui_log(tx_ui_event, format!("📥 Baixando '{}'...", name));
                    let _ = tx_ui_event.send(UiEvent::FileTransferProgress { file_name: name, percentage: 0.0, is_download: true });
                }
                FileEvent::Progress { name, progress, .. } => {
                    let percentage = (progress * 100.0).min(99.9);
                    let _ = tx_ui_event.send(UiEvent::FileTransferProgress { file_name: name, percentage, is_download: true });
                }
                FileEvent::Completed { name, path, .. } => {
                    let _ = tx_ui_event.send(UiEvent::FileTransferProgress { file_name: name.clone(), percentage: 100.0, is_download: true });
                    ui_log(tx_ui_event, format!("💾 '{}' salvo em {}. Agora você também compartilha com quem pedir.", name, path.display()));
                    if daemon {
                        println!("📁 [DAEMON ARQUIVO] '{}' recebido e conferido: {}", name, path.display());
                    }
                }
                FileEvent::Failed { name, reason, .. } => {
                    let _ = tx_ui_event.send(UiEvent::FileTransferProgress { file_name: name.clone(), percentage: -1.0, is_download: true });
                    ui_log(tx_ui_event, format!("❌ '{}': {}", name, reason));
                }
            },
        }
    }
}

fn human_size(bytes: u64) -> String {
    match bytes {
        b if b >= 1 << 30 => format!("{:.1} GB", b as f64 / (1u64 << 30) as f64),
        b if b >= 1 << 20 => format!("{:.1} MB", b as f64 / (1u64 << 20) as f64),
        b if b >= 1 << 10 => format!("{:.0} KB", b as f64 / 1024.0),
        b => format!("{} B", b),
    }
}

fn publish_content(node: &mut P2PNode, mls: &mut ServerGroups, topic: &IdentTopic, bytes: Vec<u8>) -> Result<(), PublishError> {
    let topic_name = topic.hash().into_string();
    let payload = match community::parse_server_content_topic(&topic_name) {
        Some(server_id) => mls.encrypt(server_id, &bytes).map_err(|_| PublishError::NoGroupKey)?,
        None => bytes,
    };
    node.swarm.behaviour_mut().gossipsub.publish(topic.clone(), payload).map(|_| ()).map_err(|_| PublishError::Network)
}

/// Ciclo periódico do grupo cifrado de cada servidor:
/// - dono: cria o grupo se faltar e remove quem foi banido ou saiu da allow-list;
/// - membro sem a chave: publica o pacote de chave pedindo entrada (no máximo a cada 15 s).
fn server_sync_tick(
    node: &mut P2PNode,
    servers: &ServerRegistry,
    mls: &mut ServerGroups,
    last_key_package: &mut HashMap<String, std::time::Instant>,
) {
    let now = now_secs();
    let ids: Vec<(String, bool)> = servers.list().filter(|s| s.has_chain()).map(|s| (s.server_id.clone(), s.is_owner())).collect();
    for (id, owner) in ids {
        if owner {
            if !mls.has_group(&id) {
                let _ = mls.create_group(&id);
            }
            if let Ok(Some(commit)) = e2ee::enforce_membership(mls, servers, &id, now) {
                publish_server_message(node, &id, &commit);
            }
        } else if !mls.has_group(&id)
            && last_key_package.get(&id).map_or(true, |t| t.elapsed() >= std::time::Duration::from_secs(15))
        {
            if let Ok(key_package) = mls.key_package() {
                if publish_server_message(node, &id, &ServerMessage::KeyPackage { server_id: id.clone(), key_package }) {
                    last_key_package.insert(id, std::time::Instant::now());
                }
            }
        }
    }
}

/// Publica no tópico de controle do servidor. Falha (sem ninguém no tópico) é normal e ignorada.
fn publish_server_message(node: &mut P2PNode, server_id: &str, message: &ServerMessage) -> bool {
    let Ok(bytes) = message.to_bytes() else { return false };
    node.swarm.behaviour_mut().gossipsub.publish(IdentTopic::new(server_control_topic(server_id)), bytes).is_ok()
}

/// Nome e canais do espaço, no formato da TUI
fn space_view(servers: &ServerRegistry, space: &Space) -> (String, Vec<(String, bool)>) {
    match space {
        Space::Lobby => ("🌐 Lobby".to_string(), Vec::new()),
        Space::Server(id) => match servers.get(id) {
            Some(server) => (
                format!("🏰 {}", server.name()),
                server.channels().into_iter().map(|c| (c.name, c.channel_type == ChannelType::Voice)).collect(),
            ),
            None => (format!("🏰 {}", short_id(id)), Vec::new()),
        },
    }
}

/// Atualiza na TUI o nome, os canais e os membros do espaço atual
fn refresh_space(
    node: &P2PNode,
    servers: &ServerRegistry,
    active: &ActiveChannel,
    peer_metadata: &HashMap<PeerId, (String, String)>,
    tx_ui_event: &UnboundedSender<UiEvent>,
) {
    let (space_name, channels) = space_view(servers, &active.space);
    let is_server = active.server_id().is_some();
    let _ = tx_ui_event.send(UiEvent::SpaceChanged { space_name, channels, is_server });
    publish_servers(servers, active, tx_ui_event);
    publish_channel_members(node, peer_metadata, &active.channel, &active.topic, tx_ui_event);
}

/// Envia à TUI a lista de servidores (menu "Trocar de espaço")
fn publish_servers(servers: &ServerRegistry, active: &ActiveChannel, tx_ui_event: &UnboundedSender<UiEvent>) {
    let entries = servers
        .list()
        .map(|s| ServerEntry {
            name: s.name(),
            id: s.server_id.clone(),
            current: active.server_id() == Some(s.server_id.as_str()),
            owner: s.is_owner(),
            pending: !s.has_chain(),
        })
        .collect();
    let _ = tx_ui_event.send(UiEvent::ServersChanged(entries));
}

/// Entra num canal de texto de um espaço (Lobby ou servidor) e atualiza a TUI
fn enter_channel(
    node: &mut P2PNode,
    servers: &ServerRegistry,
    active: &mut ActiveChannel,
    space: Space,
    channel: String,
    peer_metadata: &HashMap<PeerId, (String, String)>,
    tx_ui_event: &UnboundedSender<UiEvent>,
) {
    if let Err(e) = active.switch(&mut node.swarm.behaviour_mut().gossipsub, space, channel.clone()) {
        ui_log(tx_ui_event, format!("❌ Erro ao entrar no canal #{}: {:?}", channel, e));
        return;
    }
    let _ = tx_ui_event.send(UiEvent::ChannelChanged(active.channel.clone()));
    refresh_space(node, servers, active, peer_metadata, tx_ui_event);
    let (space_name, _) = space_view(servers, &active.space);
    ui_log(tx_ui_event, format!("🚀 {} #{}", space_name, active.channel));
}

/// Primeiro canal de texto do servidor (ou "geral")
fn default_channel(servers: &ServerRegistry, server_id: &str) -> String {
    servers.get(server_id).and_then(|s| s.default_text_channel()).unwrap_or_else(|| "geral".to_string())
}

/// Encontra a pubkey de um par por nick, prefixo da pubkey (6+ caracteres) ou a pubkey completa
fn resolve_pubkey(query: &str, peer_metadata: &HashMap<PeerId, (String, String)>) -> Option<String> {
    if community::is_valid_server_id(query) {
        return Some(query.to_string());
    }
    peer_metadata
        .values()
        .find(|(nick, pubkey)| nick.eq_ignore_ascii_case(query) || (query.len() >= 6 && pubkey.starts_with(query)))
        .map(|(_, pubkey)| pubkey.clone())
}

/// Nick conhecido de uma pubkey, ou o início dela
fn nick_for(pubkey: &str, peer_metadata: &HashMap<PeerId, (String, String)>, identity: &UserIdentity) -> String {
    if pubkey == identity.public_key_hex() {
        return identity.profile.display_name.clone();
    }
    peer_metadata
        .values()
        .find(|(_, pk)| pk == pubkey)
        .map(|(nick, _)| nick.clone())
        .unwrap_or_else(|| short_id(pubkey).to_string())
}

/// Entra (ou volta) num servidor pelo id. Se a cadeia ainda não chegou, pede aos membros
/// e entra automaticamente quando ela chegar.
#[allow(clippy::too_many_arguments)]
fn join_server(
    server_id: &str,
    node: &mut P2PNode,
    servers: &mut ServerRegistry,
    active: &mut ActiveChannel,
    pending_switch: &mut Option<String>,
    peer_metadata: &HashMap<PeerId, (String, String)>,
    tx_ui_event: &UnboundedSender<UiEvent>,
) {
    if let Err(e) = servers.join(server_id) {
        ui_log(tx_ui_event, format!("❌ {}", e));
        return;
    }
    follow_server(node, server_id);
    if servers.get(server_id).is_some_and(|s| s.has_chain()) {
        let channel = default_channel(servers, server_id);
        enter_channel(node, servers, active, Space::Server(server_id.to_string()), channel, peer_metadata, tx_ui_event);
    } else {
        *pending_switch = Some(server_id.to_string());
        node.dht_find(server_dht_key(server_id));
        if let Some(request) = servers.chain_request(server_id) {
            publish_server_message(node, server_id, &request);
        }
        ui_log(
            tx_ui_event,
            format!(
                "⏳ Procurando membros online do servidor {}... você entra assim que a configuração chegar \
                 (servidor fechado: é preciso estar na allow-list).",
                short_id(server_id)
            ),
        );
    }
}

/// Executa um comando `/server ...` da TUI
#[allow(clippy::too_many_arguments)]
fn run_server_command(
    cmd: ServerCommand,
    node: &mut P2PNode,
    servers: &mut ServerRegistry,
    mls: &mut ServerGroups,
    active: &mut ActiveChannel,
    pending_switch: &mut Option<String>,
    last_invite: &Option<String>,
    identity: &UserIdentity,
    peer_metadata: &HashMap<PeerId, (String, String)>,
    tx_ui_event: &UnboundedSender<UiEvent>,
) {
    let now = now_secs();
    let current = active.server_id().map(str::to_string);
    let need_server = || {
        if current.is_none() {
            ui_log(tx_ui_event, "Você está no 🌐 Lobby. Entre num servidor primeiro (/server list, /server switch <nome>).");
        }
        current.clone()
    };
    // Publica uma alteração bem-sucedida, atualiza a tela e registra o resultado
    let publish_change = |node: &mut P2PNode, servers: &ServerRegistry, active: &ActiveChannel, id: &str, result: Result<ServerMessage, community::CommunityError>, ok: String| {
        match result {
            Ok(message) => {
                publish_server_message(node, id, &message);
                refresh_space(node, servers, active, peer_metadata, tx_ui_event);
                ui_log(tx_ui_event, ok);
            }
            Err(e) => ui_log(tx_ui_event, format!("❌ {}", e)),
        }
    };

    match cmd {
        ServerCommand::Help => ui_log(tx_ui_event, SERVER_HELP),
        ServerCommand::Create(name) => match servers.create(&name, &identity.public_key_hex(), now) {
            Ok(id) => {
                follow_server(node, &id);
                if let Err(e) = mls.create_group(&id) {
                    ui_log(tx_ui_event, format!("⚠️ Grupo cifrado não criado: {}", e));
                }
                ui_log(
                    tx_ui_event,
                    format!(
                        "🏰 Servidor '{}' criado (id {}). Você é o dono (nível 0). Chat, voz e tela do servidor são cifrados de ponta a ponta. \
                         Use /server invite para convidar.",
                        name,
                        short_id(&id)
                    ),
                );
                let channel = default_channel(servers, &id);
                enter_channel(node, servers, active, Space::Server(id), channel, peer_metadata, tx_ui_event);
            }
            Err(e) => ui_log(tx_ui_event, format!("❌ {}", e)),
        },
        ServerCommand::Join(id) => join_server(id.trim(), node, servers, active, pending_switch, peer_metadata, tx_ui_event),
        ServerCommand::Accept => match last_invite {
            Some(id) => join_server(id, node, servers, active, pending_switch, peer_metadata, tx_ui_event),
            None => ui_log(tx_ui_event, "Nenhum convite recebido ainda. Peça para alguém usar /server invite no Lobby."),
        },
        ServerCommand::Leave => {
            let Some(id) = need_server() else { return };
            let name = servers.get(&id).map(|s| s.name()).unwrap_or_default();
            let was_owner = servers.get(&id).is_some_and(|s| s.is_owner());
            servers.leave(&id);
            mls.drop_group(&id);
            let _ = node.swarm.behaviour_mut().gossipsub.unsubscribe(&IdentTopic::new(server_control_topic(&id)));
            let _ = node.swarm.behaviour_mut().gossipsub.unsubscribe(&IdentTopic::new(community::screen_topic(&Space::Server(id.clone()))));
            enter_channel(node, servers, active, Space::Lobby, "geral".to_string(), peer_metadata, tx_ui_event);
            let note = if was_owner { " A chave de dono continua salva em disco." } else { "" };
            ui_log(tx_ui_event, format!("👋 Você saiu do servidor '{}'.{}", name, note));
        }
        ServerCommand::List => {
            let marker = |on: bool| if on { "▶" } else { " " };
            ui_log(tx_ui_event, format!("{} 🌐 Lobby  (/server switch lobby)", marker(active.space == Space::Lobby)));
            if servers.list().next().is_none() {
                ui_log(tx_ui_event, "  Nenhum servidor. Crie com /server create <nome> ou aceite um convite.");
            }
            let me = identity.public_key_hex();
            for server in servers.list() {
                let mut tags = Vec::new();
                if server.is_owner() {
                    tags.push("dono".to_string());
                } else if let Some(level) = server.level_of(&me, now) {
                    tags.push(format!("moderador n{}", level));
                }
                if !server.has_chain() {
                    tags.push("aguardando configuração".into());
                } else {
                    if server.chain().state().closed {
                        tags.push("fechado".into());
                    }
                    if server.is_banned(&me, now) {
                        tags.push("banido".into());
                    }
                }
                let on = current.as_deref() == Some(server.server_id.as_str());
                let tags = if tags.is_empty() { String::new() } else { format!(" [{}]", tags.join(", ")) };
                ui_log(tx_ui_event, format!("{} 🏰 {} ({}){}", marker(on), server.name(), short_id(&server.server_id), tags));
            }
        }
        ServerCommand::Info => {
            let Some(id) = need_server() else { return };
            let Some(server) = servers.get(&id) else { return };
            let state = server.effective_state(now);
            let head = server.chain().head();
            ui_log(
                tx_ui_event,
                format!(
                    "🏰 {} | bloco {} ({}) | id {}",
                    server.name(),
                    head.map_or(0, |b| b.body.height),
                    head.map_or_else(String::new, |b| fmt_utc(b.body.timestamp)),
                    id
                ),
            );
            let channels: Vec<String> = server
                .channels()
                .iter()
                .map(|c| format!("{}{}", if c.channel_type == ChannelType::Voice { "🔊 " } else { "#" }, c.name))
                .collect();
            ui_log(tx_ui_event, format!("   Canais: {}", channels.join(", ")));
            let me = identity.public_key_hex();
            let my_role = match state.level_of(&me, now) {
                Some(0) => "dono (nível 0)".to_string(),
                Some(level) => format!("moderador nível {}", level),
                None if server.is_owner() => "dono (nível 0)".to_string(),
                None => "membro".to_string(),
            };
            let access = if state.closed { format!("fechado, {} na allow-list", state.allow_list.len()) } else { "aberto".to_string() };
            ui_log(tx_ui_event, format!("   Você: {} | Acesso: {}", my_role, access));
            let mods: Vec<String> = state
                .moderators(now)
                .iter()
                .map(|(pk, level, until)| format!("{} (n{}, até {})", nick_for(pk, peer_metadata, identity), level, fmt_utc(*until)))
                .collect();
            ui_log(tx_ui_event, format!("   Moderadores: {}", if mods.is_empty() { "nenhum".to_string() } else { mods.join(", ") }));
            let bans: Vec<String> = state
                .active_bans(now)
                .iter()
                .map(|(pk, ban)| {
                    let until = ban.until.map_or("permanente".to_string(), |u| format!("até {}", fmt_utc(u)));
                    format!("{} ({}, por n{})", nick_for(pk, peer_metadata, identity), until, ban.by_level)
                })
                .collect();
            ui_log(tx_ui_event, format!("   Banidos: {}", if bans.is_empty() { "nenhum".to_string() } else { bans.join(", ") }));
            ui_log(
                tx_ui_event,
                format!(
                    "   Certificados: validade {}, renovação nos últimos {} | Ações aguardando o dono: {}",
                    format_duration(Some(state.cert_validity_secs)),
                    format_duration(Some(state.renewal_window_secs)),
                    server.pending_actions().count()
                ),
            );
        }
        ServerCommand::History => {
            let Some(id) = need_server() else { return };
            let history = servers.history(&id);
            ui_log(tx_ui_event, format!("📜 Histórico de alterações ({} blocos, mais recentes por último):", history.len()));
            for entry in history.iter().skip(history.len().saturating_sub(15)) {
                ui_log(tx_ui_event, format!("   #{} {} — {}", entry.height, fmt_utc(entry.timestamp), entry.description));
            }
        }
        ServerCommand::Switch(query) => {
            if query.eq_ignore_ascii_case("lobby") {
                enter_channel(node, servers, active, Space::Lobby, "geral".to_string(), peer_metadata, tx_ui_event);
                return;
            }
            match servers.find(&query).map(|s| (s.server_id.clone(), s.has_chain())) {
                Some((id, true)) => {
                    let channel = default_channel(servers, &id);
                    enter_channel(node, servers, active, Space::Server(id), channel, peer_metadata, tx_ui_event);
                }
                Some((id, false)) => {
                    *pending_switch = Some(id.clone());
                    ui_log(tx_ui_event, format!("⏳ A configuração de {} ainda não chegou; você entra assim que chegar.", short_id(&id)));
                }
                None => ui_log(tx_ui_event, format!("❌ Servidor '{}' não encontrado. Veja /server list.", query)),
            }
        }
        ServerCommand::Invite => {
            let Some(id) = need_server() else { return };
            let name = servers.get(&id).map(|s| s.name()).unwrap_or_default();
            let invite = ChatMessage::new_signed(identity, "geral", &invite_text(&name, &id), now);
            let lobby = IdentTopic::new(community::channel_topic(&Space::Lobby, "geral"));
            let sent = serde_json::to_vec(&invite)
                .ok()
                .is_some_and(|bytes| node.swarm.behaviour_mut().gossipsub.publish(lobby, bytes).is_ok());
            if sent {
                ui_log(tx_ui_event, format!("📨 Convite para '{}' publicado no 🌐 Lobby #geral. Quem estiver lá digita /server accept.", name));
            } else {
                ui_log(tx_ui_event, format!("⚠️ Ninguém no 🌐 Lobby #geral agora. Id do servidor para convite manual: {}", id));
            }
            if servers.get(&id).is_some_and(|s| s.chain().state().closed) {
                ui_log(tx_ui_event, "🔒 Servidor fechado: admita a pessoa com /server allow <par> para ela conseguir entrar.");
            }
        }
        ServerCommand::AddChannel { name, voice } => {
            let Some(id) = need_server() else { return };
            let kind = if voice { ChannelType::Voice } else { ChannelType::Text };
            let result = servers.add_channel(&id, &name, kind, now);
            publish_change(node, servers, active, &id, result, format!("✅ Canal {}{} criado.", if voice { "🔊 " } else { "#" }, name));
        }
        ServerCommand::RemoveChannel(name) => {
            let Some(id) = need_server() else { return };
            let result = servers.remove_channel(&id, &name, now);
            publish_change(node, servers, active, &id, result, format!("🗑️ Canal {} removido.", name));
        }
        ServerCommand::AddModerator { target, level } => {
            let Some(id) = need_server() else { return };
            let Some(pubkey) = resolve_pubkey(&target, peer_metadata) else {
                ui_log(tx_ui_event, format!("❌ Par '{}' não encontrado. Use o nick de alguém conectado ou a pubkey completa.", target));
                return;
            };
            let validity = servers.get(&id).map_or(0, |s| s.chain().state().cert_validity_secs);
            let result = servers.add_moderator(&id, &pubkey, level, now);
            let who = nick_for(&pubkey, peer_metadata, identity);
            publish_change(
                node,
                servers,
                active,
                &id,
                result,
                format!("🛡️ {} agora é moderador nível {} (certificado de {}, renovado automaticamente).", who, level, format_duration(Some(validity))),
            );
        }
        ServerCommand::RemoveModerator(target) => {
            let Some(id) = need_server() else { return };
            let Some(pubkey) = resolve_pubkey(&target, peer_metadata) else {
                ui_log(tx_ui_event, format!("❌ Par '{}' não encontrado.", target));
                return;
            };
            let result = servers.remove_moderator(&id, &pubkey, now);
            let who = nick_for(&pubkey, peer_metadata, identity);
            publish_change(
                node,
                servers,
                active,
                &id,
                result,
                format!("🛡️ Certificado de {} revogado. Ações dele ainda não consolidadas serão desfeitas.", who),
            );
        }
        ServerCommand::Close | ServerCommand::Open => {
            let Some(id) = need_server() else { return };
            let closing = matches!(cmd, ServerCommand::Close);
            let result = servers.set_closed(&id, closing, now);
            let message = if closing {
                "🔒 Servidor fechado: só dono, moderadores e quem está na allow-list participam. Admita com /server allow <par>."
            } else {
                "🔓 Servidor aberto: qualquer um com o id pode entrar."
            };
            publish_change(node, servers, active, &id, result, message.to_string());
        }
        ServerCommand::Policy { validity, renewal_window } => {
            let Some(id) = need_server() else { return };
            let result = servers.set_cert_policy(&id, validity, renewal_window, now);
            publish_change(
                node,
                servers,
                active,
                &id,
                result,
                format!(
                    "⏳ Certificados: validade {}, renovação nos últimos {}.",
                    format_duration(Some(validity)),
                    format_duration(Some(renewal_window))
                ),
            );
        }
        ServerCommand::Ban { target, duration, reason } => {
            let until = duration.map(|d| now + d);
            moderation_command(ModKind::Ban { until }, &target, &reason, node, servers, active, identity, peer_metadata, tx_ui_event);
        }
        ServerCommand::Unban(target) => {
            moderation_command(ModKind::Unban, &target, "", node, servers, active, identity, peer_metadata, tx_ui_event)
        }
        ServerCommand::Allow(target) => {
            moderation_command(ModKind::Admit, &target, "", node, servers, active, identity, peer_metadata, tx_ui_event)
        }
        ServerCommand::Disallow(target) => {
            moderation_command(ModKind::Unadmit, &target, "", node, servers, active, identity, peer_metadata, tx_ui_event)
        }
    }
}

/// Ban, desban e allow-list. O dono grava direto na cadeia; um moderador publica uma ação
/// assinada com o próprio certificado, que vale na hora e é consolidada pelo dono depois.
#[allow(clippy::too_many_arguments)]
fn moderation_command(
    kind: ModKind,
    target: &str,
    reason: &str,
    node: &mut P2PNode,
    servers: &mut ServerRegistry,
    active: &ActiveChannel,
    identity: &UserIdentity,
    peer_metadata: &HashMap<PeerId, (String, String)>,
    tx_ui_event: &UnboundedSender<UiEvent>,
) {
    let Some(id) = active.server_id().map(str::to_string) else {
        ui_log(tx_ui_event, "Você está no 🌐 Lobby, que não tem moderação. Entre num servidor primeiro.");
        return;
    };
    let Some(pubkey) = resolve_pubkey(target, peer_metadata) else {
        ui_log(tx_ui_event, format!("❌ Par '{}' não encontrado. Use o nick de alguém conectado ou a pubkey completa.", target));
        return;
    };
    if pubkey == identity.public_key_hex() {
        ui_log(tx_ui_event, "❌ Você não pode moderar a si mesmo.");
        return;
    }
    let now = now_secs();
    let owner = servers.get(&id).is_some_and(|s| s.is_owner());
    let who = nick_for(&pubkey, peer_metadata, identity);
    let text = match &kind {
        ModKind::Ban { until } => {
            format!("🔨 {} foi banido ({}).", who, format_duration(until.map(|u| u.saturating_sub(now))))
        }
        ModKind::Unban => format!("🕊️ {} foi desbanido.", who),
        ModKind::Admit => format!("✅ {} entrou na allow-list.", who),
        ModKind::Unadmit => format!("🚫 {} saiu da allow-list.", who),
    };
    match servers.moderate(&id, identity, kind, &pubkey, reason, now) {
        Ok(message) => {
            publish_server_message(node, &id, &message);
            let note = if owner { " Gravado na cadeia." } else { " Vale agora; fica definitivo quando o dono consolidar." };
            ui_log(tx_ui_event, format!("{}{}", text, note));
        }
        Err(e) => ui_log(tx_ui_event, format!("❌ {}", e)),
    }
}

/// Processa uma mensagem do tópico de controle de um servidor
#[allow(clippy::too_many_arguments)]
fn handle_server_network_message(
    topic_server_id: &str,
    data: &[u8],
    from_pubkey: Option<&str>,
    node: &mut P2PNode,
    servers: &mut ServerRegistry,
    mls: &mut ServerGroups,
    active: &mut ActiveChannel,
    pending_switch: &mut Option<String>,
    identity: &UserIdentity,
    peer_metadata: &HashMap<PeerId, (String, String)>,
    tx_ui_event: &UnboundedSender<UiEvent>,
) {
    let Ok(message) = ServerMessage::from_bytes(data) else { return };
    let now = now_secs();
    let me = identity.public_key_hex();

    // Grupo cifrado (MLS): entrada, troca de chave e boas-vindas
    match &message {
        ServerMessage::KeyPackage { server_id, key_package } => {
            let Some(from) = from_pubkey else { return };
            match e2ee::admit_from_key_package(mls, servers, server_id, from, key_package, now) {
                Ok(messages) => {
                    for m in &messages {
                        publish_server_message(node, server_id, m);
                    }
                    ui_log(tx_ui_event, format!("🔐 {} recebeu a chave do grupo cifrado.", nick_for(from, peer_metadata, identity)));
                }
                Err(E2eeError::NotOwner) => {}
                Err(e) => tracing::debug!("Pedido de entrada no grupo recusado: {}", e),
            }
            return;
        }
        ServerMessage::Commit { server_id, commit } => {
            let owner = servers.get(server_id).map(|s| s.chain().state().owner.clone()).unwrap_or_default();
            let name = servers.get(server_id).map(|s| s.name()).unwrap_or_default();
            match mls.process_commit(server_id, commit, &owner) {
                Ok(CommitOutcome::Removed) => ui_log(
                    tx_ui_event,
                    format!("🔐 Você foi removido do grupo cifrado de '{}': não recebe mais o conteúdo do servidor.", name),
                ),
                // Perdemos algum Commit: descarta e pede entrada de novo no próximo ciclo. Um Commit
                // de época futura não pode ser verificado, então só confiamos nele se quem publicou
                // (autor assinado do Gossipsub) for o dono; senão qualquer um derrubaria o grupo.
                Ok(CommitOutcome::OutOfSync) if from_pubkey == Some(owner.as_str()) => mls.drop_group(server_id),
                Ok(CommitOutcome::OutOfSync) => tracing::debug!("Commit fora de sincronia de quem não é o dono ignorado"),
                Ok(_) => {}
                Err(e) => tracing::debug!("Commit MLS inválido: {}", e),
            }
            return;
        }
        ServerMessage::Welcome { server_id, target, welcome } => {
            if *target == me && !mls.has_group(server_id) {
                let name = servers.get(server_id).map(|s| s.name()).unwrap_or_default();
                let owner = servers.get(server_id).map(|s| s.chain().state().owner.clone()).unwrap_or_default();
                match mls.join(server_id, welcome, &owner) {
                    Ok(()) => ui_log(
                        tx_ui_event,
                        format!("🔐 Chave do grupo de '{}' recebida: chat, voz e tela cifrados de ponta a ponta.", name),
                    ),
                    Err(e) => tracing::debug!("Welcome MLS recusado: {}", e),
                }
            }
            return;
        }
        _ => {}
    }
    let before = servers.get(topic_server_id).map(|s| (s.has_chain() && s.is_banned(&me, now), s.level_of(&me, now)));

    for event in servers.handle_message(message, from_pubkey, now) {
        match event {
            ServerEvent::ChainUpdated { server_id, name, height } => {
                ui_log(tx_ui_event, format!("📜 '{}' sincronizado (bloco {}).", name, height));
                if pending_switch.as_deref() == Some(server_id.as_str()) {
                    *pending_switch = None;
                    let channel = default_channel(servers, &server_id);
                    enter_channel(node, servers, active, Space::Server(server_id), channel, peer_metadata, tx_ui_event);
                } else if active.server_id() == Some(server_id.as_str()) {
                    refresh_space(node, servers, active, peer_metadata, tx_ui_event);
                }
            }
            ServerEvent::Fork { server_id, height, replaced } => ui_log(
                tx_ui_event,
                format!(
                    "⚠️ Fork na cadeia de {} no bloco {} (a chave do dono foi usada em dois lugares?): {}.",
                    short_id(&server_id),
                    height,
                    if replaced { "adotado o ramo vencedor" } else { "mantido o ramo atual" }
                ),
            ),
            ServerEvent::NeedBlocks { server_id, from_height } => {
                publish_server_message(node, &server_id, &ServerMessage::ChainRequest { server_id: server_id.clone(), from_height });
            }
            ServerEvent::ActionAccepted { server_id, action } => {
                let name = servers.get(&server_id).map(|s| s.name()).unwrap_or_default();
                let by = nick_for(action.actor(), peer_metadata, identity);
                let who = nick_for(&action.body.target, peer_metadata, identity);
                let what = match action.body.kind {
                    ModKind::Ban { until } => format!("baniu {} ({})", who, format_duration(until.map(|u| u.saturating_sub(now)))),
                    ModKind::Unban => format!("desbaniu {}", who),
                    ModKind::Admit => format!("admitiu {}", who),
                    ModKind::Unadmit => format!("removeu {} da allow-list", who),
                };
                let reason = if action.body.reason.is_empty() { String::new() } else { format!(" — motivo: {}", action.body.reason) };
                ui_log(tx_ui_event, format!("🔨 [{}] {} {}{}", name, by, what, reason));
            }
            ServerEvent::ActionsUndone { server_id, count } => {
                let name = servers.get(&server_id).map(|s| s.name()).unwrap_or_default();
                ui_log(
                    tx_ui_event,
                    format!("↩️ [{}] {} ação(ões) de moderação desfeita(s): o certificado do moderador foi revogado ou expirou.", name, count),
                );
            }
            ServerEvent::Reply { server_id, messages } => {
                for m in &messages {
                    publish_server_message(node, &server_id, m);
                }
            }
            ServerEvent::Ignored(reason) => tracing::debug!("Mensagem de servidor ignorada: {}", reason),
        }
    }

    // Mudanças que afetam este usuário
    let (Some((was_banned, was_level)), Some(server)) = (before, servers.get(topic_server_id)) else { return };
    let name = server.name();
    let banned = server.has_chain() && server.is_banned(&me, now);
    if banned != was_banned {
        ui_log(
            tx_ui_event,
            if banned {
                format!("⛔ Você foi banido de '{}': suas mensagens serão ignoradas pelos membros.", name)
            } else {
                format!("🕊️ Seu ban em '{}' acabou.", name)
            },
        );
    }
    let level = server.level_of(&me, now);
    if level != was_level && !server.is_owner() {
        ui_log(
            tx_ui_event,
            match level {
                Some(level) => format!("🛡️ Você agora é moderador nível {} em '{}'.", level, name),
                None => format!("🛡️ Você não é mais moderador em '{}'.", name),
            },
        );
    }
}

/// Pede reserva nos relays candidatos que faltam (só age quando o AutoNAT indicou NAT)
fn request_relay_reservations(
    node: &mut P2PNode,
    relay_manager: &mut RelayManager,
    tx_ui_event: &tokio::sync::mpsc::UnboundedSender<UiEvent>,
    is_daemon: bool,
) {
    for (relay, circuit_addr) in relay_manager.next_reservations() {
        match node.swarm.listen_on(circuit_addr.clone()) {
            Ok(listener_id) => {
                relay_manager.track_reservation(listener_id, relay);
                let _ = tx_ui_event.send(UiEvent::SystemLog(format!("🛰️ Pedindo reserva no relay {}", relay)));
                if is_daemon {
                    println!("🛰️ Pedindo reserva no relay: {}", circuit_addr);
                }
            }
            Err(e) => tracing::warn!("Falha ao pedir reserva em {}: {:?}", circuit_addr, e),
        }
    }
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

    /// Um nó com o mesmo estado que o loop principal mantém para servidores
    struct TestPeer {
        node: P2PNode,
        identity: UserIdentity,
        servers: ServerRegistry,
        mls: ServerGroups,
        last_key_package: HashMap<String, std::time::Instant>,
        active: ActiveChannel,
        pending: Option<String>,
        last_invite: Option<String>,
        meta: HashMap<PeerId, (String, String)>,
        /// Textos de chat recebidos (já decifrados, quando de servidor)
        received: Vec<String>,
        tx: UnboundedSender<UiEvent>,
        rx: tokio::sync::mpsc::UnboundedReceiver<UiEvent>,
    }

    impl TestPeer {
        fn new(nick: &str) -> Self {
            let identity = UserIdentity::generate_with_nick(nick);
            let mut node = P2PNode::new(identity.clone(), 0).unwrap();
            let active = ActiveChannel::new(Space::Lobby, "geral".to_string());
            node.swarm.behaviour_mut().gossipsub.subscribe(&active.topic).unwrap();
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            Self {
                mls: ServerGroups::new(&identity, None),
                last_key_package: HashMap::new(),
                node,
                identity,
                servers: ServerRegistry::in_memory(),
                active,
                pending: None,
                last_invite: None,
                meta: HashMap::new(),
                received: Vec::new(),
                tx,
                rx,
            }
        }

        fn command(&mut self, input: &str) {
            let ChatAction::Server(cmd) = parse_user_input(input) else { panic!("não é comando de servidor: {}", input) };
            run_server_command(
                cmd,
                &mut self.node,
                &mut self.servers,
                &mut self.mls,
                &mut self.active,
                &mut self.pending,
                &self.last_invite,
                &self.identity,
                &self.meta,
                &self.tx,
            );
        }

        /// Logs mostrados na TUI desde a última chamada
        fn logs(&mut self) -> Vec<String> {
            let mut out = Vec::new();
            while let Ok(ev) = self.rx.try_recv() {
                if let UiEvent::SystemLog(text) = ev {
                    out.push(text);
                }
            }
            out
        }

        /// O mesmo tratamento que o loop principal dá a Identify, controle de servidor e convites
        fn process(&mut self, event: libp2p::swarm::SwarmEvent<AppBehaviourEvent>) {
            match event {
                libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Identify(libp2p::identify::Event::Received {
                    peer_id,
                    info,
                    ..
                })) => {
                    if let Some(identity) = parse_agent_version(&info.agent_version) {
                        self.meta.insert(peer_id, identity);
                    }
                }
                libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(libp2p::gossipsub::Event::Message {
                    message,
                    ..
                })) => {
                    if let Some(server_id) = community::parse_server_control_topic(message.topic.as_str()).map(str::to_string) {
                        let from_pubkey = message.source.as_ref().and_then(pubkey_hex_from_peer_id);
                        handle_server_network_message(
                            &server_id,
                            &message.data,
                            from_pubkey.as_deref(),
                            &mut self.node,
                            &mut self.servers,
                            &mut self.mls,
                            &mut self.active,
                            &mut self.pending,
                            &self.identity,
                            &self.meta,
                            &self.tx,
                        );
                    } else {
                        // Conteúdo de servidor chega cifrado: decifra como o loop principal
                        let data = match community::parse_server_content_topic(message.topic.as_str()) {
                            Some(server_id) => match self.mls.decrypt(server_id, &message.data) {
                                Ok(d) => d.plaintext,
                                Err(_) => return,
                            },
                            None => message.data.clone(),
                        };
                        if let Ok(chat) = serde_json::from_slice::<ChatMessage>(&data) {
                            if chat.verify(message.source.as_ref()) {
                                if let Some(invite) = parse_invite(&chat.text) {
                                    self.last_invite = Some(invite);
                                }
                                self.received.push(chat.text);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Processa eventos dos dois nós até `done` ser verdadeiro. Enquanto Bob espera a cadeia,
    /// repete o pedido (no app isso é o timer de 5 s).
    async fn pump(alice: &mut TestPeer, bob: &mut TestPeer, what: &str, done: impl Fn(&TestPeer, &TestPeer) -> bool) {
        let mut retry = tokio::time::interval(std::time::Duration::from_millis(300));
        let result = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            while !done(alice, bob) {
                tokio::select! {
                    ev = alice.node.swarm.select_next_some() => alice.process(ev),
                    ev = bob.node.swarm.select_next_some() => bob.process(ev),
                    _ = retry.tick() => {
                        if let Some(request) = bob.pending.clone().and_then(|id| bob.servers.chain_request(&id)) {
                            let id = bob.pending.clone().unwrap();
                            publish_server_message(&mut bob.node, &id, &request);
                        }
                        // Ciclo do grupo cifrado (no app, o timer de 5 s); KeyPackage sem espera
                        for peer in [&mut *alice, &mut *bob] {
                            peer.last_key_package.clear();
                            server_sync_tick(&mut peer.node, &peer.servers, &mut peer.mls, &mut peer.last_key_package);
                        }
                    }
                }
            }
        })
        .await;
        assert!(result.is_ok(), "tempo esgotado esperando: {}", what);
    }

    /// Fluxo completo pela rede, com as mesmas funções do loop principal:
    /// Alice cria o servidor e convida; Bob aceita, recebe a cadeia e entra; Alice certifica Bob
    /// como moderador, Bob tenta banir a dona (recusado pelo nível), Alice revoga e bane Bob por 1h.
    #[tokio::test]
    async fn test_server_invite_join_and_ban_flow() {
        let mut alice = TestPeer::new("Alice");
        let mut bob = TestPeer::new("Bob");
        let bob_addr: libp2p::Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", bob.node.listen_port).parse().unwrap();
        alice.node.swarm.dial(bob_addr).unwrap();

        let lobby = bob.active.topic.hash();
        let bob_id = bob.node.peer_id;
        pump(&mut alice, &mut bob, "Alice identificar Bob no Lobby", |a, _| {
            a.meta.contains_key(&bob_id)
                && a.node.swarm.behaviour().gossipsub.all_peers().any(|(p, t)| p == &bob_id && t.contains(&&lobby))
        })
        .await;

        // Alice cria o servidor e já entra nele
        alice.command("/server create Rust Guild");
        let server_id = alice.servers.list().next().expect("servidor criado").server_id.clone();
        assert_eq!(alice.active.space, Space::Server(server_id.clone()));
        assert_eq!(alice.active.channel, "geral");
        assert!(alice.logs().iter().any(|l| l.contains("criado")));

        // Convite no Lobby -> Bob aceita
        alice.command("/server invite");
        assert!(alice.logs().iter().any(|l| l.contains("publicado")), "convite deveria ser publicado no Lobby");
        let sid = server_id.clone();
        pump(&mut alice, &mut bob, "convite chegar a Bob", move |_, b| b.last_invite.as_deref() == Some(sid.as_str())).await;

        bob.command("/server accept");
        assert_eq!(bob.pending.as_deref(), Some(server_id.as_str()), "Bob espera o manifesto");
        let sid = server_id.clone();
        pump(&mut alice, &mut bob, "Bob receber a cadeia e entrar", move |_, b| b.active.space == Space::Server(sid.clone()))
            .await;
        assert_eq!(bob.servers.get(&server_id).unwrap().name(), "Rust Guild");
        assert!(bob.pending.is_none());
        assert!(bob.logs().iter().any(|l| l.contains("sincronizado")));

        // Bob pede entrada no grupo cifrado; a dona admite e manda a chave
        let sid = server_id.clone();
        pump(&mut alice, &mut bob, "Bob receber a chave do grupo", move |_, b| b.mls.has_group(&sid)).await;
        assert!(bob.logs().iter().any(|l| l.contains("Chave do grupo")));

        // Chat do servidor cifrado de ponta a ponta
        let secret = ChatMessage::new_signed(&alice.identity, "geral", "segredo do servidor", now_secs());
        publish_content(&mut alice.node, &mut alice.mls, &alice.active.topic.clone(), serde_json::to_vec(&secret).unwrap()).unwrap();
        pump(&mut alice, &mut bob, "mensagem cifrada chegar a Bob", |_, b| b.received.iter().any(|t| t == "segredo do servidor")).await;

        // Sem certificado, Bob não modera
        bob.command("/server ban Alice");
        assert!(bob.logs().iter().any(|l| l.contains("não tem certificado")));

        // Alice cria um canal e certifica Bob como moderador nível 1
        alice.command("/server channel add jogos");
        alice.command("/server mod add Bob");
        assert!(alice.logs().iter().any(|l| l.contains("agora é moderador nível 1")));
        let sid = server_id.clone();
        let bob_pk = bob.identity.public_key_hex();
        let pk = bob_pk.clone();
        pump(&mut alice, &mut bob, "canal novo e certificado chegarem a Bob", move |_, b| {
            let server = b.servers.get(&sid).unwrap();
            server.has_channel("jogos", ChannelType::Text) && server.level_of(&pk, now_secs()) == Some(1)
        })
        .await;
        assert!(bob.logs().iter().any(|l| l.contains("Você agora é moderador nível 1")));

        // Moderador nível 1 não age sobre a dona (nível 0)
        bob.command("/server ban Alice");
        assert!(bob.logs().iter().any(|l| l.contains("nível igual ou superior")), "recusado pela regra de níveis");

        // Alice revoga o certificado e bane Bob por 1 hora
        alice.command("/server mod remove Bob");
        alice.command("/server ban Bob 1h spam");
        assert!(alice.logs().iter().any(|l| l.contains("foi banido (1h)")));
        let sid = server_id.clone();
        let pk = bob_pk.clone();
        pump(&mut alice, &mut bob, "revogação e ban chegarem a Bob", move |_, b| {
            let server = b.servers.get(&sid).unwrap();
            server.level_of(&pk, now_secs()).is_none() && server.is_banned(&pk, now_secs())
        })
        .await;
        let logs = bob.logs();
        assert!(logs.iter().any(|l| l.contains("Você não é mais moderador")), "{:?}", logs);
        assert!(logs.iter().any(|l| l.contains("Você foi banido")), "{:?}", logs);

        // A manutenção da dona tira Bob do grupo cifrado: a chave é trocada
        let sid = server_id.clone();
        pump(&mut alice, &mut bob, "Bob ser removido do grupo cifrado", move |_, b| !b.mls.has_group(&sid)).await;
        let removal_logs: Vec<String> = logs.iter().cloned().chain(bob.logs()).collect();
        assert!(removal_logs.iter().any(|l| l.contains("removido do grupo cifrado")), "{:?}", removal_logs);
        let after = ChatMessage::new_signed(&alice.identity, "geral", "depois do ban", now_secs());
        publish_content(&mut alice.node, &mut alice.mls, &alice.active.topic.clone(), serde_json::to_vec(&after).unwrap()).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                tokio::select! {
                    ev = alice.node.swarm.select_next_some() => alice.process(ev),
                    ev = bob.node.swarm.select_next_some() => bob.process(ev),
                }
            }
        })
        .await;
        assert!(!bob.received.iter().any(|t| t == "depois do ban"), "banido não lê mais o servidor");

        // O histórico (a cadeia) registra tudo, igual para os dois
        bob.command("/server history");
        let history = bob.logs().join("\n");
        assert!(history.contains("criado 'Rust Guild'"), "{}", history);
        assert!(history.contains("certificado de moderador nível 1"), "{}", history);
        assert!(history.contains("revogado"), "{}", history);
        assert!(history.contains("dono baniu"), "{}", history);
        assert_eq!(
            alice.servers.get(&server_id).unwrap().chain().head().map(|b| b.hash()),
            bob.servers.get(&server_id).unwrap().chain().head().map(|b| b.hash()),
            "mesma cadeia nos dois nós"
        );
    }

    #[test]
    fn test_fmt_utc() {
        assert_eq!(fmt_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(fmt_utc(951_782_400), "2000-02-29 00:00 UTC", "ano bissexto");
        assert_eq!(fmt_utc(1_800_000_000), "2027-01-15 08:00 UTC");
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
