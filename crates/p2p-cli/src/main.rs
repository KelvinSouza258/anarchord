mod ui;

use clap::Parser;
use futures::StreamExt;
use libp2p::gossipsub::IdentTopic;
use opus1::{Application, Channels, OpusDecoder, OpusEncoder, SampleRate};
use p2p_core::{
    api::ChatMessage,
    bootstrap::{get_ipfs_bootstrap_multiaddrs, OPENTRACKER_SERVERS},
    file_transfer::{
        calculate_file_hash, chunk_file, FileDecision, FileOffer, FileReceiver, FileTransferMessage,
    },
    identity::UserIdentity,
    node::P2PNode,
    protocol::AppBehaviourEvent,
    tracker::{make_info_hash, TorrentTrackerClient},
    voice::{AudioCodec, AudioDeviceManager, JitterBuffer, VoiceEngine, VoicePacket},
};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use ui::{TerminalUi, UiAction, UiEvent};

#[derive(Parser, Debug, PartialEq)]
#[command(author = "Victor Gerin", version = "0.1.0", about = "P2P Discord Daemon & CLI")]
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

    /// Desativar descoberta automática via IPFS Amino DHT e Open Trackers BitTorrent
    #[arg(long, default_value_t = false)]
    pub no_auto_bootstrap: bool,
}

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
    SendFile { recipient_query: String, file_path: String },
    AcceptFile(String),
    RejectFile(String),
    SendTextMessage(String),
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
    if trimmed.starts_with("/voice join ") {
        let v_channel = trimmed.trim_start_matches("/voice join ").trim();
        if !v_channel.is_empty() {
            return ChatAction::JoinVoice(v_channel.to_string());
        }
    }
    if trimmed == "/voice leave" {
        return ChatAction::LeaveVoice;
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
    if trimmed.starts_with("/accept ") {
        let hash = trimmed.trim_start_matches("/accept ").trim();
        if !hash.is_empty() {
            return ChatAction::AcceptFile(hash.to_string());
        }
    }
    if trimmed.starts_with("/reject ") {
        let hash = trimmed.trim_start_matches("/reject ").trim();
        if !hash.is_empty() {
            return ChatAction::RejectFile(hash.to_string());
        }
    }
    ChatAction::SendTextMessage(trimmed.to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.daemon {
        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::WARN)
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
        println!(" 🚀 P2P Discord Daemon / CLI (100% Descentralizado)");
        println!("============================================================");
    }

    // 1. Carrega ou gera a identidade permanente do usuário (JSON/PEM com perfil)
    let mut identity = UserIdentity::load_or_create(&args.identity_file)?;
    if args.nick != "Peer" || identity.profile.display_name == "Anonymous Peer" {
        identity.set_nick(&args.nick);
        let _ = identity.save_to(&args.identity_file);
    }
    if args.daemon {
        println!("👤 Apelido     : {}", identity.profile.display_name);
        println!("🔑 User ID     : {}", identity.public_key_hex());
    }

    // 2. Inicializa o Nó P2P (Swarm com Kademlia, QUIC, GossipSub, DCUtR)
    let mut node = P2PNode::new(identity.clone(), args.port)?;
    if args.daemon {
        println!("🌐 Peer ID P2P : {}", node.peer_id);
        if args.port > 0 {
            println!("🚪 Porta Local : {}", args.port);
        } else {
            println!("🚪 Porta Local : Automática (Dinâmica)");
        }
        println!("💬 Sala Ativa  : #{}", args.channel);
        println!("============================================================");
        println!("💡 Dica: Digite sua mensagem e pressione ENTER para enviar!");
        println!("         /peers           -> Lista os pares P2P conectados");
        println!("         /join <sala>     -> Troca de canal de texto");
        println!("         /voice join <id> -> Conecta na sala de voz P2P em tempo real");
        println!("         /voice leave     -> Sai da sala de voz P2P");
        println!("         /mute            -> Alterna mutar/desmutar seu microfone");
        println!("         /devices         -> Lista microfones e alto-falantes detectados");
        println!("         /quit            -> Encerra o nó");
        println!("============================================================\n");
    }

    // Canal ativo inicial
    let mut current_channel = args.channel.clone();
    let mut topic_name = format!("p2p-discord/channel/{}", current_channel);
    let mut current_topic = IdentTopic::new(topic_name.clone());
    node.swarm.behaviour_mut().gossipsub.subscribe(&current_topic)?;

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
    let (tx_assigned_port, mut rx_assigned_port) = tokio::sync::mpsc::channel::<u16>(1);

    // Rastreamento da porta real para cleanup ao sair (Ctrl+C ou /quit)
    let assigned_listen_port = Arc::new(std::sync::atomic::AtomicU16::new(args.port));
    let assigned_port_clone = Arc::clone(&assigned_listen_port);

    let is_daemon = args.daemon;

    if !args.no_auto_bootstrap {
        // 1. Conecta aos nós globais da rede IPFS DHT
        for bootstrap_addr in get_ipfs_bootstrap_multiaddrs() {
            let _ = node.swarm.dial(bootstrap_addr);
        }

        // 2. Fallback: Consulta os Open Trackers BitTorrent em background
        let p2p_id_bytes = node.peer_id.to_bytes();
        let mut bt_peer_id = [0u8; 20];
        let copy_len = p2p_id_bytes.len().min(20);
        bt_peer_id[0..copy_len].copy_from_slice(&p2p_id_bytes[0..copy_len]);

        tokio::spawn(async move {
            // Aguarda a porta real atribuída pelo OS (caso args.port == 0)
            let actual_port = rx_assigned_port.recv().await.unwrap_or(args.port);
            assigned_port_clone.store(actual_port, Ordering::SeqCst);
            let info_hash = make_info_hash("global-discord-discovery");
            for tracker in OPENTRACKER_SERVERS {
                match TorrentTrackerClient::discover_peers(tracker, &info_hash, &bt_peer_id, actual_port) {
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
        });
    }

    // Inicialização do Subsistema de Áudio P2P
    let voice_engine_res = VoiceEngine::start();
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
        let v_topic_name = format!("p2p-discord/voice/{}", v_chan);
        let v_topic = IdentTopic::new(v_topic_name);
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
            const D4: f32 = 293.66;
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

    // Leitura interativa do teclado (stdin no modo daemon ou canal do Ratatui)
    let mut stdin_lines = BufReader::new(tokio::io::stdin()).lines();

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
        );
        tokio::spawn(async move {
            let _ = ui.run(rx_ui_event, tx_ui_action).await;
        });
    }

    // Rastreamento de nós conectados para desduplicação e metadados de identificação
    let mut connected_peers: HashSet<libp2p::PeerId> = HashSet::new();
    let mut peer_metadata: HashMap<libp2p::PeerId, (String, String)> = HashMap::new(); // PeerId -> (Nick, PubKey)
    let mut port_reported = false;

    // Gerenciamento de Transferência Direta de Arquivos P2P
    // Tópico global do Gossipsub para ofertas e sinalização direta
    let files_topic = IdentTopic::new("p2p-discord/direct-files");
    let _ = node.swarm.behaviour_mut().gossipsub.subscribe(&files_topic);

    // Ofertas recebidas pendentes de aprovação pelo usuário: file_hash -> FileOffer
    let mut pending_incoming_offers: HashMap<String, FileOffer> = HashMap::new();
    // Receptores de arquivos em andamento (após aceitação): file_hash -> FileReceiver
    let mut active_file_receivers: HashMap<String, FileReceiver> = HashMap::new();
    // Arquivos locais que este nó ofereceu e estão aguardando o destinatário aceitar: file_hash -> (caminho, bytes)
    let mut pending_outgoing_files: HashMap<String, (String, Vec<u8>)> = HashMap::new();

    // Rastreamento de pares ativos falando/transmitindo áudio (pubkey -> (nome, Instant da última recepção))
    let mut active_speakers: HashMap<String, (String, std::time::Instant)> = HashMap::new();
    let mut speaker_check_interval = tokio::time::interval(std::time::Duration::from_millis(200));

    // Loop de eventos da malha P2P + Teclado + Auto-Discovery
    loop {
        tokio::select! {
            // Monitora quando pares pararam de falar/transmitir (inatividade > 600ms)
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
            // Auto-conexão com nós descobertos via Tracker / DHT
            Some(discovered_addr) = rx_peer_discovery.recv() => {
                if let Ok(multiaddr) = discovered_addr.parse::<libp2p::Multiaddr>() {
                    let _ = node.swarm.dial(multiaddr);
                }
            }

            // Transmissão de áudio do microfone para a sala de voz ativa
            Some(mut voice_pkt) = rx_voice_to_broadcast.recv() => {
                if let Some(v_topic) = &current_voice_topic {
                    if let Some(ch) = &current_voice_channel {
                        voice_pkt.channel_id = ch.clone();
                        if let Ok(pkt_bytes) = voice_pkt.to_bytes() {
                            if let Err(e) = node.swarm.behaviour_mut().gossipsub.publish(v_topic.clone(), pkt_bytes) {
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
                                let _ = tx_ui_event.send(UiEvent::SystemLog(format!("Pares conectados: {}", connected_peers.len())));
                            }
                            ChatAction::ListDevices => {
                                let _ = tx_ui_event.send(UiEvent::SystemLog("Dispositivos de áudio listados.".to_string()));
                            }
                            ChatAction::ToggleMute => {
                                if let Some(engine) = &voice_engine {
                                    let muted = engine.toggle_mute();
                                    let _ = tx_ui_event.send(UiEvent::SystemLog(if muted { "Microfone MUTADO.".to_string() } else { "Microfone ATIVADO.".to_string() }));
                                }
                            }
                            ChatAction::JoinVoice(channel_id) => {
                                let _ = tx_ui_event.send(UiEvent::SystemLog(format!("Entrou na sala de voz: {}", channel_id)));
                            }
                            ChatAction::LeaveVoice => {
                                let _ = tx_ui_event.send(UiEvent::SystemLog("Saiu da sala de voz.".to_string()));
                            }
                            ChatAction::JoinTextChannel(new_channel) => {
                                let _ = tx_ui_event.send(UiEvent::SystemLog(format!("Mudou para canal #{}", new_channel)));
                            }
                            ChatAction::SendFile { recipient_query, file_path } => {
                                let target_pubkey = peer_metadata.iter().find_map(|(pid, (nick, pubkey))| {
                                    if nick.eq_ignore_ascii_case(&recipient_query) || pid.to_string().starts_with(&recipient_query) || pubkey.starts_with(&recipient_query) {
                                        Some(pubkey.clone())
                                    } else {
                                        None
                                    }
                                });

                                let recipient_pubkey = match target_pubkey {
                                    Some(pk) => pk,
                                    None => {
                                        let _ = tx_ui_event.send(UiEvent::SystemLog(format!("❌ Destinatário '{}' não encontrado.", recipient_query)));
                                        continue;
                                    }
                                };

                                let p = std::path::Path::new(&file_path);
                                match std::fs::read(p) {
                                    Ok(data) => {
                                        let file_size = data.len() as u64;
                                        let file_hash = calculate_file_hash(&data);
                                        let file_name = p.file_name().and_then(|n| n.to_str()).unwrap_or("arquivo.bin").to_string();
                                        let chunks = chunk_file(&file_hash, &data);
                                        let total_chunks = chunks.len() as u32;

                                        let offer = FileOffer {
                                            file_hash: file_hash.clone(),
                                            file_name: file_name.clone(),
                                            file_size,
                                            total_chunks,
                                            sender_pubkey: identity.public_key_hex(),
                                            sender_name: args.nick.clone(),
                                            recipient_pubkey: recipient_pubkey.clone(),
                                        };

                                        pending_outgoing_files.insert(file_hash.clone(), (file_name.clone(), data));

                                        let msg = FileTransferMessage::Offer(offer);
                                        if let Ok(bytes) = msg.to_bytes() {
                                            let _ = node.swarm.behaviour_mut().gossipsub.publish(files_topic.clone(), bytes);
                                            let _ = tx_ui_event.send(UiEvent::SystemLog(format!("Proposta de envio de '{}' enviada para [{}]. Aguardando aceite...", file_name, recipient_query)));
                                        }
                                    }
                                    Err(e) => {
                                        let _ = tx_ui_event.send(UiEvent::SystemLog(format!("❌ Erro ao ler arquivo '{}': {:?}", file_path, e)));
                                    }
                                }
                            }
                            ChatAction::AcceptFile(hash_query) => {
                                let target_key = pending_incoming_offers.keys().find(|k| k.starts_with(&hash_query)).cloned();
                                if let Some(hash) = target_key {
                                    if let Some(offer) = pending_incoming_offers.remove(&hash) {
                                        active_file_receivers.insert(hash.clone(), FileReceiver::new(offer.file_name.clone(), offer.file_size, offer.total_chunks));
                                        let decision = FileDecision {
                                            file_hash: hash.clone(),
                                            accepted: true,
                                            responder_pubkey: identity.public_key_hex(),
                                        };
                                        let msg = FileTransferMessage::Decision(decision);
                                        if let Ok(bytes) = msg.to_bytes() {
                                            let _ = node.swarm.behaviour_mut().gossipsub.publish(files_topic.clone(), bytes);
                                            let _ = tx_ui_event.send(UiEvent::SystemLog(format!("Aceitou arquivo '{}'!", offer.file_name)));
                                        }
                                    }
                                }
                            }
                            ChatAction::RejectFile(hash_query) => {
                                let target_key = pending_incoming_offers.keys().find(|k| k.starts_with(&hash_query)).cloned();
                                if let Some(hash) = target_key {
                                    if let Some(offer) = pending_incoming_offers.remove(&hash) {
                                        let decision = FileDecision {
                                            file_hash: hash.clone(),
                                            accepted: false,
                                            responder_pubkey: identity.public_key_hex(),
                                        };
                                        let msg = FileTransferMessage::Decision(decision);
                                        if let Ok(bytes) = msg.to_bytes() {
                                            let _ = node.swarm.behaviour_mut().gossipsub.publish(files_topic.clone(), bytes);
                                            let _ = tx_ui_event.send(UiEvent::SystemLog(format!("Rejeitou arquivo '{}'.", offer.file_name)));
                                        }
                                    }
                                }
                            }
                            ChatAction::SendTextMessage(trimmed) => {
                                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                                let payload = format!("{}:{}:{}", current_channel, trimmed, now);
                                let signature = identity.sign(payload.as_bytes()).to_vec();

                                let msg = ChatMessage {
                                    channel_id: current_channel.clone(),
                                    author_pubkey: identity.public_key_hex(),
                                    author_name: args.nick.clone(),
                                    text: trimmed.clone(),
                                    timestamp: now,
                                    signature,
                                };

                                if let Ok(json_bytes) = serde_json::to_vec(&msg) {
                                    let _ = node.swarm.behaviour_mut().gossipsub.publish(current_topic.clone(), json_bytes);
                                }
                            }
                        }
                    }
                }
            }

            // Entrada do teclado (apenas no modo daemon interativo com stdin conectado)
            line = stdin_lines.next_line(), if args.daemon && false => {
                match line {
                    Ok(Some(text)) => {
                        let action = parse_user_input(&text);
                        match action {
                            ChatAction::Empty => continue,
                            ChatAction::Quit => {
                                println!("Encerrando nó P2P...");
                                break;
                            }
                            ChatAction::ListPeers => {
                                println!("\n👥 --- PARES CONECTADOS ({}) ---", connected_peers.len());
                                if connected_peers.is_empty() {
                                    println!("  (Nenhum par direto no momento. Aguardando descoberta...)");
                                } else {
                                    for peer in &connected_peers {
                                        if let Some((nick, pubkey)) = peer_metadata.get(peer) {
                                            println!("  🟢 Par: {} | Apelido: {} | User ID: {}", peer, nick, pubkey);
                                        } else {
                                            println!("  🟢 Par: {} (Identificando...)", peer);
                                        }
                                    }
                                }
                                println!("--------------------------------\n");
                                continue;
                            }
                            ChatAction::ListDevices => {
                                let inputs = AudioDeviceManager::list_input_devices();
                                let outputs = AudioDeviceManager::list_output_devices();
                                println!("\n🎤 --- DISPOSITIVOS DE ENTRADA (MICROFONES) ---");
                                for dev in inputs {
                                    println!("  🎙️  {}", dev);
                                }
                                println!("🔊 --- DISPOSITIVOS DE SAÍDA (ALTO-FALANTES) ---");
                                for dev in outputs {
                                    println!("  🔈 {}", dev);
                                }
                                println!("-----------------------------------------------\n");
                                continue;
                            }
                            ChatAction::ToggleMute => {
                                if let Some(engine) = &voice_engine {
                                    let muted = engine.toggle_mute();
                                    if muted {
                                        println!("🔇 Microfone MUTADO.");
                                    } else {
                                        println!("🎙️  Microfone ATIVADO.");
                                    }
                                } else {
                                    println!("⚠️  Engine de áudio não inicializada.");
                                }
                                continue;
                            }
                            ChatAction::JoinVoice(v_channel) => {
                                if let Some(prev) = &current_voice_topic {
                                    let _ = node.swarm.behaviour_mut().gossipsub.unsubscribe(prev);
                                }
                                let v_topic_name = format!("p2p-discord/voice/{}", v_channel);
                                let v_topic = IdentTopic::new(v_topic_name);
                                if let Err(e) = node.swarm.behaviour_mut().gossipsub.subscribe(&v_topic) {
                                    println!("❌ Falha ao entrar no canal de voz: {:?}", e);
                                } else {
                                    current_voice_channel = Some(v_channel.clone());
                                    current_voice_topic = Some(v_topic);
                                    println!("🔊 Você conectou à sala de voz [🔊 {}]!", v_channel);
                                    println!("💡 Dica: Fale no microfone ou use /mute para silenciar.");
                                }
                                continue;
                            }
                            ChatAction::LeaveVoice => {
                                if let Some(prev) = current_voice_topic.take() {
                                    let _ = node.swarm.behaviour_mut().gossipsub.unsubscribe(&prev);
                                    println!("🔇 Você saiu da sala de voz [{}].", current_voice_channel.take().unwrap_or_default());
                                } else {
                                    println!("⚠️  Você não está conectado a nenhuma sala de voz.");
                                }
                                continue;
                            }
                            ChatAction::JoinTextChannel(new_channel) => {
                                if new_channel != current_channel {
                                    let _ = node.swarm.behaviour_mut().gossipsub.unsubscribe(&current_topic);
                                    current_channel = new_channel.clone();
                                    topic_name = format!("p2p-discord/channel/{}", current_channel);
                                    current_topic = IdentTopic::new(topic_name.clone());
                                    if let Err(e) = node.swarm.behaviour_mut().gossipsub.subscribe(&current_topic) {
                                        println!("❌ Erro ao entrar no canal #{}: {:?}", current_channel, e);
                                    } else {
                                        println!("🚀 Você entrou no canal [#{}]!", current_channel);
                                    }
                                }
                                continue;
                            }
                            ChatAction::SendFile { recipient_query, file_path } => {
                                // 1. Tenta encontrar a chave pública do destinatário buscando por Nickname ou PubKey
                                let target_pubkey = peer_metadata.values().find_map(|(nick, pubkey)| {
                                    if nick.eq_ignore_ascii_case(&recipient_query) || pubkey.starts_with(&recipient_query) {
                                        Some(pubkey.clone())
                                    } else {
                                        None
                                    }
                                });

                                let recipient_pubkey = match target_pubkey {
                                    Some(pk) => pk,
                                    None => {
                                        println!("❌ Destinatário '{}' não encontrado entre os pares conectados.", recipient_query);
                                        println!("💡 Dica: Use /peers para ver apelidos e IDs dos pares.");
                                        continue;
                                    }
                                };

                                // 2. Lê o arquivo local em bytes
                                let p = std::path::Path::new(&file_path);
                                match std::fs::read(p) {
                                    Ok(data) => {
                                        let file_size = data.len() as u64;
                                        let file_hash = calculate_file_hash(&data);
                                        let file_name = p.file_name()
                                            .and_then(|n| n.to_str())
                                            .unwrap_or("arquivo.bin")
                                            .to_string();

                                        let chunks = chunk_file(&file_hash, &data);
                                        let total_chunks = chunks.len() as u32;

                                        let offer = FileOffer {
                                            file_hash: file_hash.clone(),
                                            file_name: file_name.clone(),
                                            file_size,
                                            total_chunks,
                                            sender_pubkey: identity.public_key_hex(),
                                            sender_name: args.nick.clone(),
                                            recipient_pubkey: recipient_pubkey.clone(),
                                        };

                                        // Salva localmente em pendentes aguardando confirmação do par
                                        pending_outgoing_files.insert(file_hash.clone(), (file_name.clone(), data));

                                        let msg = FileTransferMessage::Offer(offer);
                                        if let Ok(bytes) = msg.to_bytes() {
                                            let _ = node.swarm.behaviour_mut().gossipsub.publish(files_topic.clone(), bytes);
                                            println!("📦 Proposta de envio enviada para o par [{}]:", recipient_query);
                                            println!("   📄 Arquivo : {}", file_name);
                                            println!("   📏 Tamanho : {:.2} MB ({} bytes)", file_size as f64 / (1024.0 * 1024.0), file_size);
                                            println!("   🔑 Hash    : {}", file_hash);
                                            println!("   ⏳ Aguardando o destinatário aceitar a transferência...");
                                        }
                                    }
                                    Err(e) => {
                                        println!("❌ Erro ao ler arquivo '{}': {:?}", file_path, e);
                                    }
                                }
                                continue;
                            }
                            ChatAction::AcceptFile(hash_query) => {
                                // Encontra oferta pelo hash completo ou prefixo
                                let target_key = pending_incoming_offers.keys().find(|k| k.starts_with(&hash_query)).cloned();
                                if let Some(hash) = target_key {
                                    if let Some(offer) = pending_incoming_offers.remove(&hash) {
                                        // Cria o receptor de chunks ativo
                                        active_file_receivers.insert(
                                            hash.clone(),
                                            FileReceiver::new(offer.file_name.clone(), offer.file_size, offer.total_chunks),
                                        );

                                        // Envia sinal de decisão positiva
                                        let decision = FileDecision {
                                            file_hash: hash.clone(),
                                            accepted: true,
                                            responder_pubkey: identity.public_key_hex(),
                                        };
                                        let msg = FileTransferMessage::Decision(decision);
                                        if let Ok(bytes) = msg.to_bytes() {
                                            let _ = node.swarm.behaviour_mut().gossipsub.publish(files_topic.clone(), bytes);
                                            println!("✅ Você ACEITOU o arquivo '{}' de {}. Aguardando blocos P2P...", offer.file_name, offer.sender_name);
                                        }
                                    }
                                } else {
                                    println!("⚠️ Nenhuma oferta de arquivo pendente com hash correspondente a '{}'.", hash_query);
                                }
                                continue;
                            }
                            ChatAction::RejectFile(hash_query) => {
                                let target_key = pending_incoming_offers.keys().find(|k| k.starts_with(&hash_query)).cloned();
                                if let Some(hash) = target_key {
                                    if let Some(offer) = pending_incoming_offers.remove(&hash) {
                                        let decision = FileDecision {
                                            file_hash: hash.clone(),
                                            accepted: false,
                                            responder_pubkey: identity.public_key_hex(),
                                        };
                                        let msg = FileTransferMessage::Decision(decision);
                                        if let Ok(bytes) = msg.to_bytes() {
                                            let _ = node.swarm.behaviour_mut().gossipsub.publish(files_topic.clone(), bytes);
                                            println!("❌ Você REJEITOU o arquivo '{}' de {}.", offer.file_name, offer.sender_name);
                                        }
                                    }
                                } else {
                                    println!("⚠️ Nenhuma oferta de arquivo pendente com hash correspondente a '{}'.", hash_query);
                                }
                                continue;
                            }
                            ChatAction::SendTextMessage(trimmed) => {
                                // Cria mensagem assinada
                                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                                let payload = format!("{}:{}:{}", current_channel, trimmed, now);
                                let signature = identity.sign(payload.as_bytes()).to_vec();

                                let msg = ChatMessage {
                                    channel_id: current_channel.clone(),
                                    author_pubkey: identity.public_key_hex(),
                                    author_name: args.nick.clone(),
                                    text: trimmed.clone(),
                                    timestamp: now,
                                    signature,
                                };

                                if let Ok(json_bytes) = serde_json::to_vec(&msg) {
                                    if let Err(e) = node.swarm.behaviour_mut().gossipsub.publish(current_topic.clone(), json_bytes) {
                                        println!("⚠️  Aguardando outros pares na sala para enviar mensagem... ({:?})", e);
                                    } else {
                                        println!("💬 [Você]: {}", trimmed);
                                    }
                                }
                            }
                        }
                    }
                    Ok(None) if !args.daemon => break,
                    Ok(None) => {
                        // No modo daemon stdin está vazio (/dev/null), NÃO deve encerrar o processo!
                        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                    }
                    Err(e) => {
                        eprintln!("Erro ao ler entrada: {:?}", e);
                        break;
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
                        if !port_reported {
                            // Extrai a porta atribuída pelo OS (TCP ou UDP)
                            for proto in address.iter() {
                                match proto {
                                    libp2p::multiaddr::Protocol::Tcp(p) | libp2p::multiaddr::Protocol::Udp(p) => {
                                        let _ = tx_assigned_port.send(p).await;
                                        port_reported = true;
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        connected_peers.insert(peer_id);
                        let _ = tx_ui_event.send(UiEvent::SystemLog(format!("Conexão P2P com {}", peer_id)));
                        if args.daemon {
                            println!("🤝 Conexão P2P Direta estabelecida com: {} via {:?}", peer_id, endpoint.get_remote_address());
                        }
                    }
                    libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, cause, num_established, .. } => {
                        if num_established == 0 {
                            connected_peers.remove(&peer_id);
                            let _ = tx_ui_event.send(UiEvent::PeerDisconnected(peer_id.to_string()));
                            if args.daemon {
                                println!("👋 Conexão fechada com: {} (Motivo: {:?})", peer_id, cause);
                            }
                        }
                    }
                    libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Identify(
                        libp2p::identify::Event::Received { peer_id, info, .. }
                    )) => {
                        // Extrai Nickname e PubKey do agent_version ("anarchord:nick:pubkey")
                        if info.agent_version.starts_with("anarchord:") {
                            let parts: Vec<&str> = info.agent_version.split(':').collect();
                            if parts.len() >= 3 {
                                let nick = parts[1].to_string();
                                let pubkey = parts[2].to_string();
                                peer_metadata.insert(peer_id, (nick.clone(), pubkey.clone()));
                                let _ = tx_ui_event.send(UiEvent::PeerConnected {
                                    peer_id: peer_id.to_string(),
                                    nick: nick.clone(),
                                    pubkey: pubkey.clone(),
                                });
                                if args.daemon {
                                    println!("✨ Identidade confirmada: {} é '{}' (User ID: {})", peer_id, nick, pubkey);
                                }
                            }
                        }
                    }
                    libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(
                        libp2p::gossipsub::Event::Message { message, .. }
                    )) => {
                        // 1. Tenta decodificar como mensagem de chat de texto
                        if let Ok(chat_msg) = serde_json::from_slice::<ChatMessage>(&message.data) {
                            if chat_msg.author_pubkey != identity.public_key_hex() {
                                let _ = tx_ui_event.send(UiEvent::ChatMessage {
                                    channel: chat_msg.channel_id.clone(),
                                    author: chat_msg.author_name.clone(),
                                    text: chat_msg.text.clone(),
                                });
                                if args.daemon {
                                    println!("\n📩 [#{}] {}: {}", chat_msg.channel_id, chat_msg.author_name, chat_msg.text);
                                }
                            }
                        }
                        // 2. Tenta decodificar como pacote de voz P2P
                        else if let Ok(voice_pkt) = VoicePacket::from_bytes(&message.data) {
                            if voice_pkt.sender_pubkey != identity.public_key_hex() {
                                let now = std::time::Instant::now();
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
                        // 3. Tenta decodificar como mensagem de transferência direta de arquivo P2P
                        else if let Ok(file_msg) = FileTransferMessage::from_bytes(&message.data) {
                            match file_msg {
                                FileTransferMessage::Offer(offer) => {
                                    // Verifica se o arquivo é direcionado a nós
                                    if offer.recipient_pubkey == identity.public_key_hex() {
                                        if args.daemon {
                                            println!("\n📥 [TRANSFERÊNCIA DE ARQUIVO] Recebida proposta de '{}':", offer.sender_name);
                                            println!("   📄 Arquivo : {}", offer.file_name);
                                            println!("   📏 Tamanho : {:.2} MB ({} bytes em {} blocos de 64KB)", offer.file_size as f64 / (1024.0 * 1024.0), offer.file_size, offer.total_chunks);
                                            println!("   🔑 Hash    : {}", offer.file_hash);
                                        }
                                        let _ = tx_ui_event.send(UiEvent::SystemLog(format!("Proposta de arquivo '{}' de {}. Use /accept {}", offer.file_name, offer.sender_name, &offer.file_hash[..8])));

                                        // Se estiver rodando como Daemon (modo bot/servidor), aceita automaticamente
                                        if args.daemon {
                                            println!("🤖 [MODO DAEMON] Aceitando transferência automaticamente...");
                                            active_file_receivers.insert(
                                                offer.file_hash.clone(),
                                                FileReceiver::new(offer.file_name.clone(), offer.file_size, offer.total_chunks),
                                            );
                                            let decision = FileDecision {
                                                file_hash: offer.file_hash.clone(),
                                                accepted: true,
                                                responder_pubkey: identity.public_key_hex(),
                                            };
                                            let msg = FileTransferMessage::Decision(decision);
                                            if let Ok(bytes) = msg.to_bytes() {
                                                let _ = node.swarm.behaviour_mut().gossipsub.publish(files_topic.clone(), bytes);
                                            }
                                        } else {
                                            println!("   💡 Para aceitar: /accept {}", &offer.file_hash[..8]);
                                            println!("   💡 Para rejeitar: /reject {}\n", &offer.file_hash[..8]);
                                            pending_incoming_offers.insert(offer.file_hash.clone(), offer);
                                        }
                                    }
                                }
                                FileTransferMessage::Decision(decision) => {
                                    if let Some((file_name, data)) = pending_outgoing_files.get(&decision.file_hash) {
                                        if decision.accepted {
                                            let _ = tx_ui_event.send(UiEvent::SystemLog(format!("Transferência aceita de '{}'! Enviando blocos...", file_name)));
                                            if args.daemon {
                                                println!("\n🎉 O destinatário ACEITOU a transferência de '{}'! Transmitindo blocos P2P...", file_name);
                                            }
                                            // Pequeno delay para garantir sincronização do Gossipsub
                                            tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

                                            let chunks = chunk_file(&decision.file_hash, data);
                                            let total = chunks.len();
                                            for (idx, chunk) in chunks.into_iter().enumerate() {
                                                let msg = FileTransferMessage::Chunk(chunk);
                                                if let Ok(bytes) = msg.to_bytes() {
                                                    if let Err(e) = node.swarm.behaviour_mut().gossipsub.publish(files_topic.clone(), bytes) {
                                                        if args.daemon {
                                                            println!("❌ Falha ao publicar bloco #{}: {:?}", idx + 1, e);
                                                        }
                                                    }
                                                }
                                                let pct = ((idx + 1) as f32 / total as f32) * 100.0;
                                                let _ = tx_ui_event.send(UiEvent::FileTransferProgress {
                                                    file_name: file_name.clone(),
                                                    percentage: pct,
                                                    is_download: false,
                                                });
                                                if args.daemon && ((idx + 1) % 10 == 0 || (idx + 1) == total) {
                                                    println!("   📤 Enviado: {:.1}% ({}/{} blocos)", pct, idx + 1, total);
                                                }
                                                // Intervalo entre blocos para fluidez de rede
                                                tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
                                            }
                                            if args.daemon {
                                                println!("✅ Arquivo '{}' enviado com sucesso!\n", file_name);
                                            }
                                            pending_outgoing_files.remove(&decision.file_hash);
                                        } else {
                                            let _ = tx_ui_event.send(UiEvent::SystemLog(format!("Transferência de '{}' foi recusada pelo destinatário.", file_name)));
                                            if args.daemon {
                                                println!("\n❌ O destinatário REJEITOU a transferência de '{}'.", file_name);
                                            }
                                            pending_outgoing_files.remove(&decision.file_hash);
                                        }
                                    }
                                }
                                FileTransferMessage::Chunk(chunk) => {
                                    if let Some(receiver) = active_file_receivers.get_mut(&chunk.file_hash) {
                                        let file_hash_clone = chunk.file_hash.clone();
                                        let pct = receiver.add_chunk(chunk.chunk_index, chunk.data);
                                        let _ = tx_ui_event.send(UiEvent::FileTransferProgress {
                                            file_name: receiver.file_name.clone(),
                                            percentage: pct,
                                            is_download: true,
                                        });
                                        if args.daemon && ((chunk.chunk_index + 1) % 10 == 0 || receiver.is_complete()) {
                                            println!("   📥 Baixando '{}': {:.1}%", receiver.file_name, pct);
                                        }

                                        if receiver.is_complete() {
                                            let file_name = receiver.file_name.clone();
                                            match receiver.assemble_and_verify(&file_hash_clone) {
                                                Ok(completed_bytes) => {
                                                    // Salva na pasta downloads do usuário se existir, senão downloads local
                                                    let home_dir = std::env::var("HOME").ok().map(std::path::PathBuf::from);
                                                    let download_dir = home_dir.map(|h| h.join("downloads")).unwrap_or_else(|| std::path::PathBuf::from("downloads"));
                                                    let _ = std::fs::create_dir_all(&download_dir);
                                                    let save_path = download_dir.join(&file_name);
                                                    if let Ok(_) = std::fs::write(&save_path, &completed_bytes) {
                                                        let _ = tx_ui_event.send(UiEvent::SystemLog(format!("Arquivo '{}' salvo com sucesso em {:?}", file_name, save_path)));
                                                        if args.daemon {
                                                            println!("\n💾 [ARQUIVO CONCLUÍDO] '{}' salvo com sucesso em: {:?}", file_name, save_path);
                                                            println!("   🔒 Integridade SHA-256 verificada com sucesso!\n");
                                                        }
                                                    } else if args.daemon {
                                                        println!("❌ Erro ao salvar arquivo em {:?}", save_path);
                                                    }
                                                }
                                                Err(e) => {
                                                    if args.daemon {
                                                        println!("❌ Falha na verificação de integridade do arquivo: {}", e);
                                                    }
                                                }
                                            }
                                            active_file_receivers.remove(&file_hash_clone);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Graceful Shutdown: Desanuncia o par do BitTorrent Tracker com event = stopped
    let port = assigned_listen_port.load(Ordering::SeqCst);
    if !args.no_auto_bootstrap && port > 0 {
        println!("📡 Removendo nó da lista de pares dos Open Trackers (event = stopped)...");
        let p2p_id_bytes = node.peer_id.to_bytes();
        let mut bt_peer_id = [0u8; 20];
        let copy_len = p2p_id_bytes.len().min(20);
        bt_peer_id[0..copy_len].copy_from_slice(&p2p_id_bytes[0..copy_len]);
        let info_hash = make_info_hash("global-discord-discovery");

        for tracker in OPENTRACKER_SERVERS {
            let _ = TorrentTrackerClient::announce_stopped(tracker, &info_hash, &bt_peer_id, port);
        }
    }

    println!("👋 Anarchord encerrado com sucesso.");
    Ok(())
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
            ChatAction::AcceptFile("8f4a123b".to_string())
        );
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
}
