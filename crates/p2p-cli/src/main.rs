use clap::Parser;
use futures::StreamExt;
use libp2p::gossipsub::IdentTopic;
use p2p_core::{
    api::ChatMessage,
    bootstrap::{get_ipfs_bootstrap_multiaddrs, OPENTRACKER_SERVERS},
    identity::UserIdentity,
    node::P2PNode,
    protocol::AppBehaviourEvent,
    tracker::{make_info_hash, TorrentTrackerClient},
};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(author = "Victor Gerin", version = "0.1.0", about = "P2P Discord Daemon & CLI")]
struct Args {
    /// Nome de exibição (apelido no chat)
    #[arg(short, long, default_value = "Peer")]
    nick: String,

    /// Porta local para escutar conexões UDP/QUIC e TCP (0 = porta dinâmica aleatória)
    #[arg(short, long, default_value_t = 0)]
    port: u16,

    /// Caminho do arquivo de identidade e perfil do usuário (JSON com chaves PEM)
    #[arg(long, default_value = "identity.json")]
    identity_file: PathBuf,

    /// Conectar diretamente a um endereço multiaddr conhecido (opcional)
    #[arg(long)]
    connect: Option<String>,

    /// Sala inicial de chat
    #[arg(long, default_value = "geral")]
    channel: String,

    /// Desativar descoberta automática via IPFS Amino DHT e Open Trackers BitTorrent
    #[arg(long, default_value_t = false)]
    no_auto_bootstrap: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::WARN) // Logs limpos para chat no terminal
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();

    println!("============================================================");
    println!(" 🚀 P2P Discord Daemon / CLI (100% Descentralizado)");
    println!("============================================================");

    // 1. Carrega ou gera a identidade permanente do usuário (JSON/PEM com perfil)
    let mut identity = UserIdentity::load_or_create(&args.identity_file)?;
    if args.nick != "Peer" || identity.profile.display_name == "Anonymous Peer" {
        identity.set_nick(&args.nick);
        let _ = identity.save_to(&args.identity_file);
    }
    println!("👤 Apelido     : {}", identity.profile.display_name);
    println!("🔑 User ID     : {}", identity.public_key_hex());

    // 2. Inicializa o Nó P2P (Swarm com Kademlia, QUIC, GossipSub, DCUtR)
    let mut node = P2PNode::new(identity.clone(), args.port)?;
    println!("🌐 Peer ID P2P : {}", node.peer_id);
    if args.port > 0 {
        println!("🚪 Porta Local : {}", args.port);
    } else {
        println!("🚪 Porta Local : Automática (Dinâmica)");
    }
    println!("💬 Sala Ativa  : #{}", args.channel);
    println!("============================================================");
    println!("💡 Dica: Digite sua mensagem e pressione ENTER para enviar!");
    println!("         /peers        -> Lista os pares P2P conectados");
    println!("         /join <sala>  -> Troca de canal em tempo real");
    println!("         /quit         -> Encerra o nó");
    println!("============================================================\n");

    // Canal ativo inicial
    let mut current_channel = args.channel.clone();
    let mut topic_name = format!("p2p-discord/channel/{}", current_channel);
    let mut current_topic = IdentTopic::new(topic_name.clone());
    node.swarm.behaviour_mut().gossipsub.subscribe(&current_topic)?;

    // Conexão direta explícita se fornecida
    if let Some(remote_addr) = args.connect {
        let multiaddr: libp2p::Multiaddr = remote_addr.parse()?;
        println!("⏳ Conectando ao par remoto: {}", multiaddr);
        node.swarm.dial(multiaddr)?;
    }

    // Descoberta Automática Híbrida: 1) IPFS Amino DHT + 2) BitTorrent Open Trackers
    let (tx_peer_discovery, mut rx_peer_discovery) = tokio::sync::mpsc::unbounded_channel::<String>();
    let (tx_assigned_port, mut rx_assigned_port) = tokio::sync::mpsc::channel::<u16>(1);

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
            let info_hash = make_info_hash("global-discord-discovery");
            for tracker in OPENTRACKER_SERVERS {
                match TorrentTrackerClient::discover_peers(tracker, &info_hash, &bt_peer_id, actual_port) {
                    Ok(peers) => {
                        for peer in peers {
                            println!("📡 Par descoberto via BitTorrent Tracker: {}", peer);
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

    // Leitura interativa do teclado (stdin)
    let mut stdin_lines = BufReader::new(tokio::io::stdin()).lines();

    // Rastreamento de nós conectados para desduplicação
    let mut connected_peers: HashSet<libp2p::PeerId> = HashSet::new();
    let mut port_reported = false;

    // Loop de eventos da malha P2P + Teclado + Auto-Discovery
    loop {
        tokio::select! {
            // Auto-conexão com nós descobertos via Tracker / DHT
            Some(discovered_addr) = rx_peer_discovery.recv() => {
                if let Ok(multiaddr) = discovered_addr.parse::<libp2p::Multiaddr>() {
                    let _ = node.swarm.dial(multiaddr);
                }
            }

            // Entrada do teclado
            line = stdin_lines.next_line() => {
                match line {
                    Ok(Some(text)) => {
                        let trimmed = text.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        if trimmed == "/quit" {
                            println!("Encerrando nó P2P...");
                            break;
                        }

                        if trimmed == "/peers" {
                            println!("\n👥 --- PARES CONECTADOS ({}) ---", connected_peers.len());
                            if connected_peers.is_empty() {
                                println!("  (Nenhum par direto no momento. Aguardando descoberta...)");
                            } else {
                                for peer in &connected_peers {
                                    println!("  🟢 Par: {}", peer);
                                }
                            }
                            println!("--------------------------------\n");
                            continue;
                        }

                        if trimmed.starts_with("/join ") {
                            let new_channel = trimmed.trim_start_matches("/join ").trim();
                            if !new_channel.is_empty() && new_channel != current_channel {
                                // Desinscreve do canal antigo
                                let _ = node.swarm.behaviour_mut().gossipsub.unsubscribe(&current_topic);
                                
                                // Inscreve no novo canal
                                current_channel = new_channel.to_string();
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

                        // Cria mensagem assinada
                        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                        let payload = format!("{}:{}:{}", current_channel, trimmed, now);
                        let signature = identity.sign(payload.as_bytes()).to_vec();

                        let msg = ChatMessage {
                            channel_id: current_channel.clone(),
                            author_pubkey: identity.public_key_hex(),
                            author_name: args.nick.clone(),
                            text: trimmed.to_string(),
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
                    Ok(None) => break,
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
                        println!("📡 Endereço de escuta ativo: {}", address);
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
                    libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } => {
                        if connected_peers.contains(&peer_id) {
                            println!("⚠️  Conexão redundante detectada com o par {}. Fechando conexão secundária...", peer_id);
                            // Fecha apenas ESTA conexão específica, mantendo a primeira intacta!
                            let _ = node.swarm.close_connection(connection_id);
                        } else {
                            connected_peers.insert(peer_id);
                            println!("🤝 Conexão P2P Direta estabelecida com: {} via {:?}", peer_id, endpoint.get_remote_address());
                        }
                    }
                    libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, cause, num_established, .. } => {
                        if num_established == 0 {
                            connected_peers.remove(&peer_id);
                            println!("👋 Conexão fechada com: {} (Motivo: {:?})", peer_id, cause);
                        }
                    }
                    libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(
                        libp2p::gossipsub::Event::Message { message, .. }
                    )) => {
                        if let Ok(chat_msg) = serde_json::from_slice::<ChatMessage>(&message.data) {
                            if chat_msg.author_pubkey != identity.public_key_hex() {
                                println!("\n📩 [#{}] {}: {}", chat_msg.channel_id, chat_msg.author_name, chat_msg.text);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}
