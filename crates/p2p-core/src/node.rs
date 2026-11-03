use crate::bootstrap::get_ipfs_bootstrap_multiaddrs;
use crate::identity::UserIdentity;
use crate::protocol::AppBehaviour;
use libp2p::{
    autonat, dcutr, gossipsub, identify, kad::{self, store::MemoryStore},
    multiaddr::Protocol, noise, ping, swarm::Swarm, tcp, yamux, Multiaddr, PeerId, SwarmBuilder,
};
use sha2::{Digest, Sha256};
use std::net::{TcpListener, UdpSocket};
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NodeError {
    #[error("Erro ao inicializar Swarm: {0}")]
    SwarmInit(String),
    #[error("Erro de transporte: {0}")]
    Transport(#[from] libp2p::TransportError<std::io::Error>),
}

pub struct P2PNode {
    pub peer_id: PeerId,
    pub identity: UserIdentity,
    pub swarm: Swarm<AppBehaviour>,
    /// Porta efetiva compartilhada por TCP e QUIC (UDP), já resolvida quando a porta pedida é 0
    pub listen_port: u16,
}

/// Namespace do registro de provedor na DHT usado para encontrar outros nós Anarchord
pub const DHT_DISCOVERY_NAMESPACE: &str = "global-anarchord-discovery";

/// Chave do registro de provedor na DHT: multihash SHA2-256 (0x12, 0x20 + digest),
/// mesmo formato de um CIDv0 do IPFS, para ser aceita pelos nós da DHT Amino
pub fn dht_discovery_key() -> kad::RecordKey {
    let digest = Sha256::digest(DHT_DISCOVERY_NAMESPACE.as_bytes());
    let mut multihash = Vec::with_capacity(34);
    multihash.extend_from_slice(&[0x12, 0x20]);
    multihash.extend_from_slice(&digest);
    kad::RecordKey::new(&multihash)
}

/// Prefixo do `agent_version` do Identify que marca um nó Anarchord
pub const AGENT_VERSION_PREFIX: &str = "anarchord:";

/// Monta o `agent_version` anunciado no Identify: `anarchord:<nick>:<pubkey hex>`
pub fn make_agent_version(nick: &str, pubkey_hex: &str) -> String {
    format!("{}{}:{}", AGENT_VERSION_PREFIX, nick, pubkey_hex)
}

/// Extrai (nick, pubkey) do `agent_version` de um nó Anarchord.
/// A pubkey é o último campo, então nicks contendo ':' continuam funcionando.
pub fn parse_agent_version(agent_version: &str) -> Option<(String, String)> {
    let rest = agent_version.strip_prefix(AGENT_VERSION_PREFIX)?;
    let (nick, pubkey) = rest.rsplit_once(':')?;
    if nick.is_empty() || pubkey.is_empty() {
        return None;
    }
    Some((nick.to_string(), pubkey.to_string()))
}

/// Encontra uma porta livre ao mesmo tempo em TCP e UDP, para que TCP e QUIC
/// escutem na mesma porta e o anúncio no tracker (que só carrega uma porta) sirva aos dois
fn pick_shared_tcp_udp_port() -> std::io::Result<u16> {
    for _ in 0..32 {
        let tcp = TcpListener::bind(("0.0.0.0", 0))?;
        let port = tcp.local_addr()?.port();
        if UdpSocket::bind(("0.0.0.0", port)).is_ok() {
            return Ok(port);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        "nenhuma porta livre simultaneamente em TCP e UDP",
    ))
}

/// Opções de construção do nó
#[derive(Debug, Clone)]
pub struct NodeOptions {
    /// Porta TCP + QUIC (0 = escolhe uma livre)
    pub port: u16,
    /// Atende como servidor de Circuit Relay v2 (nós públicos)
    pub relay_server: bool,
    /// Rede de laboratório: endereços privados contam como "públicos" para AutoNAT e relay,
    /// e as sondagens do AutoNAT são rápidas
    pub lab: bool,
    /// Descoberta na rede local (mDNS)
    pub mdns: bool,
}

impl Default for NodeOptions {
    fn default() -> Self {
        Self { port: 0, relay_server: false, lab: false, mdns: true }
    }
}

impl P2PNode {
    /// Inicializa o Nó P2P com Kademlia DHT, GossipSub, DCUtR e Criptografia Noise
    pub fn new(identity: UserIdentity, listen_port: u16) -> Result<Self, NodeError> {
        Self::with_options(identity, NodeOptions { port: listen_port, ..Default::default() })
    }

    pub fn with_options(identity: UserIdentity, options: NodeOptions) -> Result<Self, NodeError> {
        let listen_port = options.port;
        let keypair = identity.to_libp2p_keypair();
        let peer_id = PeerId::from(keypair.public());

        let mut swarm = SwarmBuilder::with_existing_identity(keypair.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| NodeError::SwarmInit(e.to_string()))?
            .with_quic()
            .with_dns()
            .map_err(|e| NodeError::SwarmInit(e.to_string()))?
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(|e| NodeError::SwarmInit(e.to_string()))?
            .with_behaviour(|key, relay_client| {
                // 1. Kademlia DHT no protocolo da DHT Amino do IPFS (/ipfs/kad/1.0.0),
                //    usada para anunciar e encontrar outros nós Anarchord via registros de provedor
                let kad_store = MemoryStore::new(key.public().to_peer_id());
                let kad_config = kad::Config::new(kad::PROTOCOL_NAME);
                let kademlia = kad::Behaviour::with_config(key.public().to_peer_id(), kad_store, kad_config);

                // 2. GossipSub (Chat de Texto em Malha, Áudio e Vídeo P2P)
                let gossip_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_millis(500))
                    // Strict: toda mensagem precisa de autor (source) e assinatura válidos. É o que permite
                    // ligar o autor de uma ChatMessage a quem de fato a publicou (ChatMessage::verify)
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .max_transmit_size(1024 * 1024) // 1MB limite para permitir pacotes de chunks P2P e vídeo
                    .mesh_n(2)           // Alvo da malha D reduzido para funcionar até com 2 nós em testes locais
                    .mesh_n_low(1)       // Mínimo D_lo = 1 (enxerta par assim que houver 1 conectado)
                    .mesh_n_high(12)     // Máximo D_hi
                    .mesh_outbound_min(0)// D_out = 0 (permite malhas com apenas 1 nó sem forçar outbound)
                    .flood_publish(true) // Publica para todos os pares inscritos no tópico imediatamente!
                    .build()
                    .map_err(|e| NodeError::SwarmInit(e.to_string()))
                    .expect("Configuração GossipSub válida");
                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossip_config,
                )
                .expect("GossipSub behaviour válido");

                // 3. Identify com User Agent contendo o Nickname e PubKey
                let user_agent = make_agent_version(&identity.profile.display_name, &identity.public_key_hex());
                let identify_config = identify::Config::new(
                    "/p2p-anarchord/1.0.0".to_string(),
                    key.public(),
                )
                .with_agent_version(user_agent)
                // Reenvia os endereços quando mudam (ex.: reserva no relay), para a troca de pares
                .with_push_listen_addr_updates(true);
                let identify = identify::Behaviour::new(identify_config);

                // 4. mDNS: Descoberta automática instantânea em redes locais (LAN / Wi-Fi / Localhost)
                let mdns = if options.mdns {
                    Some(
                        libp2p::mdns::tokio::Behaviour::new(libp2p::mdns::Config::default(), key.public().to_peer_id())
                            .map_err(|e| NodeError::SwarmInit(format!("Falha ao inicializar mDNS: {}", e)))?,
                    )
                } else {
                    None
                }
                .into();

                // 5. Ping
                let ping = ping::Behaviour::new(ping::Config::default());

                // 6. AutoNAT & DCUtR (Hole Punching)
                let autonat_config = if options.lab {
                    autonat::Config {
                        only_global_ips: false,
                        boot_delay: Duration::from_secs(1),
                        retry_interval: Duration::from_secs(3),
                        refresh_interval: Duration::from_secs(10),
                        confidence_max: 1,
                        throttle_server_period: Duration::ZERO,
                        ..Default::default()
                    }
                } else {
                    autonat::Config::default()
                };
                let autonat = autonat::Behaviour::new(key.public().to_peer_id(), autonat_config);
                let relay_server = options
                    .relay_server
                    .then(|| {
                        // O padrão do libp2p (128 KB e 2 min por circuito) só serve para sinalização;
                        // nossos relays carregam chat, voz e arquivos de quem não consegue hole punching
                        let config = libp2p::relay::Config {
                            max_circuit_duration: Duration::from_secs(3600),
                            max_circuit_bytes: 1 << 30,
                            ..Default::default()
                        };
                        libp2p::relay::Behaviour::new(key.public().to_peer_id(), config)
                    })
                    .into();
                let dcutr = dcutr::Behaviour::new(key.public().to_peer_id());

                // 7. Protocolo de arquivos do enxame (pedaços em bytes crus, um stream por pedido)
                let files = libp2p::request_response::Behaviour::with_codec(
                    crate::files::FileCodec,
                    [(crate::files::PROTOCOL, libp2p::request_response::ProtocolSupport::Full)],
                    libp2p::request_response::Config::default().with_request_timeout(Duration::from_secs(30)),
                );

                Ok(AppBehaviour {
                    kademlia,
                    gossipsub,
                    identify,
                    mdns,
                    ping,
                    autonat,
                    dcutr,
                    relay_client,
                    relay_server,
                    files,
                })
            })
            .map_err(|e| NodeError::SwarmInit(e.to_string()))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        // Escuta na mesma porta para TCP e QUIC (porta 0 = escolhe uma livre nos dois protocolos)
        let listen_port = if listen_port == 0 {
            pick_shared_tcp_udp_port().map_err(|e| NodeError::SwarmInit(e.to_string()))?
        } else {
            listen_port
        };
        let tcp_listen: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", listen_port).parse().unwrap();
        let quic_listen: Multiaddr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", listen_port).parse().unwrap();

        swarm.listen_on(tcp_listen).map_err(|e| NodeError::SwarmInit(e.to_string()))?;
        swarm.listen_on(quic_listen).map_err(|e| NodeError::SwarmInit(e.to_string()))?;

        Ok(Self {
            peer_id,
            identity,
            swarm,
            listen_port,
        })
    }

    /// Usa `addresses` (com `/p2p/<id>` no fim) como bootstrap da DHT, no lugar dos nós do IPFS.
    /// Retorna quantos foram registrados.
    pub fn bootstrap_with(&mut self, addresses: &[Multiaddr]) -> usize {
        let mut added = 0;
        for addr in addresses {
            if let Some(Protocol::P2p(peer_id)) = addr.iter().last() {
                self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                let _ = self.swarm.dial(addr.clone());
                added += 1;
            }
        }
        if added > 0 {
            let _ = self.swarm.behaviour_mut().kademlia.bootstrap();
        }
        added
    }

    /// Registra os nós de bootstrap da DHT Amino no Kademlia e inicia o bootstrap da tabela de roteamento.
    /// Retorna quantos nós de bootstrap foram registrados.
    pub fn bootstrap_dht(&mut self) -> usize {
        let mut added = 0;
        for addr in get_ipfs_bootstrap_multiaddrs() {
            if let Some(Protocol::P2p(peer_id)) = addr.iter().last() {
                self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                added += 1;
            }
        }
        if added > 0 {
            if let Err(e) = self.swarm.behaviour_mut().kademlia.bootstrap() {
                tracing::warn!("Falha ao iniciar bootstrap da DHT: {:?}", e);
            }
        }
        added
    }

    /// Anuncia este nó como provedor da chave de descoberta Anarchord na DHT.
    /// Deve ser chamado quando houver endereço externo confirmado, pois o registro carrega esses endereços.
    pub fn dht_start_providing(&mut self) {
        self.dht_provide(dht_discovery_key());
    }

    /// Anuncia este nó como provedor de uma chave qualquer (ex.: a de um servidor que ele acompanha)
    pub fn dht_provide(&mut self, key: kad::RecordKey) {
        if let Err(e) = self.swarm.behaviour_mut().kademlia.start_providing(key) {
            tracing::warn!("Falha ao anunciar provedor na DHT: {:?}", e);
        }
    }

    /// Busca na DHT os outros nós Anarchord que anunciaram a chave de descoberta.
    /// Os resultados chegam como `kad::Event::OutboundQueryProgressed` com `GetProvidersOk::FoundProviders`.
    pub fn dht_find_peers(&mut self) {
        self.dht_find(dht_discovery_key());
    }

    /// Busca os provedores de uma chave qualquer (ex.: membros online de um servidor)
    pub fn dht_find(&mut self, key: kad::RecordKey) {
        self.swarm.behaviour_mut().kademlia.get_providers(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dht_discovery_key_is_sha256_multihash() {
        let key = dht_discovery_key();
        let bytes = key.as_ref();
        assert_eq!(bytes.len(), 34);
        assert_eq!(&bytes[..2], &[0x12, 0x20]);
        assert_eq!(key, dht_discovery_key());
    }

    #[test]
    fn test_agent_version_roundtrip() {
        let agent = make_agent_version("Bob", "224d73");
        assert_eq!(parse_agent_version(&agent), Some(("Bob".into(), "224d73".into())));
    }

    #[test]
    fn test_agent_version_nick_with_colon() {
        let agent = make_agent_version("Dr: Who", "abc123");
        assert_eq!(parse_agent_version(&agent), Some(("Dr: Who".into(), "abc123".into())));
    }

    #[test]
    fn test_agent_version_rejects_foreign_agents() {
        assert_eq!(parse_agent_version("kubo/0.30.0/"), None);
        assert_eq!(parse_agent_version("anarchord:"), None);
        assert_eq!(parse_agent_version("anarchord:semchave"), None);
    }

    #[test]
    fn test_pick_shared_port_is_free_on_tcp_and_udp() {
        let port = pick_shared_tcp_udp_port().unwrap();
        assert_ne!(port, 0);
        assert!(TcpListener::bind(("0.0.0.0", port)).is_ok());
        assert!(UdpSocket::bind(("0.0.0.0", port)).is_ok());
    }
}
