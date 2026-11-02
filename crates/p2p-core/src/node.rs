use crate::identity::UserIdentity;
use crate::protocol::AppBehaviour;
use libp2p::{
    autonat, dcutr, gossipsub, identify, kad::{self, store::MemoryStore},
    noise, ping, swarm::Swarm, tcp, yamux, Multiaddr, PeerId, SwarmBuilder,
    StreamProtocol,
};
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
}

impl P2PNode {
    /// Inicializa o Nó P2P com Kademlia DHT, GossipSub, DCUtR e Criptografia Noise
    pub fn new(identity: UserIdentity, listen_port: u16) -> Result<Self, NodeError> {
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
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(|e| NodeError::SwarmInit(e.to_string()))?
            .with_behaviour(|key, relay_client| {
                // 1. Kademlia DHT com protocolo customizado de salas P2P
                let kad_store = MemoryStore::new(key.public().to_peer_id());
                let kad_protocol = StreamProtocol::new("/p2p-discord/kad/1.0.0");
                let kad_config = kad::Config::new(kad_protocol);
                let kademlia = kad::Behaviour::with_config(key.public().to_peer_id(), kad_store, kad_config);

                // 2. GossipSub (Chat de Texto em Malha)
                let gossip_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_millis(500))
                    .validation_mode(gossipsub::ValidationMode::Permissive)
                    .build()
                    .map_err(|e| NodeError::SwarmInit(e.to_string()))
                    .expect("Configuração GossipSub válida");
                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossip_config,
                )
                .expect("GossipSub behaviour válido");

                // 3. Identify com User Agent contendo o Nickname e PubKey
                let user_agent = format!("anarchord:{}:{}", identity.profile.display_name, identity.public_key_hex());
                let identify_config = identify::Config::new(
                    "/p2p-discord/1.0.0".to_string(),
                    key.public(),
                )
                .with_agent_version(user_agent);
                let identify = identify::Behaviour::new(identify_config);

                // 4. Ping
                let ping = ping::Behaviour::new(ping::Config::default());

                // 5. AutoNAT & DCUtR (Hole Punching)
                let autonat = autonat::Behaviour::new(key.public().to_peer_id(), autonat::Config::default());
                let dcutr = dcutr::Behaviour::new(key.public().to_peer_id());

                Ok(AppBehaviour {
                    kademlia,
                    gossipsub,
                    identify,
                    ping,
                    autonat,
                    dcutr,
                    relay_client,
                })
            })
            .map_err(|e| NodeError::SwarmInit(e.to_string()))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        // Escuta na porta especificada para TCP e QUIC
        let tcp_listen: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", listen_port).parse().unwrap();
        let quic_listen: Multiaddr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", listen_port).parse().unwrap();

        swarm.listen_on(tcp_listen).map_err(|e| NodeError::SwarmInit(e.to_string()))?;
        swarm.listen_on(quic_listen).map_err(|e| NodeError::SwarmInit(e.to_string()))?;

        Ok(Self {
            peer_id,
            identity,
            swarm,
        })
    }
}
