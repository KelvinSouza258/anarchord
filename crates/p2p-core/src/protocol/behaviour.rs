use libp2p::{
    autonat, dcutr, gossipsub, identify, kad::{self, store::MemoryStore},
    mdns, ping, relay, swarm::NetworkBehaviour,
};

#[derive(NetworkBehaviour)]
pub struct AppBehaviour {
    pub kademlia: kad::Behaviour<MemoryStore>,
    pub gossipsub: gossipsub::Behaviour,
    pub identify: identify::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub ping: ping::Behaviour,
    pub autonat: autonat::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub relay_client: relay::client::Behaviour,
    /// Pedaços de arquivo do enxame, direto entre dois pares
    pub files: libp2p::request_response::Behaviour<crate::files::FileCodec>,
}
