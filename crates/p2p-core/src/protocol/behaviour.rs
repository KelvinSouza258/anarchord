use libp2p::{
    autonat, dcutr, gossipsub, identify, kad::{self, store::MemoryStore},
    ping, relay, swarm::NetworkBehaviour,
};

#[derive(NetworkBehaviour)]
pub struct AppBehaviour {
    pub kademlia: kad::Behaviour<MemoryStore>,
    pub gossipsub: gossipsub::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub autonat: autonat::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub relay_client: relay::client::Behaviour,
}
