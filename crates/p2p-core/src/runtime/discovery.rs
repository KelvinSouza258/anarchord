//! Descoberta econômica: buscas na DHT com intervalo adaptativo e troca de pares entre nós Anarchord.
//!
//! Cada busca na DHT Amino abre conexões com dezenas de nós do IPFS. Por isso:
//! - **Intervalo adaptativo:** enquanto uma busca não está resolvida (nenhum par Anarchord, ou
//!   nenhum membro online de um servidor), ela roda no intervalo base. Quando está resolvida, o
//!   intervalo dobra a cada busca até o máximo. Se deixar de estar resolvida (o par caiu), volta
//!   na hora para o intervalo base.
//! - **Resolvido não é buscado com frequência:** um servidor com membro online conectado só é
//!   buscado no intervalo máximo, para juntar grupos de membros que não se conhecem.
//! - **Troca de pares:** cada nó conta aos outros, num tópico próprio, quais pares Anarchord ele
//!   conhece e como alcançá-los. A DHT vira só o primeiro contato.

use super::{CoreEvent, NetworkEvent, Runtime};
use crate::community::server_dht_key;
use crate::relay::is_dialable_addr;
use crate::wire;
use libp2p::gossipsub::IdentTopic;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Tópico da troca de pares (todo nó Anarchord se inscreve)
pub const PEERS_TOPIC: &str = "p2p-anarchord/peers/v1";
/// Pares por anúncio
const MAX_SHARED_PEERS: usize = 20;
/// Endereços por par num anúncio
const MAX_ADDRESSES: usize = 6;
/// Acima disso, não disca mais pares recebidos na troca
const MAX_ANARCHORD_PEERS: usize = 50;

/// O que é buscado na DHT
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SearchKey {
    /// Chave de descoberta global do Anarchord
    Anarchord,
    /// Membros online de um servidor
    Server(String),
}

/// Agenda das buscas na DHT (sem IO, para teste)
#[derive(Debug)]
pub struct DhtSchedule {
    base: Duration,
    max: Duration,
    searches: HashMap<SearchKey, (Duration, Instant)>,
}

impl DhtSchedule {
    pub fn new(base: Duration, max: Duration) -> Self {
        Self { base, max, searches: HashMap::new() }
    }

    /// Diz se a busca deve rodar agora. `resolved`: já há o que a busca procura (pares conectados).
    pub fn due(&mut self, key: SearchKey, resolved: bool, now: Instant) -> bool {
        let (base, max) = (self.base, self.max);
        let (interval, next) = self.searches.entry(key).or_insert((base, now));
        // Deixou de estar resolvida com o intervalo alto: volta ao base e busca já
        if !resolved && *interval > base {
            *interval = base;
            *next = now;
        }
        if now < *next {
            return false;
        }
        *interval = if resolved { (*interval * 2).min(max) } else { base };
        *next = now + *interval;
        true
    }

    /// Esquece buscas que não existem mais (servidor removido)
    pub fn retain(&mut self, keep: impl Fn(&SearchKey) -> bool) {
        self.searches.retain(|key, _| keep(key));
    }

    /// Intervalo atual de uma busca (para teste e diagnóstico)
    pub fn interval(&self, key: &SearchKey) -> Option<Duration> {
        self.searches.get(key).map(|(interval, _)| *interval)
    }
}

/// Anúncio da troca de pares: pares Anarchord que este nó conhece e como alcançá-los
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerList {
    pub peers: Vec<SharedPeer>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SharedPeer {
    /// PeerId em bytes
    pub peer_id: Vec<u8>,
    pub addresses: Vec<String>,
}

impl wire::WireMessage for PeerList {
    const KIND: wire::Kind = wire::Kind::Peers;
}

/// Endereços que valem a pena repassar: diretos e alcançáveis, ou circuitos de relay
pub fn shareable_addresses(addresses: &[Multiaddr], allow_private: bool) -> Vec<Multiaddr> {
    addresses
        .iter()
        .filter(|addr| addr.iter().any(|p| p == Protocol::P2pCircuit) || is_dialable_addr(addr, allow_private))
        .take(MAX_ADDRESSES)
        .cloned()
        .collect()
}

/// Estado da descoberta no runtime
pub(super) struct DiscoveryState {
    pub schedule: DhtSchedule,
    /// Endereços que cada par Anarchord anunciou no Identify
    pub addresses: HashMap<PeerId, Vec<Multiaddr>>,
    /// Há par novo para contar aos outros
    pub peers_changed: bool,
    pub last_shared: Option<Instant>,
    /// Última tentativa de discar cada par indicado e com quais endereços. Não redisca um par
    /// inalcançável a cada anúncio, mas redisca na hora se os endereços mudarem (ex.: reserva no relay)
    pub dial_attempts: HashMap<PeerId, (Instant, Vec<Multiaddr>)>,
    pub redial_after: Duration,
    /// Intervalo do anúncio periódico e intervalo mínimo entre dois anúncios
    pub share_every: Duration,
    pub share_gap: Duration,
}

impl DiscoveryState {
    pub fn new(lab: bool) -> Self {
        let (base, max) = if lab { (5, 60) } else { (30, 600) };
        Self {
            schedule: DhtSchedule::new(Duration::from_secs(base), Duration::from_secs(max)),
            addresses: HashMap::new(),
            peers_changed: false,
            last_shared: None,
            dial_attempts: HashMap::new(),
            redial_after: Duration::from_secs(if lab { 30 } else { 300 }),
            share_every: Duration::from_secs(if lab { 10 } else { 120 }),
            share_gap: Duration::from_secs(if lab { 2 } else { 10 }),
        }
    }
}

impl Runtime {
    pub(super) fn subscribe_peer_exchange(&mut self) {
        let _ = self.node.swarm.behaviour_mut().gossipsub.subscribe(&IdentTopic::new(PEERS_TOPIC));
    }

    /// Pares Anarchord identificados e conectados
    pub(super) fn anarchord_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.identified.iter().filter(|p| self.connected_peers.contains(p))
    }

    /// Roda a cada segundo: buscas na DHT que estão na hora e o anúncio da troca de pares
    pub(super) fn discovery_tick(&mut self) {
        let now = Instant::now();
        if self.config.discovery {
            self.search_dht(now);
        }
        let share = &self.discovery;
        let due = match share.last_shared {
            None => share.peers_changed,
            Some(last) => {
                let elapsed = now.duration_since(last);
                (share.peers_changed && elapsed >= share.share_gap) || elapsed >= share.share_every
            }
        };
        if due {
            self.share_peers(now);
        }
    }

    fn search_dht(&mut self, now: Instant) {
        let has_anarchord = self.anarchord_peers().next().is_some();
        if self.discovery.schedule.due(SearchKey::Anarchord, has_anarchord, now) {
            self.node.dht_find_peers();
        }
        let servers: Vec<String> = self.servers.list().map(|s| s.server_id.clone()).collect();
        self.discovery.schedule.retain(|key| match key {
            SearchKey::Server(id) => servers.contains(id),
            SearchKey::Anarchord => true,
        });
        for id in servers {
            let topic = IdentTopic::new(crate::community::server_control_topic(&id)).hash();
            let member_online = self.node.swarm.behaviour().gossipsub.all_peers().any(|(_, topics)| topics.contains(&&topic));
            if self.discovery.schedule.due(SearchKey::Server(id.clone()), member_online, now) {
                self.node.dht_find(server_dht_key(&id));
            }
        }
    }

    /// Publica os pares Anarchord conhecidos (com os endereços que eles anunciaram)
    fn share_peers(&mut self, now: Instant) {
        self.discovery.last_shared = Some(now);
        self.discovery.peers_changed = false;
        let peers: Vec<SharedPeer> = self
            .anarchord_peers()
            .filter_map(|peer| {
                let addresses = shareable_addresses(self.discovery.addresses.get(peer)?, self.config.lab);
                (!addresses.is_empty()).then(|| SharedPeer { peer_id: peer.to_bytes(), addresses: addresses.iter().map(|a| a.to_string()).collect() })
            })
            .take(MAX_SHARED_PEERS)
            .collect();
        if peers.is_empty() {
            return;
        }
        let bytes = wire::encode(&PeerList { peers });
        // Sem ninguém no tópico a publicação falha, o que é normal
        let _ = self.publish_gossip(IdentTopic::new(PEERS_TOPIC), bytes);
    }

    /// Lista recebida: disca os pares que ainda não conhece. São só dicas: o Identify confirma quem é quem.
    pub(super) fn on_peer_list(&mut self, from: Option<PeerId>, list: PeerList) {
        let now = Instant::now();
        let redial_after = self.discovery.redial_after;
        self.discovery.dial_attempts.retain(|_, (at, _)| now.duration_since(*at) < redial_after);
        let mut known = self.anarchord_peers().count();
        let mut new = 0;
        for shared in list.peers.into_iter().take(MAX_SHARED_PEERS) {
            if known >= MAX_ANARCHORD_PEERS {
                break;
            }
            let Ok(peer) = PeerId::from_bytes(&shared.peer_id) else { continue };
            if peer == self.node.peer_id || self.connected_peers.contains(&peer) {
                continue;
            }
            let addresses: Vec<Multiaddr> = shared.addresses.iter().take(MAX_ADDRESSES).filter_map(|a| a.parse().ok()).collect();
            let addresses = shareable_addresses(&addresses, self.config.lab);
            if addresses.is_empty() || self.discovery.dial_attempts.get(&peer).is_some_and(|(_, tried)| *tried == addresses) {
                continue;
            }
            let opts = DialOpts::peer_id(peer).addresses(addresses.clone()).condition(PeerCondition::DisconnectedAndNotDialing).build();
            if self.node.swarm.dial(opts).is_ok() {
                self.discovery.dial_attempts.insert(peer, (now, addresses));
                new += 1;
                known += 1;
            }
        }
        if new > 0 {
            let from = from.map(|p| p.to_string()).unwrap_or_default();
            self.emit(CoreEvent::Network(NetworkEvent::PeerExchange { from, dialed: new }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    #[test]
    fn unresolved_search_runs_at_base_interval() {
        let mut schedule = DhtSchedule::new(secs(30), secs(600));
        let t0 = Instant::now();
        assert!(schedule.due(SearchKey::Anarchord, false, t0), "primeira busca é imediata");
        assert!(!schedule.due(SearchKey::Anarchord, false, t0 + secs(29)));
        assert!(schedule.due(SearchKey::Anarchord, false, t0 + secs(30)));
        assert_eq!(schedule.interval(&SearchKey::Anarchord), Some(secs(30)));
    }

    #[test]
    fn resolved_search_backs_off_up_to_max() {
        let mut schedule = DhtSchedule::new(secs(30), secs(600));
        let mut now = Instant::now();
        let mut intervals = Vec::new();
        for _ in 0..8 {
            assert!(schedule.due(SearchKey::Anarchord, true, now));
            let interval = schedule.interval(&SearchKey::Anarchord).unwrap();
            intervals.push(interval.as_secs());
            assert!(!schedule.due(SearchKey::Anarchord, true, now + interval - secs(1)));
            now += interval;
        }
        assert_eq!(intervals, vec![60, 120, 240, 480, 600, 600, 600, 600]);
    }

    #[test]
    fn losing_peers_resets_to_base_immediately() {
        let mut schedule = DhtSchedule::new(secs(30), secs(600));
        let mut now = Instant::now();
        for _ in 0..5 {
            schedule.due(SearchKey::Anarchord, true, now);
            now += schedule.interval(&SearchKey::Anarchord).unwrap();
        }
        // No meio de uma espera longa, o par cai: busca na hora e volta ao intervalo base
        let later = now - secs(300);
        assert!(schedule.due(SearchKey::Anarchord, false, later));
        assert_eq!(schedule.interval(&SearchKey::Anarchord), Some(secs(30)));
    }

    #[test]
    fn searches_are_independent_and_removed_servers_forgotten() {
        let mut schedule = DhtSchedule::new(secs(30), secs(600));
        let t0 = Instant::now();
        let guild = SearchKey::Server("guilda".into());
        assert!(schedule.due(SearchKey::Anarchord, true, t0));
        assert!(schedule.due(guild.clone(), false, t0));
        assert_eq!(schedule.interval(&SearchKey::Anarchord), Some(secs(60)));
        assert_eq!(schedule.interval(&guild), Some(secs(30)));
        schedule.retain(|key| *key == SearchKey::Anarchord);
        assert_eq!(schedule.interval(&guild), None);
    }

    #[test]
    fn only_reachable_or_circuit_addresses_are_shared() {
        let addresses: Vec<Multiaddr> = [
            "/ip4/127.0.0.1/tcp/4001",
            "/ip4/192.168.0.10/tcp/4001",
            "/ip4/8.8.8.8/udp/4001/quic-v1",
            "/ip4/8.8.8.8/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN/p2p-circuit",
        ]
        .iter()
        .map(|a| a.parse().unwrap())
        .collect();
        let shared = shareable_addresses(&addresses, false);
        assert_eq!(shared, vec![addresses[2].clone(), addresses[3].clone()]);
        // No laboratório, IP privado vale; loopback nunca
        assert_eq!(shareable_addresses(&addresses, true).len(), 3);
    }

    #[test]
    fn peer_list_roundtrip() {
        let list = PeerList { peers: vec![SharedPeer { peer_id: PeerId::random().to_bytes(), addresses: vec!["/ip4/8.8.8.8/tcp/4001".into()] }] };
        match wire::decode(&wire::encode(&list)).unwrap() {
            wire::Incoming::Peers(decoded) => assert_eq!(decoded, list),
            other => panic!("tipo errado: {:?}", other),
        }
    }
}
