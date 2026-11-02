use libp2p::{core::transport::ListenerId, multiaddr::Protocol, Multiaddr, PeerId};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Quantidade de reservas simultâneas em relays públicos mantidas quando o nó está atrás de NAT
pub const MAX_RELAY_RESERVATIONS: usize = 2;

/// Seleciona relays públicos (Circuit Relay v2) e controla as reservas feitas neles.
///
/// Quando o AutoNAT conclui que o nó está atrás de NAT, o nó reserva um endereço
/// `/p2p/<relay>/p2p-circuit` em alguns pares que oferecem o protocolo HOP. Esse endereço
/// é anunciado (Identify e registros de provedor da DHT), outros nós conectam por ele
/// e o DCUtR tenta em seguida promover a conexão relayada para uma conexão direta (hole punching).
#[derive(Debug, Default)]
pub struct RelayManager {
    behind_nat: bool,
    /// Pares que oferecem o protocolo HOP -> endereço público direto escolhido para alcançá-los
    candidates: HashMap<PeerId, Multiaddr>,
    /// Reservas pendentes ou aceitas: listener do circuito -> relay
    reservations: HashMap<ListenerId, PeerId>,
    /// Relays que recusaram ou derrubaram a reserva (não são tentados de novo)
    failed: HashSet<PeerId>,
}

impl RelayManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Atualiza o estado de NAT informado pelo AutoNAT
    pub fn set_behind_nat(&mut self, behind_nat: bool) {
        self.behind_nat = behind_nat;
    }

    pub fn is_behind_nat(&self) -> bool {
        self.behind_nat
    }

    /// Registra um par que anunciou suporte ao protocolo HOP, guardando um endereço
    /// público direto (TCP ou QUIC) que este nó consegue discar
    pub fn add_candidate(&mut self, peer: PeerId, listen_addrs: &[Multiaddr]) {
        if self.failed.contains(&peer) {
            return;
        }
        if let Some(addr) = listen_addrs.iter().find(|a| is_dialable_public_addr(a)) {
            self.candidates.insert(peer, strip_peer_id(addr));
        }
    }

    /// Esquece um par que desconectou (a reserva nele, se houver, cai junto com a conexão)
    pub fn remove_peer(&mut self, peer: &PeerId) {
        self.candidates.remove(peer);
    }

    /// Relays que ainda devem receber pedido de reserva, como endereços de circuito prontos para `listen_on`.
    /// O chamador deve registrar o `ListenerId` retornado por `listen_on` com [`Self::track_reservation`].
    pub fn next_reservations(&self) -> Vec<(PeerId, Multiaddr)> {
        if !self.behind_nat {
            return Vec::new();
        }
        let reserved: HashSet<&PeerId> = self.reservations.values().collect();
        let missing = MAX_RELAY_RESERVATIONS.saturating_sub(self.reservations.len());
        self.candidates
            .iter()
            .filter(|(peer, _)| !reserved.contains(peer) && !self.failed.contains(peer))
            .take(missing)
            .map(|(peer, addr)| {
                let circuit = addr
                    .clone()
                    .with(Protocol::P2p(*peer))
                    .with(Protocol::P2pCircuit);
                (*peer, circuit)
            })
            .collect()
    }

    pub fn track_reservation(&mut self, listener: ListenerId, relay: PeerId) {
        self.reservations.insert(listener, relay);
    }

    /// Trata o fechamento do listener de um circuito (reserva recusada, expirada ou relay desconectado).
    /// Retorna o relay correspondente, se o listener era de uma reserva.
    pub fn listener_closed(&mut self, listener: ListenerId) -> Option<PeerId> {
        let relay = self.reservations.remove(&listener)?;
        self.failed.insert(relay);
        self.candidates.remove(&relay);
        Some(relay)
    }

    pub fn active_reservations(&self) -> usize {
        self.reservations.len()
    }
}

/// Endereço direto (não relayado), com IP público ou DNS, sobre TCP ou QUIC puros
fn is_dialable_public_addr(addr: &Multiaddr) -> bool {
    let mut has_public_host = false;
    let mut has_supported_transport = false;
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => has_public_host = is_public_ipv4(&ip),
            Protocol::Ip6(ip) => has_public_host = is_public_ipv6(&ip),
            Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) => has_public_host = true,
            Protocol::Tcp(_) | Protocol::QuicV1 => has_supported_transport = true,
            Protocol::P2pCircuit
            | Protocol::Ws(_)
            | Protocol::Wss(_)
            | Protocol::WebTransport
            | Protocol::WebRTCDirect
            | Protocol::Tls => return false,
            _ => {}
        }
    }
    has_public_host && has_supported_transport
}

fn is_public_ipv4(ip: &Ipv4Addr) -> bool {
    let shared_cgnat = ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64;
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || shared_cgnat)
}

fn is_public_ipv6(ip: &Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    let unique_local = (first & 0xfe00) == 0xfc00;
    let link_local = (first & 0xffc0) == 0xfe80;
    !(ip.is_loopback() || ip.is_unspecified() || unique_local || link_local)
}

/// Remove um `/p2p/<id>` final, já que o endereço de circuito adiciona o seu próprio
fn strip_peer_id(addr: &Multiaddr) -> Multiaddr {
    addr.iter()
        .filter(|p| !matches!(p, Protocol::P2p(_)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_only_public_direct_addrs_are_candidates() {
        assert!(is_dialable_public_addr(&addr("/ip4/8.8.8.8/tcp/4001")));
        assert!(is_dialable_public_addr(&addr("/ip4/8.8.8.8/udp/4001/quic-v1")));
        assert!(is_dialable_public_addr(&addr("/dns4/relay.example.com/tcp/4001")));
        assert!(!is_dialable_public_addr(&addr("/ip4/192.168.0.10/tcp/4001")));
        assert!(!is_dialable_public_addr(&addr("/ip4/127.0.0.1/tcp/4001")));
        assert!(!is_dialable_public_addr(&addr("/ip4/100.64.1.1/tcp/4001")));
        assert!(!is_dialable_public_addr(&addr("/ip4/8.8.8.8/tcp/443/wss")));
        assert!(!is_dialable_public_addr(&addr("/ip4/8.8.8.8/udp/4001/quic-v1/webtransport")));
    }

    #[test]
    fn test_reservations_only_when_behind_nat_and_capped() {
        let mut mgr = RelayManager::new();
        for i in 1..=4u8 {
            mgr.add_candidate(PeerId::random(), &[addr(&format!("/ip4/8.8.8.{}/tcp/4001", i))]);
        }
        assert!(mgr.next_reservations().is_empty());

        mgr.set_behind_nat(true);
        let next = mgr.next_reservations();
        assert_eq!(next.len(), MAX_RELAY_RESERVATIONS);
        for (peer, circuit) in &next {
            let protos: Vec<Protocol> = circuit.iter().collect();
            assert_eq!(protos[protos.len() - 2], Protocol::P2p(*peer));
            assert_eq!(protos[protos.len() - 1], Protocol::P2pCircuit);
        }
    }

    #[test]
    fn test_closed_reservation_is_not_retried() {
        let mut mgr = RelayManager::new();
        mgr.set_behind_nat(true);
        let relay = PeerId::random();
        mgr.add_candidate(relay, &[addr("/ip4/8.8.8.8/tcp/4001")]);

        let listener = ListenerId::next();
        mgr.track_reservation(listener, relay);
        assert!(mgr.next_reservations().is_empty());

        assert_eq!(mgr.listener_closed(listener), Some(relay));
        assert_eq!(mgr.active_reservations(), 0);
        mgr.add_candidate(relay, &[addr("/ip4/8.8.8.8/tcp/4001")]);
        assert!(mgr.next_reservations().is_empty());
    }
}
