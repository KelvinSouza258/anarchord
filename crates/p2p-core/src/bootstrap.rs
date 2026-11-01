use libp2p::Multiaddr;

/// Lista oficial de nós públicos da DHT Amino do IPFS e LibP2P
pub const IPFS_BOOTSTRAP_NODES: &[&str] = &[
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoFeVvAhJWcadFstHaqww56zkvdCkp7i7eKvdVS",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
    "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
];

/// Lista de Open Trackers UDP públicos globais de alta disponibilidade
pub const OPENTRACKER_SERVERS: &[&str] = &[
    "tracker.opentrackr.org:1337",
    "open.stealth.si:80",
    "tracker.torrent.eu.org:451",
    "explodie.org:6969",
    "tracker.moeking.me:6969",
];

/// Retorna os nós de bootstrap convertidos em Multiaddr válidos
pub fn get_ipfs_bootstrap_multiaddrs() -> Vec<Multiaddr> {
    IPFS_BOOTSTRAP_NODES
        .iter()
        .filter_map(|s| s.parse::<Multiaddr>().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipfs_bootstrap_addresses_are_valid() {
        let addrs = get_ipfs_bootstrap_multiaddrs();
        assert_eq!(addrs.len(), IPFS_BOOTSTRAP_NODES.len());
        for addr in addrs {
            assert!(!addr.to_string().is_empty());
        }
    }

    #[test]
    fn test_opentrackers_list_not_empty() {
        assert!(!OPENTRACKER_SERVERS.is_empty());
        for tracker in OPENTRACKER_SERVERS {
            assert!(tracker.contains(':'));
        }
    }
}
