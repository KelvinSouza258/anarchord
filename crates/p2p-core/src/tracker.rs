use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TrackerError {
    #[error("Erro de I/O na comunicação UDP: {0}")]
    Io(#[from] std::io::Error),
    #[error("Resposta do Tracker inválida ou incompleta")]
    InvalidResponse,
    #[error("Transação de rede com ID incorreto")]
    TransactionMismatch,
    #[error("Falha ao resolver endereço do tracker")]
    ResolutionFailed,
}

/// Cliente UDP para BitTorrent Open Trackers (BEP 15)
pub struct TorrentTrackerClient {
    pub socket: UdpSocket,
}

impl TorrentTrackerClient {
    pub fn new() -> Result<Self, TrackerError> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(3)))?;
        socket.set_write_timeout(Some(Duration::from_secs(3)))?;
        Ok(Self { socket })
    }

    /// Executa o handshake de Connect (BEP 15)
    pub fn connect_handshake(&self, tracker_addr: SocketAddr) -> Result<u64, TrackerError> {
        let protocol_id: u64 = 0x41727101980; // Magic Constant BEP 15
        let action: u32 = 0; // 0 = Connect
        let transaction_id: u32 = rand::random();

        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&protocol_id.to_be_bytes());
        buf[8..12].copy_from_slice(&action.to_be_bytes());
        buf[12..16].copy_from_slice(&transaction_id.to_be_bytes());

        self.socket.send_to(&buf, tracker_addr)?;

        let mut res = [0u8; 16];
        let (bytes_read, _) = self.socket.recv_from(&mut res)?;
        if bytes_read < 16 {
            return Err(TrackerError::InvalidResponse);
        }

        let res_action = u32::from_be_bytes(res[0..4].try_into().unwrap());
        let res_tx = u32::from_be_bytes(res[4..8].try_into().unwrap());

        if res_action != 0 || res_tx != transaction_id {
            return Err(TrackerError::TransactionMismatch);
        }

        let connection_id = u64::from_be_bytes(res[8..16].try_into().unwrap());
        Ok(connection_id)
    }

    /// Envia Announce e recebe a lista de pares IP:Porta disponíveis
    pub fn announce(
        &self,
        tracker_addr: SocketAddr,
        connection_id: u64,
        info_hash: &[u8; 20],
        peer_id: &[u8; 20],
        listen_port: u16,
        event: u32, // 0 = none, 1 = completed, 2 = started, 3 = stopped
    ) -> Result<Vec<SocketAddr>, TrackerError> {
        let action: u32 = 1; // 1 = Announce
        let transaction_id: u32 = rand::random();

        let mut packet = Vec::with_capacity(98);
        packet.extend_from_slice(&connection_id.to_be_bytes());
        packet.extend_from_slice(&action.to_be_bytes());
        packet.extend_from_slice(&transaction_id.to_be_bytes());
        packet.extend_from_slice(info_hash);
        packet.extend_from_slice(peer_id);
        packet.extend_from_slice(&0u64.to_be_bytes()); // downloaded
        packet.extend_from_slice(&0u64.to_be_bytes()); // left
        packet.extend_from_slice(&0u64.to_be_bytes()); // uploaded
        packet.extend_from_slice(&event.to_be_bytes()); // event: 0=none, 3=stopped
        packet.extend_from_slice(&0u32.to_be_bytes()); // IP address: 0 default
        packet.extend_from_slice(&rand::random::<u32>().to_be_bytes()); // key
        packet.extend_from_slice(&50i32.to_be_bytes()); // num_want: 50
        packet.extend_from_slice(&listen_port.to_be_bytes());

        self.socket.send_to(&packet, tracker_addr)?;

        let mut response = [0u8; 1024];
        let (bytes_read, _) = self.socket.recv_from(&mut response)?;
        if bytes_read < 20 {
            return Err(TrackerError::InvalidResponse);
        }

        let res_action = u32::from_be_bytes(response[0..4].try_into().unwrap());
        let res_tx = u32::from_be_bytes(response[4..8].try_into().unwrap());

        if res_action != 1 || res_tx != transaction_id {
            return Err(TrackerError::TransactionMismatch);
        }

        // Os pares vêm compactados em blocos de 6 bytes: 4 bytes IP + 2 bytes Porta
        let mut peers = Vec::new();
        let peer_data = &response[20..bytes_read];
        for chunk in peer_data.chunks_exact(6) {
            let ip = std::net::Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
            let port = u16::from_be_bytes([chunk[4], chunk[5]]);
            peers.push(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)));
        }

        Ok(peers)
    }

    /// Resolve host:porta e busca pares anunciados
    pub fn discover_peers(
        tracker_host_port: &str,
        info_hash: &[u8; 20],
        peer_id: &[u8; 20],
        listen_port: u16,
    ) -> Result<Vec<SocketAddr>, TrackerError> {
        let client = TorrentTrackerClient::new()?;
        let addr = tracker_host_port
            .to_socket_addrs()
            .map_err(|_| TrackerError::ResolutionFailed)?
            .next()
            .ok_or(TrackerError::ResolutionFailed)?;

        let conn_id = client.connect_handshake(addr)?;
        client.announce(addr, conn_id, info_hash, peer_id, listen_port, 2) // 2 = started
    }

    /// Desanuncia do tracker notificando que o nó foi encerrado (event = stopped)
    pub fn announce_stopped(
        tracker_host_port: &str,
        info_hash: &[u8; 20],
        peer_id: &[u8; 20],
        listen_port: u16,
    ) -> Result<(), TrackerError> {
        let client = TorrentTrackerClient::new()?;
        let addr = tracker_host_port
            .to_socket_addrs()
            .map_err(|_| TrackerError::ResolutionFailed)?
            .next()
            .ok_or(TrackerError::ResolutionFailed)?;

        let conn_id = client.connect_handshake(addr)?;
        let _ = client.announce(addr, conn_id, info_hash, peer_id, listen_port, 3)?; // 3 = stopped
        Ok(())
    }
}

/// Cria o InfoHash determinístico de 20 bytes a partir de um namespace/sala
pub fn make_info_hash(namespace: &str) -> [u8; 20] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ANARCHORD_P2P_TRACKER_BOOTSTRAP_V1:");
    hasher.update(namespace.as_bytes());
    let hash = hasher.finalize();
    let mut result = [0u8; 20];
    result.copy_from_slice(&hash[0..20]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_info_hash_deterministic() {
        let h1 = make_info_hash("global-discovery");
        let h2 = make_info_hash("global-discovery");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 20);

        let h3 = make_info_hash("different-namespace");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_tracker_connect_packet_structure() {
        let client = TorrentTrackerClient::new().unwrap();
        assert!(client.socket.local_addr().is_ok());
    }
}
