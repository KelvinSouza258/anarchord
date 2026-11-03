//! Rede: conexões, identificação, descoberta (mDNS, DHT, trackers), NAT e despacho das
//! mensagens recebidas nos tópicos.

use super::{CoreEvent, NetworkEvent, Runtime};
use crate::api::pubkey_hex_from_peer_id;
use crate::bootstrap::OPENTRACKER_SERVERS;
use crate::community::{self, server_dht_key};
use crate::files as swarm_files;
use crate::node::{parse_agent_version, DHT_DISCOVERY_NAMESPACE};
use crate::protocol::AppBehaviourEvent;
use crate::tracker::{make_info_hash, TorrentTrackerClient};
use crate::wire::{self, Incoming};
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::SwarmEvent;
use libp2p::{gossipsub, Multiaddr, PeerId};
use std::collections::HashMap;

impl Runtime {
    /// Trackers em uso: os informados e, com `public_defaults`, os públicos embutidos
    fn trackers(&self) -> Vec<String> {
        let mut trackers = self.config.trackers.clone();
        if self.config.public_defaults {
            trackers.extend(OPENTRACKER_SERVERS.iter().map(|t| t.to_string()));
        }
        trackers
    }

    /// Bootstrap da DHT e trackers BitTorrent (se a descoberta estiver ligada)
    pub(super) fn start_discovery(&mut self) {
        if !self.config.discovery {
            return;
        }
        let mut nodes = 0;
        if self.config.public_defaults {
            nodes += self.node.bootstrap_dht();
        }
        if !self.config.bootstrap.is_empty() {
            let bootstrap = self.config.bootstrap.clone();
            nodes += self.node.bootstrap_with(&bootstrap);
        }
        self.emit(CoreEvent::Network(NetworkEvent::DhtBootstrap { nodes }));

        let trackers = self.trackers();
        if trackers.is_empty() {
            return;
        }
        // Trackers em segundo plano: TCP e QUIC usam a mesma porta, então a porta anunciada vale para os dois
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        self.tracker_rx = Some(rx);
        let port = self.node.listen_port;
        let bt_peer_id = self.bt_peer_id();
        let events = self.events.clone();
        let interval = std::time::Duration::from_secs(if self.config.lab { 3 } else { 10 });
        tokio::task::spawn_blocking(move || {
            let info_hash = make_info_hash(DHT_DISCOVERY_NAMESPACE);
            loop {
                for tracker in &trackers {
                    if let Ok(peers) = TorrentTrackerClient::discover_peers(tracker, &info_hash, &bt_peer_id, port) {
                        for peer in peers {
                            let _ = events.send(CoreEvent::Network(NetworkEvent::TrackerPeer(peer.to_string())));
                            let _ = tx.send(format!("/ip4/{}/tcp/{}", peer.ip(), peer.port()));
                            if tx.send(format!("/ip4/{}/udp/{}/quic-v1", peer.ip(), peer.port())).is_err() {
                                return;
                            }
                        }
                        break;
                    }
                }
                std::thread::sleep(interval);
            }
        });
    }

    /// Desanuncia o nó dos trackers (event = stopped)
    pub(super) fn stop_discovery(&mut self) {
        if !self.config.discovery {
            return;
        }
        let info_hash = make_info_hash(DHT_DISCOVERY_NAMESPACE);
        let bt_peer_id = self.bt_peer_id();
        for tracker in self.trackers() {
            let _ = TorrentTrackerClient::announce_stopped(&tracker, &info_hash, &bt_peer_id, self.node.listen_port);
        }
    }

    fn bt_peer_id(&self) -> [u8; 20] {
        let bytes = self.node.peer_id.to_bytes();
        let mut id = [0u8; 20];
        let len = bytes.len().min(20);
        id[..len].copy_from_slice(&bytes[..len]);
        id
    }

    pub(super) fn search_dht(&mut self) {
        self.node.dht_find_peers();
        // Membros online dos servidores acompanhados
        for id in self.servers.list().map(|s| s.server_id.clone()).collect::<Vec<_>>() {
            self.node.dht_find(server_dht_key(&id));
        }
    }

    pub(super) fn dial_discovered(&mut self, address: String) {
        if let Ok(multiaddr) = address.parse::<Multiaddr>() {
            // O tracker repete os mesmos pares a cada 10 s: não redisca quem já está conectado
            if !self.dialed_open.contains(&multiaddr) {
                let _ = self.node.swarm.dial(multiaddr);
            }
        }
    }

    pub(super) fn handle_swarm_event(&mut self, event: SwarmEvent<AppBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => self.emit(CoreEvent::Network(NetworkEvent::Listening(address.to_string()))),
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                let address = endpoint.get_remote_address().clone();
                // Do lado de quem recebe, o endereço de uma conexão relayada é só /p2p/<id>
                let relayed = endpoint.is_relayed();
                // Avisa a primeira conexão e a primeira direta (ex.: depois do hole punching)
                let first = self.connected_peers.insert(peer_id);
                if first || (!relayed && self.relayed_only.remove(&peer_id)) {
                    if relayed {
                        self.relayed_only.insert(peer_id);
                    }
                    self.emit(CoreEvent::Network(NetworkEvent::Connected { peer_id: peer_id.to_string(), address: address.to_string(), relayed }));
                }
                if let libp2p::core::ConnectedPoint::Dialer { address, .. } = &endpoint {
                    self.dialed_open.insert(address.clone());
                }
                // A maioria das conexões é com nós do IPFS; os pares Anarchord aparecem quando o Identify confirma
                tracing::debug!("Conexão P2P com {} via {:?}", peer_id, endpoint.get_remote_address());
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, num_established, endpoint, .. } => {
                if let libp2p::core::ConnectedPoint::Dialer { address, .. } = &endpoint {
                    self.dialed_open.remove(address);
                }
                if num_established == 0 {
                    self.connected_peers.remove(&peer_id);
                    self.relayed_only.remove(&peer_id);
                    self.identified.remove(&peer_id);
                    self.relay_manager.remove_peer(&peer_id);
                    if let Some((nick, _)) = self.peer_metadata.get(&peer_id).cloned() {
                        self.emit(CoreEvent::PeerLeft { peer_id: peer_id.to_string(), nick });
                        let cause = cause.map(|c| c.to_string()).unwrap_or_default();
                        self.emit(CoreEvent::Network(NetworkEvent::ConnectionClosed { peer_id: peer_id.to_string(), cause }));
                        self.publish_channel_members();
                    }
                }
            }
            SwarmEvent::Behaviour(AppBehaviourEvent::Identify(libp2p::identify::Event::Received { peer_id, info, .. })) => {
                // Alimenta a tabela de roteamento da DHT com os endereços de quem fala Kademlia
                if info.protocols.contains(&libp2p::kad::PROTOCOL_NAME) {
                    for addr in &info.listen_addrs {
                        self.node.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                    }
                }
                // Pares que oferecem Circuit Relay v2 (HOP) viram candidatos a reserva
                if info.protocols.contains(&libp2p::relay::HOP_PROTOCOL_NAME) {
                    self.relay_manager.add_candidate(peer_id, &info.listen_addrs);
                    self.request_relay_reservations();
                }
                if let Some((nick, pubkey)) = parse_agent_version(&info.agent_version) {
                    // O Identify se repete a cada conexão: só avisa na primeira identificação ou se o nick mudou
                    let changed = self.peer_metadata.insert(peer_id, (nick.clone(), pubkey.clone())) != Some((nick.clone(), pubkey.clone()));
                    if self.identified.insert(peer_id) || changed {
                        self.emit(CoreEvent::PeerIdentified { peer_id: peer_id.to_string(), nick, pubkey });
                        self.publish_channel_members();
                    }
                }
            }
            SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic })) => {
                self.on_subscribed(peer_id, topic)
            }
            SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Unsubscribed { topic, .. })) => {
                if topic == self.active.topic.hash() {
                    self.publish_channel_members();
                }
            }
            SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => self.on_gossip_message(message),
            SwarmEvent::Behaviour(AppBehaviourEvent::Mdns(libp2p::mdns::Event::Discovered(list))) => {
                // Um par anuncia vários endereços: disca uma vez por par, com todos eles,
                // e só se não houver conexão nem discagem em andamento
                let mut by_peer: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
                for (peer_id, multiaddr) in list {
                    if peer_id != self.node.peer_id && !self.connected_peers.contains(&peer_id) {
                        by_peer.entry(peer_id).or_default().push(multiaddr);
                    }
                }
                for (peer_id, addresses) in by_peer {
                    tracing::debug!("Par local descoberto via mDNS: {} ({} endereços)", peer_id, addresses.len());
                    let opts = DialOpts::peer_id(peer_id).addresses(addresses).condition(PeerCondition::DisconnectedAndNotDialing).build();
                    let _ = self.node.swarm.dial(opts);
                }
            }
            SwarmEvent::Behaviour(AppBehaviourEvent::Files(event)) => self.on_files_event(event),
            // Provedores achados na DHT: outros nós Anarchord, membros de servidor ou quem tem um arquivo
            SwarmEvent::Behaviour(AppBehaviourEvent::Kademlia(libp2p::kad::Event::OutboundQueryProgressed {
                result: libp2p::kad::QueryResult::GetProviders(Ok(libp2p::kad::GetProvidersOk::FoundProviders { key, providers })),
                ..
            })) => {
                let file = self.files.engine.downloading().find(|cid| swarm_files::dht_key(cid) == key).copied();
                if let Some(cid) = file {
                    let found: Vec<PeerId> = providers.iter().filter(|p| **p != self.node.peer_id).copied().collect();
                    let actions = self.files.engine.add_providers(&cid, found, std::time::Instant::now());
                    self.apply_file_actions(actions);
                }
                for provider in providers {
                    if provider != self.node.peer_id && !self.connected_peers.contains(&provider) {
                        let opts = DialOpts::peer_id(provider).condition(PeerCondition::DisconnectedAndNotDialing).build();
                        let _ = self.node.swarm.dial(opts);
                    }
                }
            }
            // Endereço externo confirmado: (re)anuncia na DHT para o registro carregar esse endereço
            SwarmEvent::ExternalAddrConfirmed { address } => {
                self.emit(CoreEvent::Network(NetworkEvent::ExternalAddress(address.to_string())));
                if self.config.discovery {
                    self.node.dht_start_providing();
                    for id in self.servers.list().filter(|s| s.has_chain()).map(|s| s.server_id.clone()).collect::<Vec<_>>() {
                        self.node.dht_provide(server_dht_key(&id));
                    }
                    for cid in self.files.engine.providing() {
                        self.node.dht_provide(swarm_files::dht_key(&cid));
                    }
                }
            }
            SwarmEvent::Behaviour(AppBehaviourEvent::Autonat(libp2p::autonat::Event::StatusChanged { new, .. })) => match new {
                libp2p::autonat::NatStatus::Private => {
                    self.emit(CoreEvent::Network(NetworkEvent::BehindNat));
                    self.relay_manager.set_behind_nat(true);
                    self.request_relay_reservations();
                }
                libp2p::autonat::NatStatus::Public(addr) => {
                    tracing::info!("AutoNAT: nó publicamente acessível em {}", addr);
                    self.relay_manager.set_behind_nat(false);
                }
                libp2p::autonat::NatStatus::Unknown => {}
            },
            SwarmEvent::Behaviour(AppBehaviourEvent::RelayClient(libp2p::relay::client::Event::ReservationReqAccepted {
                relay_peer_id,
                renewal,
                ..
            })) => {
                if !renewal {
                    self.emit(CoreEvent::Network(NetworkEvent::RelayReserved(relay_peer_id.to_string())));
                }
            }
            SwarmEvent::ListenerClosed { listener_id, reason, .. } => {
                if let Some(relay) = self.relay_manager.listener_closed(listener_id) {
                    tracing::info!("Reserva no relay {} encerrada: {:?}", relay, reason);
                    self.request_relay_reservations();
                }
            }
            SwarmEvent::Behaviour(AppBehaviourEvent::Dcutr(libp2p::dcutr::Event { remote_peer_id, result })) => match result {
                Ok(_) => self.emit(CoreEvent::Network(NetworkEvent::HolePunched(remote_peer_id.to_string()))),
                Err(e) => self.emit(CoreEvent::Network(NetworkEvent::HolePunchFailed { peer_id: remote_peer_id.to_string(), error: e.to_string() })),
            },
            _ => {}
        }
    }

    /// Alguém entrou num tópico: presença, keyframe para quem começou a assistir, cadeia de servidor
    fn on_subscribed(&mut self, peer_id: PeerId, topic: gossipsub::TopicHash) {
        if topic == self.active.topic.hash() {
            self.publish_channel_members();
        }
        if self.screen.my_stream.is_some() && topic == self.screen.publish_topic.hash() {
            self.screen.engine.request_keyframe();
        }
        // Entrou no tópico de controle de um servidor que conhecemos: entrega a cadeia
        // (servidor fechado: só para quem está na allow-list)
        if let Some(server_id) = community::parse_server_control_topic(topic.as_str()).map(str::to_string) {
            let recently = self.last_snapshot_reply.get(&server_id).is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(2));
            let peer_pubkey = pubkey_hex_from_peer_id(&peer_id);
            let allowed = self
                .servers
                .get(&server_id)
                .is_some_and(|s| peer_pubkey.as_deref().is_some_and(|pk| s.is_allowed(pk, super::now_secs())));
            if !recently && allowed {
                let snapshot = self.servers.snapshot(&server_id);
                if !snapshot.is_empty() {
                    for message in &snapshot {
                        self.publish_server_message(&server_id, message);
                    }
                    self.last_snapshot_reply.insert(server_id, std::time::Instant::now());
                }
            }
        }
    }

    /// Mensagem num tópico. O tipo vem no envelope; conteúdo de servidor chega cifrado com MLS
    /// (que também autentica quem enviou: quem não está no grupo não produz nada que decifre).
    fn on_gossip_message(&mut self, message: gossipsub::Message) {
        let topic = message.topic.as_str().to_string();
        if let Some(server_id) = community::parse_server_control_topic(&topic).map(str::to_string) {
            let from = message.source.as_ref().and_then(pubkey_hex_from_peer_id);
            return match wire::decode_as(&message.data) {
                Ok(server_message) => self.handle_server_network_message(&server_id, server_message, from.as_deref()),
                Err(e) => tracing::debug!("Mensagem de servidor ilegível: {}", e),
            };
        }
        let mut data = message.data;
        let mut mls_sender: Option<String> = None;
        if let Some(server_id) = community::parse_server_content_topic(&topic) {
            match self.mls.decrypt(server_id, &data) {
                Ok(decrypted) => {
                    data = decrypted.plaintext;
                    mls_sender = Some(decrypted.sender);
                }
                Err(e) => return tracing::debug!("Conteúdo de servidor não decifrado: {}", e),
            }
        }
        // Autor declarado no pacote precisa ser quem o MLS diz que enviou
        let sender_matches = |author: &str| mls_sender.as_deref().is_none_or(|s| s == author);
        let incoming = match wire::decode(&data) {
            Ok(incoming) => incoming,
            Err(e) => return tracing::debug!("Mensagem descartada em {}: {}", topic, e),
        };
        let source = message.source;
        match incoming {
            Incoming::Chat(chat) => {
                let matches = sender_matches(&chat.author_pubkey);
                self.on_chat_message(chat, source.as_ref(), matches)
            }
            Incoming::Voice(packet) => {
                if sender_matches(&packet.sender_pubkey) {
                    self.on_voice_packet(packet)
                }
            }
            Incoming::Swarm(swarm) => {
                // Oferta: quem publicou precisa ser o dono da pubkey anunciada
                let authentic = match &swarm {
                    swarm_files::SwarmMessage::Offer(offer) => {
                        offer.publisher != self.my_pubkey()
                            && sender_matches(&offer.publisher)
                            && source.as_ref().and_then(pubkey_hex_from_peer_id).as_deref() == Some(offer.publisher.as_str())
                    }
                    _ => true,
                };
                if let (true, Some(source)) = (authentic, source) {
                    let actions = self.files.engine.on_gossip(source, &topic, swarm, std::time::Instant::now());
                    self.apply_file_actions(actions);
                }
            }
            Incoming::ScreenFrame(packet) => {
                if sender_matches(&packet.sender_pubkey) {
                    self.on_screen_frame(packet)
                }
            }
            Incoming::ScreenAnnounce(announce) => {
                if sender_matches(&announce.sender_pubkey) {
                    self.on_screen_announce(announce, &topic)
                }
            }
            Incoming::Server(_) => tracing::debug!("Mensagem de servidor fora do tópico de controle descartada"),
        }
    }

    /// Pede reserva nos relays candidatos que faltam (só age quando o AutoNAT indicou NAT)
    fn request_relay_reservations(&mut self) {
        for (relay, circuit_addr) in self.relay_manager.next_reservations() {
            match self.node.swarm.listen_on(circuit_addr.clone()) {
                Ok(listener_id) => {
                    self.relay_manager.track_reservation(listener_id, relay);
                    self.emit(CoreEvent::Network(NetworkEvent::RelayRequested { relay: relay.to_string(), address: circuit_addr.to_string() }));
                }
                Err(e) => tracing::warn!("Falha ao pedir reserva em {}: {:?}", circuit_addr, e),
            }
        }
    }
}
