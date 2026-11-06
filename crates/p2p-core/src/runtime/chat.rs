//! Canais de texto: canal ativo, presença, envio e recebimento de mensagens.

use super::{CoreError, CoreEvent, ChannelInfo, PublishError, Runtime, ServerSummary, SpaceInfo};
use crate::api::ChatMessage;
use crate::community::{channel_topic, ChannelType, Space};
use libp2p::gossipsub::{self, IdentTopic};
use libp2p::PeerId;
use std::collections::{HashMap, HashSet};

/// Canal de texto em que o usuário está (espaço + nome + tópico inscrito)
pub struct ActiveChannel {
    pub space: Space,
    pub channel: String,
    pub topic: IdentTopic,
}

impl ActiveChannel {
    pub fn new(space: Space, channel: String) -> Self {
        let topic = IdentTopic::new(channel_topic(&space, &channel));
        Self { space, channel, topic }
    }

    /// Sai do tópico atual e entra no do novo canal. Não faz nada se já estiver nele.
    pub fn switch(&mut self, gossipsub: &mut gossipsub::Behaviour, space: Space, channel: String) -> Result<(), gossipsub::SubscriptionError> {
        if self.space == space && self.channel == channel {
            return Ok(());
        }
        let next = ActiveChannel::new(space, channel);
        gossipsub.subscribe(&next.topic)?;
        let _ = gossipsub.unsubscribe(&self.topic);
        *self = next;
        Ok(())
    }

    pub fn server_id(&self) -> Option<&str> {
        match &self.space {
            Space::Server(id) => Some(id),
            Space::Lobby => None,
        }
    }
}

/// Nicks dos pares Anarchord (identificados via Identify) inscritos no tópico do canal.
/// Suporta resolução através do Behaviour do GossipSub e também via rastreamento de eventos
/// `peer_topics` (garantindo barreira reativa determinística independente da ordem de chegada de Identify/Subscribed).
pub fn channel_members_with_topics(
    gossipsub: &gossipsub::Behaviour,
    peer_metadata: &HashMap<PeerId, (String, String)>,
    peer_topics: &HashMap<PeerId, HashSet<gossipsub::TopicHash>>,
    topic: &IdentTopic,
) -> Vec<String> {
    let topic_hash = topic.hash();
    let mut members: Vec<String> = peer_metadata
        .iter()
        .filter(|(peer, _)| {
            peer_topics.get(peer).is_some_and(|topics| topics.contains(&topic_hash))
                || gossipsub.all_peers().any(|(p, topics)| p == *peer && topics.contains(&&topic_hash))
        })
        .map(|(_, (nick, _))| nick.clone())
        .collect();
    members.sort();
    members.dedup();
    members
}

/// Nicks dos pares Anarchord inscritos no tópico do canal (compatibilidade com testes e API externa)
#[allow(dead_code)]
pub fn channel_members(gossipsub: &gossipsub::Behaviour, peer_metadata: &HashMap<PeerId, (String, String)>, topic: &IdentTopic) -> Vec<String> {
    channel_members_with_topics(gossipsub, peer_metadata, &HashMap::new(), topic)
}

impl Runtime {
    pub(super) fn send_chat(&mut self, text: &str) {
        if let Some(peer_pk) = self.dm.active_dm_peer.clone() {
            return self.send_dm(&peer_pk, text, None);
        }
        if let Some(server) = self.active.server_id().and_then(|id| self.servers.get(id)) {
            let me = self.my_pubkey();
            if server.is_banned(&me, super::now_secs()) {
                return self.error(CoreError::BannedHere);
            }
            if !server.is_allowed(&me, super::now_secs()) {
                return self.error(CoreError::NotOnAllowList);
            }
        }
        let message = ChatMessage::new_signed(&self.identity, &self.active.channel, text, super::now_millis());
        let topic = self.active.topic.clone();
        if let Err(PublishError::NoGroupKey) = self.publish_content(&topic, crate::wire::encode(&message)) {
            self.error(CoreError::NoGroupKey);
        }
    }

    pub(super) fn join_text_channel(&mut self, channel: String) {
        // No Lobby qualquer nome vira canal; num servidor, só os canais da configuração
        if let Some(server) = self.active.server_id().and_then(|id| self.servers.get(id)) {
            if !server.has_channel(&channel, ChannelType::Text) {
                return self.error(CoreError::NoSuchChannel { name: channel, voice: false });
            }
        }
        let space = self.active.space.clone();
        self.enter_channel(space, channel);
    }

    /// Entra num canal de texto de um espaço (Lobby ou servidor)
    pub(super) fn enter_channel(&mut self, space: Space, channel: String) {
        self.dm.active_dm_peer = None;
        if let Err(e) = self.active.switch(&mut self.node.swarm.behaviour_mut().gossipsub, space, channel) {
            return self.error(CoreError::Network(format!("{:?}", e)));
        }
        self.refresh_space();
        self.emit(CoreEvent::ChannelEntered { space: self.space_info(&self.active.space), channel: self.active.channel.clone() });
    }

    pub(super) fn space_info(&self, space: &Space) -> SpaceInfo {
        match space {
            Space::Lobby => SpaceInfo::Lobby,
            Space::Server(id) => SpaceInfo::Server { id: id.clone(), name: self.servers.get(id).filter(|s| s.has_chain()).map(|s| s.name()) },
        }
    }

    /// Nome, canais e membros do espaço atual
    pub(super) fn refresh_space(&mut self) {
        let channels = match self.active.server_id().and_then(|id| self.servers.get(id)) {
            Some(server) => server
                .channels()
                .into_iter()
                .map(|c| ChannelInfo { voice: c.channel_type == ChannelType::Voice, name: c.name })
                .collect(),
            None => Vec::new(),
        };
        self.emit(CoreEvent::SpaceChanged { space: self.space_info(&self.active.space), channels });
        self.publish_servers();
        self.publish_channel_members();
    }

    pub(super) fn publish_servers(&self) {
        let entries = self
            .servers
            .list()
            .map(|s| ServerSummary {
                name: s.name(),
                id: s.server_id.clone(),
                current: self.active.server_id() == Some(s.server_id.as_str()),
                owner: s.is_owner(),
                pending: !s.has_chain(),
            })
            .collect();
        self.emit(CoreEvent::ServersChanged(entries));
    }

    pub(super) fn publish_channel_members(&self) {
        let members = channel_members_with_topics(
            &self.node.swarm.behaviour().gossipsub,
            &self.peer_metadata,
            &self.peer_topics,
            &self.active.topic,
        );
        self.emit(CoreEvent::ChannelMembers { channel: self.active.channel.clone(), members });
    }

    /// Mensagem de chat recebida. `sender_matches` confere o autor com quem o MLS diz que enviou.
    pub(super) fn on_chat_message(&mut self, message: ChatMessage, source: Option<&PeerId>, sender_matches: bool) {
        if message.author_pubkey == self.my_pubkey() || !sender_matches {
            return;
        }
        let now = super::now_secs();
        let server = self.active.server_id().and_then(|id| self.servers.get(id));
        if !message.verify(source) {
            // Assinatura inválida ou publicada por outro par que não o autor
            tracing::debug!("Mensagem de chat não autêntica descartada (autor alegado: {})", message.author_name);
        } else if server.is_some_and(|s| s.is_banned(&message.author_pubkey, now)) {
            tracing::debug!("Mensagem de usuário banido descartada: {}", message.author_name);
        } else if server.is_some_and(|s| !s.is_allowed(&message.author_pubkey, now)) {
            tracing::debug!("Mensagem de quem está fora da allow-list descartada: {}", message.author_name);
        } else {
            if let Some(invite) = super::parse_invite(&message.text) {
                let known = self.servers.get(&invite).is_some();
                self.emit(CoreEvent::InviteReceived { from: message.author_name.clone(), server_id: invite.clone(), known });
                self.last_invite = Some(invite);
            }
            self.emit(CoreEvent::ChatMessage {
                channel: message.channel_id,
                author: message.author_name,
                author_pubkey: message.author_pubkey,
                text: message.text,
                timestamp: message.timestamp,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::community::channel_topic as space_channel_topic;
    use crate::{parse_agent_version, protocol::AppBehaviourEvent, P2PNode, UserIdentity};
    use futures::StreamExt;
    use libp2p::swarm::SwarmEvent;
    use libp2p::{identify, Multiaddr};
    use std::time::Duration;

    fn topic_for(channel: &str) -> IdentTopic {
        IdentTopic::new(space_channel_topic(&Space::Lobby, channel))
    }

    fn node(nick: &str) -> P2PNode {
        P2PNode::new(UserIdentity::generate_with_nick(nick), 0).expect("nó P2P deve iniciar")
    }

    fn record_identity(event: SwarmEvent<AppBehaviourEvent>, metadata: &mut HashMap<PeerId, (String, String)>) {
        if let SwarmEvent::Behaviour(AppBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) = event {
            if let Some(identity) = parse_agent_version(&info.agent_version) {
                metadata.insert(peer_id, identity);
            }
        }
    }

    /// Regressão: Bob conectado e inscrito em #canal aparece como membro da sala para Alice
    /// (e vice-versa), sem precisar mandar mensagem de chat antes.
    #[tokio::test]
    async fn test_connected_peer_appears_as_room_member_without_chatting() {
        let mut alice = node("Alice");
        let mut bob = node("Bob");
        // Canal exclusivo do teste, para não misturar com nós Anarchord reais na LAN (mDNS)
        let topic = topic_for(&format!("teste-{}", alice.peer_id));
        alice.swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
        bob.swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
        let bob_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", bob.listen_port).parse().unwrap();
        alice.swarm.dial(bob_addr).unwrap();

        let (mut alice_meta, mut bob_meta) = (HashMap::new(), HashMap::new());
        let result = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                tokio::select! {
                    ev = alice.swarm.select_next_some() => record_identity(ev, &mut alice_meta),
                    ev = bob.swarm.select_next_some() => record_identity(ev, &mut bob_meta),
                }
                let seen_by_alice = channel_members(&alice.swarm.behaviour().gossipsub, &alice_meta, &topic);
                let seen_by_bob = channel_members(&bob.swarm.behaviour().gossipsub, &bob_meta, &topic);
                if seen_by_alice == ["Bob"] && seen_by_bob == ["Alice"] {
                    break;
                }
            }
        })
        .await;
        assert!(result.is_ok(), "Alice e Bob deveriam se ver como membros da sala");
    }

    #[tokio::test]
    async fn test_peer_in_other_channel_is_not_a_member() {
        let mut alice = node("Alice");
        let mut bob = node("Bob");
        let geral = topic_for(&format!("geral-{}", alice.peer_id));
        let outro = topic_for(&format!("outro-{}", alice.peer_id));
        alice.swarm.behaviour_mut().gossipsub.subscribe(&geral).unwrap();
        bob.swarm.behaviour_mut().gossipsub.subscribe(&outro).unwrap();
        let bob_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", bob.listen_port).parse().unwrap();
        alice.swarm.dial(bob_addr).unwrap();

        let (mut alice_meta, mut bob_meta) = (HashMap::new(), HashMap::new());
        let _ = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                tokio::select! {
                    ev = alice.swarm.select_next_some() => record_identity(ev, &mut alice_meta),
                    ev = bob.swarm.select_next_some() => record_identity(ev, &mut bob_meta),
                }
                let bob_known = alice_meta.contains_key(&bob.peer_id);
                let bob_in_outro =
                    alice.swarm.behaviour().gossipsub.all_peers().any(|(p, topics)| p == &bob.peer_id && topics.contains(&&outro.hash()));
                if bob_known && bob_in_outro {
                    break;
                }
            }
        })
        .await;
        assert!(alice_meta.contains_key(&bob.peer_id), "Alice deveria ter identificado Bob");
        assert!(channel_members(&alice.swarm.behaviour().gossipsub, &alice_meta, &geral).is_empty());
        assert_eq!(channel_members(&alice.swarm.behaviour().gossipsub, &alice_meta, &outro), ["Bob"]);
    }
}
