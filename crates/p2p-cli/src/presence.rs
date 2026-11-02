use libp2p::gossipsub::{self, IdentTopic};
use libp2p::PeerId;
use std::collections::HashMap;

/// Tópico Gossipsub de um canal de texto
pub fn channel_topic(channel: &str) -> IdentTopic {
    IdentTopic::new(format!("p2p-anarchord/channel/{}", channel))
}

/// Nicks dos pares Anarchord (identificados via Identify) inscritos no tópico do canal.
/// É a presença exibida em "Membros da Sala" na TUI.
pub fn channel_members(
    gossipsub: &gossipsub::Behaviour,
    peer_metadata: &HashMap<PeerId, (String, String)>,
    topic: &IdentTopic,
) -> Vec<String> {
    let topic_hash = topic.hash();
    let mut members: Vec<String> = gossipsub
        .all_peers()
        .filter(|(_, topics)| topics.contains(&&topic_hash))
        .filter_map(|(peer, _)| peer_metadata.get(peer).map(|(nick, _)| nick.clone()))
        .collect();
    members.sort();
    members.dedup();
    members
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use libp2p::swarm::SwarmEvent;
    use libp2p::{identify, Multiaddr};
    use p2p_core::{parse_agent_version, protocol::AppBehaviourEvent, P2PNode, UserIdentity};
    use std::time::Duration;

    fn node(nick: &str) -> P2PNode {
        P2PNode::new(UserIdentity::generate_with_nick(nick), 0).expect("nó P2P deve iniciar")
    }

    fn record_identity(
        event: SwarmEvent<AppBehaviourEvent>,
        metadata: &mut HashMap<PeerId, (String, String)>,
    ) {
        if let SwarmEvent::Behaviour(AppBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) = event
        {
            if let Some(identity) = parse_agent_version(&info.agent_version) {
                metadata.insert(peer_id, identity);
            }
        }
    }

    /// Regressão: Bob conectado e inscrito em #canal deve aparecer como membro da sala para Alice
    /// (e vice-versa), sem precisar mandar mensagem de chat antes.
    #[tokio::test]
    async fn test_connected_peer_appears_as_room_member_without_chatting() {
        let mut alice = node("Alice");
        let mut bob = node("Bob");

        // Canal exclusivo do teste, para não misturar com nós Anarchord reais na LAN (mDNS)
        let topic = channel_topic(&format!("teste-{}", alice.peer_id));
        alice.swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
        bob.swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();

        let bob_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", bob.listen_port).parse().unwrap();
        alice.swarm.dial(bob_addr).unwrap();

        let mut alice_meta = HashMap::new();
        let mut bob_meta = HashMap::new();

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

        assert!(
            result.is_ok(),
            "Alice e Bob deveriam se ver como membros da sala. Alice vê {:?}, Bob vê {:?}",
            channel_members(&alice.swarm.behaviour().gossipsub, &alice_meta, &topic),
            channel_members(&bob.swarm.behaviour().gossipsub, &bob_meta, &topic),
        );
    }

    #[tokio::test]
    async fn test_peer_in_other_channel_is_not_a_member() {
        let mut alice = node("Alice");
        let mut bob = node("Bob");

        let geral = channel_topic(&format!("geral-{}", alice.peer_id));
        let outro = channel_topic(&format!("outro-{}", alice.peer_id));
        alice.swarm.behaviour_mut().gossipsub.subscribe(&geral).unwrap();
        bob.swarm.behaviour_mut().gossipsub.subscribe(&outro).unwrap();

        let bob_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", bob.listen_port).parse().unwrap();
        alice.swarm.dial(bob_addr).unwrap();

        let mut alice_meta = HashMap::new();
        let mut bob_meta = HashMap::new();
        let _ = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                tokio::select! {
                    ev = alice.swarm.select_next_some() => record_identity(ev, &mut alice_meta),
                    ev = bob.swarm.select_next_some() => record_identity(ev, &mut bob_meta),
                }
                let bob_known = alice_meta.contains_key(&bob.peer_id);
                let bob_in_outro = alice
                    .swarm
                    .behaviour()
                    .gossipsub
                    .all_peers()
                    .any(|(p, topics)| p == &bob.peer_id && topics.contains(&&outro.hash()));
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
