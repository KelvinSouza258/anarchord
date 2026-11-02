//! Testes de integração com dois nós P2P reais conversando em localhost.
//! Cobrem o caminho que a aplicação usa: conexão TCP/QUIC, Identify com nick/pubkey,
//! inscrição em tópico e entrega de mensagens de chat via Gossipsub.

use futures::StreamExt;
use libp2p::gossipsub::{self, IdentTopic};
use libp2p::swarm::SwarmEvent;
use libp2p::{identify, Multiaddr, PeerId};
use p2p_core::{parse_agent_version, protocol::AppBehaviourEvent, ChatMessage, P2PNode, UserIdentity};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(20);

fn node(nick: &str) -> P2PNode {
    P2PNode::new(UserIdentity::generate_with_nick(nick), 0).expect("nó P2P deve iniciar")
}

/// Tópico exclusivo do teste, para não misturar com nós Anarchord reais na LAN (mDNS)
fn unique_topic(prefix: &str) -> IdentTopic {
    IdentTopic::new(format!("p2p-anarchord/channel/{}-{}", prefix, PeerId::random()))
}

enum Side {
    Alice,
    Bob,
}

async fn next_event(alice: &mut P2PNode, bob: &mut P2PNode) -> (Side, SwarmEvent<AppBehaviourEvent>) {
    tokio::select! {
        ev = alice.swarm.select_next_some() => (Side::Alice, ev),
        ev = bob.swarm.select_next_some() => (Side::Bob, ev),
    }
}

#[tokio::test]
async fn test_identify_exchanges_nick_and_pubkey() {
    let mut alice = node("Alice");
    let mut bob = node("Bob");
    let alice_pubkey = alice.identity.public_key_hex();
    let bob_pubkey = bob.identity.public_key_hex();

    let bob_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", bob.listen_port).parse().unwrap();
    alice.swarm.dial(bob_addr).unwrap();

    let (mut alice_saw, mut bob_saw) = (None, None);
    let bob_id = bob.peer_id;
    let alice_id = alice.peer_id;
    tokio::time::timeout(TIMEOUT, async {
        while alice_saw.is_none() || bob_saw.is_none() {
            if let (side, SwarmEvent::Behaviour(AppBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }))) =
                next_event(&mut alice, &mut bob).await
            {
                match side {
                    Side::Alice if peer_id == bob_id => alice_saw = parse_agent_version(&info.agent_version),
                    Side::Bob if peer_id == alice_id => bob_saw = parse_agent_version(&info.agent_version),
                    _ => {}
                }
            }
        }
    })
    .await
    .expect("Identify deveria ser trocado entre Alice e Bob");

    assert_eq!(alice_saw, Some(("Bob".to_string(), bob_pubkey)));
    assert_eq!(bob_saw, Some(("Alice".to_string(), alice_pubkey)));
}

#[tokio::test]
async fn test_chat_message_delivered_between_nodes() {
    let mut alice = node("Alice");
    let mut bob = node("Bob");
    let topic = unique_topic("chat");
    alice.swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    bob.swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();

    let bob_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", bob.listen_port).parse().unwrap();
    alice.swarm.dial(bob_addr).unwrap();

    // Espera Alice saber que Bob está no tópico antes de publicar
    let bob_id = bob.peer_id;
    tokio::time::timeout(TIMEOUT, async {
        loop {
            if let (Side::Alice, SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic: t }))) =
                next_event(&mut alice, &mut bob).await
            {
                if peer_id == bob_id && t == topic.hash() {
                    break;
                }
            }
        }
    })
    .await
    .expect("Alice deveria ver Bob inscrito no tópico do canal");

    let msg = ChatMessage {
        channel_id: "geral".to_string(),
        author_pubkey: alice.identity.public_key_hex(),
        author_name: "Alice".to_string(),
        text: "olá Bob".to_string(),
        timestamp: 0,
        signature: vec![],
    };
    alice
        .swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic.clone(), serde_json::to_vec(&msg).unwrap())
        .expect("publicação deveria encontrar Bob no tópico");

    let received = tokio::time::timeout(TIMEOUT, async {
        loop {
            if let (Side::Bob, SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. }))) =
                next_event(&mut alice, &mut bob).await
            {
                return serde_json::from_slice::<ChatMessage>(&message.data).unwrap();
            }
        }
    })
    .await
    .expect("Bob deveria receber a mensagem de Alice");

    assert_eq!(received.author_name, "Alice");
    assert_eq!(received.text, "olá Bob");
}

#[tokio::test]
async fn test_tcp_and_quic_listen_on_same_port() {
    let mut alice = node("Alice");
    let port = alice.listen_port;
    assert_ne!(port, 0);

    let (mut tcp_ok, mut quic_ok) = (false, false);
    tokio::time::timeout(TIMEOUT, async {
        while !(tcp_ok && quic_ok) {
            if let SwarmEvent::NewListenAddr { address, .. } = alice.swarm.select_next_some().await {
                let s = address.to_string();
                tcp_ok |= s.ends_with(&format!("/tcp/{}", port));
                quic_ok |= s.ends_with(&format!("/udp/{}/quic-v1", port));
            }
        }
    })
    .await
    .expect("TCP e QUIC deveriam escutar na mesma porta anunciada ao tracker");
}

#[tokio::test]
async fn test_quic_connection_on_shared_port() {
    let mut alice = node("Alice");
    let mut bob = node("Bob");
    let bob_quic: Multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", bob.listen_port).parse().unwrap();
    alice.swarm.dial(bob_quic).unwrap();

    let bob_id = bob.peer_id;
    tokio::time::timeout(TIMEOUT, async {
        loop {
            if let (Side::Alice, SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. }) =
                next_event(&mut alice, &mut bob).await
            {
                if peer_id == bob_id && endpoint.get_remote_address().to_string().contains("quic-v1") {
                    break;
                }
            }
        }
    })
    .await
    .expect("Alice deveria conectar no Bob via QUIC na porta compartilhada");
}
