//! Testes de integração com dois nós P2P reais conversando em localhost.
//! Cobrem o caminho que a aplicação usa: conexão TCP/QUIC, Identify com nick/pubkey,
//! inscrição em tópico e entrega de mensagens de chat via Gossipsub.

use futures::StreamExt;
use libp2p::gossipsub::{self, IdentTopic};
use libp2p::swarm::SwarmEvent;
use libp2p::{identify, Multiaddr, PeerId};
use p2p_core::community::{server_control_topic, ModKind, ServerEvent, ServerMessage, ServerRegistry};
use p2p_core::{
    api::pubkey_hex_from_peer_id, parse_agent_version, protocol::AppBehaviourEvent, ChatMessage, P2PNode, UserIdentity,
};
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

/// Conecta Alice a Bob e espera que Alice veja Bob inscrito em `topic`
async fn connect_and_wait_subscription(alice: &mut P2PNode, bob: &mut P2PNode, topic: &IdentTopic) {
    let bob_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", bob.listen_port).parse().unwrap();
    alice.swarm.dial(bob_addr).unwrap();
    let bob_id = bob.peer_id;
    let alice_id = alice.peer_id;
    let (mut alice_sees_bob, mut bob_sees_alice) = (false, false);
    tokio::time::timeout(TIMEOUT, async {
        while !(alice_sees_bob && bob_sees_alice) {
            match next_event(alice, bob).await {
                (Side::Alice, SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic: t })))
                    if peer_id == bob_id && t == topic.hash() => alice_sees_bob = true,
                (Side::Bob, SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic: t })))
                    if peer_id == alice_id && t == topic.hash() => bob_sees_alice = true,
                _ => {}
            }
        }
    })
    .await
    .expect("Alice e Bob deveriam se ver inscritos no tópico");
}

/// Próxima mensagem Gossipsub recebida por um dos lados, com o autor (source) informado pela rede
async fn next_message(alice: &mut P2PNode, bob: &mut P2PNode, want: Side) -> gossipsub::Message {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            if let (side, SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. }))) =
                next_event(alice, bob).await
            {
                if std::mem::discriminant(&side) == std::mem::discriminant(&want) {
                    return message;
                }
            }
        }
    })
    .await
    .expect("mensagem deveria chegar")
}

/// A assinatura do chat fica ligada a quem publicou: Bob aceita a mensagem genuína de Alice
/// e recusa uma mensagem em que Alice finge ser outra pessoa.
#[tokio::test]
async fn test_chat_author_is_bound_to_publisher() {
    let mut alice = node("Alice");
    let mut bob = node("Bob");
    let topic = unique_topic("auth");
    alice.swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    bob.swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    connect_and_wait_subscription(&mut alice, &mut bob, &topic).await;

    let genuine = ChatMessage::new_signed(&alice.identity, "geral", "sou a Alice", 1);
    alice.swarm.behaviour_mut().gossipsub.publish(topic.clone(), serde_json::to_vec(&genuine).unwrap()).unwrap();
    let received = next_message(&mut alice, &mut bob, Side::Bob).await;
    let msg: ChatMessage = serde_json::from_slice(&received.data).unwrap();
    assert_eq!(received.source, Some(alice.peer_id), "Strict: a rede informa quem publicou");
    assert!(msg.verify(received.source.as_ref()));

    // Alice se passa por uma terceira pessoa (Carol), assinando com a própria chave
    let carol = UserIdentity::generate_with_nick("Carol");
    let mut forged = ChatMessage::new_signed(&alice.identity, "geral", "sou a Carol", 2);
    forged.author_pubkey = carol.public_key_hex();
    forged.author_name = "Carol".into();
    alice.swarm.behaviour_mut().gossipsub.publish(topic.clone(), serde_json::to_vec(&forged).unwrap()).unwrap();
    let received = next_message(&mut alice, &mut bob, Side::Bob).await;
    let msg: ChatMessage = serde_json::from_slice(&received.data).unwrap();
    assert_eq!(msg.author_name, "Carol");
    assert!(!msg.verify(received.source.as_ref()), "falsificação deveria ser recusada");
}

/// Publica no tópico e entrega ao outro lado o que chegar, devolvendo os eventos do registro dele
async fn send_server_messages(
    alice: &mut P2PNode,
    bob: &mut P2PNode,
    from: Side,
    topic: &IdentTopic,
    messages: Vec<ServerMessage>,
    registry: &mut ServerRegistry,
    now: u64,
) -> Vec<ServerEvent> {
    let count = messages.len();
    for m in messages {
        let sender = match from {
            Side::Alice => &mut *alice,
            Side::Bob => &mut *bob,
        };
        sender.swarm.behaviour_mut().gossipsub.publish(topic.clone(), m.to_bytes().unwrap()).unwrap();
    }
    let receiver = match from {
        Side::Alice => Side::Bob,
        Side::Bob => Side::Alice,
    };
    let mut events = Vec::new();
    for _ in 0..count {
        let received = next_message(alice, bob, match receiver {
            Side::Alice => Side::Alice,
            Side::Bob => Side::Bob,
        })
        .await;
        // Quem publicou vem do PeerId (Strict), que embute a pubkey Ed25519
        let from_pubkey = received.source.as_ref().and_then(pubkey_hex_from_peer_id);
        let message = ServerMessage::from_bytes(&received.data).unwrap();
        events.extend(registry.handle_message(message, from_pubkey.as_deref(), now));
    }
    events
}

/// Protocolo de servidor pela rede, com a cadeia de configuração:
/// Bob entra e sincroniza; Alice (dona) certifica Bob como moderador; Bob bane alguém
/// (ação provisória); a manutenção da Alice consolida a ação num bloco que volta ao Bob.
#[tokio::test]
async fn test_server_chain_sync_and_moderation_over_network() {
    const T0: u64 = 1_800_000_000;
    let mut alice = node("Alice");
    let mut bob = node("Bob");

    let mut alice_servers = ServerRegistry::in_memory();
    let server_id = alice_servers.create("Rust Guild", &alice.identity.public_key_hex(), T0).unwrap();
    let mut bob_servers = ServerRegistry::in_memory();
    assert!(bob_servers.join(&server_id).unwrap());

    let control = IdentTopic::new(server_control_topic(&server_id));
    alice.swarm.behaviour_mut().gossipsub.subscribe(&control).unwrap();
    bob.swarm.behaviour_mut().gossipsub.subscribe(&control).unwrap();
    connect_and_wait_subscription(&mut alice, &mut bob, &control).await;

    // 1. Bob pede a cadeia; Alice responde; Bob sincroniza
    let request = bob_servers.chain_request(&server_id).unwrap();
    let events = send_server_messages(&mut alice, &mut bob, Side::Bob, &control, vec![request], &mut alice_servers, T0).await;
    let Some(ServerEvent::Reply { messages, .. }) = events.into_iter().next() else { panic!("Alice deveria responder") };
    let events = send_server_messages(&mut alice, &mut bob, Side::Alice, &control, messages, &mut bob_servers, T0).await;
    assert!(events.iter().any(|e| matches!(e, ServerEvent::ChainUpdated { height: 0, .. })), "{:?}", events);
    assert_eq!(bob_servers.get(&server_id).unwrap().name(), "Rust Guild");

    // 2. Alice certifica Bob (bloco novo)
    let cert_block = alice_servers.add_moderator(&server_id, &bob.identity.public_key_hex(), 1, T0 + 10).unwrap();
    send_server_messages(&mut alice, &mut bob, Side::Alice, &control, vec![cert_block], &mut bob_servers, T0 + 10).await;
    assert_eq!(bob_servers.get(&server_id).unwrap().level_of(&bob.identity.public_key_hex(), T0 + 10), Some(1));

    // 3. Bob (moderador) bane um spammer: ação provisória que chega à Alice
    let spammer = UserIdentity::generate().public_key_hex();
    let bob_identity = bob.identity.clone();
    let action = bob_servers.moderate(&server_id, &bob_identity, ModKind::Ban { until: None }, &spammer, "spam", T0 + 20).unwrap();
    let events = send_server_messages(&mut alice, &mut bob, Side::Bob, &control, vec![action], &mut alice_servers, T0 + 21).await;
    assert!(matches!(events.as_slice(), [ServerEvent::ActionAccepted { .. }]), "{:?}", events);
    assert!(alice_servers.get(&server_id).unwrap().is_banned(&spammer, T0 + 21));

    // 4. Manutenção da dona consolida; o bloco volta ao Bob e a ação sai da fila provisória
    let block = alice_servers.owner_maintenance(&server_id, T0 + 30).expect("consolidação");
    send_server_messages(&mut alice, &mut bob, Side::Alice, &control, vec![block], &mut bob_servers, T0 + 30).await;
    let bob_view = bob_servers.get(&server_id).unwrap();
    assert!(bob_view.chain().state().is_banned(&spammer, T0 + 30), "ban definitivo na cadeia");
    assert_eq!(bob_view.pending_actions().count(), 0);
}
