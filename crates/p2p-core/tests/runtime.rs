//! Dois nós completos (`Core`) conversando em localhost só por comandos e eventos, como uma
//! interface faria: Lobby, servidor, convite, grupo cifrado, moderação e histórico.

use p2p_core::runtime::{
    Core, CoreCommand, CoreConfig, CoreError, CoreEvent, CoreHandle, ServerChange, ServerCommand, ServerNotice, SpaceInfo,
};
use p2p_core::UserIdentity;
use std::path::PathBuf;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(40);

struct Peer {
    handle: CoreHandle,
    /// Tudo o que o core já mandou
    seen: Vec<CoreEvent>,
}

impl Peer {
    fn send(&self, command: CoreCommand) {
        self.handle.send(command);
    }

    fn server(&self, command: ServerCommand) {
        self.send(CoreCommand::Server(command));
    }

    /// Lê eventos até algum (já recebido ou novo) satisfazer `pred`
    async fn wait(&mut self, what: &str, pred: impl Fn(&CoreEvent) -> bool) -> CoreEvent {
        if let Some(found) = self.seen.iter().find(|e| pred(e)) {
            return found.clone();
        }
        let result = tokio::time::timeout(TIMEOUT, async {
            loop {
                let event = self.handle.next_event().await.expect("core encerrou");
                self.seen.push(event.clone());
                if pred(&event) {
                    return event;
                }
            }
        })
        .await;
        result.unwrap_or_else(|_| panic!("tempo esgotado esperando: {}. Eventos vistos:\n{:#?}", what, self.seen))
    }

    /// Lê o que chegar por `duration`
    async fn drain(&mut self, duration: Duration) {
        let _ = tokio::time::timeout(duration, async {
            while let Some(event) = self.handle.next_event().await {
                self.seen.push(event);
            }
        })
        .await;
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("anarchord_runtime_{}_{}_{}", tag, std::process::id(), rand_suffix()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn rand_suffix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64
}

fn start(nick: &str, connect_to: Option<u16>) -> (Peer, p2p_core::runtime::CoreTask) {
    let mut config = CoreConfig::new(UserIdentity::generate_with_nick(nick), temp_dir(&format!("{}_srv", nick)), temp_dir(&format!("{}_down", nick)));
    // Canal exclusivo do teste, para não misturar com nós Anarchord reais na LAN (mDNS)
    config.channel = format!("teste-{}", rand_suffix());
    config.connect = connect_to.map(|port| format!("/ip4/127.0.0.1/tcp/{}", port).parse().unwrap());
    let (handle, task) = Core::start(config).expect("core deve iniciar");
    (Peer { handle, seen: Vec::new() }, task)
}

fn start_with_dirs(
    _nick: &str,
    identity: UserIdentity,
    srv_dir: PathBuf,
    down_dir: PathBuf,
    channel: String,
    connect_to: Option<u16>,
) -> (Peer, p2p_core::runtime::CoreTask) {
    let mut config = CoreConfig::new(identity, srv_dir, down_dir);
    config.channel = channel;
    config.connect = connect_to.map(|port| format!("/ip4/127.0.0.1/tcp/{}", port).parse().unwrap());
    let (handle, task) = Core::start(config).expect("core deve iniciar");
    (Peer { handle, seen: Vec::new() }, task)
}

fn chat_text(event: &CoreEvent) -> Option<&str> {
    match event {
        CoreEvent::ChatMessage { text, .. } => Some(text),
        _ => None,
    }
}

#[tokio::test]
async fn test_two_cores_server_lifecycle() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (mut alice, alice_task) = start("Alice", None);
            let alice_port = alice_task.listen_port();
            tokio::task::spawn_local(alice_task.run());
            let (mut bob, bob_task) = start("Bob", Some(alice_port));
            tokio::task::spawn_local(bob_task.run());

            let CoreEvent::PeerIdentified { pubkey: bob_pk, .. } =
                alice.wait("Alice identificar Bob", |e| matches!(e, CoreEvent::PeerIdentified { nick, .. } if nick == "Bob")).await
            else {
                unreachable!()
            };
            let CoreEvent::PeerIdentified { pubkey: alice_pk, .. } =
                bob.wait("Bob identificar Alice", |e| matches!(e, CoreEvent::PeerIdentified { nick, .. } if nick == "Alice")).await
            else {
                unreachable!()
            };

            // Alice cria o servidor e entra nele
            alice.server(ServerCommand::Create("Rust Guild".into()));
            let CoreEvent::Server(ServerNotice::Created { id, .. }) =
                alice.wait("servidor criado", |e| matches!(e, CoreEvent::Server(ServerNotice::Created { .. }))).await
            else {
                unreachable!()
            };
            let in_server = |id: String| move |e: &CoreEvent| matches!(e, CoreEvent::ChannelEntered { space: SpaceInfo::Server { id: sid, .. }, .. } if *sid == id);
            alice.wait("Alice entrar no servidor", in_server(id.clone())).await;

            // Convite no Lobby #geral: os dois precisam estar lá (o canal de teste é outro)
            alice.send(CoreCommand::Server(ServerCommand::Switch("lobby".into())));
            bob.send(CoreCommand::JoinChannel("geral".into()));
            alice.send(CoreCommand::JoinChannel("geral".into()));
            bob.wait("Bob ver Alice em #geral", |e| matches!(e, CoreEvent::ChannelMembers { channel, members } if channel == "geral" && members.iter().any(|m| m == "Alice"))).await;
            alice.send(CoreCommand::Server(ServerCommand::Switch("Rust Guild".into())));
            // Repete até a malha do #geral se formar (sem ninguém lá, o convite não é publicado)
            for _ in 0..20 {
                alice.server(ServerCommand::Invite);
                alice.drain(Duration::from_millis(500)).await;
                if alice.seen.iter().any(|e| matches!(e, CoreEvent::Server(ServerNotice::InviteSent { .. }))) {
                    break;
                }
            }
            alice.wait("convite publicado", |e| matches!(e, CoreEvent::Server(ServerNotice::InviteSent { .. }))).await;
            let sid = id.clone();
            bob.wait("convite chegar", move |e| matches!(e, CoreEvent::InviteReceived { server_id, .. } if *server_id == sid)).await;

            // Bob aceita, recebe a cadeia, entra e ganha a chave do grupo cifrado
            bob.server(ServerCommand::Accept);
            bob.wait("Bob entrar no servidor", in_server(id.clone())).await;
            bob.wait("Bob receber a chave do grupo", |e| matches!(e, CoreEvent::Server(ServerNotice::KeyReceived { .. }))).await;

            // Chat do servidor (cifrado de ponta a ponta); repete até a malha do tópico se formar
            let mut received = false;
            for _ in 0..20 {
                alice.send(CoreCommand::SendMessage("segredo do servidor".into()));
                bob.drain(Duration::from_millis(500)).await;
                if bob.seen.iter().any(|e| chat_text(e) == Some("segredo do servidor")) {
                    received = true;
                    break;
                }
            }
            assert!(received, "mensagem cifrada deveria chegar a Bob");

            // Sem certificado, Bob não modera
            bob.server(ServerCommand::Ban { target: "Alice".into(), duration: None, reason: String::new() });
            bob.wait("ban recusado sem certificado", |e| matches!(e, CoreEvent::Error(CoreError::Server(m)) if m.contains("não tem certificado"))).await;

            // O líder determinístico atual (menor pubkey entre Alice e Bob) gira a chave MLS (/server rotate-key)
            if alice_pk < bob_pk {
                alice.server(ServerCommand::RotateKey);
                alice.wait("Alice rotacionar chave MLS", |e| matches!(e, CoreEvent::Server(ServerNotice::KeyRotated { .. }))).await;
            } else {
                bob.server(ServerCommand::RotateKey);
                bob.wait("Bob rotacionar chave MLS", |e| matches!(e, CoreEvent::Server(ServerNotice::KeyRotated { .. }))).await;
            }

            // Alice cria um canal de texto e um canal de voz (que também é canal de texto com o mesmo nome!)
            alice.server(ServerCommand::AddChannel { name: "jogos".into(), voice: false });
            alice.server(ServerCommand::AddChannel { name: "taverna".into(), voice: true });
            alice.wait("canal taverna adicionado", |e| {
                matches!(e, CoreEvent::Server(ServerNotice::Changed { change: ServerChange::ChannelAdded { name, voice: true }, .. }) if name == "taverna")
            }).await;

            // Entrar por /join num canal de voz (taverna) deve ser aceito porque todo canal de voz é também de texto
            alice.send(CoreCommand::JoinChannel("taverna".into()));
            alice.wait("Alice entrar no chat de texto do canal de voz taverna", |e| {
                matches!(e, CoreEvent::ChannelEntered { channel, .. } if channel == "taverna")
            }).await;

            // Entrar por /voice join num canal de voz também deve trocar o canal de texto ativo automaticamente
            alice.send(CoreCommand::JoinChannel("geral".into()));
            alice.wait("Alice voltar para #geral", |e| matches!(e, CoreEvent::ChannelEntered { channel, .. } if channel == "geral")).await;
            alice.send(CoreCommand::JoinVoice("taverna".into()));
            alice.wait("Alice entrar na voz e texto de taverna", |e| {
                matches!(e, CoreEvent::ChannelEntered { channel, .. } if channel == "taverna")
            }).await;
            alice.send(CoreCommand::LeaveVoice);
            alice.send(CoreCommand::JoinChannel("geral".into()));

            // Alice certifica Bob como moderador nível 1
            alice.server(ServerCommand::AddModerator { target: "Bob".into(), level: 1 });
            alice
                .wait("Bob certificado", |e| matches!(e, CoreEvent::Server(ServerNotice::Changed { change: ServerChange::ModeratorAdded { level: 1, .. }, .. })))
                .await;
            bob.wait("Bob virar moderador", |e| matches!(e, CoreEvent::Server(ServerNotice::Role { level: Some(1), .. }))).await;

            // Moderador nível 1 não age sobre a dona (nível 0)
            bob.server(ServerCommand::Ban { target: "Alice".into(), duration: None, reason: String::new() });
            bob.wait("ban recusado pela regra de níveis", |e| matches!(e, CoreEvent::Error(CoreError::Server(m)) if m.contains("nível igual ou superior"))).await;

            // Alice revoga o certificado e bane Bob por 1 hora
            alice.server(ServerCommand::RemoveModerator("Bob".into()));
            alice.server(ServerCommand::Ban { target: "Bob".into(), duration: Some(3600), reason: "spam".into() });
            alice.wait("ban gravado", |e| matches!(e, CoreEvent::Server(ServerNotice::Moderated { recorded_by_owner: true, .. }))).await;
            bob.wait("Bob perder o certificado", |e| matches!(e, CoreEvent::Server(ServerNotice::Role { level: None, .. }))).await;
            bob.wait("Bob ser avisado do ban", |e| matches!(e, CoreEvent::Server(ServerNotice::BanStatus { banned: true, .. }))).await;

            // A manutenção da dona tira Bob do grupo cifrado; depois disso ele não lê mais nada
            bob.wait("Bob sair do grupo cifrado", |e| matches!(e, CoreEvent::Server(ServerNotice::RemovedFromGroup { .. }))).await;
            for _ in 0..4 {
                alice.send(CoreCommand::SendMessage("depois do ban".into()));
                bob.drain(Duration::from_millis(500)).await;
            }
            assert!(!bob.seen.iter().any(|e| chat_text(e) == Some("depois do ban")), "banido não lê mais o servidor");

            // O histórico (a cadeia) registra tudo
            bob.server(ServerCommand::History);
            let CoreEvent::Server(ServerNotice::History(history)) =
                bob.wait("histórico", |e| matches!(e, CoreEvent::Server(ServerNotice::History(_)))).await
            else {
                unreachable!()
            };
            let text: Vec<&str> = history.iter().map(|h| h.description.as_str()).collect();
            let joined = text.join("\n");
            assert!(joined.contains("criado 'Rust Guild'"), "{}", joined);
            assert!(joined.contains("certificado de moderador nível 1"), "{}", joined);
            assert!(joined.contains("revogado"), "{}", joined);
            assert!(joined.contains("dono baniu"), "{}", joined);

            alice.send(CoreCommand::Shutdown);
            alice.wait("Alice encerrar", |e| matches!(e, CoreEvent::Stopped)).await;
        })
        .await;
}

/// Arquivo compartilhado na sala chega a quem pede, tudo pelo core
#[tokio::test]
async fn test_two_cores_share_file_in_room() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (mut alice, alice_task) = start("Carol", None);
            let alice_port = alice_task.listen_port();
            tokio::task::spawn_local(alice_task.run());
            let (mut bob, bob_task) = start("Dave", Some(alice_port));
            tokio::task::spawn_local(bob_task.run());
            let room = format!("arquivos-{}", rand_suffix());
            for peer in [&alice, &bob] {
                peer.send(CoreCommand::JoinChannel(room.clone()));
            }
            let r = room.clone();
            alice.wait("Alice ver Bob na sala", move |e| matches!(e, CoreEvent::ChannelMembers { channel, members } if channel == &r && members.iter().any(|m| m == "Dave"))).await;

            let dir = temp_dir("arquivo");
            let path = dir.join("notas.txt");
            let data: Vec<u8> = (0..700_000).map(|i| (i % 251) as u8).collect();
            std::fs::write(&path, &data).unwrap();
            alice.send(CoreCommand::ShareFile(path));

            let CoreEvent::File(p2p_core::files::FileEvent::Offered { cid, .. }) =
                bob.wait("oferta chegar", |e| matches!(e, CoreEvent::File(p2p_core::files::FileEvent::Offered { .. }))).await
            else {
                unreachable!()
            };
            bob.send(CoreCommand::GetFile(cid.short()));
            let CoreEvent::File(p2p_core::files::FileEvent::Completed { path, .. }) =
                bob.wait("download terminar", |e| matches!(e, CoreEvent::File(p2p_core::files::FileEvent::Completed { .. }))).await
            else {
                unreachable!()
            };
            assert_eq!(std::fs::read(path).unwrap(), data);
        })
        .await;
}

/// Issue #68 & #66: Download interrompido retoma automaticamente ao iniciar o app,
/// reconecta aos seeders via tópico de enxame `anarchord/file/<cid>`, emite o progresso
/// inicial herdado (> 0.0) e conclui os pedaços restantes com sucesso
#[tokio::test]
async fn test_two_cores_resume_file_after_restart() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let alice_ident = UserIdentity::generate_with_nick("Alice");
            let alice_srv = temp_dir("alice_srv");
            let alice_down = temp_dir("alice_down");
            let room = format!("resume-room-{}", rand_suffix());

            let (mut alice, alice_task) = start_with_dirs("Alice", alice_ident.clone(), alice_srv, alice_down, room.clone(), None);
            let alice_port = alice_task.listen_port();
            tokio::task::spawn_local(alice_task.run());

            let bob_ident = UserIdentity::generate_with_nick("Bob");
            let bob_srv = temp_dir("bob_srv");
            let bob_down = temp_dir("bob_down");

            // Alice entra na sala e compartilha o arquivo
            let dir = temp_dir("orig_arquivo");
            let path = dir.join("grande.bin");
            let data: Vec<u8> = (0..800_000).map(|i| (i * 17 % 255) as u8).collect();
            std::fs::write(&path, &data).unwrap();

            alice.send(CoreCommand::JoinChannel(room.clone()));
            alice.send(CoreCommand::ShareFile(path.clone()));
            let CoreEvent::File(p2p_core::files::FileEvent::Shared { cid, .. }) =
                alice.wait("Alice concluir compartilhamento e semear", |e| {
                    matches!(e, CoreEvent::File(p2p_core::files::FileEvent::Shared { .. }))
                }).await
            else {
                unreachable!()
            };

            // Encontra o manifesto exato com o mesmo timestamp gerado por Alice
            let t_now = p2p_core::runtime::now_secs();
            let manifest = (t_now.saturating_sub(2)..=t_now + 2)
                .find_map(|t| {
                    p2p_core::files::Manifest::from_file(&path, &alice_ident, None, t)
                        .ok()
                        .filter(|m| m.cid() == cid)
                })
                .expect("manifesto correspondente ao CID da Alice");

            // Simula um download parcial interrompido em Bob: grava 2 de 4 pedaços no disco de Bob
            let partial_dir = bob_down.join(".parcial").join(&bob_ident.public_key_hex()[..8]);
            let alice_store = p2p_core::files::PieceStore::seed(manifest.clone(), path.clone(), None);
            let p0 = alice_store.serve_piece(0).unwrap();
            let p1 = alice_store.serve_piece(1).unwrap();
            {
                let mut bob_store = p2p_core::files::PieceStore::create(
                    &partial_dir,
                    manifest.clone(),
                    None,
                    Some(p2p_core::files::Origin::Topic(room.clone())),
                )
                .unwrap();
                bob_store.accept_piece(0, &p0).unwrap();
                bob_store.accept_piece(1, &p1).unwrap();
            }

            // Bob inicia pela primeira vez com o download já pendente na pasta .parcial
            let (mut bob, bob_task) = start_with_dirs("Bob", bob_ident, bob_srv, bob_down, room.clone(), Some(alice_port));
            tokio::task::spawn_local(bob_task.run());
            bob.send(CoreCommand::JoinChannel(room.clone()));

            // Issue #68: Bob emite imediatamente o progresso inicial herdado (50% = 0.5)
            bob.wait("Bob emitir progresso inicial herdado", |e| {
                matches!(e, CoreEvent::File(p2p_core::files::FileEvent::Progress { progress, .. }) if *progress >= 0.5)
            })
            .await;

            // Issue #66: Bob se conecta ao tópico anarchord/file/<cid> e conclui os 50% restantes
            let CoreEvent::File(p2p_core::files::FileEvent::Completed { path: downloaded_path, .. }) =
                bob.wait("Bob concluir download retomado", |e| {
                    matches!(e, CoreEvent::File(p2p_core::files::FileEvent::Completed { .. }))
                })
                .await
            else {
                unreachable!()
            };

            // Validação estrita de integridade via SHA-512 do arquivo antes e depois da transferência
            let original_sha512 = {
                use sha2::{Digest, Sha512};
                Sha512::digest(&data)
            };
            let downloaded_bytes = std::fs::read(downloaded_path).unwrap();
            let downloaded_sha512 = {
                use sha2::{Digest, Sha512};
                Sha512::digest(&downloaded_bytes)
            };
            assert_eq!(original_sha512, downloaded_sha512, "SHA-512 do arquivo retomado deve ser idêntico ao original");
            assert_eq!(downloaded_bytes, data);
        })
        .await;
}


/// Issue #74: Nós que iniciam no mesmo canal devem se ver mutuamente em ChannelMembers
/// ao se conectarem, sem precisar de JoinChannel manual nem de mensagem de chat.
#[tokio::test]
async fn test_two_cores_see_each_other_in_same_channel_on_connect() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let room = format!("geral-{}", rand_suffix());
            let (mut alice, alice_task) = start_with_dirs(
                "Alice",
                UserIdentity::generate_with_nick("Alice"),
                temp_dir("alice_srv"),
                temp_dir("alice_down"),
                room.clone(),
                None,
            );
            let alice_port = alice_task.listen_port();
            tokio::task::spawn_local(alice_task.run());

            let (mut bob, bob_task) = start_with_dirs(
                "Bob",
                UserIdentity::generate_with_nick("Bob"),
                temp_dir("bob_srv"),
                temp_dir("bob_down"),
                room.clone(),
                Some(alice_port),
            );
            tokio::task::spawn_local(bob_task.run());

            let r = room.clone();
            let r2 = room.clone();
            let alice_sees_bob = alice.wait("Alice ver Bob em ChannelMembers", move |e| {
                matches!(e, CoreEvent::ChannelMembers { channel, members } if channel == &r && members.iter().any(|m| m == "Bob"))
            });
            let bob_sees_alice = bob.wait("Bob ver Alice em ChannelMembers", move |e| {
                matches!(e, CoreEvent::ChannelMembers { channel, members } if channel == &r2 && members.iter().any(|m| m == "Alice"))
            });

            tokio::time::timeout(Duration::from_secs(10), async {
                tokio::join!(alice_sees_bob, bob_sees_alice);
            })
            .await
            .expect("Ambos os nós devem se ver em ChannelMembers após conexão direta");
        })
        .await;
}
