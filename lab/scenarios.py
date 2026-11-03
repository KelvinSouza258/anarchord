"""Cenários do laboratório: testes de ponta a ponta com vários nós, cada um atrás do seu NAT.

Cada cenário recebe um `Lab` vazio, monta a topologia, sobe os contêineres (`await lab.up()`),
dirige os nós com comandos e valida com `wait`. Um passo que não acontece no tempo levanta
StepFailed, e o cenário falha com o log completo em lab/results/<cenário>/events.log.
"""

from anarlab import scenario
from anarlab.node import StepFailed

MB = 1024 * 1024


@scenario("Hole punching entre dois NATs cone")
async def hole_punching_cone(lab):
    a, b = lab.nat("a", "cone"), lab.nat("b", "cone")
    alice, bob = lab.peer("alice", a), lab.peer("bob", b)
    lab.relay()
    await lab.up()
    await lab.start_relay()
    await alice.start()
    await bob.start()

    lab.step("os dois detectam o NAT e reservam um endereço no relay")
    await lab.relay_address(alice)
    await lab.relay_address(bob)

    lab.step("Bob conecta em Alice pelo relay")
    await lab.connect(bob, alice)

    lab.step("DCUtR promove a conexão para direta")
    direct = lambda c: not c["relayed"]
    await bob.wait("Network.Connected", where=lambda c: c["peer_id"] == alice.peer_id and direct(c), desc="conexão direta com Alice")

    lab.step("chat funciona pela conexão")
    await lab.join_room("sala", alice, bob)
    alice.send({"SendMessage": "olá pelo buraco no NAT"})
    await bob.wait("ChatMessage", where=lambda m: m["text"] == "olá pelo buraco no NAT")


@scenario("NAT simétrico: tudo passa pelo relay")
async def symmetric_nat_relay(lab):
    a, b = lab.nat("a", "symmetric"), lab.nat("b", "symmetric")
    alice, bob = lab.peer("alice", a), lab.peer("bob", b)
    lab.relay()
    await lab.up()
    await lab.start_relay()
    await alice.start()
    await bob.start()

    lab.step("conexão pelo relay")
    await lab.connect(bob, alice)
    await bob.wait("Network.Connected", where=lambda c: c["peer_id"] == alice.peer_id and c["relayed"], desc="conexão relayada")

    lab.step("chat e arquivo pelo relay")
    await lab.join_room("sala", alice, bob)
    alice.send({"SendMessage": "via relay"})
    await bob.wait("ChatMessage", where=lambda m: m["text"] == "via relay")
    digest = await alice.make_file("/data/relatorio.bin", 2 * MB)
    alice.send({"ShareFile": "/data/relatorio.bin"})
    offer = await bob.wait("File.Offered", where=lambda o: o["name"] == "relatorio.bin")
    bob.send({"GetFile": offer["cid"][8:16]})
    await bob.wait("File.Completed", where=lambda c: c["name"] == "relatorio.bin", timeout=120)
    await lab.same_file({bob: f"{bob.downloads}/relatorio.bin"}, digest)

    lab.step("sem conexão direta (o NAT simétrico impede o hole punching)")
    if bob.find("Network.Connected", where=lambda c: c["peer_id"] == alice.peer_id and not c["relayed"]):
        raise StepFailed("conexão direta não era esperada atrás de NAT simétrico")


@scenario("Chat entre três LANs")
async def chat_three_lans(lab):
    nodes = [lab.peer(name, lab.nat(name)) for name in ("alice", "bob", "carol")]
    alice, bob, carol = nodes
    lab.relay()
    await lab.up()
    await lab.start_relay()
    for node in nodes:
        await node.start()

    lab.step("malha completa: Bob e Carol conectam em Alice, Carol em Bob")
    await lab.connect(bob, alice)
    await lab.connect(carol, alice)
    await lab.connect(carol, bob)
    await lab.join_room("geral3", *nodes)

    lab.step("cada um fala; todos recebem de todos, com o autor certo")
    for node in nodes:
        node.send({"SendMessage": f"oi de {node.nick}"})
    for node in nodes:
        for other in nodes:
            if other is not node:
                await node.wait(
                    "ChatMessage",
                    where=lambda m, o=other: m["text"] == f"oi de {o.nick}" and m["author"] == o.nick and m["author_pubkey"],
                    desc=f"mensagem de {other.nick}",
                )


@scenario("Enxame: quem baixou distribui depois que o publicador sai")
async def file_swarm(lab):
    alice, bob, carol = (lab.peer(n, lab.nat(n)) for n in ("alice", "bob", "carol"))
    lab.relay()
    await lab.up()
    await lab.start_relay()
    for node in (alice, bob, carol):
        await node.start()
    await lab.connect(bob, alice)
    await lab.connect(carol, alice)
    await lab.connect(carol, bob)
    await lab.join_room("arquivos", alice, bob, carol)

    lab.step("Alice compartilha 6 MB; todos veem a oferta")
    digest = await alice.make_file("/data/filme.bin", 6 * MB)
    alice.send({"ShareFile": "/data/filme.bin"})
    offer = await bob.wait("File.Offered", where=lambda o: o["name"] == "filme.bin")
    await carol.wait("File.Offered", where=lambda o: o["name"] == "filme.bin")
    file_id = offer["cid"][8:16]

    lab.step("Bob baixa tudo")
    bob.send({"GetFile": file_id})
    await bob.wait("File.Completed", where=lambda c: c["name"] == "filme.bin", timeout=180)

    lab.step("Alice cai; Carol baixa de Bob")
    await alice.kill()
    carol.send({"GetFile": file_id})
    await carol.wait("File.Completed", where=lambda c: c["name"] == "filme.bin", timeout=180)
    await lab.same_file({bob: f"{bob.downloads}/filme.bin", carol: f"{carol.downloads}/filme.bin"}, digest)


@scenario("Download interrompido retoma depois de reiniciar")
async def resume_download(lab):
    # Banda de conexão doméstica: o download leva tempo suficiente para ser interrompido no meio
    # (netem age na saída da interface: quem envia os dados é a Alice)
    alice, bob = lab.peer("alice", lab.nat("a"), netem="rate 8mbit"), lab.peer("bob", lab.nat("b"))
    lab.relay()
    await lab.up()
    await lab.start_relay()
    await alice.start()
    await bob.start()
    await lab.connect(bob, alice)
    await lab.join_room("arquivos", alice, bob)

    digest = await alice.make_file("/data/grande.bin", 24 * MB)
    alice.send({"ShareFile": "/data/grande.bin"})
    offer = await bob.wait("File.Offered", where=lambda o: o["name"] == "grande.bin")

    lab.step("Bob começa a baixar e cai no meio")
    bob.send({"GetFile": offer["cid"][8:16]})
    await bob.wait("File.Progress", where=lambda p: p["progress"] > 0.05, timeout=120, desc="algum progresso")
    mark_alice = alice.mark()
    await bob.kill()
    # Espera a Alice perceber a queda (a conexão antiga expira por inatividade). Se o Bob voltasse
    # antes, o gossipsub dela não reenviaria as inscrições na conexão nova (limitação do libp2p)
    await alice.wait("PeerLeft", where=lambda p: p["peer_id"] == bob.peer_id, since=mark_alice, timeout=90, desc="perceber a queda de Bob")
    partial = await bob.sh("ls /data/agent/downloads/.parcial/*/ | wc -l")
    if int(partial) == 0:
        raise StepFailed("o download parcial deveria ficar em disco")

    lab.step("Bob volta, reconecta e o download continua de onde parou")
    mark = bob.mark()
    await bob.start()
    await bob.wait("File.Started", where=lambda s: s["name"] == "grande.bin", since=mark, desc="download retomado")
    await lab.connect(bob, alice)
    await bob.wait("File.Completed", where=lambda c: c["name"] == "grande.bin", since=mark, timeout=240)
    await lab.same_file({bob: f"{bob.downloads}/grande.bin"}, digest)


@scenario("Servidor entre NATs: convite, grupo cifrado, moderação e ban")
async def server_lifecycle(lab):
    alice, bob = lab.peer("alice", lab.nat("a")), lab.peer("bob", lab.nat("b"))
    lab.relay()
    await lab.up()
    await lab.start_relay()
    await alice.start()
    await bob.start()
    await lab.connect(bob, alice)
    await lab.join_room("geral", alice, bob)

    lab.step("Alice cria o servidor e convida no Lobby #geral")
    alice.server({"Create": "Guilda"})
    created = await alice.wait("Server.Created")
    server_id = created["id"]
    alice.server("Invite")
    await alice.wait("Server.InviteSent")
    await bob.wait("InviteReceived", where=lambda i: i["server_id"] == server_id)

    lab.step("Bob aceita, recebe a configuração e a chave do grupo cifrado")
    bob.server("Accept")
    in_server = lambda c: isinstance(c["space"], dict) and c["space"].get("Server", {}).get("id") == server_id
    await bob.wait("ChannelEntered", where=in_server, timeout=60)
    await bob.wait("Server.KeyReceived", timeout=60)

    lab.step("chat cifrado do servidor chega")
    for _ in range(20):
        alice.send({"SendMessage": "segredo"})
        try:
            await bob.wait("ChatMessage", where=lambda m: m["text"] == "segredo", timeout=1)
            break
        except StepFailed:
            continue
    await bob.wait("ChatMessage", where=lambda m: m["text"] == "segredo")

    lab.step("moderação por níveis")
    alice.server({"AddModerator": {"target": "Bob", "level": 1}})
    await bob.wait("Server.Role", where=lambda r: r["level"] == 1)
    bob.server({"Ban": {"target": "Alice", "duration": None, "reason": ""}})
    await bob.wait("Error.Server", where=lambda m: "nível igual ou superior" in m)

    lab.step("Alice bane Bob: ele sai do grupo cifrado e não lê mais nada")
    alice.server({"Ban": {"target": "Bob", "duration": 3600, "reason": "teste"}})
    await bob.wait("Server.BanStatus", where=lambda b: b["banned"])
    await bob.wait("Server.RemovedFromGroup", timeout=60)
    mark = bob.mark()
    for _ in range(3):
        alice.send({"SendMessage": "depois do ban"})
    await bob.expect_none("ChatMessage", where=lambda m: m["text"] == "depois do ban", since=mark, during=4)


@scenario("Voz e tela entre NATs")
async def voice_and_screen(lab):
    alice, bob = lab.peer("alice", lab.nat("a")), lab.peer("bob", lab.nat("b"))
    lab.relay()
    await lab.up()
    await lab.start_relay()
    await alice.start("--synth-audio", "--synth-video", "--auto-voice", "sala")
    await bob.start("--auto-voice", "sala")
    await lab.connect(bob, alice)

    lab.step("Bob ouve Alice na sala de voz")
    await bob.wait("Voice.Speaking", where=lambda s: s["nick"] == "Alice" and s["speaking"], desc="Alice falando")

    lab.step("Bob vê a tela anunciada e assiste")
    await bob.wait("Screen.StreamAvailable", where=lambda s: s["nick"] == "Alice")
    bob.send({"WatchScreen": {"query": "Alice"}})
    await bob.wait("Screen.Watching")
    frames = await bob.wait("Screen.FrameReceived", where=lambda f: f["seq"] >= 120 and f["bytes"] > 0, timeout=60)
    if (frames["width"], frames["height"]) != (640, 360):
        raise StepFailed(f"resolução inesperada: {frames}")


@scenario("Rede ruim: perda e latência no enxame e no chat")
async def lossy_network(lab):
    alice = lab.peer("alice", lab.nat("a"), netem="delay 60ms 20ms loss 3%")
    bob = lab.peer("bob", lab.nat("b"), netem="delay 40ms loss 3%")
    lab.relay()
    await lab.up()
    await lab.start_relay()
    await alice.start()
    await bob.start()
    await lab.connect(bob, alice, timeout=90)
    await lab.join_room("sala", alice, bob, timeout=90)

    lab.step("chat chega mesmo com perda")
    for i in range(5):
        alice.send({"SendMessage": f"msg {i}"})
    for i in range(5):
        await bob.wait("ChatMessage", where=lambda m, i=i: m["text"] == f"msg {i}", timeout=60)

    lab.step("arquivo de 3 MB chega íntegro")
    digest = await alice.make_file("/data/ruim.bin", 3 * MB)
    alice.send({"ShareFile": "/data/ruim.bin"})
    offer = await bob.wait("File.Offered", where=lambda o: o["name"] == "ruim.bin", timeout=60)
    bob.send({"GetFile": offer["cid"][8:16]})
    await bob.wait("File.Completed", where=lambda c: c["name"] == "ruim.bin", timeout=240)
    await lab.same_file({bob: f"{bob.downloads}/ruim.bin"}, digest)


# ---------------------------------------------------------------------- bootstrap e --connect
# Tudo em rede isolada: nenhum nó conhece os bootstraps do IPFS nem os trackers públicos, e o
# mDNS fica desligado. Se os pares se acham, foi pelo mecanismo que o cenário está testando.


@scenario("--connect direto entre dois nós públicos")
async def connect_direct(lab):
    alice, bob = lab.public("alice"), lab.public("bob")
    await lab.up()
    await alice.start("--no-discovery")
    await bob.start("--no-discovery", "--connect", alice.address)
    await bob.wait("PeerIdentified", where=lambda p: p["nick"] == "Alice", desc="identificar Alice")
    await alice.wait("PeerIdentified", where=lambda p: p["nick"] == "Bob", desc="identificar Bob")
    await bob.wait("Network.Connected", where=lambda c: c["peer_id"] == alice.peer_id and not c["relayed"])


@scenario("--connect de dentro de um NAT para um nó público")
async def connect_from_behind_nat(lab):
    alice = lab.public("alice")
    bob = lab.peer("bob", lab.nat("b"))
    await lab.up()
    await alice.start("--no-discovery")
    await bob.start("--no-discovery", "--connect", alice.address)
    await alice.wait("PeerIdentified", where=lambda p: p["nick"] == "Bob", desc="Alice ver Bob (conexão de saída pelo NAT)")

    lab.step("chat pela conexão que Bob abriu")
    await lab.join_room("sala", alice, bob)
    bob.send({"SendMessage": "saindo pelo NAT"})
    await alice.wait("ChatMessage", where=lambda m: m["text"] == "saindo pelo NAT")


@scenario("Bootstrap só pelo tracker BitTorrent do laboratório")
async def tracker_bootstrap(lab):
    tracker = lab.tracker()
    alice, bob = lab.public("alice"), lab.public("bob")
    await lab.up()
    await alice.start("--tracker", tracker)
    await bob.start("--tracker", tracker)

    lab.step("o tracker apresenta um ao outro")
    await bob.wait("Network.TrackerPeer", where=lambda p: p.startswith(alice.ip + ":"), desc="Alice no tracker")
    await bob.wait("PeerIdentified", where=lambda p: p["nick"] == "Alice", desc="identificar Alice")
    await alice.wait("PeerIdentified", where=lambda p: p["nick"] == "Bob", desc="identificar Bob")
    if alice.find("Network.DhtBootstrap", where=lambda b: b["nodes"] > 0):
        raise StepFailed("sem --bootstrap, a DHT não deveria ter nós de bootstrap")


@scenario("Bootstrap só pela DHT de um nó raiz")
async def dht_root_bootstrap(lab):
    alice, bob = lab.public("alice"), lab.public("bob")
    lab.root()
    await lab.up()
    await lab.start_root()
    await alice.start()
    await bob.start()

    lab.step("os dois entram na DHT pelo nó raiz e se acham pelo registro de provedor")
    await alice.wait("Network.DhtBootstrap", where=lambda b: b["nodes"] >= 1)
    await bob.wait("PeerIdentified", where=lambda p: p["nick"] == "Alice", timeout=90, desc="achar Alice pela DHT")
    await alice.wait("PeerIdentified", where=lambda p: p["nick"] == "Bob", timeout=90, desc="achar Bob pela DHT")
    if bob.find("Network.TrackerPeer"):
        raise StepFailed("nenhum tracker foi configurado")
    await lab.join_room("sala", alice, bob)
    alice.send({"SendMessage": "achei você pela DHT"})
    await bob.wait("ChatMessage", where=lambda m: m["text"] == "achei você pela DHT")
