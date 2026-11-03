"""Topologia do laboratório: WAN, LANs atrás de roteadores NAT, nós; compose gerado por cenário."""

import asyncio
import json
import re
import subprocess
import time
from pathlib import Path

from .node import Node, StepFailed

IMAGE = "anarchord-lab"
WAN_SUBNET = "172.31.77.0/24"
RELAY_PORT = 4001
TRACKER_PORT = 6969


def wan_ip(n):
    return f"172.31.77.{n}"


def lan_subnet(i):
    return f"10.77.{i}.0/24"


def lan_ip(i, n):
    return f"10.77.{i}.{n}"


class Nat:
    def __init__(self, name, index, kind):
        self.name = name
        self.index = index
        self.kind = kind
        self.network = f"lan_{name}"
        self.router = f"router_{name}"
        self.router_lan_ip = lan_ip(index, 254)
        self.router_wan_ip = wan_ip(100 + index)
        self.hosts = 0


class Lab:
    def __init__(self, scenario, results_dir):
        slug = re.sub(r"[^a-z0-9]+", "_", scenario.lower()).strip("_")
        self.project = f"anarlab_{slug}"[:50]
        self.dir = Path(results_dir) / slug
        self.dir.mkdir(parents=True, exist_ok=True)
        self.log_file = open(self.dir / "events.log", "w", encoding="utf-8")
        self.started_at = time.time()
        self.nats = {}
        self.nodes = {}
        self.publics = 0
        self.tracker_ip = None

    # ------------------------------------------------------------------ topologia

    def nat(self, name, kind="cone"):
        """Uma LAN com roteador NAT (kind: cone ou symmetric)"""
        nat = Nat(name, len(self.nats) + 1, kind)
        self.nats[name] = nat
        return nat

    def public(self, name):
        """Nó direto na WAN (relay/bootstrap)"""
        self.publics += 1
        node = Node(self, name, wan_ip(10 + self.publics - 1), "public")
        self.nodes[name] = node
        return node

    def relay(self, name="relay"):
        """Declara o nó público de relay/bootstrap (iniciado depois com start_relay)"""
        return self.public(name)

    def root(self, name="root"):
        """Declara o nó raiz da DHT (iniciado depois com start_root)"""
        return self.public(name)

    def tracker(self):
        """Tracker BitTorrent UDP na WAN (no lugar dos trackers públicos). Devolve `host:porta`."""
        self.tracker_ip = wan_ip(5)
        return f"{self.tracker_ip}:{TRACKER_PORT}"

    def peer(self, name, nat, netem=None):
        """Nó dentro da LAN de `nat`"""
        nat.hosts += 1
        node = Node(self, name, lan_ip(nat.index, 10 + nat.hosts - 1), "peer", gateway=nat.router_lan_ip)
        node.nat = nat
        node.netem = netem
        self.nodes[name] = node
        return node

    def compose(self):
        networks = {"wan": {"internal": True, "ipam": {"config": [{"subnet": WAN_SUBNET}]}}}
        services = {}
        base = {"image": IMAGE, "cap_add": ["NET_ADMIN"], "init": True}
        for nat in self.nats.values():
            # A LAN não pode ser "internal": o Docker descartaria os pacotes para fora da sub-rede antes
            # de chegarem ao roteador. O isolamento vem das rotas (ver node-entry.sh) e é conferido em up().
            networks[nat.network] = {"ipam": {"config": [{"subnet": lan_subnet(nat.index)}]}}
            services[nat.router] = {
                **base,
                "container_name": f"{self.project}_{nat.router}",
                "environment": {"ROLE": "router", "LAN_IP": nat.router_lan_ip, "WAN_IP": nat.router_wan_ip, "NAT": nat.kind},
                "sysctls": {"net.ipv4.ip_forward": "1"},
                "networks": {"wan": {"ipv4_address": nat.router_wan_ip}, nat.network: {"ipv4_address": nat.router_lan_ip}},
            }
        for node in self.nodes.values():
            env = {"ROLE": node.role}
            service = {**base, "container_name": node.container}
            if node.role == "peer":
                env["GATEWAY"] = node.gateway
                if node.netem:
                    env["NETEM"] = node.netem
                service["networks"] = {node.nat.network: {"ipv4_address": node.ip}}
                service["depends_on"] = [node.nat.router]
            else:
                service["networks"] = {"wan": {"ipv4_address": node.ip}}
            service["environment"] = env
            services[node.name] = service
        if self.tracker_ip:
            services["tracker"] = {
                **base,
                "container_name": f"{self.project}_tracker",
                "environment": {"ROLE": "tracker"},
                "networks": {"wan": {"ipv4_address": self.tracker_ip}},
            }
        return {"name": self.project, "networks": networks, "services": services}

    # ------------------------------------------------------------------ ciclo de vida

    async def up(self):
        compose_file = self.dir / "compose.json"
        compose_file.write_text(json.dumps(self.compose(), indent=2), encoding="utf-8")
        await self._docker("compose", "-f", str(compose_file), "up", "-d", "--no-build", "--quiet-pull")
        # Espera os scripts de rede (rotas, iptables, netem) terminarem
        for node in self.nodes.values():
            marker = "netem em" if getattr(node, "netem", None) else ("rota padrão" if node.role == "peer" else "nó público")
            await self._wait_log(node.container, marker)
        for nat in self.nats.values():
            await self._wait_log(f"{self.project}_{nat.router}", "roteador NAT")
        if self.tracker_ip:
            await self._wait_log(f"{self.project}_tracker", "tracker UDP")
        await self.check_isolated()

    async def check_isolated(self):
        """Nenhum contêiner do laboratório pode alcançar a internet"""
        containers = [n.container for n in self.nodes.values()] + [f"{self.project}_{n.router}" for n in self.nats.values()]
        for container in containers:
            out = await self._docker(
                "exec", container, "sh", "-c", "ping -c1 -W1 1.1.1.1 >/dev/null 2>&1 && echo VAZOU || echo isolado", check=False
            )
            if "VAZOU" in out:
                raise StepFailed(f"{container} alcança a internet: o laboratório precisa ser isolado")

    async def _wait_log(self, container, marker):
        for _ in range(100):
            text = await self._docker("logs", container, check=False)
            if marker in text:
                return
            await asyncio.sleep(0.2)
        raise StepFailed(f"{container} não ficou pronto (esperando '{marker}')")

    async def start_relay(self, name="relay"):
        """Inicia o nó público de relay (--relay-server). Ele também é nó da DHT: os outros nós
        o usam como bootstrap passando `*relay.bootstrap_args` no start"""
        relay = self.nodes[name]
        await relay.start("--relay-server", nick="Relay")
        return relay

    async def start_root(self, name="root"):
        """Inicia o nó raiz da DHT (sem relay). Os outros nós o usam como bootstrap passando
        `*root.bootstrap_args` no start"""
        root = self.nodes[name]
        await root.start(nick="Root")
        return root

    async def down(self, keep=False):
        for node in self.nodes.values():
            if node.running:
                try:
                    await node.stop()
                except Exception:
                    pass
        # Estado da rede de cada contêiner, para investigar falhas
        if not keep:
            await self._docker("compose", "-f", str(self.dir / "compose.json"), "down", "-v", "--remove-orphans", "-t", "1", check=False)
        self.log_file.close()

    async def _docker(self, *args, check=True):
        proc = await asyncio.create_subprocess_exec("docker", *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await proc.communicate()
        text = out.decode(errors="replace")
        if check and proc.returncode != 0:
            raise StepFailed(f"docker {' '.join(args[:3])} falhou:\n{text}")
        return text

    # ------------------------------------------------------------------ log

    def log(self, who, arrow, text):
        elapsed = time.time() - self.started_at
        self.log_file.write(f"{elapsed:8.3f} {who:>8} {arrow} {text}\n")
        self.log_file.flush()

    def step(self, text):
        """Marca um passo do cenário no log (e no terminal)"""
        self.log("lab", "■", text)
        print(f"      · {text}", flush=True)

    # ------------------------------------------------------------------ atalhos de cenário

    async def relay_address(self, node, timeout=60):
        """Endereço de circuito de `node` no relay (depois do AutoNAT detectar o NAT e a reserva ser aceita)"""
        await node.wait("Network.RelayReserved", timeout=timeout, desc="reserva no relay")
        circuit = await node.wait("Network.Listening", where=lambda a: "p2p-circuit" in a, timeout=timeout, desc="endereço de circuito")
        if f"/p2p/{node.peer_id}" not in circuit:
            circuit += f"/p2p/{node.peer_id}"
        return circuit

    async def connect(self, dialer, target, timeout=60):
        """`dialer` conecta em `target` pelo relay e os dois se identificam"""
        address = await self.relay_address(target, timeout)
        since_dialer, since_target = dialer.mark(), target.mark()
        dialer.send({"Dial": address})
        await dialer.wait("PeerIdentified", where=lambda p: p["peer_id"] == target.peer_id, since=since_dialer, timeout=timeout, desc=f"identificar {target.name}")
        # Se o alvo já conhecia o par (ex.: o par reiniciou e a conexão antiga ainda não expirou),
        # o core não repete o aviso de identificação
        known = target.find("PeerIdentified", where=lambda p: p["peer_id"] == dialer.peer_id, since=0)
        if not known:
            await target.wait("PeerIdentified", where=lambda p: p["peer_id"] == dialer.peer_id, since=since_target, timeout=timeout, desc=f"identificar {dialer.name}")

    async def join_room(self, room, *nodes, timeout=60):
        """Todos entram em `room` e cada um vê todos os outros como membros (barreira)"""
        for node in nodes:
            node.send({"JoinChannel": room})
        for node in nodes:
            others = {n.nick for n in nodes if n is not node}
            await node.wait(
                "ChannelMembers",
                where=lambda m, others=others: m["channel"] == room and others <= set(m["members"]),
                timeout=timeout,
                desc=f"ver {sorted(others)} em #{room}",
            )

    async def same_file(self, path_by_node, expected):
        """Confere o SHA-256 do arquivo em cada nó"""
        for node, path in path_by_node.items():
            digest = await node.sha256(path)
            if digest != expected:
                raise StepFailed(f"{node.name}: {path} diferente ({digest[:12]} ≠ {expected[:12]})")


def run_sync(*args):
    return subprocess.run(args, capture_output=True, text=True)
