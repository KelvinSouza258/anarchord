"""Um nó do laboratório: o contêiner e o anarchord-agent rodando nele, controlado pelo stdin/stdout."""

import asyncio
import os
import json
import time

from .events import get, kind

DEFAULT_TIMEOUT = 45

# Todo nó: modo laboratório (IPs privados valem como públicos, AutoNAT rápido), rede isolada
# (--isolated: sem bootstraps do IPFS nem trackers públicos), sem mDNS, porta fixa
BASE_ARGS = ["--lab", "--isolated", "--no-mdns", "--port", "4001"]


class StepFailed(Exception):
    """Um passo do cenário não aconteceu no tempo esperado"""


class Node:
    def __init__(self, lab, name, ip, role, gateway=None):
        self.lab = lab
        self.name = name
        self.ip = ip
        self.role = role
        self.gateway = gateway
        self.container = f"{lab.project}_{name}"
        self.proc = None
        self.nick = name.capitalize()
        self.events = []  # (instante, evento)
        self.peer_id = None
        self.pubkey = None
        self.port = None
        self._changed = asyncio.Condition()
        self._readers = []

    # ------------------------------------------------------------------ processo

    async def start(self, *extra, nick=None):
        """Inicia o agente no contêiner e espera o evento Started.

        Argumentos fixos de todo nó do laboratório (BASE_ARGS): rede isolada, sem os bootstraps
        do IPFS, sem trackers públicos e sem mDNS. Todo o resto vem do cenário em `extra`,
        inclusive como o nó acha os outros (`*relay.bootstrap_args`, `--tracker`, `--connect`).
        """
        self.nick = nick or self.name.capitalize()
        args = ["--nick", self.nick, "--data-dir", "/data/agent", *BASE_ARGS, *extra]
        self.proc = await asyncio.create_subprocess_exec(
            "docker", "exec", "-i", "-e", f"RUST_LOG={os.environ.get('LAB_RUST_LOG', 'warn')}", self.container, "anarchord-agent", *args,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            limit=16 * 1024 * 1024,
        )
        self.lab.log(self.name, "▶", "anarchord-agent " + " ".join(args))
        self._readers = [asyncio.create_task(self._read_events()), asyncio.create_task(self._read_stderr())]
        started = await self.wait("Started", desc="agente iniciar")
        self.peer_id = started["peer_id"]
        self.pubkey = started.get("pubkey")
        self.port = started["port"]
        return self

    async def _read_events(self):
        async for raw in self.proc.stdout:
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                self.lab.log(self.name, "?", line)
                continue
            self.lab.log(self.name, "←", f"{kind(event)} {line}")
            async with self._changed:
                self.events.append((time.time(), event))
                self._changed.notify_all()
        async with self._changed:
            self._changed.notify_all()

    async def _read_stderr(self):
        async for raw in self.proc.stderr:
            self.lab.log(self.name, "!", raw.decode("utf-8", "replace").rstrip())

    @property
    def running(self):
        return self.proc is not None and self.proc.returncode is None

    def send(self, command):
        """Manda um CoreCommand (ex.: {"JoinChannel": "geral"} ou "ListPeers")"""
        line = json.dumps(command, ensure_ascii=False)
        self.lab.log(self.name, "→", line)
        self.proc.stdin.write((line + "\n").encode("utf-8"))

    def server(self, command):
        """Atalho para {"Server": command}"""
        self.send({"Server": command})

    async def stop(self):
        """Encerra o agente com calma (Shutdown) e espera ele sair"""
        if not self.running:
            return
        try:
            self.send("Shutdown")
            await asyncio.wait_for(self.proc.wait(), 10)
        except (asyncio.TimeoutError, ConnectionError, BrokenPipeError):
            await self.kill()

    async def kill(self):
        """Derruba o agente na hora (como uma queda de energia)"""
        await self.sh("pkill -9 -x anarchord-agent || true")
        if self.proc is not None:
            try:
                await asyncio.wait_for(self.proc.wait(), 10)
            except asyncio.TimeoutError:
                self.proc.kill()
        for task in self._readers:
            task.cancel()

    # ------------------------------------------------------------------ eventos

    def mark(self):
        """Posição atual do histórico, para esperar só eventos que chegarem depois"""
        return len(self.events)

    def find(self, path, where=None, since=0):
        for _, event in self.events[since:]:
            value = get(event, path)
            if value is not None and (where is None or where(value)):
                return value
        return None

    def all(self, path, where=None, since=0):
        return [v for _, e in self.events[since:] if (v := get(e, path)) is not None and (where is None or where(v))]

    async def wait(self, path, where=None, timeout=DEFAULT_TIMEOUT, desc=None, since=0):
        """Espera um evento `path` (ex.: "File.Completed") que satisfaça `where`"""
        desc = desc or path
        deadline = time.monotonic() + timeout
        async with self._changed:
            while True:
                found = self.find(path, where, since)
                if found is not None:
                    return found
                remaining = deadline - time.monotonic()
                if remaining <= 0 or (self.proc is not None and self.proc.returncode is not None and self.proc.stdout.at_eof()):
                    raise StepFailed(f"{self.name}: tempo esgotado esperando {desc}")
                try:
                    await asyncio.wait_for(self._changed.wait(), remaining)
                except asyncio.TimeoutError:
                    pass

    async def expect_none(self, path, where=None, during=3, since=0, desc=None):
        """Garante que nenhum evento `path` chegou durante `during` segundos"""
        await asyncio.sleep(during)
        found = self.find(path, where, since)
        if found is not None:
            raise StepFailed(f"{self.name}: não deveria ter recebido {desc or path}: {found}")

    # ------------------------------------------------------------------ contêiner

    async def sh(self, command):
        """Executa um comando de shell no contêiner e devolve o stdout"""
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", self.container, "sh", "-c", command,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        if proc.returncode != 0:
            raise StepFailed(f"{self.name}: `{command}` falhou: {err.decode(errors='replace').strip()}")
        return out.decode("utf-8", "replace").strip()

    async def make_file(self, path, size):
        """Cria um arquivo aleatório no contêiner e devolve o SHA-256"""
        await self.sh(f"mkdir -p $(dirname {path}) && head -c {size} /dev/urandom > {path}")
        return await self.sha256(path)

    async def sha256(self, path):
        return (await self.sh(f"sha256sum {path}")).split()[0]

    @property
    def address(self):
        """Endereço direto (TCP) do nó, com /p2p/<id>"""
        return f"/ip4/{self.ip}/tcp/4001/p2p/{self.peer_id}"

    @property
    def quic_address(self):
        """Endereço direto (QUIC) do nó, com /p2p/<id>"""
        return f"/ip4/{self.ip}/udp/4001/quic-v1/p2p/{self.peer_id}"

    @property
    def bootstrap_args(self):
        """Argumentos para outro nó usar este como bootstrap da DHT (TCP e QUIC).

        O QUIC importa para o hole punching: a conexão QUIC usa a mesma porta UDP da escuta,
        então o endereço que o relay observa serve para o DCUtR.
        """
        return ["--bootstrap", self.address, "--bootstrap", self.quic_address]

    @property
    def downloads(self):
        return "/data/agent/downloads"

    # ------------------------------------------------------------------ sniffer de pacotes brutos

    async def packets(self, kind=None, direction=None):
        """Lê os pacotes brutos de aplicação capturados em `/data/agent/packets.jsonl` deste nó.

        Cada item contém `raw_hex`, `wire_version`, `kind`, `topic`, `direction` ("TX"/"RX")
        e o dicionário `crypto` (`sender_pubkey`, `recipient_pubkey`, `ephemeral_x25519_pubkey`,
        `nonce_hex`, `ciphertext_hex`, `signing_bytes_hex`, `signature_hex`, `signature_valid`).
        """
        raw = await self.sh("cat /data/agent/packets.jsonl 2>/dev/null || true")
        items = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                pkt = json.loads(line)
            except json.JSONDecodeError:
                continue
            if kind is not None and pkt.get("kind") != kind:
                continue
            if direction is not None and pkt.get("direction") != direction:
                continue
            items.append(pkt)
        return items

    async def wait_packet(self, kind=None, direction=None, where=None, timeout=DEFAULT_TIMEOUT, desc=None):
        """Espera um pacote bruto específico aparecer no sniffer (`/data/agent/packets.jsonl`)"""
        desc = desc or f"pacote {kind or '*'} ({direction or '*'})"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for pkt in await self.packets(kind=kind, direction=direction):
                if where is None or where(pkt):
                    return pkt
            await asyncio.sleep(0.3)
        raise StepFailed(f"{self.name}: tempo esgotado esperando {desc} no sniffer")

    def __repr__(self):
        return f"<Node {self.name} {self.ip}>"
