#!/usr/bin/env python3
"""Tracker BitTorrent UDP (BEP 15) mínimo, para o laboratório isolado.

Faz o papel dos trackers públicos (opentrackr etc.) na rede sem internet: guarda quem anunciou
cada info_hash (endereço de origem do pacote + porta anunciada) e devolve os outros pares.
Uso: tracker.py [porta]   (padrão 6969)
"""

import os
import socket
import struct
import sys
import time

PROTOCOL_ID = 0x41727101980
CONNECT, ANNOUNCE, ERROR = 0, 1, 3
EVENT_STOPPED = 3
PEER_TTL = 60  # anúncio que não se repete por esse tempo some da lista


def log(*parts):
    print(time.strftime("%H:%M:%S"), *parts, flush=True)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 6969
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    log(f"tracker UDP em :{port}")
    swarms = {}  # info_hash -> {(ip, porta): último anúncio}

    while True:
        data, (ip, src_port) = sock.recvfrom(2048)
        if len(data) < 16:
            continue
        connection_id, action, transaction = struct.unpack(">QII", data[:16])

        if action == CONNECT and connection_id == PROTOCOL_ID:
            new_id = int.from_bytes(os.urandom(8), "big")
            sock.sendto(struct.pack(">IIQ", CONNECT, transaction, new_id), (ip, src_port))
            continue

        if action == ANNOUNCE and len(data) >= 98:
            info_hash = data[16:36]
            event, = struct.unpack(">I", data[80:84])
            announced_port, = struct.unpack(">H", data[96:98])
            me = (ip, announced_port)
            now = time.time()
            swarm = swarms.setdefault(info_hash, {})
            for peer, seen in list(swarm.items()):
                if now - seen > PEER_TTL:
                    del swarm[peer]
            if event == EVENT_STOPPED:
                swarm.pop(me, None)
                log(f"saiu {ip}:{announced_port}")
                continue
            if me not in swarm:
                log(f"anunciou {ip}:{announced_port} ({len(swarm) + 1} no enxame)")
            swarm[me] = now
            others = [p for p in swarm if p != me][:50]
            reply = struct.pack(">IIIII", ANNOUNCE, transaction, 10, 0, len(swarm))
            for peer_ip, peer_port in others:
                reply += socket.inet_aton(peer_ip) + struct.pack(">H", peer_port)
            sock.sendto(reply, (ip, src_port))
            continue

        sock.sendto(struct.pack(">II", ERROR, transaction) + b"pedido invalido", (ip, src_port))


if __name__ == "__main__":
    main()
