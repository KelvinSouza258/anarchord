#!/bin/sh
# Prepara a rede do contêiner e fica parado: o orquestrador (lab/) inicia o anarchord-agent
# com `docker exec -i` e conversa com ele pelo stdin/stdout.
#
# ROLE=router  roteador NAT entre uma LAN e a WAN (LAN_IP, WAN_IP; NAT=cone|symmetric)
# ROLE=peer    nó dentro de uma LAN: a rota padrão passa a ser o roteador (GATEWAY)
# ROLE=public  nó direto na WAN (bootstrap/relay)
# ROLE=tracker tracker BitTorrent UDP na WAN (porta 6969)
# NETEM        opcional, aplicado na interface principal (ex.: "delay 50ms loss 5%")
# Sem ROLE: executa o comando recebido (ex.: docker run anarchord p2p-cli --help)
set -e

iface_of() {
    ip -o -4 addr show | awk -v ip="$1" '{ split($4, a, "/"); if (a[1] == ip) print $2 }'
}

case "$ROLE" in
    router)
        LAN_IF=$(iface_of "$LAN_IP")
        WAN_IF=$(iface_of "$WAN_IP")
        # cone: mapeamento independente do destino (hole punching funciona)
        # symmetric: porta aleatória por conexão (hole punching não funciona; só relay)
        EXTRA=""
        [ "$NAT" = "symmetric" ] && EXTRA="--random-fully"
        iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE $EXTRA
        iptables -P FORWARD DROP
        iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -j ACCEPT
        iptables -A FORWARD -i "$WAN_IF" -o "$LAN_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        # Como um roteador doméstico: pacote não solicitado vindo da WAN é descartado. Sem isso o
        # conntrack registraria a sonda do outro lado do hole punching como conexão local e o
        # MASQUERADE trocaria a porta do mapeamento (o NAT viraria simétrico na prática)
        iptables -A INPUT -i "$WAN_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -i "$WAN_IF" -j DROP
        # Sem rota padrão: o roteador só conhece a LAN e a WAN do laboratório (nada de internet)
        ip route del default 2>/dev/null || true
        echo "roteador NAT ($NAT): $LAN_IF -> $WAN_IF"
        ;;
    peer)
        ip route replace default via "$GATEWAY"
        echo "nó atrás de NAT, rota padrão via $GATEWAY"
        ;;
    public)
        echo "nó público"
        ;;
    tracker)
        exec python3 /usr/local/bin/tracker.py 6969
        ;;
    "")
        exec "$@"
        ;;
esac

if [ -n "$NETEM" ]; then
    MAIN_IF=$(ip -o -4 route show default | awk '{print $5}' | head -n1)
    [ -z "$MAIN_IF" ] && MAIN_IF=eth0
    tc qdisc add dev "$MAIN_IF" root netem $NETEM
    echo "netem em $MAIN_IF: $NETEM"
fi

exec sleep infinity
