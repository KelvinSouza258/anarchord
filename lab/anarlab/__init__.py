"""Laboratório de testes distribuídos do Anarchord.

Cada nó é um contêiner com o `anarchord-agent`, controlado pelo stdin/stdout (JSON por linha).
Cada LAN tem um roteador NAT de verdade (iptables). O orquestrador sobe a topologia de cada
cenário, sincroniza os nós com barreiras e valida os eventos.
"""

SCENARIOS = []


def scenario(title):
    """Registra uma função `async def cenario(lab)` como cenário"""

    def register(fn):
        SCENARIOS.append((fn.__name__, title, fn))
        return fn

    return register
