"""Leitura dos eventos do core (CoreEvent em JSON, formato padrão do serde).

Variantes com dados viram objetos de uma chave ({"Network": {"Connected": {...}}}) e variantes
sem dados viram strings ("Stopped"). `get(evento, "Network.Connected")` devolve o conteúdo
da variante (ou True para variantes sem dados), ou None se o evento for de outro tipo.
"""


def get(event, path):
    current = event
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif current == part:
            return True
        else:
            return None
    return current


def kind(event):
    """Nome do evento para os logs: "Network.Connected", "Stopped"..."""
    parts = []
    current = event
    while isinstance(current, dict) and len(current) == 1:
        name = next(iter(current))
        if not name[:1].isupper():
            break
        parts.append(name)
        current = current[name]
    if isinstance(current, str) and current[:1].isupper() and not parts:
        parts.append(current)
    return ".".join(parts) or "?"
