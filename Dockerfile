FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libasound2 \
    iproute2 \
    iptables \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copia o binário Linux já compilado nativamente (sem precisar compilar do zero no Docker)
COPY p2p-cli-linux /usr/local/bin/p2p-cli
RUN chmod +x /usr/local/bin/p2p-cli

# Diretório padrão para download de arquivos P2P
RUN mkdir -p /app/downloads

ENTRYPOINT ["p2p-cli"]
CMD ["--help"]
