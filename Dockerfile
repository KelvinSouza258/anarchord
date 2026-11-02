# Etapa 1: Build da aplicação em Rust
FROM rust:1.85-slim-bookworm AS builder

# Instala dependências de áudio necessárias para compilação (ALSA / pkg-config)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libasound2-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copia arquivos do workspace
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Compila o binário de CLI/Daemon em modo release
RUN cargo build --release -p p2p-cli

# Etapa 2: Imagem final enxuta para testes de integração
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libasound2 \
    iproute2 \
    iptables \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copia o executável construído
COPY --from=builder /app/target/release/p2p-cli /usr/local/bin/p2p-cli

# Diretório padrão para download de arquivos P2P
RUN mkdir -p /app/downloads

ENTRYPOINT ["p2p-cli"]
CMD ["--help"]
