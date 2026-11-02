# ==============================================================================
# Etapa 1: Build (Compilação do binário Rust com todas as dependências nativas)
# ==============================================================================
FROM rust:latest AS builder

# Instala ferramentas e bibliotecas de desenvolvimento C/C++ necessárias para compilar
# crates nativos (OpenH264, ALSA, X11/XCB, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    nasm \
    clang \
    libasound2-dev \
    libxcb1-dev \
    libxcb-randr0-dev \
    libgbm-dev \
    libegl1-mesa-dev \
    libgl1-mesa-dev \
    libpipewire-0.3-dev \
    libspa-0.2-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/anarchord

# Copia manifests de dependências primeiro para cache eficiente de camadas Docker
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Compila o binário de produção p2p-cli em modo release
RUN cargo build --release -p p2p-cli

# ==============================================================================
# Etapa 2: Runtime (Ambiente minimalista apenas para execução)
# ==============================================================================
FROM debian:bookworm-slim AS runtime

# Instala apenas as bibliotecas de runtime dinâmicas e utilitários de rede essenciais
RUN apt-get update && apt-get install -y --no-install-recommends \
    libasound2 \
    libgbm1 \
    libxcb1 \
    libxcb-randr0 \
    libegl1 \
    libgl1 \
    libpipewire-0.3-0 \
    libspa-0.2-modules \
    iproute2 \
    iptables \
    iputils-ping \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copia apenas o binário compilado da etapa de builder
COPY --from=builder /usr/src/anarchord/target/release/p2p-cli /usr/local/bin/p2p-cli
RUN chmod +x /usr/local/bin/p2p-cli

RUN mkdir -p /app/downloads

ENTRYPOINT ["p2p-cli"]
CMD ["--help"]
