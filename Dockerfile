# syntax=docker/dockerfile:1
# Imagem do Anarchord: agente sem interface (anarchord-agent) e TUI (p2p-cli).
# Também é a imagem do laboratório de testes (lab/): o mesmo contêiner vira nó atrás de NAT,
# roteador NAT, nó público ou tracker, conforme a variável ROLE (ver lab/node-entry.sh).
#
# Dois jeitos de obter os binários (build-arg BINS):
#   docker build .                          compila tudo aqui dentro (padrão)
#   docker build --build-arg BINS=local .   usa os binários já compilados em target/lab-linux/
#                                           (é o que o lab/run.py faz: compila com `docker run`
#                                           reaproveitando a pasta target do projeto)
ARG BINS=docker

# ==============================================================================
# Ferramentas de compilação (também usada pelo lab/run.py para compilar fora do build)
# ==============================================================================
# Mesma distribuição do runtime (bookworm): a glibc do build e da execução batem
FROM rust:1-bookworm AS toolchain
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake nasm clang pkg-config \
    libasound2-dev libxcb1-dev libxcb-randr0-dev libgbm-dev \
    libegl1-mesa-dev libgl1-mesa-dev libpipewire-0.3-dev libspa-0.2-dev \
    && rm -rf /var/lib/apt/lists/*

# ==============================================================================
# Binários compilados dentro do docker build
# ==============================================================================
FROM toolchain AS bins-docker
WORKDIR /usr/src/anarchord
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/anarchord/target \
    cargo build --release -p p2p-agent -p p2p-cli \
    && mkdir -p /out \
    && cp target/release/anarchord-agent target/release/p2p-cli /out/

# ==============================================================================
# Binários já compilados em target/lab-linux/ (lab/run.py)
# ==============================================================================
FROM scratch AS bins-local
COPY target/lab-linux/release/anarchord-agent target/lab-linux/release/p2p-cli /out/

FROM bins-${BINS} AS bins

# ==============================================================================
# Runtime
# ==============================================================================
FROM debian:bookworm-slim AS runtime

# Bibliotecas de runtime e ferramentas do laboratório (rotas, NAT, netem, tracker em Python)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libasound2 libgbm1 libxcb1 libxcb-randr0 libegl1 libgl1 \
    libpipewire-0.3-0 libspa-0.2-modules \
    iproute2 iptables iputils-ping procps python3-minimal ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=bins /out/anarchord-agent /out/p2p-cli /usr/local/bin/
COPY lab/node-entry.sh lab/tracker.py /usr/local/bin/
RUN chmod +x /usr/local/bin/node-entry.sh /usr/local/bin/tracker.py && mkdir -p /data

WORKDIR /data
ENTRYPOINT ["node-entry.sh"]
