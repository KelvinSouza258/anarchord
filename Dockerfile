FROM rust:latest AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libasound2-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p p2p-cli

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libasound2 \
    iproute2 \
    iptables \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/p2p-cli /usr/local/bin/p2p-cli
RUN chmod +x /usr/local/bin/p2p-cli

RUN mkdir -p /app/downloads

ENTRYPOINT ["p2p-cli"]
CMD ["--help"]
