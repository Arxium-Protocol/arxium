# syntax=docker/dockerfile:1

# rocksdb (core/storage) builds from source via librocksdb-sys — needs
# clang/cmake/a C++ toolchain, not just rustc.
FROM rust:1-slim-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang cmake build-essential libclang-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release -p arxd

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /data arxium
COPY --from=builder /src/target/release/arxd /usr/local/bin/arxd

USER arxium
WORKDIR /data
VOLUME /data
# RPC (HTTP) and P2P (libp2p tcp+quic — quic needs the udp variant too) —
# see core/cli's RunArgs defaults.
EXPOSE 30333 30334/tcp 30334/udp

ENTRYPOINT ["arxd"]
# rpc-bind defaults to loopback-only (core/cli's RunArgs default) — RPC
# stays unreachable from outside the container unless a caller explicitly
# overrides it (with --rpc-token). NodeIndexer doesn't need RPC at all, it
# only talks P2P (port 30334).
CMD ["--base-path", "/data"]
