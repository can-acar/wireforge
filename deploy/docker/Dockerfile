# syntax=docker/dockerfile:1.7
#
# Cross-compiling multi-arch build. The builder always runs on the NATIVE
# build platform ($BUILDPLATFORM) and cross-compiles to the requested
# $TARGETPLATFORM with cargo-zigbuild. This avoids QEMU CPU emulation entirely
# — emulated rustc segfaults when building linux/amd64 on Apple Silicon — so
# both amd64 and arm64 build fast and reliably from a macOS host.

FROM --platform=$BUILDPLATFORM rust:1.88-bookworm AS builder
ARG TARGETPLATFORM
WORKDIR /build

# zig (the cross-linker cargo-zigbuild drives) + the cross-compile tooling.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl xz-utils && rm -rf /var/lib/apt/lists/*
ENV ZIG_VERSION=0.13.0
RUN set -eux; \
    host="$(uname -m)"; \
    curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-${host}-${ZIG_VERSION}.tar.xz" \
        | tar -xJ -C /opt; \
    ln -s "/opt/zig-linux-${host}-${ZIG_VERSION}/zig" /usr/local/bin/zig
RUN cargo install cargo-zigbuild --locked
RUN rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu

# Resolve the Docker platform → Rust target triple once.
RUN set -eux; case "$TARGETPLATFORM" in \
        "linux/amd64") echo x86_64-unknown-linux-gnu  > /tmp/triple ;; \
        "linux/arm64") echo aarch64-unknown-linux-gnu > /tmp/triple ;; \
        *) echo "unsupported TARGETPLATFORM: $TARGETPLATFORM" >&2; exit 1 ;; \
    esac

# Dependency cache layer: build with stub sources so the heavy crate graph is
# cached independently of source changes.
COPY Cargo.toml Cargo.lock* ./
COPY crates/wireforge-core/Cargo.toml crates/wireforge-core/Cargo.toml
COPY crates/wireforge-infra/Cargo.toml crates/wireforge-infra/Cargo.toml
COPY crates/wireforge-web/Cargo.toml crates/wireforge-web/Cargo.toml
COPY crates/wireforge-api/Cargo.toml crates/wireforge-api/Cargo.toml
COPY crates/wireforge-cli/Cargo.toml crates/wireforge-cli/Cargo.toml
COPY crates/wireforge-bin/Cargo.toml crates/wireforge-bin/Cargo.toml
RUN mkdir -p crates/wireforge-core/src crates/wireforge-infra/src \
             crates/wireforge-web/src crates/wireforge-api/src \
             crates/wireforge-cli/src crates/wireforge-bin/src && \
    echo "fn main(){}" > crates/wireforge-cli/src/main.rs && \
    echo "fn main(){}" > crates/wireforge-bin/src/main.rs && \
    touch crates/wireforge-core/src/lib.rs crates/wireforge-infra/src/lib.rs \
          crates/wireforge-web/src/lib.rs crates/wireforge-api/src/lib.rs && \
    cargo zigbuild --release --locked --target "$(cat /tmp/triple)" \
        -p wireforge-bin -p wireforge-cli || true

# Real build. `COPY . .` brings in rust-toolchain.toml, which pins a toolchain
# that differs from the image default — so re-add the cross targets to the
# pinned toolchain. Touch sources so cargo rebuilds past the cached stub.
COPY . .
RUN rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu && \
    find crates -name '*.rs' -exec touch {} + && \
    cargo zigbuild --release --locked --target "$(cat /tmp/triple)" \
        -p wireforge-bin -p wireforge-cli && \
    install -D "target/$(cat /tmp/triple)/release/wireforge-server" /out/wireforge-server && \
    install -D "target/$(cat /tmp/triple)/release/wireforge"        /out/wireforge

# --- Runtime (native $TARGETPLATFORM image) ---
FROM debian:bookworm-slim AS runtime
LABEL org.opencontainers.image.title="Wireforge" \
      org.opencontainers.image.description="Next-generation WireGuard management platform" \
      org.opencontainers.image.source="https://github.com/can-acar/wireforge" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates wireguard-tools iproute2 iptables && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --uid 990 --home /var/lib/wireforge --shell /usr/sbin/nologin wireforge && \
    mkdir -p /var/lib/wireforge /etc/wireforge && \
    chown -R wireforge:wireforge /var/lib/wireforge /etc/wireforge

COPY --from=builder /out/wireforge-server /usr/local/bin/
COPY --from=builder /out/wireforge        /usr/local/bin/
COPY config/wireforge.sample.toml /etc/wireforge/wireforge.sample.toml

USER wireforge
WORKDIR /var/lib/wireforge
# Web UI / API (TCP). WireGuard listen ports are UDP and chosen per interface
# at runtime, so they cannot all be enumerated here — the docker-compose `prod`
# profile uses host networking, which exposes every bound port (web + each
# interface's UDP listen port) without per-port publishing. 51820/udp is the
# conventional WireGuard default and is declared for documentation.
EXPOSE 8080
EXPOSE 51820/udp
ENV WIREFORGE_DATABASE__PATH=/var/lib/wireforge/wireforge.sqlite

# Drop capabilities at the orchestrator level; this image expects
# `--cap-add NET_ADMIN` or systemd's `AmbientCapabilities=CAP_NET_ADMIN`.
ENTRYPOINT ["/usr/local/bin/wireforge-server"]
CMD ["--config", "/etc/wireforge/wireforge.toml"]
