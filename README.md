# Wireforge

> Next-generation WireGuard management platform — Rust rewrite of [Linguard](https://github.com/joseantmazonsb/linguard) with enterprise-grade features.

[![License: MIT/Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange?logo=rust)](https://www.rust-lang.org)

Wireforge is a memory-safe, single-binary, cross-platform web GUI and REST API for managing WireGuard VPN servers. It is a from-scratch Rust port of the Linguard project, with significantly expanded capabilities.

## Highlights

- 🦀 **Single static binary** — no Python, no virtualenv, no system dependencies beyond WireGuard.
- 🛡️ **Memory-safe** — Rust + `argon2` + `age` (XChaCha20-Poly1305) + `CAP_NET_ADMIN` (no `sudo`).
- 🔐 **RBAC + 2FA** — admin/operator/auditor/viewer roles, TOTP, recovery codes, OIDC-ready.
- 📜 **Audit log** — every mutation tracked with actor, IP, resource and metadata.
- 🌐 **REST API + OpenAPI** — auto-generated Swagger UI at `/swagger-ui`.
- 📡 **Real-time** — WebSocket push for peer handshakes and traffic deltas.
- 📊 **Prometheus metrics** — `/metrics` endpoint for monitoring.
- 🌍 **i18n** — English, Türkçe, Español, Deutsch, Français out of the box.
- 🎯 **Cross-platform** — Linux (kernel + userspace), Windows (WireGuard-NT), macOS (boringtun).

## Crates

| Crate | Purpose |
|-------|---------|
| `wireforge-core` | Domain & application layer (pure, framework-free) |
| `wireforge-infra` | SQLite/Postgres adapters, WireGuard adapter, notifier |
| `wireforge-web` | Axum HTTP handlers, Askama templates, HTMX assets |
| `wireforge-api` | REST API v1 + OpenAPI |
| `wireforge-cli` | `wireforge` CLI tool |
| `wireforge-bin` | Main server binary |

## Quick Start

```bash
# Clone
git clone https://github.com/can-acar/wireforge.git && cd wireforge

# Run from source
cargo run --release -- serve

# Or use Docker
docker build -t wireforge -f deploy/docker/Dockerfile .
docker run -d --network host --cap-add NET_ADMIN \
    -v $PWD/data:/var/lib/wireforge wireforge
```

Open <http://localhost:8080>. Create the first admin account, then start managing interfaces and peers.

## Development

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo test --workspace
cargo audit
```

## Platform model: develop on macOS, deploy on Linux

Wireforge runs in production on **Linux** (kernel WireGuard via netlink) and
targets **x86_64 + aarch64**. Day-to-day development happens on **macOS**, where
the WireGuard kernel module isn't available — so the adapter automatically runs
in **dry-run** (no kernel I/O) and the full web UI / REST API / CLI remain
testable.

### Dev loop (macOS)

```bash
./run.sh                 # auto dry-run on macOS → http://127.0.0.1:8080
```

### Build Linux artifacts from macOS (Docker buildx)

No host cross-toolchain needed — `build.sh` uses Docker buildx (bundled with
Docker Desktop; emulates the foreign arch via QEMU).

```bash
./build.sh linux-bin both        # → dist/linux-amd64/ and dist/linux-arm64/
file dist/linux-amd64/wireforge-server   # ELF 64-bit x86-64
file dist/linux-arm64/wireforge-server   # ELF 64-bit aarch64
```

### Deploy A — binary + systemd

```bash
scp dist/linux-amd64/wireforge-server dist/linux-amd64/wireforge host:/tmp/
# on the Linux host (from a checkout of this repo):
sudo ./install.sh --no-build     # installs binaries + service + CAP_NET_ADMIN
```

### Deploy B — container image

```bash
# multi-arch manifest pushed to a registry:
./build.sh image --push ghcr.io/can-acar/wireforge:latest
# on the host:
docker run -d --network host --cap-add NET_ADMIN \
    -v /var/lib/wireforge:/var/lib/wireforge wireforge:latest
# or: docker compose -f deploy/docker/docker-compose.yaml up -d
```

> **Linux host prerequisites:** the `wireguard` kernel module (built-in on
> kernels ≥ 5.6, otherwise `modprobe wireguard`) and `wireguard-tools`.
> `arm64` images built under QEMU are correct but ~3–5× slower to build;
> multi-arch manifests can only be `--push`ed (not `--load`ed) locally.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
