# Introduction

**Wireforge** is a next-generation WireGuard management platform, written from
scratch in Rust. It is a memory-safe, single-binary, cross-platform rewrite of
[Linguard](https://github.com/joseantmazonsb/linguard) with enterprise-grade
features added on top.

## Why Wireforge?

- **Single static binary** — no Python, no virtualenv, no shell scripts.
- **No `sudo`, no `shell=True`** — operations go through
  `defguard_wireguard_rs` netlink/userspace APIs with `CAP_NET_ADMIN`.
- **Argon2id + age (XChaCha20-Poly1305)** for credentials and encryption-at-rest.
- **RBAC + 2FA** — admin/operator/auditor/viewer roles, TOTP, recovery
  workflow.
- **Audit log** — every mutation persisted with actor, IP, resource and
  metadata.
- **REST API + OpenAPI** at `/api/v1/*` with Swagger UI at `/swagger-ui`.
- **Real-time** — WebSocket `/ws/events` for peer status and traffic deltas.
- **Prometheus** `/metrics` endpoint for monitoring.
- **i18n** — English / Türkçe out of the box; more locales drop in with a
  single `.ftl` file.
- **Encrypted backups** — `wireforge backup create` produces a portable
  `.age` blob that can be restored on any host with the same master key.

## Crate layout

```
wireforge/
├── crates/wireforge-core      # Domain entities, services, ports (no I/O)
├── crates/wireforge-infra     # SQLite + WireGuard adapters
├── crates/wireforge-web       # Axum + Askama + HTMX
├── crates/wireforge-api       # REST API v1 + OpenAPI
├── crates/wireforge-cli       # `wireforge` CLI
└── crates/wireforge-bin       # Server binary (wireforge-server)
```

The dependency direction is strictly one-way:
`bin → web/api/cli → core ← infra`. Core never depends on a framework.
