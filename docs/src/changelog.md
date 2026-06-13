# Changelog

## 0.1.0 (Faz 5 milestone)

- 6-crate Cargo workspace (`core` / `infra` / `web` / `api` / `cli` / `bin`)
- Web UI: Askama + HTMX + Tailwind, dark mode toggle, flash messages
- Interface and peer CRUD with server-side keypair sealing
- TOTP 2FA, RBAC (admin/operator/auditor/viewer), audit log
- Brute-force IP lockout
- REST API v1 + OpenAPI + Swagger UI
- WebSocket `/ws/events` heartbeat
- Prometheus `/metrics`
- Background poller — peer stats + bandwidth quota enforcement
- Background scheduler — time-based peer access window
- `wireforge` CLI: user/peer/interface/audit/backup subcommands
- Encrypted backup (`age`) + restore
- Webhooks with HMAC-SHA256 signing
- i18n (English + Türkçe)
