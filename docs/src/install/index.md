# Installation

Three supported deployment shapes:

- **systemd** — recommended for bare-metal / VPS hosts.
- **Docker / docker-compose** — easiest local trial.
- **Kubernetes (Helm)** — for clusters.

All three rely on the same `wireforge-server` binary and SQLite file, so
moving between them is just a matter of copying `wireforge.sqlite` and the
config file.
