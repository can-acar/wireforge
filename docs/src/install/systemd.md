# systemd

A hardened unit file is provided under `deploy/systemd/wireforge.service`.

```bash
sudo install -Dm755 target/release/wireforge-server /usr/local/bin/wireforge-server
sudo install -Dm755 target/release/wireforge        /usr/local/bin/wireforge
sudo install -Dm644 deploy/systemd/wireforge.service /etc/systemd/system/wireforge.service
sudo useradd --system --home /var/lib/wireforge --shell /usr/sbin/nologin wireforge
sudo install -d -o wireforge -g wireforge /var/lib/wireforge /etc/wireforge
sudo install -Dm600 -o wireforge -g wireforge config/wireforge.sample.toml /etc/wireforge/wireforge.toml
sudo systemctl daemon-reload
sudo systemctl enable --now wireforge
```

The service runs as a non-root user with `AmbientCapabilities=CAP_NET_ADMIN`,
so it can manage WireGuard interfaces without `sudo`.
