# Docker

```bash
docker build -t wireforge:dev -f deploy/docker/Dockerfile .
docker run -d --name wireforge \
    --network host \
    --cap-add NET_ADMIN \
    -v $PWD/data:/var/lib/wireforge \
    -v $PWD/wireforge.toml:/etc/wireforge/wireforge.toml:ro \
    wireforge:dev
```

## Compose

`deploy/docker/docker-compose.yaml` defines two profiles:

```bash
# Dev — publishes the web port (8080) only; WireGuard dry-run. Works on macOS.
docker compose -f deploy/docker/docker-compose.yaml --profile dev up

# Prod — host networking exposes ALL ports (web + every interface's dynamic
# WireGuard UDP listen port) and runs the real data plane. Linux only.
docker compose -f deploy/docker/docker-compose.yaml --profile prod up
```

The `prod` profile uses `network_mode: host`, so peers can reach whatever UDP
listen port each interface is configured with — no per-port publishing needed.
On a Linux host this also requires the `wireguard` kernel module and the
`NET_ADMIN` capability (already requested by the compose service).
