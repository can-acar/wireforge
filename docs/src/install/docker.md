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

`docker-compose.yaml` ships under `deploy/docker/` for convenience.
