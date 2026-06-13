# Monitoring (Prometheus)

`GET /metrics` returns Prometheus text-format metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `wireforge_build_info{version}` | gauge | Always 1; emits build version label. |
| `wireforge_interfaces_total` | gauge | Number of configured interfaces. |
| `wireforge_interfaces_up` | gauge | Subset currently up. |
| `wireforge_peers_total` | gauge | Number of peers. |
| `wireforge_peers_enabled` | gauge | Peers with `enabled=true`. |
| `wireforge_bandwidth_used_bytes_total` | counter | Lifetime TX+RX bytes across all peers. |

Scrape config:

```yaml
- job_name: wireforge
  metrics_path: /metrics
  static_configs:
    - targets: ['wireforge.internal:8080']
```
