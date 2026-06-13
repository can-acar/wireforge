# Kubernetes (Helm)

A minimal chart ships under `deploy/helm/wireforge/`. It produces:

- a `StatefulSet` (so the SQLite PVC follows the pod),
- a `Service` of type `LoadBalancer` (override to `NodePort` for kubeadm),
- a hostPath-mounted `WireGuard` device file inside the pod,
- a `Secret` for `master_key`.

```bash
helm install wireforge ./deploy/helm/wireforge \
    --set security.master_key=$(openssl rand -base64 48) \
    --set wireguard.endpoint=vpn.example.com:51820
```

> **Note**: WireGuard kernel module must be present on the host (or use the
> `userspace` adapter via `WIREFORGE_WG_DRY_RUN=1` for testing).
