# Configuration

Wireforge reads `wireforge.toml` (path overridable with `--config` or
`WIREFORGE_CONFIG`). Every key can also be supplied via
`WIREFORGE_<SECTION>__<KEY>` environment variables.

```toml
[server]
bind = "0.0.0.0:8080"
session_secure = true        # set true behind HTTPS

[database]
path = "/var/lib/wireforge/wireforge.sqlite"

[security]
master_key = "REPLACE-ME"    # openssl rand -base64 48
login_max_attempts = 5
login_lockout_secs = 300
totp_issuer = "Wireforge"

[wireguard]
endpoint = "vpn.example.com:51820"

[log]
level = "info"

[web]
locale_default = "en"        # en | tr
```

## Master key

The `security.master_key` value is used to seal:
- WireGuard interface private keys,
- TOTP secrets,
- Peer private keys generated server-side.

Rotate by `wireforge backup create` → reset the key in config →
`wireforge backup restore`.
