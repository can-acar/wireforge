# CLI: `wireforge`

```text
wireforge [--config PATH] <SUBCOMMAND>
```

| Subcommand | Purpose |
|------------|---------|
| `version` | Print build version |
| `init [--output PATH]` | Write a sample `wireforge.toml` |
| `migrate` | Apply database migrations |
| `user list` | List all users |
| `user create <name> [--role …] [--password-stdin]` | Create a user |
| `user reset-password <name>` | Change a user's password |
| `user disable-totp <name>` | Disable TOTP (account recovery) |
| `peer list` | List all peers |
| `interface list` | List all interfaces |
| `audit [--limit N]` | Tail the audit log |
| `backup create [--output PATH]` | Encrypted backup |
| `backup restore <PATH>` | Restore from backup |

> **Note**: `wireforge` operates directly on the SQLite DB. Pass the same
> `--config` the server uses (or set `WIREFORGE_CONFIG`).
