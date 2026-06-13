# Backup and restore

Wireforge bundles the entire SQLite state into an `age`-encrypted blob using
the configured `security.master_key`.

```bash
# Create
wireforge backup create --output /backups/wireforge-$(date +%F).age

# Restore (server must be stopped first)
systemctl stop wireforge
wireforge backup restore /backups/wireforge-2026-05-15.age
systemctl start wireforge
```

The blob is portable: copy it to a different host with the same master key
and `wireforge backup restore` will reconstruct the database verbatim.

> **Note**: `master_key` is the *only* secret you must keep safe outside the
> backup. Without it the backup is unrecoverable; with it the backup is
> sufficient to bring a fresh host up identically.
