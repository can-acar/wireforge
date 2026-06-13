# Audit log

Every mutating action — user creation, login (success/failure), interface or
peer CRUD, 2FA enable/disable — is recorded with:

- `actor_user_id` (nullable: anonymous failed logins, system events)
- `actor_ip`
- `action` (`peer.created`, `interface.deleted`, `user.login_failed`, …)
- `resource_type` + `resource_id`
- `metadata` (JSON blob)
- `created_at`

UI: `/audit` (admin or `auditor` role required).
CLI: `wireforge audit --limit 200`.

The schema is **append-only**; events are never updated.
