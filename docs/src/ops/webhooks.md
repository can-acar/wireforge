# Webhooks

Wireforge can POST events to external services as they happen.

## Registering a webhook

```sql
-- Faz 5 ships the table; admin UI lands in Faz 6.
INSERT INTO webhooks (id, url, secret, events, enabled, created_at)
VALUES (
    lower(hex(randomblob(16))),
    'https://hooks.example.com/wireforge',
    'shared-secret-string',
    '["peer.created", "peer.deleted", "interface.started"]',
    1,
    datetime('now')
);
```

A wildcard `"*"` subscribes to every event.

## Payload

```json
{
  "event": "peer.created",
  "ts": "2026-05-15T10:23:11Z",
  "data": { ... }
}
```

## Signing

If `secret` is set, every request includes:

```
X-Wireforge-Event: peer.created
X-Wireforge-Signature: sha256=<hex(hmac-sha256(secret, body))>
```

Verify on the receiver side and reject mismatches.
