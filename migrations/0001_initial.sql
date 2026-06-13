-- Wireforge initial schema (v0.1.0)
-- SQLite. Compatible with later PostgreSQL migration via TEXT/INTEGER types.

CREATE TABLE IF NOT EXISTS users (
    id                       TEXT PRIMARY KEY,
    username                 TEXT NOT NULL UNIQUE,
    email                    TEXT UNIQUE,
    password_hash            TEXT NOT NULL,
    role                     TEXT NOT NULL DEFAULT 'admin',
    totp_enabled             INTEGER NOT NULL DEFAULT 0,
    totp_secret_encrypted    BLOB,
    oidc_subject             TEXT UNIQUE,
    created_at               TEXT NOT NULL,
    updated_at               TEXT NOT NULL,
    last_login_at            TEXT
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

CREATE TABLE IF NOT EXISTS recovery_codes (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id                  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash                TEXT NOT NULL,
    used_at                  TEXT
);
CREATE INDEX IF NOT EXISTS idx_recovery_user ON recovery_codes(user_id);

CREATE TABLE IF NOT EXISTS interfaces (
    id                       TEXT PRIMARY KEY,
    name                     TEXT NOT NULL UNIQUE,
    public_key               TEXT NOT NULL,
    private_key_sealed       BLOB NOT NULL,
    listen_port              INTEGER NOT NULL,
    endpoint                 TEXT,
    ipv4_cidr                TEXT,
    ipv6_cidr                TEXT,
    mtu                      INTEGER,
    dns                      TEXT,            -- JSON array
    on_up                    TEXT,
    on_down                  TEXT,
    status                   TEXT NOT NULL DEFAULT 'down',
    created_at               TEXT NOT NULL,
    updated_at               TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS peers (
    id                       TEXT PRIMARY KEY,
    interface_id             TEXT NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
    name                     TEXT NOT NULL,
    public_key               TEXT NOT NULL,
    preshared_key_sealed     BLOB,
    allowed_ips              TEXT NOT NULL,   -- JSON array of CIDRs
    endpoint                 TEXT,
    persistent_keepalive     INTEGER,
    bandwidth_quota_bytes    INTEGER,
    bandwidth_used_bytes     INTEGER NOT NULL DEFAULT 0,
    expires_at               TEXT,
    schedule                 TEXT,            -- JSON
    enabled                  INTEGER NOT NULL DEFAULT 1,
    owner_user_id            TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at               TEXT NOT NULL,
    updated_at               TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_peers_iface ON peers(interface_id);
CREATE INDEX IF NOT EXISTS idx_peers_owner ON peers(owner_user_id);

CREATE TABLE IF NOT EXISTS traffic_snapshots (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id                  TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    tx_bytes                 INTEGER NOT NULL DEFAULT 0,
    rx_bytes                 INTEGER NOT NULL DEFAULT 0,
    last_handshake_at        TEXT,
    recorded_at              TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_traffic_peer_time ON traffic_snapshots(peer_id, recorded_at);

CREATE TABLE IF NOT EXISTS audit_events (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id            TEXT REFERENCES users(id) ON DELETE SET NULL,
    actor_ip                 TEXT,
    action                   TEXT NOT NULL,
    resource_type            TEXT,
    resource_id              TEXT,
    metadata                 TEXT,            -- JSON
    created_at               TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(actor_user_id);

CREATE TABLE IF NOT EXISTS ip_bans (
    ip                       TEXT PRIMARY KEY,
    banned_until             TEXT NOT NULL,
    attempt_count            INTEGER NOT NULL DEFAULT 0,
    updated_at               TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id                       TEXT PRIMARY KEY,
    user_id                  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                     TEXT NOT NULL,
    token_hash               TEXT NOT NULL UNIQUE,
    scopes                   TEXT,            -- JSON
    created_at               TEXT NOT NULL,
    expires_at               TEXT,
    revoked_at               TEXT
);

CREATE TABLE IF NOT EXISTS webhooks (
    id                       TEXT PRIMARY KEY,
    url                      TEXT NOT NULL,
    secret                   TEXT,
    events                   TEXT NOT NULL,   -- JSON array
    enabled                  INTEGER NOT NULL DEFAULT 1,
    created_by               TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at               TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS backups (
    id                       TEXT PRIMARY KEY,
    filename                 TEXT NOT NULL,
    size_bytes               INTEGER NOT NULL,
    encrypted                INTEGER NOT NULL DEFAULT 1,
    created_at               TEXT NOT NULL
);

-- tower-sessions sqlite store table is created automatically by the crate.
