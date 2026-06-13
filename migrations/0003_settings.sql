-- 0003_settings.sql
-- Runtime-mutable configuration values, keyed by a string identifier and
-- holding a JSON-encoded scalar in `value`. The application overlays these
-- on top of `wireforge.toml` defaults at boot and after each write.

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_by TEXT REFERENCES users(id),
    updated_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
