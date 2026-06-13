-- Per-peer client DNS and NAT (full-tunnel) toggle.
--
-- primary_dns / secondary_dns override the interface-level DNS in the
-- generated client config. nat=1 (default) keeps the historical full-tunnel
-- behaviour (client AllowedIPs = 0.0.0.0/0, ::/0); nat=0 restricts the client
-- to the interface's own subnet (split tunnel).
ALTER TABLE peers ADD COLUMN primary_dns   TEXT;
ALTER TABLE peers ADD COLUMN secondary_dns TEXT;
ALTER TABLE peers ADD COLUMN nat           INTEGER NOT NULL DEFAULT 1;
