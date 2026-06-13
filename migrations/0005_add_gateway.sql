-- Egress gateway (host interface, e.g. eth0) used for NAT/masquerade when the
-- WireGuard interface is brought up. NULL means no NAT is applied.
ALTER TABLE interfaces ADD COLUMN gateway TEXT;
