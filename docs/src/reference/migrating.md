# Migrating from Linguard

Wireforge is a from-scratch Rust rewrite — there is no in-place upgrade.
However the WireGuard `.conf` output is byte-identical to what Linguard
produces, so existing peers continue to work without changes.

## Steps

1. Install Wireforge alongside Linguard.
2. Recreate interfaces with the same listen ports and CIDRs (`wireforge` or
   the web UI).
3. Re-issue peer configs from Wireforge (or import the public keys by hand;
   private keys cannot be recovered from Linguard's `linguard.yaml`).
4. Stop Linguard, start Wireforge.

A first-class `wireforge import --from-linguard /etc/linguard/linguard.yaml`
command is on the Faz 6 roadmap.
