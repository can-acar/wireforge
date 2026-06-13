# First login & 2FA

On first launch the database is empty. Wireforge will redirect any visitor
to `/setup` to create the first administrator account.

```text
Username:          admin
Password (≥ 12):   ········
Confirm password:  ········
Email (optional):  admin@example.com
```

After login you can navigate to **Profile** and enable **TOTP**. Scan the QR
with your authenticator app (Authy, 1Password, Google Authenticator, …) and
enter the 6-digit code to confirm.

If you lose access to the authenticator app, an admin can disable TOTP from
the CLI:

```bash
wireforge user disable-totp admin
```

## Brute-force protection

After `security.login_max_attempts` consecutive failed logins from the same
IP, that IP is locked out for `security.login_lockout_secs` seconds.
Defaults: **5 attempts**, **5-minute lockout**. Tunable per deployment.
