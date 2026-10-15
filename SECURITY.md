# Security policy

NetworkVision holds credentials for core network infrastructure, so security reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's *Report a vulnerability* (private security advisory)
on this repository. Include steps to reproduce and the affected version. You should get a response within a week.

## Design notes

- Device credentials are encrypted at rest (Fernet, key derived from `NV_SECRET_KEY` via HKDF) or kept
  entirely in environment variables via `env:NAME` references. References to `NV_*` variables are refused.
- Secrets are never returned by the API. The UI only ever sees a mask or the `env:` reference name.
- Sessions are HS256 JWTs in an `HttpOnly`, `SameSite=Strict` cookie (`Secure` with `NV_COOKIE_SECURE=true`).
- Login attempts are rate limited per client IP.
- Optional TOTP MFA: ±1 step drift window, replay protection, single-use SHA-256-hashed recovery codes,
  password + code re-authentication for MFA changes, and all other sessions revoked when MFA is turned on or off.
  The half-login token issued after the password step only works on the MFA endpoint, for 5 minutes.
- KeePass references (`kp:`) are resolved server-side at poll time. The API only ever lists entry paths and
  field names, never values.
- The WebSocket rejects cross-origin connections.
- Strict security headers (CSP, frame denial, nosniff) are sent on every response.
- The container runs as an unprivileged user with all Linux capabilities dropped and `no-new-privileges`.

## Hardening recommendations

- Put NetworkVision behind a reverse proxy with TLS and set `NV_COOKIE_SECURE=true`.
- Use read-only accounts/keys on every integrated device.
- Restrict the syslog port to your management network. Syslog is unauthenticated by nature.
- Only use `NV_TRUSTED_PROXY_HEADER` / `NV_AUTH_DISABLED` when the app port is unreachable except through your SSO proxy.
