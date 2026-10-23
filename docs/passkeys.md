# Passkeys and authentication migration

PB Auth Proxy implements WebAuthn using `github.com/go-webauthn/webauthn` pinned to **v0.18.2**. Passkeys created for this application can be stored in Google Password Manager, iCloud Keychain, Windows Hello, or a FIDO2 security key. A passkey created for google.com cannot authenticate to this application. OAuth2/OIDC is outside this implementation.

## Setup

Back up PocketBase first. Deploy `pb_migrations/1792800000_passkeys_sessions.js` and run PocketBase `migrate up` (or restart `serve`, which applies migrations automatically). The Docker image copies migrations at build time; rebuild it when upgrading:

```sh
docker compose up --build
```

The migration locks public create/update access on `proxy_users`, adds `locked_until` and `auth_version`, and creates private `passkey_credentials`, `auth_tokens`, `auth_consumptions`, and `webauthn_ceremonies` collections. Every rule on these new collections is `null` (superuser only). Preserve these rules. The proxy uses the existing PocketBase superuser connection. For a custom user collection, adapt the migration's `proxy_users` lookup **before** applying it; the relations must point to the collection configured by `POCKETBASE_COLLECTION`.

Production configuration:

```dotenv
PUBLIC_ORIGIN=https://auth.example.com
COOKIE_SECURE=true
WEBAUTHN_ENABLED=true
WEBAUTHN_RP_ID=example.com
WEBAUTHN_RP_NAME=PB Auth Proxy
WEBAUTHN_ORIGIN=https://auth.example.com
WEBAUTHN_USER_VERIFICATION=required
```

`PUBLIC_ORIGIN` is required even when WebAuthn is disabled. Origins are exact scheme/host/port values without a trailing slash or path. `WEBAUTHN_ORIGIN` must equal `PUBLIC_ORIGIN`. The RP ID must be the origin's host or a valid parent domain. Choose the RP ID carefully: changing it requires enrolling new passkeys. Host and forwarded headers never determine WebAuthn settings or cookie security.

Serve the public origin through HTTPS, including behind a TLS-terminating reverse proxy. The Go listener can remain HTTP on a private network; auth and browser-binding cookies still have `Secure=true`. The application rejects non-HTTPS or insecure-cookie configuration outside localhost/loopback. The local Docker demo uses `http://localhost:8080`, RP ID `localhost`, and `COOKIE_SECURE=false`; a LAN IP is not a substitute for localhost's secure-context exception. Generate `SESSION_SECRET` with at least 32 bytes of entropy and `XSRF_SECRET_KEY` with `openssl rand -base64 32`. Replace the seeded demo accounts and secrets before production.

## User experience and recovery

Both Go/JS and PHP frontends use the same browser WebAuthn module. Sign in with a password first, open **My Account**, name a passkey, and select **Add a passkey**. Registration requires a login or password reauthentication within the last five minutes. Use **Verify identity** when that window has elapsed. A successful passkey login with required user verification also starts that five-minute window.

The login form supports both **Sign in with a passkey** and browser autofill (`autocomplete="username webauthn"`) with conditional mediation when supported. Conditional challenges renew before expiry and are cancelled before explicit login or password submission. Unsupported browsers retain password login. Adding multiple passkeys on different authenticators is supported; existing credential IDs are excluded during registration.

The account page lists names, creation dates, and last-use dates. Deletion requires recent authentication and user confirmation. The credential is first marked revoked, which is rechecked by concurrent logins, before rotating the user's authentication version and removing the credential. It revokes **all** of that user's browser sessions, access tokens, and refresh tokens, then returns to login. Password changes and account status changes also revoke all existing tokens. A normal logout revokes the current browser session only; GET `/logout` is a confirmation page and the mutation uses POST with XSRF protection.

Keep the existing password as the recovery method. Losing every passkey does not prevent password login. An administrator can restore access with the configured PocketBase superuser connection:

```sh
go run ./cmd/admin-cli --reset-password --username alice --password 'new-strong-recovery-password'
```

This updates the proxy's Argon2id hash and rotates `auth_version`, revoking existing sessions and tokens. If the account was disabled, separately enable `is_active`. Avoid retaining the reset password in shell history; use an administrative session with appropriate history controls. Never set PocketBase's compatibility `password` as the proxy password. Use the CLI to create a separate emergency administrator account. Protect that password and the PocketBase superuser credentials independently from daily-use passkeys.

## API

Browser clients first fetch `GET /api/auth/browser`, which sets an HttpOnly, SameSite=Strict `browser_id` cookie and returns `csrf_token` plus `passkeys_enabled`. Mutations below require that cookie, exact `Origin: <PUBLIC_ORIGIN>`, and `X-XSRF-Token: <csrf_token>`. CSRF tokens expire after 15 minutes; fetch fresh bootstrap data when needed. No cross-origin CORS access is enabled.

| Method | Endpoint | Requirement |
| --- | --- | --- |
| POST | `/api/auth/reauthenticate` | Session cookie; JSON `{ "password": "…" }` |
| POST | `/api/auth/passkeys/register/begin` | Recent session; JSON `{ "name": "Phone" }` |
| POST | `/api/auth/passkeys/register/finish` | Same recent session and browser |
| POST | `/api/auth/passkeys/login/begin` | Browser binding; no account identifier |
| POST | `/api/auth/passkeys/login/finish` | Same browser binding |
| GET | `/api/auth/passkeys` | Session cookie |
| DELETE | `/api/auth/passkeys/{id}` | Recent session; ownership verified |

Begin returns `{ "ceremony_id": "…", "options": { "publicKey": { … } } }`. Finish accepts `{ "ceremony_id": "…", "credential": { …WebAuthn JSON… } }`. The shared JS decodes/encodes base64url binary fields. Login finish sets the ordinary session cookie and returns `{ "redirect": "/" }`. It does not expose bearer tokens to browser JavaScript. Passkey endpoints return 404 when disabled and do not fall through to the upstream application. Their fixed `/api/auth/` namespace remains reserved even when `API_PATH` changes.

Cookie-authenticated internal admin and protected proxy API mutations also require the browser CSRF token and exact Origin. Explicit `Authorization: Bearer` clients use their access token without browser CSRF. Web forms retain path-specific XSRF protection.

## Security and persistence

Resident keys and user verification are **required**; attestation is **none** and authenticator attachment is unrestricted. The library generates 32-byte random challenges and verifies challenge, origin, RP ID hash, signature, user presence, and user verification. It rejects cross-origin ceremonies. The stable PocketBase record ID is the user handle. Credential IDs have a database uniqueness constraint, and the complete library Credential JSON is persisted, including counters, transports, and backup flags. Zero counters from synced passkeys are accepted by the library; a library clone warning denies login and allows password recovery.

Ceremonies last five minutes, are bound to a browser and (for enrollment) a specific session, and are stored server-side. A unique insert into `auth_consumptions` guarantees one winner for each ceremony and refresh-token exchange, including across proxy replicas. Plain DELETE is insufficient because concurrent PocketBase DELETE calls can both report success. Consumed or malformed finish attempts cannot reuse a challenge. Expired tokens, ceremonies, and consumption records are cleaned hourly; expiry is checked during every use.

JWTs contain random `jti` values. Only SHA-256 token hashes are stored, and every session/access/refresh request checks the persisted token and the current user's `is_active` and `auth_version`. No pre-upgrade stateless token is accepted. Administrative suspension never auto-unlocks: only password brute-force lockout uses `locked_until`. Valid passkeys can bypass the password-specific lockout, but cannot bypass `is_active=false`.

Browser authentication mutations are limited to 60 per minute per socket peer per process, with a bounded in-memory table. The limiter does not trust user-supplied forwarding headers. Behind a reverse proxy this groups callers under the proxy's peer address; add trusted edge rate limiting for larger installations and across replicas. Token/ceremony consumption remains database-coordinated across replicas. Application DEBUG/INFO logs go to stdout and WARN/ERROR to stderr; fatal startup errors exit 1. Authentication secrets, passwords, and full credentials are not logged by the proxy.

## Breaking changes and upgrade checks

- Apply migrations before running the new proxy; keep the old binary stopped during the upgrade. Existing users and password hashes remain, but every old session and JWT requires a fresh sign-in.
- Configure the explicit public origin and production secure cookies. A `SESSION_SECRET` shorter than 32 bytes now fails startup.
- Refresh tokens rotate at `POST /api/auth/refresh`; the old `/auth/refresh` routing is removed. Store the new refresh token after every successful exchange. Racing or retrying a consumed refresh token returns 401 and requires a fresh login if the replacement response was lost.
- API bearer tokens now require a PocketBase lookup. Update browser integrations to send CSRF headers on cookie-authenticated API mutations.
- PocketBase user creation/update is restricted to the proxy/superuser. Provision users through the proxy or its CLI.
- Keep the library version pinned; review upstream breaking changes and rerun the security/browser suites before updating.

## Verification

```sh
go test ./...
PB_BINARY=/path/to/pocketbase go test -race ./...
# Requires Chromium, PHP-FPM, and pip install playwright:
PB_BINARY=/path/to/pocketbase python3 tests/passkeys_e2e.py
```

The integration test starts a disposable PocketBase using the production migrations. It tests concurrent refresh/ceremony consumption, replay, expiry, session revocation, disabled users, credential ownership, and private collection rules. Browser tests use Chromium's virtual CTAP2 authenticator against both JS and PHP frontends. Test a real synced passkey and cross-device QR flow on your production HTTPS origin before rollout; virtual authenticators do not validate external password-manager synchronization.

References: [go-webauthn documentation](https://pkg.go.dev/github.com/go-webauthn/webauthn@v0.18.2/webauthn), [Google passkey autofill guide](https://developers.google.com/codelabs/passkey-form-autofill), [PocketBase migrations](https://pocketbase.io/docs/js-migrations/).
