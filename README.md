<p align="center">
  <img src="https://raw.githubusercontent.com/bradjtrammell/openv/master/docs/branding/openv-transparent.png" alt="OpenV logo" width="720">
</p>

# OpenV Identity

Standalone, community-hosted Go identity and server directory prototype for OpenV.

**Development status (October 14, 2026):** runnable MVP source committed; automated CI validation is being established. **Not production-ready and not yet integrated with the OpenV multiplayer client/server.**

## Run locally

Requires Go 1.22+.

```sh
export OPENV_BOOTSTRAP_SECRET="$(openssl rand -hex 32)"
go run . -listen 127.0.0.1:8088 -data ./data/identity.json
```

Keep the bootstrap secret securely and avoid exposing plain HTTP publicly. Default listener is loopback. For remote access, deploy behind a correctly configured HTTPS reverse proxy.

```sh
go test -count=1 ./...
go vet ./...
go build -o openv-identity .
```

## Implemented routes

| Method | Route | Purpose |
|---|---|---|
| GET | `/health` | Health |
| GET | `/.well-known/openv-identity` | Community metadata |
| GET | `/api/v1/keys` | Public Ed25519 key |
| POST | `/api/v1/bootstrap` | One-time protected admin setup |
| POST | `/api/v1/admin/accounts` | Admin creates player accounts |
| POST | `/api/v1/auth/login` | Password login, token session |
| POST | `/api/v1/auth/logout` | Revoke session |
| POST | `/api/v1/servers/register` | Admin registers server credentials |
| GET | `/api/v1/servers` | Authenticated directory |
| POST | `/api/v1/tickets` | Issue signed, short-lived server-specific ticket |
| POST | `/api/v1/tickets/redeem` | Authorized server redeems ticket once |

## Important limitations

- Passwords use PBKDF2-HMAC-SHA256 (310,000 iterations) and salted hashes, **not yet Argon2id**.
- Rate limiting is in memory; it does not persist across restart or apply globally across many proxy nodes.
- Persistent storage is a single JSON file containing signing material; use restrictive filesystem permissions and secure backups. This is not a transactional database.
- Signing key rotation, server secret rotation, account recovery, per-account security events, refresh tokens, and advanced roles are not implemented.
- Tickets use an OpenV-specific Ed25519 JSON format, **not** FiveM's native `cfxTicket2`. There is no real game-client/server integration yet.
- The `tickets/redeem` API relies on the identity server; a future authorized game-server adapter will need to define its behavior during an identity outage.
- Docker Compose binds the service to host loopback only. Do not publicly expose it without HTTPS, authentication protections, and a security review.

## Related repositories

- [openv](https://github.com/bradjtrammell/openv) — main game client and core source
- [openv-server](https://github.com/bradjtrammell/openv-server) — dedicated server integration and releases
- [openv-admin](https://github.com/bradjtrammell/openv-admin) — administration
- [openv-data](https://github.com/bradjtrammell/openv-data) — default resources and compatibility

See [protocol draft](docs/PROTOCOL.md). Existing game ownership, entitlement, licensing and source redistribution requirements remain applicable.
