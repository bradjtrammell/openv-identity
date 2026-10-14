# OpenV Identity protocol — initial draft

Status: **design draft, not an implemented API**. Version namespace: `/api/v1`.

## Community configuration

Client starts with community-selected HTTPS base URL; no centralized OpenV directory is assumed. Every community owns its user registry and server list. Discovery metadata should expose service version, supported auth methods, public verification-key set, and compatibility requirements. TLS must be authenticated; protect against SSRF, unsafe redirects and lookalike identity endpoints.

## Proposed operations (not yet stable)

| Operation | Purpose |
|---|---|
| `GET /.well-known/openv-identity` | Capability and metadata discovery |
| `POST /api/v1/auth/login` | Secure user authentication and session issuance |
| `POST /api/v1/auth/refresh` | Session refresh with rotation |
| `POST /api/v1/auth/logout` | Session revocation |
| `GET /api/v1/servers` | Authorized community server directory |
| `POST /api/v1/tickets` | Ticket for a specific registered server |
| `GET /api/v1/keys` | Public key set for verification |
| `POST /api/v1/servers/register` | Authenticated server registration and lease renewal |

## Connection ticket security contract

Tickets must be signed; short-lived; audience-scoped to a specific server; bound to a stable community-local subject ID and protocol version; and one-time-use at the server. Verify issuance time, expiry, signer and key ID, audience, subject, protocol version, and replay nonce. Protect against clock skew and key rollover. Do not expose signing keys to the game client or publicly registered servers.

The upstream game handshake currently uses a binary `cfxTicket2` structure with RSA/SHA-1 checks. This service does **not** claim wire compatibility: protocol negotiation and client/server implementation must be coordinated, authorization and licensing constraints respected, and compatibility tested against a permitted build.

## Server registration

Servers authenticate with their own credentials or asymmetric identity, never user passwords. Record server IDs, endpoints, ownership, lease expiration and health status. Server visibility and connection privileges belong to the community.

## Persistence and migration

Use stable opaque community-scoped IDs. Legacy identifiers are aliases only after explicit proof of ownership or verified administrator migration. Never silently equate a legacy `license:`, `fivem:`, `steam:`, or Discord ID with an OpenV account.

## Failure handling

Previously admitted players remain connected during identity outages. New sessions and tickets fail closed if verification is unavailable, unless an explicit, cryptographically verifiable offline ticket is still valid. Rotate keys without invalidating properly authorized in-flight sessions unexpectedly.

## Outstanding decisions

Choose final token serialization and algorithm, client UI auth method (password/passkey/OIDC), admin role policy, data retention, API error schema, schema migration mechanism, and high availability. These choices must be backed by interoperability and security tests before finalizing v1.
