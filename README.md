# OpenV Identity

Community-owned identity and server discovery for OpenV.

**Status:** Initial development scaffold (October 14, 2026). No production security audit or game integration has been completed.

OpenV Identity will be a standalone, self-hosted Go binary. A community chooses its own identity URL. Its players authenticate directly with that community; the community controls its account records, keys and registered server list. No OpenV-wide hosted identity service is required.

## Intended responsibilities

- Persistent local accounts and sessions, with secure password storage and recovery flows
- Authentication and secure, short-lived connection-ticket issuance
- Server registration and community-owned server directory
- Verification keys, key rotation, revocation and anti-replay protections
- Stable opaque player IDs and explicit migration/alias mappings
- Administrative authorization and audit logging
- Offline-friendly operation: established in-game sessions remain alive when identity service is unavailable

## Repository boundaries

- [openv](https://github.com/bradjtrammell/openv): game client/runtime and connection handshake
- [openv-server](https://github.com/bradjtrammell/openv-server): dedicated-server integration and packaging
- [openv-admin](https://github.com/bradjtrammell/openv-admin): administration UI integration
- [openv-data](https://github.com/bradjtrammell/openv-data): resource compatibility

Protocol outline: [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Security baseline

No default administrator password, no unsigned tickets, no unbounded sessions, no implicit trust in client-submitted identifiers, and no automatic merging of existing accounts by display name. Never substitute account authentication for lawful game ownership or asset entitlements.

## Development status

Design contracts are being recorded first. Do not represent the service as production-ready until persistent storage, threat-model review, automated tests, authorized client/server interoperability, and recovery procedures have been verified.
