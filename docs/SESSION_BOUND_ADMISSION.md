# Session-bound admission and revocation (ov2)

**Status:** Implemented on the `engineering/session-bound-v2-admission-20261024` branch; not a game-engine integration or playable client.

## Protocol

The community login endpoint issues an opaque bearer. Identity stores only its SHA-256 digest (base64url, unpadded). `POST /api/v1/tickets` issues an Ed25519-signed **ov2** ticket containing the existing issuer, subject, audience, JTI, issued and expiry claims, plus `sid`, the SHA-256 digest of the **specific** issuing login bearer. The signed payload must contain exactly eight fields, with no duplicate or unknown keys.

`POST /api/v1/tickets/redeem` requires the registered server ID and secret, verifies the signature, protocol version, audience, time window, exact claim shape, and single-use JTI. For ov2 it additionally requires that the `sid` still exists in Identity's login store, has the same subject and is not expired. Logout removes the issuing login; an unrelated login by the same account cannot rescue the ticket. The successful response includes `login_session` for ov2 only, not the bearer.

Previously signed ov1 tickets remain verifiable and redeemable for compatibility until expiry; ov1 has no login-session binding and must never contain `sid`. New issuance is ov2. The discovery endpoint explicitly reports `ticket_format: "ov2"`, `accepted_ticket_formats: ["ov1","ov2"]`, and `session_liveness: "/api/v1/sessions/check"`.

## Already-admitted players

Registered game servers call `POST /api/v1/sessions/check` with:

```json
{
  "server_id": "<registered server ID>",
  "server_secret": "<registered server secret>",
  "sessions": [
    { "subject": "<redeemed subject>", "login_session": "<redeemed login_session>" }
  ]
}
```

The response is a positional boolean array, `{"active":[true]}`. Requests require an enabled server with the correct credential, contain 1–64 entries, use canonical 43-character unpadded base64url SHA-256 login digests, and must fit the existing 16 KiB JSON request limit. A false result means the server must revoke that admitted game session. **Identity does not forcibly disconnect game players:** the game server must poll, fence in-flight operations, and enforce revocation. If Identity is unreachable, the server must apply an explicit fail-closed admission and bounded existing-session outage policy.

The endpoint intentionally does not return raw bearer tokens, password material, user profiles, or server credentials. All state checks use the same Identity authorization mutex as logout. Network response writes happen after unlocking.

## Verification and deployment limits

GitHub CI exercises unit tests, signed v1/v2 claim downgrade regressions, login/logout/restart, replay protection, batch validation, race detection, vet and a Linux build. Actual Windows CEF execution, GTA V ownership validation, OneSync entity creation, and two licensed-PC gameplay are **not** verified by these tests. The recovered cumulative Go gateway already has a compatible ov2 liveness client, but its 256-file engineering source tree has not yet been reconciled and published to `bradjtrammell/openv-server`.

Do not expose Identity's built-in plaintext HTTP listener to untrusted networks. Place it behind authenticated TLS transport, keep server secrets private, and preserve legitimate GTA V entitlements and upstream licenses.
