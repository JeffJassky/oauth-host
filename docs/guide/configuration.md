# Configuration

Every key `createOAuthHost(config)` accepts, its default, and why it exists.

There is no recon to cite here — this package is greenfield, so the rule is
stricter rather than looser: **every key cites a spec clause or an explicit
product decision.** A key with neither was cut before any code was written.
Where a spec says MUST, that is not a config key.

## Required

| Key | Type | Why |
|---|---|---|
| `issuer` | `string` | RFC 8414 metadata, `iss` on every authorization response (RFC 9207), and `id_token.iss`. Must be the public origin, absolute `http(s)`, **no trailing slash** — every metadata URL is built by concatenation, and `https://x.com//token` is a different origin to some clients. Both are boot errors. |
| `resources` | `ResourceSpec[]` | RFC 8707 resource indicators; MCP requires audience-bound tokens. At least one, so `protect()` knows what audience to demand. A host with one API declares one resource — one line. Ids must be absolute URIs with no fragment. |
| `scopes` | `(ScopeSpec \| string)[]` | The catalog. The consent endpoint's entire job is serving `label` / `description` / `sensitive` to your UI, which is why these are objects. A bare string is shorthand for `{ id, label: id }`. Ids may not contain whitespace or quotes — `scope` is space-delimited (RFC 6749 §3.3) and a space would make the whole parameter ambiguous. |
| `consentUrl` | `string` | Where `/authorize` sends a signed-in user. The consent UI is yours by requirement. The package appends `?request_id=…`, merging correctly into a URL that already has a query. |

## Mounting

| Key | Default | Why |
|---|---|---|
| `connection` | the global `mongoose` | Your connection, your database. |
| `mountPath` | `'/oauth'` | Where you mount `routes.oauth`, relative to `issuer`. The package has to be **told**: discovery publishes absolute endpoint URLs, and a router cannot see its own mount path until a request arrives — by which time the metadata document is already built. A mismatch is the failure where discovery looks fine and every client 404s on `/token`. Normalized, so `/oauth`, `oauth/` and `/oauth/` are the same. |

## Sign-in and identity

| Key | Default | Why |
|---|---|---|
| `loginUrl` | — | `/authorize` is a package route a signed-out user lands on **directly**, so your "bounce to login" middleware never runs for it and the redirect is the package's to perform. With no `loginUrl`, a signed-out `/authorize` answers `401 login_required` rather than looping. |
| `returnParam` | `'next'` | The query parameter carrying the return URL on that bounce. |
| `userAdapter` | `{ resolveUser: defaultResolveUser }` | See [Adapters](/guide/adapters). |
| `resolveUser` | `defaultResolveUser` | Shorthand. Reads `req.user._id` / `req.user.id`, then `req.authUserId`. **Mutually exclusive** with `userAdapter` — passing both is a boot error, not a silent pick. |
| `loadUser` | — | Shorthand for `userAdapter.loadUser`. Without it, `profile` and `email` claims on `/userinfo` and the `id_token` come back empty; the package logs a warning at boot saying so. |
| `grantContext` | — | Org/workspace-scoped grants. Omitted means single-subject mode, with no picker, no `contextId`, and no membership re-check. Both `list()` and `verify()` are required when present. |
| `claims` | — | Extra `id_token` / `/userinfo` claims. Omitted, `profile` and `email` map from user-adapter fields. |

## Lifetimes

| Key | Default | Why |
|---|---|---|
| `ttl.code` | `60` (s) | RFC 6749 §4.1.2 caps an authorization code at 10 minutes; a code is redeemed within seconds in practice. |
| `ttl.accessToken` | `3600` (s) | Also the `id_token` lifetime. |
| `ttl.refreshToken` | `5_184_000` (60 d) | The **sliding** window, refreshed on each rotation. This is what the TTL index reaps. |
| `ttl.refreshAbsolute` | `15_552_000` (180 d) | The ceiling from first issuance, copied unchanged onto every rotation so no amount of refreshing extends it. Past it, re-consent is the only way back. |
| `ttl.authorizationRequest` | `600` (s) | How long a pending consent handle lives. Surfaced as `expiresAt` in the consent payload. |

## Identity and signing

| Key | Default | Why |
|---|---|---|
| `subjectMode` | `'public'` | OIDC Core §8. `public` means `sub` is your user id. `pairwise` means `HMAC(userId, clientId, salt)` — stable per client, unlinkable across them. **Choose before first issuance**: partners store `sub` as their primary key, so switching later is a breaking change for them. |
| `pairwiseSalt` | — | Required when `subjectMode` is `pairwise`; a boot error otherwise. Permanent — changing it changes every `sub` a partner has stored. (Issued subjects are persisted per client, so an accidental rotation does not re-identify existing users.) |
| `signing.keys` | — | `SigningKeySpec[]`: PKCS#8 ES256 PEM from the environment. The production answer — the key is not in the same database as the tokens it signs. A malformed PEM or a non-P-256 curve is a boot error naming the `kid`. |
| `signing.autoGenerate` | `false` | Generate a keypair and persist it in `oauth_keys` when none exists. A documented development convenience, not a default: a server that invents a fresh key every boot invalidates every `id_token` it ever issued, and the symptom shows up in the client. With neither source configured, `getSigningKey()` throws a message naming this flag. |
| `clockSkewMs` | `0` | Tolerance for a *client's* wrong clock on `id_token` `iat` / `nbf`. It widens the window at both ends rather than shifting it. Every expiry in the package is server time compared against server `now` — never a client-supplied timestamp. |

## Rate limiting

| Key | Default | Why |
|---|---|---|
| `rateLimits.token` | `{ max: 60, windowMs: 60_000 }` | Brute force on `/token` is the classic authorization-server failure. Keyed by client id, falling back to IP. Also covers `/revoke`. |
| `rateLimits.authorize` | `{ max: 60, windowMs: 60_000 }` | Keyed by IP. |
| `rateLimits.consent` | `{ max: 60, windowMs: 60_000 }` | Keyed by IP. Covers both `GET` and `POST /consent/:requestId`. |
| `rateLimits.store` | in-memory | Per process, so on N instances the effective limit is `max × N`. Stated rather than hidden; the hook is how you make it Redis. Fails **open**, loudly — a counter outage must not be an auth outage. |

Any of the three rules may be `false` to disable that bucket entirely, which
short-circuits to a passthrough rather than to an infinite `max`. Exceeding a
limit is `429 {"error": "too_many_requests"}` with `Retry-After`.

`/userinfo`, `/jwks`, `/me/grants` and the discovery routes are **not** rate
limited by the package.

## Storage

| Key | Default | Why |
|---|---|---|
| `modelNames` | `OAuthClient`, `OAuthGrant`, `OAuthCode`, `OAuthToken`, `OAuthRequest`, `OAuthKey`, `OAuthAudit` | The mongoose model registry is process-global. If any of those names is plausibly taken in your app, rename it here — see [Data model](/guide/data-model#name-collisions). |
| `collectionPrefix` | `'oauth_'` | Collection names, independent of model names. |
| `audit.retentionDays` | `400` | A TTL index on `oauth_audit.createdAt`. A log nothing prunes is an outage waiting. |

## Flags that ship off

Two keys are shipped dormant rather than smuggled in on by default. Both are
named for what they cost.

| Key | Default | Why |
|---|---|---|
| `cors.tokenEndpoint` | `false` | Send CORS headers on `/token` and `/revoke`. v1 has no public clients, so a browser has no business calling either. When off, the middleware is a **passthrough, not a header-stripper** — your own CORS layer is not overridden. When on, `OPTIONS` preflights on both routes answer 204. |
| `cors.origins` | `[]` | Empty means `Access-Control-Allow-Origin: *`. A non-empty list echoes a matching `Origin` and sets `Vary: Origin`, without which a shared cache can hand one origin another's answer. |
| `tokenCache.ttlMs` | `0` | **Off, and v1 has no cache to turn on.** Caching introspection results is exactly the thing that turns "revocation is instant" into a lie: any non-zero value would be the window in which a revoked token still works. The key is accepted and normalized so the tradeoff has a name, but no code path currently reads it — access tokens are checked against the database on every request. Leave it at `0`. |

## Client ID metadata documents

Off by default. A full page — including what it costs — is at [Client ID
metadata](/guide/cimd); this is the key list.

| Key | Default | Why |
|---|---|---|
| `clientIdMetadata.enabled` | `false` | A client whose `client_id` is an `https://` URL serving a JSON document describing itself, fetched and treated as the registration. Both Claude and ChatGPT prefer it over DCR. Off is the safe default: **the SSRF surface does not exist until you turn it on.** |
| `clientIdMetadata.allowedHosts` | — | **Required when enabled — an empty or missing list is a boot error, never an implicit "any host."** `claude.ai` matches that hostname exactly and case-insensitively (`evilclaude.ai` does not match). `.claude.ai` also admits subdomains. `localhost:8080` names a port; otherwise the URL must use the scheme default. A URL (`https://claude.ai/`) or a wildcard (`*.claude.ai`) is a boot error naming what to write instead. |
| `clientIdMetadata.cacheTtlMs` | `3_600_000` (1h) | How long a fetched document is trusted before a re-fetch. Successes persist in `oauth_clients`, so the cache survives a restart. Failures are cached separately for 60s, in memory — that one is a security control, not a performance knob. |
| `clientIdMetadata.fetchTimeoutMs` | `5_000` | Hard ceiling on the outbound request, via `AbortSignal.timeout`. |
| `clientIdMetadata.maxBytes` | `65_536` | Response body cap, enforced **while reading**. `Content-Length` is a claim by the party being defended against, so it is not trusted. |
| `clientIdMetadata.allowedScopes` | the full catalog | Scopes a CIMD client may ever request, whatever its document claims. The document's own `scope` narrows further; a scope you do not have is dropped rather than fatal. Entries must be in the catalog — a boot error otherwise. |

Redirects are **not followed** and there is no key to make them followed: a 3xx
from a metadata URL is a failure, because following one is how an allowlisted
host becomes an open proxy to everything else.

## Observability

| Key | Default | Why |
|---|---|---|
| `logger` | no-op | `{ debug, info, warn, error }`, all optional. Structured first argument, message second. |
| `track` | no-op | An optional peer seam for analytics. Receives `OAuthEvent`. Never a hard dependency; absent, events go nowhere and no collection is created. Must be a function — a boot error otherwise. |

## What was cut

Named so their absence reads as a decision:

`introspection` (no second resource server yet) · `dcr` (RFC 7591 dynamic client
registration — still a [non-goal](/guide/introduction#non-goals); the answer for
clients that will not be registered by hand is
[`clientIdMetadata`](/guide/cimd), above) · `deviceCode` ·
`clientCredentials` · `logoUpload` (branding is URLs you already host; the
moment the package accepts an upload it owns image validation, SSRF on fetch,
and a CDN story).

## Related

- [`createOAuthHost`](/reference/factory) — what it returns and what it throws
- [Adapters](/guide/adapters)
- [Client ID metadata](/guide/cimd)
- [Security](/guide/security) — key rotation, secret rotation, revocation
