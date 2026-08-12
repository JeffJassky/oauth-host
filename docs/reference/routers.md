# Routers

Two routers. Paths below are shown with the conventional `/oauth` mount for
`routes.oauth`; the discovery router's paths are fixed.

```ts
app.use(oauth.routes.discovery);       // origin root
app.use('/oauth', oauth.routes.oauth); // must match config.mountPath
```

## Trust bands

`routes.oauth` carries four kinds of caller on one mount, because they share the
path a client sees. Each handler authenticates its own; there is deliberately no
`router.use(requireSomething)` covering all of them, because mixing the bands is
how a session cookie ends up sufficient to exchange somebody else's
authorization code.

| Band | How it authenticates | Routes |
|---|---|---|
| **host session** | your `resolveUser(req)` — a cookie *you* issued | `GET /authorize`, `GET/POST /consent/:requestId`, `GET /me/grants`, `DELETE /me/grants/:id` |
| **client** | `client_secret_basic` or `client_secret_post` | `POST /token`, `POST /revoke` |
| **bearer** | an access token this server minted | `GET /userinfo` |
| **public** | nothing | `GET /jwks`, all discovery routes |

Every failure answers JSON — `{ error, error_description }` with the RFC token —
including 500s (`{"error": "server_error"}`).

## Discovery router

Mounted at the origin root. Public.

### `GET /.well-known/oauth-authorization-server`
### `GET /.well-known/openid-configuration`

RFC 8414 and OpenID Connect Discovery. **The same object** from both paths — one
grant type, one signing algorithm, one set of endpoints, generated from one
table. Serving one document from both is what keeps them from diverging.

`200`:

```json
{
  "issuer": "https://auth.test",
  "authorization_endpoint": "https://auth.test/oauth/authorize",
  "token_endpoint": "https://auth.test/oauth/token",
  "revocation_endpoint": "https://auth.test/oauth/revoke",
  "userinfo_endpoint": "https://auth.test/oauth/userinfo",
  "jwks_uri": "https://auth.test/oauth/jwks",
  "scopes_supported": ["openid", "profile", "email", "contacts.read", "contacts.write"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["ES256"],
  "authorization_response_iss_parameter_supported": true
}
```

Endpoint URLs are `issuer + mountPath + path`. `subject_types_supported`
reflects `config.subjectMode`. `code_challenge_methods_supported` lists `S256`
only — `plain` is implemented nowhere, so advertising it would be a lie a client
discovers at redemption.

### `GET /.well-known/oauth-protected-resource[/<suffix>]`

RFC 9728. The suffix is the **path component of the resource id**: a resource
`https://api.example.com/mcp` publishes at
`…/.well-known/oauth-protected-resource/mcp`. A resource that is a bare origin
publishes at the unsuffixed path.

The unsuffixed path also serves the **first** configured resource, so a host with
one API never has to know suffixes exist.

`200`:

```json
{
  "resource": "https://auth.test/mcp",
  "authorization_servers": ["https://auth.test"],
  "scopes_supported": ["openid", "profile", "email", "contacts.read", "contacts.write"],
  "bearer_methods_supported": ["header"]
}
```

`scopes_supported` is the resource's own `scopes` list, falling back to the whole
catalog.

`404` for a suffix that matches no configured resource:

```json
{ "error": "not_found", "error_description": "No resource is registered at 'nope'" }
```

This is the URL `protect()` names in its `WWW-Authenticate` challenge. Both come
from one function, so they cannot drift.

## OAuth router

### `GET /authorize`

**Host session.** Rate limited (`authorize`, keyed by IP).

| Parameter | Required | Notes |
|---|---|---|
| `response_type` | yes | `code` only |
| `client_id` | yes | |
| `redirect_uri` | yes | **exact string match** against the registration |
| `scope` | — | space-delimited; each must be in the catalog **and** in the client's `allowedScopes` |
| `resource` | — | RFC 8707. May repeat. Defaults to the client's first allowed resource |
| `state` | — | echoed on every response, success and error |
| `code_challenge` | yes | PKCE, RFC 7636 |
| `code_challenge_method` | yes | must be `S256`; an omitted value is rejected rather than defaulting to `plain` |
| `nonce` | — | echoed into the `id_token` |
| `prompt` | — | stored on the request |
| `max_age` | — | non-negative integer |

Any security parameter that **repeats** is treated as absent — "first one wins"
is a parameter-pollution primitive. `resource` is the one parameter allowed to
repeat.

Outcomes:

| | |
|---|---|
| Signed in, valid | `302` → `consentUrl?request_id=<handle>` |
| Signed out, `loginUrl` set | `302` → `loginUrl?<returnParam>=<absolute return URL>` |
| Signed out, no `loginUrl` | `401 {"error": "login_required"}` |
| Unredirectable error | `400` JSON, **no `Location`** |
| Redirectable error | `302` → `redirect_uri?error=…&error_description=…&state=…&iss=…` |

Which errors go which way is a security boundary — see
[the redirect-vs-render boundary](/guide/security#the-redirect-vs-render-boundary).
Unredirectable: missing/unknown/disabled `client_id`, missing or unregistered
`redirect_uri`. Everything else redirects.

Every authorization response carries `iss` (RFC 9207), errors included.

### `GET /consent/:requestId`

**Host session.** Rate limited (`consent`, keyed by IP).

Returns the [consent payload](/guide/consent-screen#the-payload). No internal
ids, no secrets.

| Status | Body |
|---|---|
| 200 | `ConsentPayload` |
| 401 | `{"error": "login_required"}` |
| 403 | `{"error": "access_denied", "error_description": "this authorization request belongs to another user"}` |
| 404 | `{"error": "invalid_request", "error_description": "unknown or expired authorization request"}` |

Unknown, expired and already-decided are one answer — distinguishing them makes
the endpoint an oracle for whether a handle ever existed.

### `POST /consent/:requestId`

**Host session.** JSON body (your `express.json()` parses it). Rate limited
(`consent`, keyed by IP).

```json
{ "approve": true, "scopes": ["openid", "contacts.read"], "contextId": "org_1" }
```

`approve` must be a boolean. `scopes` defaults to everything requested and may
only ever **narrow** it. `contextId` is required exactly when a `grantContext`
adapter is configured, and rejected when one is not.

`200`:

```json
{ "redirectTo": "https://claude.ai/api/mcp/auth_callback?code=…&state=st-123&iss=https://api.example.test" }
```

On denial the same field carries `error=access_denied` instead of `code`.

Errors: `400 invalid_request` (bad `approve`, a scope outside the request,
already decided, `contextId` missing or unexpected), `401 login_required`,
`403 access_denied` (another user's handle, or `verify()` returned false),
`404 invalid_request`.

A decision is claimed atomically, so two concurrent approvals cannot mint two
codes. A *rejected* decision leaves the handle usable.

### `POST /token`

**Client-authenticated.** `application/x-www-form-urlencoded`. Rate limited
(`token`, keyed by client id, falling back to IP). CORS headers only when
`cors.tokenEndpoint` is on.

Always answers `Cache-Control: no-store` and `Pragma: no-cache`, on errors too.

The route mounts `express.urlencoded({ extended: false, limit: '10kb' })`
**itself**, at the route level and nowhere else, because RFC 6749 §4.1.3
requires form encoding and hosts mount `express.json()` only. It does not leak
onto any other route; there is a test for that.

Client authentication is `client_secret_basic` (the `Authorization` header) or
`client_secret_post` (`client_id` + `client_secret` in the body). Basic wins when
both are present.

#### `grant_type=authorization_code`

| Field | Required |
|---|---|
| `grant_type` | yes |
| `code` | yes |
| `redirect_uri` | yes — must equal the one the code was issued for, exactly |
| `code_verifier` | yes — PKCE |

#### `grant_type=refresh_token`

| Field | Required |
|---|---|
| `grant_type` | yes |
| `refresh_token` | yes |
| `scope` | no — may only narrow |
| `resource` | no — may repeat; must be a subset of the token's audience |

`200` for both:

```json
{
  "access_token": "…",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "…",
  "scope": "openid profile contacts.read",
  "id_token": "eyJhbGciOiJFUzI1NiIs…"
}
```

`id_token` is present only when `openid` is among the granted scopes — minting
one unasked hands a client an identity assertion it never got consent for. A
refresh never echoes `nonce`: it belongs to an authorization request that is long
gone.

Errors:

| Status | `error` | When |
|---|---|---|
| 400 | `invalid_grant` | unknown/expired/consumed code or refresh token; wrong `redirect_uri`; PKCE failure; wrong client; revoked grant; family past its absolute lifetime; ended context membership |
| 400 | `invalid_scope` | a refresh asked for a scope it does not hold |
| 400 | `invalid_target` | a resource the authorization is not bound to |
| 400 | `unsupported_grant_type` | anything but the two above |
| 401 | `invalid_client` | any client-auth failure — one answer for all of them |
| 429 | `too_many_requests` | with `Retry-After` |

A replayed code or a reused refresh token additionally **revokes the whole token
family** — see [Reuse detection](/guide/security#reuse-detection-and-family-revocation).

### `POST /revoke`

**Client-authenticated.** Form-encoded, same parser exception and rate-limit
bucket as `/token`. `Cache-Control: no-store`.

| Field | Required |
|---|---|
| `token` | yes |

Always `200 {}` — for an unknown token, an expired one, an already-revoked one,
and one belonging to another client (RFC 7009 §2.1–2.2). Answering anything else
turns the endpoint into a token-existence oracle.

Revoking a **refresh** token kills its entire family. Revoking an **access**
token kills only that token.

`401 invalid_client` if client authentication fails.

### `GET /userinfo`

**Bearer.** Not rate limited by the package. `Cache-Control: no-store`.

Requires `Authorization: Bearer <access_token>` and the `openid` scope.

`200` — claims are read **live** on every call; access tokens carry none:

```json
{ "sub": "…", "name": "Alice", "email": "alice@example.com", "picture": "https://x/a.png" }
```

`sub` matches the `id_token`'s and is the only claim a `claims` adapter cannot
override. `name` / `picture` need the `profile` scope, `email` needs `email`, and
all three need a [`loadUser`](/guide/adapters#loaduseruserid--who-is-this-id)
adapter — without one they come back empty while everything else looks correct.

A deleted user is a bare `{ sub }`, not a 500.

| Status | `error` | `WWW-Authenticate` |
|---|---|---|
| 401 | `invalid_request` | `Bearer error="invalid_request", …` — no token presented |
| 401 | `invalid_token` | expired, revoked, unknown, or the client no longer exists |
| 403 | `insufficient_scope` | `Bearer error="insufficient_scope", scope="openid"` |

### `GET /jwks`

**Public.** Not rate limited. `Cache-Control: public, max-age=300` — a client
refetching JWKS on every validation is a self-inflicted DoS.

```json
{ "keys": [{ "kty": "EC", "crv": "P-256", "x": "…", "y": "…", "kid": "…", "alg": "ES256", "use": "sig" }] }
```

Active **and** retiring keys, public halves only. Retiring keys stay published so
tokens they already signed still validate. The private scalar `d` is never
present.

### `OPTIONS /token`, `OPTIONS /revoke`

Registered **only** when `cors.tokenEndpoint` is true. `204`. Without the flag,
these fall through to your app's own handling.

### `GET /me/grants`

**Host session.** Not rate limited by the package.

| Query | Default | Bounds |
|---|---|---|
| `limit` | 20 | clamped to 1–100 |
| `skip` | 0 | ≥ 0 |

`200`:

```json
{
  "limit": 20,
  "items": [
    {
      "id": "66ba…",
      "client": { "clientId": "…", "name": "Claude", "branding": { "publisher": "Anthropic" } },
      "scopes": [{ "id": "contacts.read", "label": "Read your contacts" }],
      "createdAt": "2026-08-12T09:00:00.000Z",
      "lastUsedAt": "2026-08-12T09:04:11.000Z"
    }
  ]
}
```

Live grants only, newest first. `contextId` appears only when the grant has one.

**The grant id is the only identifier that leaves** — the `DELETE` below needs
it. No user id, no client `_id`, no token ids. There is a test asserting their
absence rather than asserting a UI hides them.

`401 login_required` for a signed-out caller, with no `items` in the body.

### `DELETE /me/grants/:id`

**Host session.**

Scoped to the signed-in user's own grants. Revokes the grant (`revokedBy:
'user'`) and every live token under it, fires `oauth.grant_revoked` on `track`,
and writes an audit row.

`200`:

```json
{ "revoked": true, "tokensRevoked": 3 }
```

`404 {"error": "not_found", "error_description": "No such grant"}` for an id that
is unparseable, unknown, already revoked, **or belongs to another user** — a
malformed id is a 404, not a cast error surfacing as a 500, and another user's
grant is a 404 rather than a 403.

### Route order

Literal paths are declared **before** parameter paths in this router, and the
tests are named after the failure (`does not shadow /me/grants with the
/me/grants/:id route`). A parameter segment will happily swallow a literal
declared after it. Do not reorder the file.

## Rate limiting

Three buckets, each `{ max: 60, windowMs: 60_000 }` by default and each
individually disableable with `false`.

| Bucket | Routes | Key |
|---|---|---|
| `authorize` | `GET /authorize` | IP |
| `consent` | `GET`/`POST /consent/:requestId` | IP |
| `token` | `POST /token`, `POST /revoke` | client id, falling back to IP |

Exceeded:

```json
{ "error": "too_many_requests", "error_description": "Rate limit exceeded for token. Retry in 42s." }
```

`429`, with `Retry-After` in seconds. The store fails **open** — a throw is
logged at `error` and the request is allowed.

## Related

- [The consent screen](/guide/consent-screen)
- [`protect()`](/reference/protect)
- [Security](/guide/security)
