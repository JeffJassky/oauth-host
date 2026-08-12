# Security

The parts of this package that exist to fail safely, and what each one costs.

## Rotating refresh tokens

Every use of a refresh token mints a new pair and **consumes the old one**. The
client always gets a `refresh_token` back from `/token`, and it is never the one
it sent.

```json
{
  "access_token": "…new…",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "…new…",
  "scope": "openid profile contacts.read"
}
```

Rotation is what makes theft *detectable*. Because the old token is consumed the
instant a new one is minted, a second presentation of it can only come from
someone who is not the current holder.

Two lifetimes bound the chain:

- `ttl.refreshToken` (60 d) is the **sliding** window, reset on each rotation.
- `ttl.refreshAbsolute` (180 d) is the **ceiling**, copied unchanged onto every
  rotation. Past it the family is revoked and re-authorization is the only way
  back — a compromised-but-actively-refreshed token cannot live forever.

A refresh may **narrow** the scope set (RFC 6749 §6) but never widen it. The
ceiling is the intersection of what the token carries and what the grant still
says, so a grant narrowed after issuance cannot be widened back by a refresh.
Likewise `resource`: a refresh may request a subset of the token's existing
audience, never a new one.

## Reuse detection and family revocation

Every token descended from one authorization code shares a `familyId`. When a
consumed refresh token is presented again:

1. The **entire family** is revoked — every access and refresh token under it.
2. `oauth.refresh_reuse_detected` fires on `track`.
3. An audit row is written with the client, user, grant and family.
4. `logger.warn` gets `oauth-host: rotated refresh token reused — family revoked`.
5. The caller gets `400 {"error": "invalid_grant"}`.

Which of the two presenters is the attacker is unknowable, so both lose. That is
the correct trade: a legitimate client that lost a race re-authorizes, an
attacker with a stolen token gets nothing and you find out.

The same happens on other impossible states:

| Trigger | Reason recorded |
|---|---|
| An authorization code redeemed twice | `code_replay` |
| A rotated refresh token presented again | `refresh_reuse_detected` |
| A refresh token presented by a client it was not issued to | `refresh_wrong_client` |
| The family's absolute lifetime reached | `family_absolute_expiry` |
| `grantContext.verify()` returned false on refresh | `context_membership_ended` |

**This is the house idempotency rule inverted, deliberately.** Elsewhere a
replay is a duplicate to swallow. Here it is an attack signal: silently
returning the same tokens hands the attacker exactly what they asked for.

`oauth.refresh_reuse_detected` is the event to alert on. It has no benign cause.

## The redirect-vs-render boundary

`/authorize` reports errors two different ways, and which one it picks is a
security boundary rather than formatting.

**Rendered as JSON, never redirected:**

- missing `client_id`
- unknown `client_id`
- disabled client
- missing `redirect_uri`
- `redirect_uri` not registered for that client

Until `client_id` resolves to a live registration **and** `redirect_uri` matches
that registration exactly, there is no address proven safe to send a browser to.
Redirecting anyway is the open-redirect hole. These answer `400` with a JSON
body and no `Location` header.

**Redirected back to the client**, with `state` and `iss` intact: everything
after that point — `response_type` other than `code`, missing or non-`S256`
`code_challenge`, an unknown or disallowed scope, an undeclared resource, a
malformed `max_age`. Both identifiers are proven at that stage, so the client is
a safe place to report to and is the party that can fix it.

`redirect_uri` matching is **exact string equality**. Not a prefix match, not an
origin match, not "ignore the query string". A registered
`https://claude.ai/api/mcp/auth_callback` does not match
`https://claude.ai/api/mcp/auth_callback/`, `…?x=1`, or `…/../../evil` — every
relaxation of this rule is a published attack. A client that needs a second
callback registers a second URI.

## PKCE

Mandatory, `S256` only — for confidential clients too, and it is the *entire*
credential for a public one.

`code_challenge_method` must be present and must be `S256`. RFC 7636 §4.3
defaults an omitted method to `plain`, which this package does not implement
anywhere — requiring the parameter makes that rejection explicit instead of
letting a downgrade arrive as a default. The verifier is length- and
charset-checked before hashing (an unbounded verifier is a hashing DoS).

For a [public client](/guide/cimd#public-clients) there is no secret behind the
PKCE check, so it is the only thing binding the code to the party that started
the flow. That is the reason `code_challenge` is required at `/authorize` rather
than checked opportunistically at `/token`: a public-client authorization with
no challenge is refused before a code is ever minted, and there is a test named
after that.

A code is **consumed before it is validated**. A code that fails its
`redirect_uri` or PKCE check has still been presented, and leaving it live for a
second attempt turns a failed injection into a retried one. The cost is that a
client bug burns the code, which is what the spec asks for anyway.

## What revocation actually revokes

| Call | Grants | Tokens | Codes | Effect |
|---|---|---|---|---|
| `DELETE /oauth/me/grants/:id` | that one, `revokedBy: 'user'` | all under it | — | instant |
| `grants.revoke(id)` | that one | all under it | — | instant |
| `clients.disable(id)` | all for the client | all for the client | deleted | instant |
| `users.revokeAll(id)` | all for the user | all for the user | deleted | instant |
| `users.forget(id)` | **deleted** | **deleted** | deleted | instant |
| `contexts.revoked(u, c)` | matching that context | matching | deleted | instant |
| `POST /oauth/revoke` (refresh) | untouched | the whole family | — | instant |
| `POST /oauth/revoke` (access) | untouched | that one | — | instant |

"Instant" is literal, and it is a property of two things: access tokens are
opaque and checked against the database on every request, and introspection
**re-reads the grant** as well as the token. A live token whose grant died does
not work.

`POST /oauth/revoke` always answers `200 {}` — for an unknown token, an expired
one, an already-revoked one, and one belonging to another client (RFC 7009
§2.1–2.2). The client's goal is satisfied either way, and a 400 would turn the
endpoint into a token-existence oracle.

## What `tokenCache.ttlMs` costs

The default is `0`, off, and the whole reason it is spelled that way.

Any non-zero value would be **the window in which a revoked token still works**.
That is the price of the read it saves, and naming the key after the tradeoff
rather than after the performance is deliberate: caching is exactly the thing
that turns "revocation is instant" into a lie.

In v1 there is no cache to enable. The key is accepted and normalized so the
tradeoff has a name in the config surface, but nothing reads it — every
introspection goes to the database. Leave it at `0`.

## Signing keys

ES256 (P-256) only. One curve means one code path, and P-256 is the intersection
of "every OIDC client supports it" and "Node signs it without a dependency".

Two sources, in this order:

**1. `signing.keys` — PEM from the environment.** The production answer: the key
is not in the same database as the tokens it signs.

```ts
signing: {
  keys: [{ kid: 'prod-2026-08', privateKeyPem: process.env.OAUTH_SIGNING_KEY }],
}
```

Validation is eager, so a malformed PEM or a wrong curve is a boot error naming
the `kid`, not a 500 on the first client that asks for an `id_token`.

**2. `signing.autoGenerate: true` — generate once and persist** in `oauth_keys`,
reused on the next boot. A development convenience, and named as one. It puts
the private key next to the data it authenticates.

**Neither is not a default.** With no key configured, `getSigningKey()` throws a
message naming `signing.autoGenerate`. A server that silently invents a fresh
key per boot invalidates every `id_token` it ever issued on restart, and the
symptom shows up in the client rather than in your logs.

### Rotating a signing key

Add the new key as `active` and mark the old one `retiring`:

```ts
signing: {
  keys: [
    { kid: 'prod-2026-09', privateKeyPem: NEW, status: 'active' },
    { kid: 'prod-2026-08', privateKeyPem: OLD, status: 'retiring' },
  ],
}
```

Retiring keys keep being published in `/jwks` so tokens they already signed still
validate; only `active` is used to sign. Drop the old entry once every
`id_token` it signed has expired (`ttl.accessToken`, one hour by default).

`/jwks` is cached for five minutes (`Cache-Control: public, max-age=300`) — a
client refetching JWKS on every token validation is a self-inflicted DoS. Budget
for that when timing a rotation.

The private scalar `d` is stripped from every published JWK, and there is a test
asserting it.

## Rotating a client secret

Two live secrets at once is what makes rotation deployable without downtime.

```ts
const { clientSecret } = await oauth.clients.rotateSecret(clientId, {
  retireAfter: 7 * 24 * 60 * 60 * 1000,   // ms; default 0 = immediate
  label: 'sept-rotation',
});
```

1. Call `rotateSecret` with a `retireAfter` window. Both secrets verify.
2. Deploy the new one to the client.
3. Watch `lastUsedAt` on the new secret move — that is the whole reason the
   field exists. `oauth.models.Client.findOne({ clientId })` shows it.
4. The old secret stops verifying at `retiresAt`, exactly.

A second rotation never pushes an existing retirement *later*: an operator who
scheduled a secret to die at noon does not expect a later call to resurrect it
until midnight.

Every authentication failure — unknown client id, wrong secret, retired secret,
disabled client — answers the identical `401 {"error": "invalid_client",
"error_description": "client authentication failed"}`. Distinguishing them turns
the token endpoint into a client-id oracle, and the extra detail helps an
attacker strictly more than it helps an integrator, who has the audit log. A 401
answering a Basic credential carries the `WWW-Authenticate: Basic` challenge RFC
6749 §5.2 requires.

Both `client_secret_basic` and `client_secret_post` are accepted. Basic wins when
both are present — a client that sends both and disagrees with itself has a bug
that should not be papered over by picking whichever happens to verify.

## Public clients cannot be forged into existence

A public client — today, only a [CIMD](/guide/cimd) registration — authenticates
by presenting `client_id` alone, `token_endpoint_auth_method=none`, with PKCE as
the binding. Two symmetric rules, and the second is the one that matters:

- A **public** client presenting a secret is refused.
- A **confidential** client omitting its secret is refused.

If omitting a secret were sufficient, every confidential registration in your
database would be downgradeable to public by anyone who knows a `client_id` —
and a `client_id` is a public value by design. Both violations answer the same
`401 invalid_client` as every other client-auth failure, so neither reveals
which kind of client an id names.

`clients.rotateSecret()` on a public client **throws** rather than returning a
credential the token endpoint would refuse.

## The CIMD fetch

Enabling `clientIdMetadata` makes this server issue an outbound HTTP request to
a URL chosen by an unauthenticated request parameter. **That is server-side
request forgery by construction**, and it is the only place in this package
where the server initiates a connection at all.

It ships **off**. When on, `clientIdMetadata.allowedHosts` is required — an
empty list is a boot error rather than an implicit "any host" — and it carries
most of the defense. The rest:

| Control | What it stops |
|---|---|
| `https:` only, before any socket | `file:`, `http:` to an internal address |
| Hostname matched by **equality**, never suffix | `evilclaude.ai` matching `claude.ai` |
| Subdomains only for a `.example.com` entry | An allowlist covering more than intended |
| No URL credentials, no fragment | `https://a@allowed@evil/` parser differentials |
| No non-default port unless the entry names one | Internal services on an allowlisted host |
| **Redirects not followed** — a 3xx is a failure | An allowlisted host proxying to anything, cloud metadata endpoints included |
| `AbortSignal.timeout(fetchTimeoutMs)` | A slow endpoint holding request workers |
| Body cap enforced while reading | `Content-Length` is a claim by the party being defended against |
| JSON content type required | Being fed something that is not a metadata document |
| **Negative caching** (60s) | A replayed `client_id` turning `/authorize` into an outbound traffic amplifier |

Two things it does not do: there is no IP-level filtering (an allowlisted host
resolving to a private address is still fetched) and no DNS-rebinding defense.
The allowlist is a statement of trust in named vendors; keep it short. Full
detail on [the CIMD page](/guide/cimd#what-this-costs-ssrf).

`clients.disable()` on a CIMD client survives a re-fetch — the status check runs
before the fetch and the write-back never sets `status`. That is the failure
mode most likely to go unnoticed, so it has a test named after it.

## Errors are loud and spec-shaped

Every failure answers `{ error, error_description }` with the RFC-mandated
token, as JSON, including 500s. Clients switch on `error`, and a made-up code is
indistinguishable from a broken server.

This is the "reject junk quietly" rule inverted: an authorization server that
swallows bad input teaches an integrator nothing and hides an attack. Volume is
absorbed by rate limiting, not by silent drops.

Where the package *does* stay quiet, it is to avoid an oracle: unknown vs.
expired consent handles are one 404; every client-auth failure is one 401;
`/revoke` is always 200.

## The audit log

`oauth_audit` is append-only, TTL'd at `audit.retentionDays` (400 by default),
indexed by `{clientId, createdAt}` and `{userId, createdAt}`.

An audit write **never fails a request** — a throw is caught and logged. It is
evidence, not control flow.

Types written: `oauth.client_created`, `oauth.client_updated`,
`oauth.client_secret_rotated`, `oauth.client_disabled`,
`oauth.consent_granted`, `oauth.consent_denied`, `oauth.grant_revoked`,
`oauth.user_forgotten`, `oauth.user_access_revoked`, `token_issued`,
`token_revoked`, `code_replay`, `refresh_reuse_detected`,
`refresh_wrong_client`, `grant_revoked`.

Bulk operations write **one** row, not one per grant: `clients.disable()` on a
popular client would otherwise bury the event that caused the storm.

## A short operational checklist

- `issuer` is the public origin, no trailing slash, and matches what clients use.
- `signing.keys` comes from the environment in production. `autoGenerate` is off.
- `subjectMode` was decided before the first partner integration.
- `rateLimits.store` is shared if you run more than one instance.
- `cors.tokenEndpoint` is off unless you know why it is on.
- `clientIdMetadata` is off, or its `allowedHosts` names only vendors you would
  trust with an outbound request.
- `tokenCache.ttlMs` is `0`.
- Something alerts on `oauth.refresh_reuse_detected`.
- `users.revokeAll` is wired to password change and deactivation, and
  `users.forget` to deletion — see [Account deletion](/guide/account-deletion).
- `oauth.syncIndexes()` is awaited at boot.

## Related

- [Account deletion](/guide/account-deletion)
- [Client ID metadata](/guide/cimd) — the SSRF surface in full
- [Data model](/guide/data-model) — why nothing replayable is stored
- [Admin API](/reference/admin-api)
