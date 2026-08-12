# oauth-host — build plan

Stage 3 output. **Greenfield** — no recon, no synthesis. Stages 1–2 are skipped
by construction: there is no existing implementation to lift. The input is the
requirements interview (2026-08-12) plus `standards/`.

That inverts one house rule and it needs saying out loud: `working-style.md`
says "you are not writing a new product, business logic survives verbatim."
Here there is no source logic to preserve. **The specifications are the source
implementation** — RFC 6749/6750/7009/7636/8414/8707/9207/9728, OpenID Connect
Core, and the MCP authorization spec. Every design choice below either cites one
of those or is named as ours. Where a spec says MUST, that is not a config key.

Everything after this document is execution.

---

## 0. The paper test

The degenerate case is not "a host with no config." It is **a user connecting
this platform to Claude and ChatGPT as an MCP server**, because that is the
whole reason the package exists. Express it as config; if it needs a special
case, the config layer isn't real.

```ts
const oauth = createOAuthHost({
  connection,                                   // host's mongoose connection
  issuer: 'https://api.example.com',            // MUST be the public origin
  resources: [{ id: 'https://api.example.com/mcp', label: 'MCP server' }],

  scopes: [
    { id: 'openid',        label: 'Sign you in',            oidc: true },
    { id: 'profile',       label: 'Your name and avatar',   oidc: true },
    { id: 'email',         label: 'Your email address',     oidc: true },
    { id: 'contacts.read', label: 'Read your contacts',
      description: 'View names, emails and notes on your contacts.' },
    { id: 'contacts.write', label: 'Create and edit contacts', sensitive: true },
  ],

  consentUrl: '/settings/authorize',            // host's SPA route
  loginUrl:   '/login',                         // adapters.md sign-in contract
  returnParam: 'next',

  userAdapter,                                  // default reads req.user (passport)
  // grantContext omitted  → single-subject mode, no picker
  // claims omitted        → profile/email derived from userAdapter fields
})

app.use(oauth.routes.discovery)                 // at origin root, not under /oauth
app.use('/oauth', express.json(), oauth.routes.oauth)
app.use('/mcp', oauth.protect('contacts.read'), mcpRouter)

// one-time, from a script or the host's own admin route
await oauth.clients.create({
  name: 'Claude',
  redirectUris: ['<Claude connector callback, from their docs>'],
  allowedScopes: ['openid', 'profile', 'email', 'contacts.read'],
  branding: { logoUrl: 'https://…/claude.png', publisher: 'Anthropic' },
})   // → { clientId, clientSecret }  ← secret returned once, never again
```

**Verdict: passes, with three things the config surface must absorb.**

1. **`resources` is not optional decoration.** MCP requires the client to send
   `resource` (RFC 8707) and requires tokens to be audience-bound. A host with
   one API still declares one resource, so `protect()` knows what audience to
   demand. Cost at the degenerate case: one line. Kept.
2. **`grantContext` absent must mean absent** — no picker, no context field on
   the grant, no claim in the token, no membership re-check on refresh. Verified
   below in §12.
3. **Scope objects, not strings.** The consent endpoint's entire job is serving
   `label`/`description`/`sensitive` to the host's UI. A bare string array would
   force a second parallel catalog immediately. Strings are accepted as
   shorthand and inflated to `{ id, label: id }`.

---

## 1. Name

Both checked 2026-08-12 (404 = free):

| Candidate | Scoped | Unscoped |
|---|---|---|
| `oauth-host` | `@jeffjassky/oauth-host` 404 | **`oauth-host` 404 — free** |
| `grantly` | `@jeffjassky/grantly` 404 | `grantly` 404 — free |
| `consent` | `@jeffjassky/consent` 404 | `consent` 200 — taken |
| `authorize` | `@jeffjassky/authorize` 404 | `authorize` 200 — taken |
| `handshake` | `@jeffjassky/handshake` 404 | — |
| `oauth-provider` | `@jeffjassky/oauth-provider` 404 | — |

`publishing.md` says take the scope; it also says `mailery`/`featureboard` went
unscoped because the words happened to be free. Two words here *are* free, so
that luck is available again — but the scope is still the recommendation for
consistency with telemetry and everything after it.

**User's call. No default assumed.** Repo slug and `__SLUG__` token follow the
word (`oauth-host` → slug `oauth-host`).

## 2. Public API (one screen)

```ts
createOAuthHost(config)                         // → oauth

// ── routers the host mounts (house style: routers, never an app) ──
oauth.routes.discovery       // GET /.well-known/oauth-authorization-server
                             //     /.well-known/openid-configuration
                             //     /.well-known/oauth-protected-resource[/*]
oauth.routes.oauth           // GET  /authorize            → 302 to consentUrl
                             // GET  /consent/:requestId    → consent JSON
                             // POST /consent/:requestId    → { redirectTo }
                             // POST /token  POST /revoke
                             // GET  /userinfo   GET /jwks
                             // GET  /me/grants  DELETE /me/grants/:id
oauth.protect(...scopes)     // → resource-server middleware; sets req.oauth

// ── programmatic admin (no UI ships; this is what a UI would call) ──
oauth.clients.create(spec)   // → { clientId, clientSecret }  secret shown once
oauth.clients.rotateSecret(clientId, { retireAfter? })
oauth.clients.update(clientId, patch) / .list(query) / .get(clientId)
oauth.clients.disable(clientId)          // revokes every token it holds

oauth.grants.list({ userId | clientId })
oauth.grants.revoke(grantId, { by })

oauth.users.forget(userId)               // outbound: user deleted
oauth.users.revokeAll(userId, { reason })// outbound: password change, deactivate
oauth.contexts.revoked(userId, contextId)// outbound: membership ended

oauth.syncIndexes()                      // boot; awaited before first write
oauth.models                             // escape hatch: the mongoose models
```

Writes are verbs (`create`, `rotateSecret`, `revoke`, `forget`, `protect`);
reads are the noun returned (`grants`, `clients`, `models`). Fits one screen.

`routes.oauth` deliberately carries three trust bands on one router because they
share the mount path a client sees: **client-authenticated** (`/token`,
`/revoke`), **bearer-authenticated** (`/userinfo`), **host-session**
(`/authorize`, `/consent/*`, `/me/*`). Each handler states its band; there is no
shared "authenticated" middleware, because mixing them is how a session cookie
ends up authorizing a token exchange.

## 3. Config surface — every key, and what proves it

Greenfield means `process/3-build-plan.md`'s "every key cites the implementation
that proves it" has no recon to cite. The substitute is stricter, not looser:
**every key cites a spec clause or an interview decision.** A key with neither
is invented and gets cut.

| Key | Proven by |
|---|---|
| `issuer` | RFC 8414 metadata + `iss` in every authorization response (RFC 9207) + `id_token.iss` |
| `resources[]` | RFC 8707 `resource` param; MCP requires audience-bound tokens |
| `scopes[]` (objects w/ label, description, sensitive, oidc) | Interview: scope catalog in host config, mirrored to DB. Consent endpoint has nothing to serve without it |
| `consentUrl` | Interview: consent UI is the host's |
| `loginUrl` + `returnParam` | `standards/adapters.md` §Sign-in redirects — `/authorize` is a package route a signed-out user lands on directly |
| `ttl.{code,accessToken,refreshToken,refreshAbsolute,authorizationRequest}` | Spec guidance (code ≤10 min, RFC 6749 §4.1.2) + operational tuning. Defaults 60s / 1h / 60d sliding / 180d absolute / 10m |
| `subjectMode: 'public' \| 'pairwise'` | OIDC Core §8. Default `public` (`sub` = host user id) — pairwise is HMAC(userId, clientId, salt) and permanent per client, so it must be chosen before first issuance |
| `signing.keys[]` \| `signing.autoGenerate` | OIDC requires a signed `id_token`; JWKS needs `kid` + rotation. Env-supplied PEM in prod, generate-and-persist as the documented dev convenience |
| `rateLimits.{token,authorize,consent}` + `rateLimits.store` | Brute force on `/token` is the classic host failure. In-memory default is per-process and says so; store hook is how you make it Redis |
| `tokenCache.ttlMs` | **Default 0 = off.** Opt-in only, because caching is exactly the thing that turns "revocation is instant" into a lie. Documented as that tradeoff, not as a perf knob |
| `modelNames` / `collectionPrefix` | traps #2 — the mongoose registry is process-global |
| `audit.retentionDays` | Default 400. TTL index; a log nothing prunes is an outage waiting |
| `cors.tokenEndpoint` | RFC 6749 + browser-based public clients. **Default off** — v1 has no public clients (§10), so this ships as a documented flag with a warning, not as an assumption |
| `clockSkewMs` | traps §15 — `id_token` `iat`/`nbf` against a client's wrong clock |

Cut before writing: `introspection` (no second resource server yet), `dcr`
(interview: no), `deviceCode`/`clientCredentials` (interview: no), `logoUpload`
(branding is URLs the host already hosts — no storage adapter, stated in §4).

## 4. Adapters — both directions, named

| Adapter | Inbound (package asks host) | Outbound (host tells package) | Absent |
|---|---|---|---|
| `userAdapter` | `resolveUser(req) → { id, email?, displayName?, avatarUrl? } \| null`. Pure read of what the host's session middleware left behind (`adapters.md`: never verify a token inside it) | `oauth.users.forget(id)` — delete grants, tokens, codes, pseudonymous subjects, audit tombstone. `oauth.users.revokeAll(id)` — password change / deactivate | Default reads `req.user` then `req.authUserId`; passport apps configure nothing |
| `grantContext` | `list(user, { client, scopes }) → [{ id, label, description? }]` — what can this user grant on behalf of. `verify(user, contextId) → boolean`, re-checked on **every refresh**, not just at consent | `oauth.contexts.revoked(userId, contextId)` — membership ended, kill matching grants | Omitted ⇒ single-subject mode: no picker, no `context` on the grant, no claim, no re-check |
| `claims` | `claims(user, { scopes, contextId }) → Record<string, unknown>` — fills `id_token` and `/userinfo` beyond the standard set | **None, and that is the design.** Claims are a read-only projection of host data the host already owns; there is no lifecycle event for "a claim changed" because tokens carry no claims — `/userinfo` reads live. Stated so its one-directionality doesn't look like an oversight | Default: `profile`/`email` scopes map from `userAdapter` fields |
| `logger` | `{ debug, info, warn, error }` | — | No-op default |
| `track` | — | Cross-package optional peer (§6) | No-op default, records nothing |
| `rateLimits.store` | `hit(key, windowMs) → { count, resetAt }` | — | In-memory per-process default |

**No storage adapter, deliberately.** Client logos are `logoUrl` strings. The
moment the package accepts an upload it owns image validation, SSRF on fetch,
and a CDN story — for a field the host can already serve. Named here so it reads
as a decision, not an omission.

**`isAdmin` gates nothing** (`adapters.md`). The programmatic admin API is a
plain module export, so there is no admin router for a host to leave unguarded —
the strongest available form of that rule. If the host wraps `oauth.clients.*`
in its own route, that guard is the host's, and `examples/` ships the test.

## 5. Package split

**One package, one entry.** The trust test (`split on trust, not features`)
finds no seam: nothing here ships to a browser, nothing carries a publishable
key, there is no client SDK — the OAuth *client* is Claude or ChatGPT, and they
already have one. Every line touches mongoose, express, or a secret.

No `dist/ui`, so traps #7 (`import.meta.url` in CJS) and #8 (SPA base href) do
not apply to this package. That is the main thing the missing UI buys.

## 6. Cross-package deps

None hard. Two optional peers, both no-op by default:

- **telemetry** — `track` receives `oauth.authorization_requested`,
  `consent_granted`, `consent_denied`, `token_issued`, `token_refreshed`,
  `refresh_reuse_detected`, `client_secret_rotated`, `grant_revoked`. Absent:
  events go nowhere, no collection, no config.
- **mcp-server** (future sibling, depends on *this*, never the reverse) — will
  consume `oauth.protect()` and the protected-resource metadata. The contract it
  needs is fixed here: `req.oauth = { userId, clientId, contextId, scopes[],
  grantId, tokenId }`. Absent: nothing; this package has no idea it exists.

## 7. Data layer (expensive to reverse — settled now)

Seven collections, prefix configurable, every model built by a factory that
takes the connection and returns the existing model if the name is claimed
(traps #2).

| Collection | Holds | Key indexes |
|---|---|---|
| `oauth_clients` | clientId, `secrets[{hash,label,createdAt,lastUsedAt,retiresAt}]`, redirectUris[], allowedScopes[], allowedResources[], branding, status | `{clientId}` unique |
| `oauth_grants` | the consent record — userId, clientId, contextId, scopes[], resources[], version, lastUsedAt, revokedAt | `{clientId,userId,contextId}` unique **partial** on `revokedAt: null`; `{userId}`; `{clientId}` |
| `oauth_codes` | codeHash, snapshot of the authorization, codeChallenge, nonce, authTime, consumedAt | `{codeHash}` unique; `{expiresAt}` TTL |
| `oauth_tokens` | discriminated `kind: access\|refresh`, tokenHash, familyId, parentId, grantId, scopes[], audience[] | `{tokenHash}` unique; `{expiresAt}` TTL; `{familyId}`; `{grantId}`; `{userId,clientId}` |
| `oauth_requests` | pending consent handle: requestId, userId, full param snapshot, decision | `{requestId}` unique; `{expiresAt}` TTL |
| `oauth_keys` | kid, alg, publicJwk, privateJwk, status active\|retiring | `{kid}` unique |
| `oauth_audit` | append-only: type, actor, clientId, userId, grantId, ip | `{createdAt}` TTL(400d); `{clientId,createdAt}`; `{userId,createdAt}` |

Decisions that are expensive to reverse, made here:

- **Nothing is stored in a form that can be replayed.** Codes, tokens and client
  secrets are stored as SHA-256 (tokens/codes: high-entropy random, so a plain
  hash is right and bcrypt would be a throughput bug) — client secrets likewise
  high-entropy and package-generated, never user-chosen. Lookup is by hash;
  comparison is `timingSafeEqual`.
- **Grants and tokens are separate documents.** A grant outlives every token
  issued under it — it is what "connected apps" lists and what revocation
  cascades from. Collapsing them (tokens as the record of consent) makes
  "revoke access" mean "expire in an hour."
- **`familyId` on every refresh token**, with `parentId` chaining rotations.
  Reuse of a consumed refresh token revokes the entire family — the single most
  important stolen-token defense, and it does not work if the chain isn't stored.
- **Codes are consumed atomically** via `findOneAndUpdate({consumedAt: null})`.
  Second redemption revokes the family issued from that code and audits it.
- **`sub` is decided before first issuance** (§3 `subjectMode`). Pairwise
  subjects persist in a small map inside `oauth_clients`; switching modes after
  a partner has stored user ids is a breaking change for them, not for us.
- **`Model.init()` awaited before first write** (traps #3) — cold-DB unique
  index races would let two grants exist for one (client, user, context).
- **No time-series collections** (traps #17): erasure needs `deleteMany`.

## 8. UI shape

**API + no UI.** Interview: no admin dashboard in v1. Consent UI is the host's
by requirement. Two consequences worth stating:

- The consent JSON payload *is* the UI contract, so it is versioned and tested
  as strictly as any route: internal ids never appear (`adapters.md`: omit
  internal ids from `/me`-style payloads), only `{ client: {name, logoUrl,
  publisher, homepageUrl, tosUrl, privacyUrl}, scopes: [{id, label, description,
  sensitive, isNew}], contexts?, user: {displayName, email}, expiresAt }`.
- When a dashboard is built later, it mounts on §2's programmatic API with no
  server changes — that API was designed as its backend, which is why it exists
  in v1 with no caller.

## 9. Traps

Applicable classic traps: **#2** model factory, **#4** literal routes before
`/:requestId` (with the test named after the failure), **#5** body parsing —
see below, **#6** JSON not HTML on throw, **#9** `types/test-d.ts`, **#10** peer
matrix (mongoose 7/8/9 × express 4/5), **#13** VitePress dead links.

**#5 deserves its own paragraph.** RFC 6749 requires `/token` and `/revoke` to
accept `application/x-www-form-urlencoded`, but hosts mount `express.json()`
only. The router therefore mounts `express.urlencoded({ extended: false, limit:
'10kb' })` **on those two routes and nowhere else** — the sanctioned single-route
exception, documented, with a test asserting a form POST works on an app that
never mounted a urlencoded parser.

§15–19 are the high-volume set. This package has public unauthenticated
endpoints, so they get answered — and **two of them invert**, which is the
useful part:

- **§15 time.** Client clocks matter only for `id_token` validation; hence
  `clockSkewMs`, and `iat`/`nbf`/`exp` are minted from server time exclusively.
  Every expiry is a server-side `expiresAt` compared to server `now` — never a
  client-supplied timestamp. `auth_time` comes from the host session via the
  user adapter, and drives `max_age`/`prompt=login`.
- **§16 idempotency — inverted.** Telemetry dedupes replays silently. Here a
  replayed authorization code or refresh token is an **attack signal**: fail
  loudly, revoke the family, audit. The only genuinely idempotent operations are
  revocation (`/revoke` returns 200 for an already-revoked or unknown token, per
  RFC 7009) and consent re-approval of an identical scope set.
- **§17 no time-series.** Held; erasure requires `deleteMany`.
- **§18 cap every query.** `grants.list` and `clients.list` take a bounded limit
  with a hard ceiling inside the query. `/me/grants` is capped and paginated
  even though a realistic user has under twenty.
- **§19 reject junk quietly — inverted.** A public ingest path swallows bad
  input; an authorization server must not. Errors are spec-shaped and loud:
  `{ error, error_description }` with the RFC-mandated code, and the
  redirect-vs-render split is a security boundary — **an invalid `client_id` or
  an unregistered `redirect_uri` is never redirected to** (that is the open-redirect
  hole), everything else redirects the error back to the client with `state` and
  `iss` intact. Rate limiting is what absorbs junk volume, not silent drops.

## 10. Non-goals (explicit)

Dynamic client registration · admin dashboard UI · consent screen markup ·
login, sessions, password reset, MFA · public/first-party clients (no
PKCE-only-no-secret flow) · `client_credentials` · device authorization ·
token exchange (RFC 8693) · token introspection (RFC 7662) · JWT access tokens ·
SAML · upstream federation / social login · RP-initiated or back-channel logout ·
session management · CIBA · request objects (JAR/PAR) · OpenID certification ·
per-client quota/billing · storage adapter for logo uploads · email notification
on new connection (host's job via `track`).

Three of these are deliberately *shaped for* rather than built: the client model
carries `type: 'confidential'` and a `trusted` flag so public and first-party
clients are additive; discovery metadata is generated from a table so
`introspection_endpoint` is one row; `signing` already does key rotation so JWT
access tokens would be a token-format branch, not an architecture change.

## 11. Size estimate

Greenfield, so there is no "thing it replaces" to come in under. The yardstick
is `node-oidc-provider` — a certified, everything-on implementation an order of
magnitude larger. Shipping ~2.5k lines against it is the claim that a **single
grant type with a host-rendered consent screen** is a genuinely smaller problem.

| Area | est. lines |
|---|---|
| models + factories + index/boot sync | ~700 |
| protocol services (authorize, consent, code, token, rotation, revoke, userinfo, jwks, discovery) | ~900 |
| resource-server middleware + protected-resource metadata + challenges | ~150 |
| programmatic admin API (clients, grants, tokens, users, contexts) | ~250 |
| config validation, scope mirror, key management | ~250 |
| errors, express glue, rate limiting | ~200 |
| **total shipped** | **~2,450** |
| tests | ~1,300 |
| docs (VitePress) | ~600 |

If this lands materially over ~3k, the likely cause is a non-goal that crept in.

## 12. Sanity checks

- **Degenerate case** (§0: one resource, no `grantContext`, no `claims`, default
  everything): the picker never renders, grants carry no context field, refresh
  skips the membership re-check, `sub` is the host's user id, tokens have one
  audience, rate limiting is in-memory, no cache. The generalizations cost one
  config line each and zero runtime branches at zero-config. ✓
- **Every config key cites a spec clause or an interview decision** (§3). Two
  are flagged as shipped-but-dormant rather than smuggled in: `cors.tokenEndpoint`
  (off; no public clients in v1) and `tokenCache.ttlMs` (0; on-by-default would
  contradict the revocation guarantee). ✓
- **Non-goals non-empty.** ✓ — 20+ items, three named as shaped-for.
- **Traps named and answered**, including the two §15–19 inversions. ✓
- **Both adapter directions documented**, including `claims`, where "no outbound"
  is argued rather than left blank. ✓

## 13. Execution order (Stage 4 preview)

1. Models + factories + `syncIndexes()` + boot validation. The unique partial
   index on grants and the TTL indexes are the load-bearing pieces.
2. Token core in isolation: issue, hash, rotate, family revoke, **reuse
   detection**. Unit-tested before any HTTP exists — it is the security core.
3. `/authorize` → consent JSON → approve → code → `/token` end-to-end over
   supertest, including the redirect-vs-render error split.
4. `oauth.protect()` + `/.well-known/oauth-protected-resource` +
   `WWW-Authenticate` challenges + audience enforcement.
5. OIDC layer: `id_token`, `nonce`, `/userinfo`, `/jwks`, key rotation.
6. `/me/grants`, programmatic admin API, audit log.
7. `examples/` app + **a real connector round-trip**: add the example server to
   Claude and to ChatGPT as a custom connector and complete an authorization.
   Spec compliance is not the acceptance test; those two clients are.

---

*Open item carried into Stage 4, not an unknown:* manual `client_id`/`client_secret`
entry (no DCR) is currently supported in both Claude's and ChatGPT's custom
connector setup, but that is their product UI, not a spec guarantee. Step 7
verifies it against the live products before publish. If either drops it,
DCR-with-admin-approval returns as the first post-v1 item — the client model and
discovery table are already shaped for it.

---

## 14. Post-plan reversal: client ID metadata documents

**Added after §10 was written, and it reverses two of its non-goals.** Recorded
here rather than quietly edited into the list above, because a non-goal that
changes without a reason is just a list nobody trusts.

### What changed

| §10 non-goal | Status |
|---|---|
| "public/first-party clients (no PKCE-only-no-secret flow)" | **Public clients: reversed.** First-party (consent-skipping) stays a non-goal. |
| "Dynamic client registration" | **Narrowed.** RFC 7591 DCR is still a non-goal — no registration endpoint, no registration access tokens, no approval queue. "No dynamic registration at all" is no longer accurate. |

Everything else in §10 holds.

### The reason

The open item above resolved in a direction the plan did not anticipate. Both
Claude and ChatGPT support Client ID Metadata Documents and **prefer** them to
manual credentials: a client whose `client_id` is an `https://` URL serving a
JSON document describing itself. Manual-only does not fail, it just makes every
single install a support interaction — someone generating a secret, pasting it
into a vendor UI, and asking for help when it does not work. That is the cost
§0 was written to avoid, arriving through a door the plan left open.

The predicted fallback in the open item was DCR-with-admin-approval. CIMD is
strictly less machinery for the same outcome: no endpoint to guard, no
credential to issue, no approval queue, and the registration is verifiable
against a URL the vendor already publishes.

### The trust decision

CIMD makes the authorization server issue an outbound HTTP request driven by an
unauthenticated request parameter. That is SSRF by construction and there is no
version of this feature where it isn't.

**The trust boundary chosen is a host allowlist**, not open registration.
`clientIdMetadata.allowedHosts` is required whenever the feature is enabled —
an empty list is a boot error, never an implicit "any". An allowlisted host is
trusted enough to auto-activate a client; anything else is refused before a byte
is fetched. The feature ships **off**, so §12's degenerate case is unchanged.

The rest is defense the allowlist alone has historically not been enough for:
`https:` only, hostname matched by equality rather than suffix, no URL
credentials or fragment, no non-default port unless the entry names one,
**redirects not followed** (a 3xx is a failure, not a hop), a hard timeout, a
body cap enforced while reading rather than from `Content-Length`, a required
JSON content type, and negative caching so a replayed `client_id` cannot make
this server into a traffic amplifier. Successful resolutions persist in
`oauth_clients` so the cache survives a restart.

Two limits stated rather than hidden: no IP-level filtering and no
DNS-rebinding defense. The allowlist is a statement of trust in named vendors.

### What it cost in the model

§10 predicted this shape correctly, which is the useful part: `type` widened
from the literal `'confidential'` to a union, and discovery grew two entries in
the existing table. Added: `registration: 'manual' | 'cimd'` plus
`metadataUrl` / `metadataFetchedAt` / `metadataEtag` on the client document. No
new collection, no migration for existing rows.

The one invariant worth naming because it is the likeliest bug: **`disable()`
survives a re-fetch.** A `cimd` row is re-derived from its document on every
cache miss, so a disabled client that reactivated an hour later would be a
revocation that silently expires. The status check runs before the fetch and the
write-back never sets `status`; there is a test named after that failure.

Size: ~430 lines of source and ~450 of tests, against §11's ~2,450 estimate —
still inside the ~3k ceiling.
