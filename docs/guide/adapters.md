# Adapters

Five seams between the package and your app. Only the first is close to
mandatory; the rest exist so that omitting them means *nothing* — no field, no
branch, no key in a payload.

| Adapter | Inbound (package asks host) | Outbound (host tells package) | Absent |
|---|---|---|---|
| `userAdapter` | `resolveUser(req)`, `loadUser(userId)` | `users.forget(id)`, `users.revokeAll(id)` | Default reads `req.user` then `req.authUserId` |
| `grantContext` | `list(user, ctx)`, `verify(user, contextId)` | `contexts.revoked(userId, contextId)` | Single-subject mode |
| `claims` | `claims(user, ctx)` | **None, deliberately** | `profile`/`email` from the user adapter |
| `logger` | `{ debug, info, warn, error }` | — | No-op |
| `track` | — | receives `OAuthEvent`s | No-op |
| `rateLimits.store` | `hit(key, windowMs)` | — | In-memory, per process |

## The user adapter

The seam between your user system and this package. The package never queries
your user collection, never joins against it, and never writes to it.

It has **two inbound directions**, and the second one is the one people miss.

### `resolveUser(req)` — who is making this browser request

```ts
const oauth = createOAuthHost({
  // …
  resolveUser: (req) => req.user && {
    id: req.user._id,
    email: req.user.email,
    displayName: req.user.name,
    avatarUrl: req.user.avatar,
    authTime: req.session.loggedInAt,   // drives auth_time / max_age
  },
});
```

Return `null` for a signed-out caller. It runs on `/authorize`, both `/consent`
endpoints, and `/me/grants*` — the host-session band.

**It is a pure read of what your session middleware already left behind.** Never
verify a token inside it. It runs on every request through `/authorize`, and a
throw there becomes a 500 where you wanted a clean redirect to the login page.

Omit it and the default reads `req.user._id` / `req.user.id`, then
`req.authUserId`. Passport apps configure nothing.

`authTime` is worth supplying: it is where `auth_time` in the `id_token` comes
from, and it is what would drive `max_age` / `prompt=login`. Omitted means those
are unsupported for your host.

`isAdmin` is accepted and **gates nothing**. It cannot: the package cannot know
what admin means in your app, and there is no admin router to guard. See
[the admin API](/reference/admin-api).

### `loadUser(userId)` — who is this id

```ts
loadUser: async (id) => {
  const u = await User.findById(id).lean();
  return u && { id: u._id, email: u.email, displayName: u.name, avatarUrl: u.avatar };
},
```

**Normalize the id with `String(id)` before you compare it.** `UserId` is
`Types.ObjectId | string` and `findById()` accepts both, so a host that writes
`loadUser: (id: string) => …` typechecks and works right up until something
compares ids — at which point an `ObjectId` and its string form are not equal
and the mismatch surfaces somewhere else entirely.

`resolveUser` **cannot serve `/userinfo` or the `id_token`.** Those are reached
on the bearer and client-authenticated bands, where there is no host session to
read and the only identity available is the `userId` stored on the token. There
is no `req` with a cookie on it.

Without `loadUser`, the `profile` and `email` claims come back empty while every
other part of the flow looks correct — which is exactly the kind of bug that
costs an afternoon. The package logs a warning at boot when it is missing, but
it is not fatal: a host that never grants `profile` or `email` has nothing to
load.

If `loadUser` returns `null` (the user was deleted between issuance and the
call), `/userinfo` answers a bare `{ sub }` document rather than a 500. It is a
public route; it must not blow up because a host forgot to call
[`users.forget`](/guide/account-deletion).

**Why not snapshot the profile onto the grant at consent time?** Because then
`/userinfo` serves a name the user changed eight months ago. This package's
stated contract is that access tokens carry no claims and `/userinfo` reads
live. `loadUser` is what makes that true.

### Object form

`userAdapter` and the `resolveUser` / `loadUser` shorthands are mutually
exclusive — passing both is a boot error rather than a silent pick.

```ts
import { createUserAdapter } from '@jeffjassky/oauth-host';

createOAuthHost({ userAdapter: createUserAdapter({ resolveUser, loadUser }) });
```

### Outbound

The user adapter's outbound direction is two calls you make from your own
account lifecycle: `oauth.users.forget(id)` and `oauth.users.revokeAll(id)`. The
difference between them is the whole reason both exist — see
[Account deletion](/guide/account-deletion).

## `grantContext` — granting on behalf of an org

Some products let a user connect an app *as* an organization, workspace, or
team. `grantContext` is that, and omitting it is genuinely free.

```ts
grantContext: {
  // What this user may grant, for this client and scope set.
  list: async (user, { client, scopes }) => {
    const orgs = await Membership.find({ userId: user.id }).populate('org');
    return orgs.map((m) => ({
      id: String(m.org._id),
      label: m.org.name,
      description: m.role,
    }));
  },
  // Still a member? Re-checked on EVERY refresh, not only at consent.
  verify: async (user, contextId) =>
    Boolean(await Membership.exists({ userId: user.id, orgId: contextId })),
}
```

`list()` fills the `contexts` array in the consent payload. `verify()` runs at
consent **and again on every single refresh**, because a grant made as an
employee has to die when the employment does, and a refresh is the only moment
the package is guaranteed to get to ask again. When it returns false mid-flight,
the grant is revoked, the token family is killed, and the refresh fails with
`invalid_grant`.

`verify()` receives a **fully populated `PackageUser` when `loadUser` is
configured** — the package resolves it through the same adapter `/userinfo`
uses. That matters for the rules people actually write: "a member of this
account **or** an admin" cannot be evaluated from an id alone, and without this
the host would have to re-read the same user from the database on every single
refresh just to see a flag.

**Without a `loadUser` adapter, `verify()` gets `{ id }` and nothing else.** So
if your rule reads any attribute beyond the id, configure `loadUser` — the same
one that fills the `profile` and `email` claims.

Both methods are required; supplying one is a boot error.

### Absent means absent

With no adapter configured, the package runs in **single-subject mode**:

- no `contexts` key in the consent payload (absent, not `[]`)
- `contextId` on grants, codes and tokens is `null`
- no `context` key on `grants.list()` summaries
- `req.oauth.contextId` is `null`
- no membership re-check on refresh — `verify` is never called
- posting a `contextId` to `/consent/:requestId` is a `400 invalid_request`

Zero runtime branches at zero config.

### Outbound

`oauth.contexts.revoked(userId, contextId)` is the push half of the pair. Call
it when a membership ends. `verify()` catches it on the next refresh, but an
access token already issued is valid for its full hour and nothing re-checks it —
this is what closes that window.

## `claims` — extra claims on `id_token` and `/userinfo`

```ts
claims: (user, { scopes, contextId, client }) => ({
  ...(scopes.includes('profile') ? { locale: user.locale } : {}),
  ...(contextId ? { org: contextId } : {}),
}),
```

Gate on `scopes` yourself. The package gates only the standard set it derives
(`name` and `picture` on `profile`, `email` on `email`); anything you return is
emitted as-is.

Reserved claims are stripped before yours are merged: `iss`, `sub`, `aud`,
`exp`, `iat`, `nonce`, `at_hash` on the `id_token`, and `sub` on `/userinfo`.
That is a guard, not a filter — every other key you return survives. Letting
host data overwrite `sub` or `aud` would turn a projection of profile fields
into impersonation, and `nonce` / `at_hash` are the client's replay and
token-binding checks.

The `client` argument is a `PublicClient` — no secret digests, no
pairwise-subject map. There is a test asserting a secret hash cannot reach it.

### Why `claims` has no outbound direction

This looks like an oversight and is not.

Claims are a **read-only projection of data you already own**. Access tokens
carry no claims at all; `/userinfo` calls your adapter live on every request.
So there is no "a claim changed" event to fire, because there is nothing cached
to invalidate. Change the value in your database and the next `/userinfo` call
returns it.

The one exception is the `id_token`, which is a signed snapshot by construction —
and that is what `id_token` means everywhere. Clients that want current data
call `/userinfo`.

## `logger`

```ts
logger: console,   // or pino, or anything with debug/info/warn/error
```

Every method is optional and the default is a no-op. It receives structured
first arguments (`{ err, path }`, `{ familyId, reason, tokensRevoked }`) followed
by a message, pino-style.

Things worth having a real logger for: `refresh token reused — family revoked`,
`authorization code replayed — family revoked`, the boot warning about a missing
`loadUser`, and `rate limit store failed, allowing request`.

## `track`

An optional cross-package seam, no-op by default. It is called synchronously and
must not throw.

```ts
track: (event) => telemetry.track(event),
```

| Event `type` | When |
|---|---|
| `oauth.authorization_requested` | `/authorize` parked a valid request |
| `oauth.consent_granted` | user approved; a code was minted |
| `oauth.consent_denied` | user denied |
| `oauth.token_issued` | a code was exchanged |
| `oauth.token_refreshed` | a refresh rotated |
| `oauth.refresh_reuse_detected` | **a rotated refresh token was presented again** |
| `oauth.client_secret_rotated` | `clients.rotateSecret()` |
| `oauth.grant_revoked` | any revocation path |

Each carries `userId?`, `clientId?`, `grantId?`, `contextId?`, `scopes?`, `meta?`.
This is the seam for "email the user when a new app connects" — that notification
is your job, not the package's.

`oauth.refresh_reuse_detected` is the one to alert on. See
[Security](/guide/security#reuse-detection).

## `rateLimits.store`

The default counter is in-memory and therefore **per process**: on N instances
the effective limit is `max × N`. That is stated rather than hidden.

```ts
rateLimits: {
  store: {
    async hit(key, windowMs) {
      const count = await redis.incr(key);
      if (count === 1) await redis.pexpire(key, windowMs);
      return { count, resetAt: Date.now() + await redis.pttl(key) };
    },
  },
},
```

The store **fails open, loudly**: a throw is logged at `error` and the request is
allowed. A transient Redis failure must not take every token exchange in the
fleet down with it.

## No storage adapter

Client logos are `branding.logoUrl` strings pointing at something you already
serve. The moment the package accepts an upload it owns image validation, SSRF
on fetch, and a CDN story — for a field you can already host. Named here so it
reads as a decision rather than a gap.

## Related

- [Account deletion](/guide/account-deletion) — the outbound calls, in detail
- [Configuration](/guide/configuration) — where each adapter is passed
- [Types](/reference/types) — the exact signatures
