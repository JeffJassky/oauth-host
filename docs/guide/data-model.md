# Data model

Seven collections in your database, under your connection. Every model is built
by a factory that returns the already-compiled model if the name is taken, and
every name is overridable.

| Collection | Holds | Key indexes |
|---|---|---|
| `oauth_clients` | `clientId`, `secrets[{hash,label,createdAt,lastUsedAt,retiresAt}]`, `redirectUris[]`, `allowedScopes[]`, `allowedResources[]`, `branding`, `status`, `pairwiseSubjects` | `{clientId}` unique |
| `oauth_grants` | the consent record — `userId`, `clientId`, `contextId`, `scopes[]`, `resources[]`, `version`, `lastUsedAt`, `revokedAt` | `{clientId,userId,contextId}` unique **partial** on `revokedAt: null`; `{userId}`; `{clientId}` |
| `oauth_codes` | `codeHash`, a snapshot of the authorization, `codeChallenge`, `nonce`, `authTime`, `consumedAt` | `{codeHash}` unique; `{expiresAt}` TTL |
| `oauth_tokens` | discriminated `kind: access\|refresh`, `tokenHash`, `familyId`, `parentId`, `grantId`, `scopes[]`, `audience[]` | `{tokenHash}` unique; `{expiresAt}` TTL; `{familyId}`; `{grantId}`; `{userId,clientId}` |
| `oauth_requests` | pending consent handle — `requestId`, `userId`, the full parameter snapshot, `decision` | `{requestId}` unique; `{expiresAt}` TTL |
| `oauth_keys` | `kid`, `alg`, `publicJwk`, `privateJwk`, `status: active\|retiring` | `{kid}` unique |
| `oauth_audit` | append-only — `type`, `actor`, `clientId`, `userId`, `grantId`, `ip`, `meta` | `{createdAt}` TTL (400 d); `{clientId,createdAt}`; `{userId,createdAt}` |

Field-level shapes are in [Types](/reference/types#documents); the model handles
are on [`oauth.models`](/reference/models).

## Build the indexes before the first write

```ts
await oauth.syncIndexes();
```

Mongoose builds indexes in the background. On a cold database that is exactly
long enough for a write to land before the unique partial index on grants
exists — and then one user holds two live grants for one client, forever, and
nothing after that will tell you why.

`syncIndexes()` awaits `Model.init()` on all seven. Call it at boot, before you
start serving.

**The package fails closed until it resolves.** `/authorize`,
`POST /consent/:requestId` and `POST /token` — the three routes that write —
answer `503 { "error": "server_error" }` with a description naming
`syncIndexes()`. Discovery, `/jwks`, `/userinfo` and `protect()` keep serving:
they write nothing an index could be violated by, and taking a read-only API
down would turn a boot-order mistake into a total outage.

`oauth.ready` is the boolean behind that gate, readable so a host can check its
own wiring. It is deliberately not a promise — a promise would have to exist
from construction, so never calling `syncIndexes()` would present as an `await`
that never settles rather than a value that is plainly `false`.

The flag is read **per request**, not captured at mount time, because the common
mistake is calling `syncIndexes()` inside the `app.listen` callback — after the
routers are mounted. That leaves a window even when the call itself is correct;
the gate is what closes it. Awaiting it before `app.use` removes the window
entirely.

## Decisions that are expensive to reverse

These were settled before any code was written, because unwinding them later
means a migration in somebody else's database.

### Nothing is stored in a form that can be replayed

Authorization codes, access tokens, refresh tokens, and client secrets are all
256 bits of CSPRNG output. Only their **SHA-256** is written; every lookup is by
hash and every comparison is constant-time. The raw value exists in exactly one
place: the return value of the call that minted it.

A plain hash rather than bcrypt is correct here and not a shortcut: password
hashing is slow specifically to defend low-entropy inputs, and there are none —
these are not user-chosen. bcrypt would be a throughput bug on the token
endpoint with no security gain.

The practical consequence: **there is no way to read a client secret back.**
Losing it means [`rotateSecret()`](/guide/security#rotating-a-client-secret).

### Grants and tokens are separate documents

A grant is the consent record and outlives every token issued under it. It is
what a "connected apps" screen lists and what revocation cascades from.

Collapsing them — treating tokens as the record of consent — makes "revoke
access" mean "expire in an hour", because there is nothing left to revoke once
the access token is out the door. Which is why token introspection re-reads the
grant: a live token whose grant died does not work.

### The unique index on grants is partial

`{clientId, userId, contextId}` unique, but only where `revokedAt: null`. One
**live** grant per triple.

Without the partial filter, a revoked grant blocks re-consent forever, and the
only fixes are deleting revocation history or hitting a duplicate key on the
user's second connect. Both are worse.

`contextId` is stored as `null`, never absent, because a missing field and a
null field index differently and the index has to see one consistent value in
single-subject mode.

### `familyId` on every refresh token, with `parentId` chaining rotations

Reuse of a consumed refresh token revokes the **entire family** — the single
most important stolen-token defense, and it does not work if the chain is not
stored. See [Security](/guide/security#reuse-detection).

The family id is *derived* from the code hash rather than stored as a
back-reference, because a replayed code arrives carrying nothing but its own
hash and the family it spawned still has to be revocable from that alone. It
stays unguessable because the input is a hash of 256 random bits.

### Codes are consumed atomically

`findOneAndUpdate({ consumedAt: null })`, not read-then-write. An
`if (doc.consumedAt)` check is a race that two concurrent redemptions both win.

A consumed code is **marked, not deleted** — it has to stay readable long enough
to detect the replay. The TTL index reaps it later.

### `sub` is decided before first issuance

`subjectMode` is `public` or `pairwise` and cannot be changed after a partner has
stored user ids: `sub` is their primary key. Pairwise subjects are persisted in a
map on the client document (`pairwiseSubjects`), keyed by user id, so the value
survives anything that could change the derivation — including a rotated salt.

Reading it on every token issuance for that client is a single document read,
which is why it lives there rather than in a collection of its own.

### Two `expiresAt` fields on a refresh token, on purpose

`expiresAt` is the **sliding** window and is what the TTL index reaps.
`familyExpiresAt` is the **absolute** ceiling and is copied unchanged onto every
rotation. Letting Mongo delete a row is only safe if nothing downstream needed
it, and the ceiling has to survive rotations that reset the sliding window.

### No time-series collections

Erasure needs `deleteMany`, and time-series collections do not support it. The
audit log is an ordinary collection with a TTL index.

## Name collisions

The mongoose model registry is process-global. Calling `connection.model(name,
schema)` twice for one name throws `OverwriteModelError`, so a library cannot
own seven global names unconditionally — you may already have a `Grant`, or the
package may be loaded twice through a hoisting mismatch.

The factory therefore **reuses an already-compiled model when the name is
taken.** That is the right behaviour for a double-load and the wrong behaviour
for a genuine collision: if the existing model is not this package's, queries
fail confusingly rather than loudly.

So: if a collision is plausible in your app, rename explicitly.

```ts
createOAuthHost({
  modelNames: { grant: 'ThirdPartyGrant', client: 'OAuthAppClient' },
  collectionPrefix: 'authz_',
});
```

Model names and collection names are independent — `modelNames` affects the
registry, `collectionPrefix` affects the database.

## Retention and growth

| Collection | Grows with | Pruned by |
|---|---|---|
| `oauth_codes` | authorizations in flight | TTL on `expiresAt` (60 s default) |
| `oauth_requests` | authorizations in flight | TTL on `expiresAt` (10 min default) |
| `oauth_tokens` | issuances × rotations | TTL on `expiresAt` |
| `oauth_audit` | every protocol event | TTL on `createdAt` (`audit.retentionDays`, default 400) |
| `oauth_grants` | connections | never automatically — a grant is a record, not a cache |
| `oauth_clients` | registrations | never |
| `oauth_keys` | key rotations | never |

Revoked grants are kept. They carry `revokedAt` and `revokedBy` and are what
makes the audit trail resolve. The only thing that deletes them is
[`users.forget()`](/guide/account-deletion).

## Reading the models directly

```ts
oauth.models.Grant.countDocuments({ revokedAt: null });
```

An escape hatch, and an unguarded one — the models carry no invariants. Prefer
[the admin API](/reference/admin-api), which does: it clamps every list, projects
secrets out of everything that leaves, and cascades revocation to tokens. A
direct `Grant.updateOne({ revokedAt })` leaves every access token under that
grant working until introspection next reads the grant, and a direct
`Client.find()` hands you secret digests.

## Related

- [Models reference](/reference/models)
- [Account deletion](/guide/account-deletion) — what `forget()` deletes
- [Security](/guide/security)
