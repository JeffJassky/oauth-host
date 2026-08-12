# Admin API

Four namespaces on the instance: `clients`, `grants`, `users`, `contexts`.

**There is no admin router, deliberately.** The package cannot know what "admin"
means in your app, and `isAdmin` from the user adapter gates nothing. Shipping
these as plain functions is the strongest available form of that rule: there is
no admin router for a host to forget to guard. If you want them over HTTP, you
write the route and you own the guard — and you
[test it](/guide/testing#3-any-admin-route-you-wrote-is-guarded).

Everything that leaves this module is projected: a client document carries secret
digests and the pairwise-subject map, and neither has any business in a response,
a log line, or a dashboard payload. Every list is clamped inside the query
(`limit` default 50, hard ceiling 200) so no caller-supplied value ever becomes
the ceiling.

Failures here are plain `Error`s with readable messages, not `OAuthError`s — an
RFC token like `invalid_client` means something specific on the wire and would be
a lie thrown at a script.

## Clients

### `clients.create(spec)`

```ts
const { client, clientId, clientSecret } = await oauth.clients.create({
  name: 'Claude',
  redirectUris: ['https://claude.ai/api/mcp/auth_callback'],
  allowedScopes: ['openid', 'profile', 'email', 'contacts.read'],
  allowedResources: ['https://api.example.com/mcp'],   // defaults to all configured
  branding: { logoUrl: 'https://…/claude.png', publisher: 'Anthropic' },
  trusted: false,
  clientId: undefined,     // supply a fixed id for a re-provisioned client
  type: 'confidential',    // the default; see below for 'public'
});
```

Returns `{ client: PublicClient, clientId, type: 'confidential', clientSecret }`.

**`clientSecret` is returned once.** Only its SHA-256 is stored; there is no way
to read it back. Losing it means `rotateSecret()`.

#### Registering a public client

`type: 'public'` generates **no secret at all**. The registration is `client_id`
plus PKCE, `secrets` is empty, and there is no `clientSecret` in the return
value:

```ts
const { clientId } = await oauth.clients.create({
  name: 'Codex CLI',
  type: 'public',
  redirectUris: ['http://localhost/callback'],
  allowedScopes: ['openid', 'contacts.read'],
});
// → { client, clientId, type: 'public' }
```

Register one for a client that takes a client id and nothing else and publishes
no metadata document — `codex mcp login` has `oauth_client_id` and no
`oauth_client_secret`, and no document for CIMD to fetch. Public and CIMD are
[independent](/guide/cimd#public-clients): this needs no `clientIdMetadata`
config and makes no outbound request.

The return type is a union discriminated on `type`, so a caller that does not
know statically which kind it asked for has to narrow before reaching
`clientSecret` — see [`CreatedClient`](/reference/types).
`type` defaults to `'confidential'`, so every existing caller is unaffected.

Validation, all with the offending value in the message:

- `name` non-empty — it is what the consent screen shows
- at least one `redirectUri`; each absolute, `https` (or `http` on
  `localhost` / `127.0.0.1` / `[::1]`, because connector development needs it),
  and **without a fragment** (RFC 6749 §3.1.2)
- at least one `allowedScopes` entry, every one in the configured catalog —
  otherwise registering a client would implicitly extend the catalog and the
  consent screen would have no label to render
- `allowedResources`, when given, non-empty and all configured
- `type`, when given, exactly `'confidential'` or `'public'` — a typo must not
  silently fall back to one of them

`redirectUris` is the field nothing downstream can rescue: `/authorize` compares
by exact string equality, so a typo registered today is a partner integration
that half-works six weeks later with no error pointing back here.

Writes an `oauth.client_created` audit row.

### `clients.rotateSecret(clientId, opts?)`

```ts
const { clientSecret } = await oauth.clients.rotateSecret(clientId, {
  retireAfter: 7 * 24 * 60 * 60 * 1000,   // ms; default 0 = immediate
  label: 'sept-rotation',
});
```

Issues a **second** valid secret and schedules the existing ones to retire after
`retireAfter`. Two live secrets is what makes a rotation deployable without
downtime.

**Throws on a [public client](/guide/cimd#public-clients)** — whether it got
there through CIMD or through `create({ type: 'public' })` — rather than
returning a secret it has no use for — the token endpoint refuses a public
client that presents one, so a no-op here would hand a provisioning script a
credential that breaks the client the moment it is used.

A second rotation never pushes an already-scheduled retirement *later*. An
operator who scheduled a secret to die at noon does not expect a later call to
resurrect it until midnight.

Watch `lastUsedAt` on the new secret to know the cutover is safe to finish. See
[Rotating a client secret](/guide/security#rotating-a-client-secret).

Fires `oauth.client_secret_rotated` on `track` and writes an audit row.

Throws if the client does not exist.

### `clients.update(clientId, patch)`

```ts
await oauth.clients.update(clientId, {
  redirectUris: ['https://claude.ai/api/mcp/auth_callback'],
  branding: { publisher: 'Anthropic' },
});
```

Accepts `name`, `redirectUris`, `allowedScopes`, `allowedResources`, `branding`,
`trusted`. Each runs the **same validator as `create`** — a field is only
writable through the gate that proved it at registration, or the second write is
the hole.

Returns the updated `PublicClient`. Writes `oauth.client_updated`.
Throws if the client does not exist.

### `clients.list(query?)`

```ts
const { items, limit } = await oauth.clients.list({ status: 'active', limit: 50, skip: 0 });
```

Newest first. `limit` defaults to 50 and is clamped to 1–200 **before** it
reaches the query. Returns `PublicClient[]` — never secrets.

[CIMD](/guide/cimd) clients appear here like any other, distinguishable by
`registration: 'cimd'` and `type: 'public'`.

### `clients.get(clientId)`

`PublicClient | null`.

### `clients.disable(clientId)`

```ts
const { grantsRevoked, tokensRevoked } = await oauth.clients.disable(clientId);
```

Sets `status: 'disabled'` and cascades: revokes **every** grant and token the
client holds, for every user, and deletes its outstanding authorization codes
and pending consent requests. Codes are single-use credentials with no revoked
flag to set, so they are deleted rather than marked.

Disabling without the cascade would leave every issued access token valid until
its own expiry — "revoke access" would mean "in an hour".

Writes **one** audit row, not one per grant: a popular client holds thousands,
and a revocation storm in the audit log buries the event that caused it.

Disabling a [CIMD](/guide/cimd) client **sticks across a re-fetch**. The status
check runs before the metadata fetch and the write-back never sets `status`, so
a client you revoked does not quietly reactivate an hour later when its document
is re-read.

A disabled client is refused at `/authorize` (unredirectably) and at `/token`.

Throws if the client does not exist.

## Grants

### `grants.list(query)`

```ts
const { items, limit } = await oauth.grants.list({ userId, clientId, limit: 50, skip: 0 });
```

Live grants only, newest first, clamped to 1–200. Both filters optional; passing
neither lists every live grant.

Each item is a `GrantSummary`:

```ts
{
  id: string;
  client: { clientId, name, branding };
  scopes: ScopeSpec[];        // hydrated from the catalog for a UI to render
  context?: GrantContext;     // key ABSENT without a grantContext adapter
  createdAt: Date;
  lastUsedAt?: Date;
}
```

Clients are fetched in one query for the whole page, not per row. Context labels
are resolved through your adapter and cached per (user, client) pair.

Three fallbacks worth knowing, all of which prefer showing something to hiding a
row:

- A scope that has left the catalog renders as `{ id, label: id }` — a
  connected-apps screen missing a line understates what the client can still do.
- A grant can outlive a hard-deleted client row; the summary then names the
  `clientId` rather than rendering a blank card.
- A context whose membership already ended shows its id as the label — which is
  exactly when the user most wants to see the row.

### `grants.revoke(grantId, opts?)`

```ts
const { tokensRevoked } = await oauth.grants.revoke(grantId, { by: 'admin' });
```

`by` is `'user' | 'admin' | 'system' | 'client'`, default `'admin'`, and is
stored as `revokedBy`.

Idempotent, and tolerant of an id that no longer resolves — `users.forget()`
deletes grants outright, so a revoke arriving after an erasure is a no-op
returning `{ tokensRevoked: 0 }` rather than an error.

The **token sweep runs even on a repeat call**: a token issued in the window
between the first revocation and this one would otherwise survive it. The event
and audit row fire only on the first.

## Users

The outbound direction of the user adapter. The distinction between these two is
the whole reason both exist — see [Account deletion](/guide/account-deletion).

### `users.forget(userId)`

```ts
const { grants, tokens } = await oauth.users.forget(userId);
```

Erasure. **Deletes** grants, tokens, codes and pending requests; `$unset`s the
user's pairwise subject from every client that holds one; deletes that user's
audit rows.

Writes one tombstone (`oauth.user_forgotten`) naming **no personal data** — no
user id, no client, no scopes, only counts. It exists to prove the erasure ran,
which is the only thing an auditor may still ask after the subject is gone.

Idempotent.

### `users.revokeAll(userId, opts?)`

```ts
const { grantsRevoked, tokensRevoked } = await oauth.users.revokeAll(userId, {
  reason: 'password_changed',
});
```

Password change, deactivation, suspected compromise. **Marks** grants and tokens
revoked and deletes codes and pending requests — keeping the grant documents so
the connected-apps view still resolves, and keeping the audit rows because that
is the record you called this to create.

Fires one `oauth.grant_revoked` per live grant (a user's grant count is bounded
by how many apps they connected). Writes one `oauth.user_access_revoked` row with
`reason` in `meta`.

Idempotent.

## Contexts

### `contexts.revoked(userId, contextId)`

```ts
const { grantsRevoked, tokensRevoked } = await oauth.contexts.revoked(userId, orgId);
```

A membership ended. Revokes only the grants this user made for that context and
their tokens, and deletes matching codes. Their other connections are untouched.

`grantContext.verify()` catches an ended membership on the next refresh, but an
access token already issued is valid for its full hour and nothing re-checks it.
This is the push half of that pair, and it is why the adapter has an outbound
direction at all.

Idempotent.

## Putting it behind HTTP

If you do, the guard is yours:

```ts
app.post('/admin/oauth/clients', requireAuth, requireAdmin, async (req, res) => {
  const created = await oauth.clients.create(req.body);
  // The secret is returned once. This is the only moment it can be shown.
  res.json(created);
});
```

Ship a test that asserts a non-admin is refused **and that nothing was written**.
A guard that returns 403 after doing the write is not a guard.

## Related

- [Account deletion](/guide/account-deletion)
- [Security](/guide/security)
- [Types](/reference/types)
