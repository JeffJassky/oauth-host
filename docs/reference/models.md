# Models

```ts
oauth.models   // { Client, Grant, Code, Token, Request, Key, Audit }
```

Seven Mongoose models, on your connection. An escape hatch — prefer the
[admin API](/reference/admin-api), which carries the invariants these do not.
See [Data model](/guide/data-model) for what each collection holds and why.

| Handle | Default model name | Default collection | Document type |
|---|---|---|---|
| `Client` | `OAuthClient` | `oauth_clients` | [`OAuthClientDoc`](/reference/types#oauthclientdoc) |
| `Grant` | `OAuthGrant` | `oauth_grants` | [`OAuthGrantDoc`](/reference/types#oauthgrantdoc) |
| `Code` | `OAuthCode` | `oauth_codes` | [`OAuthCodeDoc`](/reference/types#oauthcodedoc) |
| `Token` | `OAuthToken` | `oauth_tokens` | [`OAuthTokenDoc`](/reference/types#oauthtokendoc) |
| `Request` | `OAuthRequest` | `oauth_requests` | [`OAuthRequestDoc`](/reference/types#oauthrequestdoc) |
| `Key` | `OAuthKey` | `oauth_keys` | [`OAuthKeyDoc`](/reference/types#oauthkeydoc) |
| `Audit` | `OAuthAudit` | `oauth_audit` | [`OAuthAuditDoc`](/reference/types#oauthauditdoc) |

Model names are set by `config.modelNames`, collection names by
`config.collectionPrefix` — the two are independent.

## `syncIndexes()`

```ts
await oauth.syncIndexes();
```

Awaits `Model.init()` on all seven. **Call it at boot, before the first write.**
Mongoose builds indexes in the background, and on a cold database that is exactly
long enough for a write to land before the unique partial index on grants exists.

## Reading them safely

The models have no guards attached. Two things the admin API does that a direct
query does not:

- **Projection.** `Client` documents carry `secrets[].hash` and
  `pairwiseSubjects`. A raw `find()` hands you both. Everything that leaves the
  admin API goes through a `PublicClient` projection.
- **Cascade.** Setting `revokedAt` on a grant by hand leaves every access token
  under it working until introspection next reads the grant — which it does, so
  the effect arrives, but no `track` event fires, no audit row is written, and
  `tokensRevoked` is never counted. Use `grants.revoke()`.

Safe uses: counts, dashboards, one-off inspection.

```ts
await oauth.models.Grant.countDocuments({ revokedAt: null });
await oauth.models.Audit.find({ type: 'refresh_reuse_detected' }).sort({ createdAt: -1 }).limit(50);
await oauth.models.Client.findOne({ clientId }, { 'secrets.lastUsedAt': 1, 'secrets.label': 1 });
```

That last one is the supported way to watch a
[secret rotation](/guide/security#rotating-a-client-secret) land.

## `createModels(opts)`

Build the models without constructing a host. Useful for a migration script or a
test harness.

```ts
import { createModels, syncModelIndexes } from '@jeffjassky/oauth-host';

const models = createModels({
  connection: mongoose,              // defaults to the global mongoose
  modelNames: { grant: 'ThirdPartyGrant' },
  collectionPrefix: 'oauth_',
  auditRetentionDays: 400,
});

await syncModelIndexes(models);
```

Both are exported from the package root. `auditRetentionDays` is baked into the
TTL index on `oauth_audit.createdAt` at schema-build time, so it has to match
whatever the running host uses.

## Name collisions

The factory **reuses an already-compiled model when the name is taken**, because
the Mongoose registry is process-global and a library cannot own seven global
names unconditionally — you may already have a `Grant`, or the package may be
loaded twice through a hoisting mismatch.

That is right for a double-load and wrong for a genuine collision: if the
existing model is not this package's, queries fail confusingly rather than
loudly. Set `modelNames` when a collision is plausible. See
[Name collisions](/guide/data-model#name-collisions).

## Related

- [Data model](/guide/data-model)
- [Admin API](/reference/admin-api)
- [Types](/reference/types#documents)
