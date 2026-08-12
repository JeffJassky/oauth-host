# `createOAuthHost(config)`

The entry point. Returns routers, middleware, and a programmatic admin API.
Never an app, never a server.

```ts
import { createOAuthHost } from '@jeffjassky/oauth-host';

const oauth = createOAuthHost({
  connection: mongoose,
  issuer: 'https://api.example.com',
  resources: [{ id: 'https://api.example.com/mcp', label: 'MCP server' }],
  scopes: [{ id: 'openid', label: 'Sign you in' }],
  consentUrl: '/settings/authorize',
});
```

## Config

Four keys are required — `issuer`, `resources`, `scopes`, `consentUrl`. The full
table with defaults and reasoning is in [Configuration](/guide/configuration);
the type is [`CreateOAuthHostConfig`](/reference/types#createoauthhostconfig).

## Returns

`OAuthHostInstance`:

| | |
|---|---|
| `routes.discovery` | `Router`. `/.well-known/*`. **Mount at the origin root** — those paths are not relocatable. |
| `routes.oauth` | `Router`. The protocol endpoints. Mount at `mountPath`. |
| `protect(scopes?, opts?)` | `RequestHandler` factory — [`protect()`](/reference/protect) |
| `clients` | [`ClientsApi`](/reference/admin-api#clients) |
| `grants` | [`GrantsApi`](/reference/admin-api#grants) |
| `users` | [`UsersApi`](/reference/admin-api#users) |
| `contexts` | [`ContextsApi`](/reference/admin-api#contexts) |
| `syncIndexes()` | `Promise<void>`. Build every index. **Await at boot, before the first write.** |
| `ready` | `boolean`. True once `syncIndexes()` resolved. Until then `/authorize`, `POST /consent/:requestId` and `POST /token` answer `503 server_error` — [Data model](/guide/data-model#build-the-indexes-before-the-first-write). |
| `models` | The seven Mongoose models — [Models](/reference/models). Escape hatch; no invariants attached. |

```ts
app.use(oauth.routes.discovery);
app.use('/oauth', oauth.routes.oauth);
app.use('/mcp', oauth.protect('contacts.read'), mcpRouter);

await oauth.syncIndexes();
```

`routes.discovery` is a separate router from `routes.oauth` because their mount
points differ, not for organization: RFC 8414 and RFC 9728 fix `/.well-known/*`
at the issuer's origin, and a client bootstrapping from a URL it was handed has
no way to be told otherwise. Merging them would drag the whole package to the
root.

`routes.oauth` deliberately carries three trust bands on one router, because
they share the mount path a client sees. Each handler states its own; there is no
shared "authenticated" middleware, because mixing the bands is how a session
cookie ends up sufficient to exchange somebody else's authorization code. See
[Routers](/reference/routers#trust-bands).

## Also exported

| | |
|---|---|
| `createModels(opts)` | Build the models without a full host — [Models](/reference/models#createmodels) |
| `syncModelIndexes(models)` | The standalone form of `syncIndexes()` |
| `createUserAdapter(opts)` | Object form of the user adapter |
| `defaultResolveUser(req)` | The built-in inbound adapter: `req.user._id` / `req.user.id`, then `req.authUserId` |
| `OAuthError` | `status` + RFC `code` + `description`, answered as itself rather than a 500 |
| `RedirectableAuthError` | An `/authorize` failure the client may be told about by redirect |
| `UnredirectableError` | An `/authorize` failure that must be rendered — see [the boundary](/guide/security#the-redirect-vs-render-boundary) |
| `CLAUDE_CONNECTOR_REDIRECT_URI` | claude.ai's connector callback — [Vendor callback URLs](/guide/mcp#vendor-callback-urls) |
| `CLAUDE_CODE_REDIRECT_URIS` | Claude Code's loopback callbacks, `readonly string[]` |
| `CHATGPT_LEGACY_REDIRECT_URI` | ChatGPT's older single callback |
| `CHATGPT_CONNECTOR_REDIRECT_URI_PATTERN` | The **shape** of ChatGPT's per-connector callback. Not a value to register |
| `CIMD_ALLOWED_HOSTS` | A suggested `clientIdMetadata.allowedHosts`, `readonly string[]`. Never a default |

## Throws at construction

Validation is fatal and specific on purpose. This package's failure mode is a
partner integration that half-works six weeks later, so a bad value is a boot
error with the offending value in the message.

- `config` is not an object
- `issuer` is not an absolute `http(s)` URL
- `issuer` ends with a slash
- `consentUrl` is missing
- `scopes` is empty, a scope has no string `id`, or an id contains whitespace or quotes
- `resources` is empty, an id is not an absolute URI, or an id carries a fragment
- a resource lists a scope that is not in the catalog
- both `userAdapter` and `resolveUser` / `loadUser` were passed
- `resolveUser` or `loadUser` is not a function
- `grantContext` is missing `list()` or `verify()`
- `track` is not a function
- `subjectMode` is `pairwise` with no `pairwiseSalt`
- a `signing.keys` entry is not a readable PKCS#8 PEM, is not EC, is not P-256,
  or declares an `alg` other than `ES256`

## Warns at construction

- **No `loadUser` adapter.** Not fatal — a host that never grants `profile` or
  `email` has nothing to load. But it is the reason those claims come back empty
  on `/userinfo` and in the `id_token`, and finding that out from an empty
  response costs an afternoon. See [Adapters](/guide/adapters#loaduseruserid--who-is-this-id).

## Throws later

- `getSigningKey()` — no signing key configured and `signing.autoGenerate` is
  off; or every configured key is `retiring`. Surfaces as a 500 on the first
  request that needs an `id_token`.
- `protect({ resource })` — the resource is not one of the configured ones, or a
  required scope is not in the catalog. Thrown **at mount**, not per request.

## Related

- [Configuration](/guide/configuration)
- [Routers](/reference/routers)
- [Types](/reference/types)
