# Quickstart

Five steps: configure, sync indexes, mount both routers, register a client, run
the flow. A complete runnable version of everything below is in
[`examples/express/server.js`](https://github.com/JeffJassky/oauth-host/blob/main/examples/express/server.js).

```bash
npm install @jeffjassky/oauth-host
```

## 1. Configure

```ts
import { createOAuthHost } from '@jeffjassky/oauth-host';

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

  consentUrl: '/settings/authorize',            // host's own page
  loginUrl:   '/login',
  returnParam: 'next',

  userAdapter,                                  // default reads req.user (passport)
  // grantContext omitted  → single-subject mode, no picker
  // claims omitted        → profile/email derived from userAdapter fields
});
```

Four keys are required: `issuer`, `resources`, `scopes`, `consentUrl`.
Everything else has a default. The full table is in
[Configuration](/guide/configuration).

Two of them cause the most first-boot trouble:

- **`issuer` must be the public origin, with no trailing slash.** Every metadata
  URL is built by concatenating onto it, and a mismatch with the URL the client
  actually used is a spec violation clients do check. A trailing slash is a boot
  error rather than a silent `https://x.com//token`.
- **`mountPath` (default `/oauth`) must match where you actually mount
  `routes.oauth`.** A router cannot see its own mount path until a request
  arrives, by which time the discovery document has already been built. Get this
  wrong and discovery looks perfect while every client 404s on `/token`.

You also need a signing key before anything can issue an `id_token` — see
[Signing keys](/guide/security#signing-keys). For a first local run,
`signing: { autoGenerate: true }` generates one and persists it in `oauth_keys`.
That is a development convenience and named as one: it puts the private key in
the same database as the tokens it signs.

## 2. Sync indexes before the first write

```ts
await oauth.syncIndexes();
```

Not optional and not lazy. Mongoose builds indexes in the background, so a cold
database will happily serve the write that violates the unique partial index on
grants — which is exactly long enough for one user to end up with two live
grants for one client. Await this at boot.

## 3. Mount both routers

```ts
const app = express();
app.use(express.json());              // yours, not ours

// `/.well-known/*` at the ORIGIN ROOT. RFC 8414 and RFC 9728 fix those paths
// relative to the issuer's origin; they cannot live under a prefix.
app.use(oauth.routes.discovery);

app.use('/oauth', oauth.routes.oauth);

// A protected API. This is what an MCP server mounts behind.
app.use('/mcp', oauth.protect('contacts.read'), mcpRouter);
```

Two routers rather than one because their mount points differ: discovery is
pinned to the root, the protocol router is not.

**You mount the body parser, not the package.** The one exception:
`/token` and `/revoke` mount `express.urlencoded()` at the route level, because
RFC 6749 requires them to accept form encoding and no host mounts it for them.
It is scoped to those two routes and does not leak onto anything else — there is
a test named after that failure.

## 4. Register a client

Once, from a script or your own admin route. There is no dynamic client
registration.

```ts
const { clientId, clientSecret } = await oauth.clients.create({
  name: 'Claude',
  redirectUris: ['<Claude connector callback, from their docs>'],
  allowedScopes: ['openid', 'profile', 'email', 'contacts.read'],
  branding: { logoUrl: 'https://…/claude.png', publisher: 'Anthropic' },
});
// → { client, clientId, clientSecret }
//   the secret is returned once. Only its SHA-256 is stored; there is no way
//   to read it back. Losing it means rotateSecret().
```

`redirectUris` is compared by **exact string equality** at `/authorize` — no
prefix match, no wildcard, no ignoring the query string. A typo registered today
is a partner integration that half-works six weeks later with no error pointing
back here, which is why `create()` validates hard and names the offending value.
`https` is required except on `localhost` / `127.0.0.1`, where connector
development actually happens.

`allowedScopes` must be a subset of the configured catalog. `allowedResources`
defaults to every configured resource.

## 5. Run the flow

The client sends the user to `/authorize`:

```
GET /oauth/authorize
  ?response_type=code
  &client_id=<clientId>
  &redirect_uri=https://client.example/cb
  &scope=openid%20profile%20contacts.read
  &resource=https://api.example.com/mcp
  &state=xyz-state
  &code_challenge=<S256 of the verifier>
  &code_challenge_method=S256
```

PKCE is mandatory and `S256` is the only accepted method — an omitted
`code_challenge_method` is rejected rather than defaulting to `plain`.

`scope` is optional per RFC 6749 §3.3, and what an omitted one means is yours to
decide: it falls back to
[`defaultScopes`](/guide/configuration#default-scopes), intersected with the
client's `allowedScopes`. Configure that key or the request is a redirected
`invalid_scope` error — an empty scope set would be a token that can do nothing.
Note that it is deliberately *not* the client's `allowedScopes`; that list is a
registration ceiling, not a request.

What happens next:

1. **Signed out?** 302 to `loginUrl` with the full return URL in `returnParam`
   (`/login?next=%2Foauth%2Fauthorize%3F…`). Your login page sends them back.
2. **Signed in?** The validated request is parked as an opaque handle and the
   browser is 302'd to `consentUrl?request_id=<handle>` — your page.
3. Your page fetches `GET /oauth/consent/<handle>`, renders it, and POSTs the
   decision back. See [The consent screen](/guide/consent-screen).
4. The POST answers `{ "redirectTo": "…" }`. Your page sets `location.href` to
   it; the browser lands on the client's `redirect_uri` carrying `code`, `state`
   and `iss`.

The client then exchanges the code, form-encoded, with its credentials:

```http
POST /oauth/token
Authorization: Basic <base64(clientId:clientSecret)>
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=…&redirect_uri=https://client.example/cb&code_verifier=…
```

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

`id_token` appears only when `openid` was among the granted scopes. The response
carries `Cache-Control: no-store` and `Pragma: no-cache`.

And the token works against your API:

```http
GET /mcp
Authorization: Bearer <access_token>
```

## Verify the wiring

Two URLs answer the question "is this mounted correctly", with no client
involved:

```bash
curl https://api.example.com/.well-known/oauth-authorization-server
curl https://api.example.com/.well-known/oauth-protected-resource
```

The first must show `token_endpoint` and `authorization_endpoint` at the path
you actually mounted. The second must name your resource and list your issuer
under `authorization_servers`. If either is wrong, no client will get further
than discovery.

## Next

- [The consent screen](/guide/consent-screen) — the one page you have to write
- [MCP connectors](/guide/mcp) — the discovery chain and connecting Claude
- [Configuration](/guide/configuration) — every key and why it exists
- [Security](/guide/security) — key management, rotation, revocation semantics
