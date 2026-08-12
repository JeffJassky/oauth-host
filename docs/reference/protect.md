# `oauth.protect(scopes?, opts?)`

Resource-server middleware. Verifies a bearer token, enforces audience and
scope, and sets `req.oauth`.

```ts
app.use('/mcp', oauth.protect('contacts.read'), mcpRouter);
```

## Signature

```ts
protect(scopes?: string | string[], opts?: ProtectOptions): RequestHandler

interface ProtectOptions {
  /** Which declared resource this middleware guards. Defaults to the first. */
  resource?: string;
  /** Require every listed scope (the default) or any one of them. */
  mode?: 'all' | 'any';
}
```

| Call | Requires |
|---|---|
| `protect()` | any valid, unrevoked token for the default resource |
| `protect('contacts.read')` | that scope |
| `protect(['a', 'b'])` | both (`mode: 'all'`) |
| `protect(['a', 'b'], { mode: 'any' })` | either |
| `protect('x', { resource: OTHER })` | that scope, on a token audience-bound to `OTHER` |

## Throws at mount

```
TypeError: oauth-host: protect({ resource: 'https://nope.test/api' }) is not one of
the configured resources (https://api.example.com/mcp, https://api.example.com/reports)

TypeError: oauth-host: protect() requires scope 'contacts.delete', which is not in
the scope catalog
```

Both are thrown when the middleware is **created**, not on the first request. A
typo'd resource means every token is the wrong audience, and the symptom —
universal 401s — does not point at the guard that caused it.

## What it checks, in order

1. **A bearer token in the `Authorization` header.** Header only. A token in
   `?access_token=` is ignored: tokens in URLs land in access logs, `Referer`
   headers and browser history, and the published protected-resource metadata
   says `bearer_methods_supported: ["header"]`.
2. **The token is live.** Looked up by SHA-256, must be `kind: 'access'`, not
   revoked, not expired — **and its grant must still be live**. That last read is
   what makes revocation instant; skipping it would quietly turn "revocation is
   instant" into "revocation takes an hour".
3. **The audience includes this resource.** A token minted for another resource
   is rejected even though it is otherwise perfect. See
   [audience binding](/guide/mcp#audience-binding).
4. **The scopes.** `all` or `any`.

Then it sets `req.oauth` and calls `next()`.

## `req.oauth`

```json
{
  "userId": "66b9…",
  "clientId": "kJ3f…",
  "contextId": null,
  "scopes": ["openid", "contacts.read"],
  "grantId": "66ba…",
  "tokenId": "66bb…",
  "audience": ["https://auth.test/mcp"]
}
```

A fixed contract — the key set is asserted **exactly** in `test/protect.test.ts`,
so adding a field is a deliberate change to a published interface. `grantId` and
`tokenId` are stringified so a consumer never has to know they were ObjectIds.
`contextId` is `null` in single-subject mode.

The type is on the Express `Request` interface globally:

```ts
declare global {
  namespace Express {
    interface Request {
      oauth?: OAuthRequestContext;   // absent on unprotected routes
    }
  }
}
```

## Failures

Every failure carries a `WWW-Authenticate` header ending in
`resource_metadata="<the RFC 9728 URL for this resource>"`, and a JSON body.

| Situation | Status | Header | Body `error` |
|---|---|---|---|
| No `Authorization` header | 401 | `Bearer resource_metadata="…"` | `invalid_request` |
| Malformed header | 401 | as above | `invalid_request` |
| Unknown / expired / revoked token | 401 | `Bearer error="invalid_token", error_description="The access token is expired, revoked or unknown", resource_metadata="…"` | `invalid_token` |
| Grant revoked | 401 | as above | `invalid_token` |
| Wrong audience | 401 | `Bearer error="invalid_token", error_description="The access token was not issued for this resource", resource_metadata="…"` | `invalid_token` |
| Missing scope | 403 | `Bearer error="insufficient_scope", error_description="Requires all of: contacts.write", scope="contacts.write", resource_metadata="…"` | `insufficient_scope` |

Two deliberate choices in there:

**The bare challenge carries no `error`** (RFC 6750 §3.1) — nothing was wrong
with what was sent, because nothing was sent. The body still says
`invalid_request` so a JSON client has something to switch on.

**Wrong audience is `invalid_token`, not `insufficient_scope`.** From this
resource's point of view the token is not addressed to it at all, and saying
"wrong audience" out loud would confirm to whoever stole it that the token is
otherwise good.

## The `resource_metadata` parameter

The most important line in this middleware. It is how an MCP client that has
never heard of your server discovers where to authorize: it calls your API,
gets a 401, reads the metadata URL out of the challenge, and walks from there to
the authorization server.

```
WWW-Authenticate: Bearer resource_metadata="https://auth.test/.well-known/oauth-protected-resource/mcp"
```

Without it the discovery chain is a dead end and the only remaining fix is
out-of-band configuration. The URL is produced by the same function the
discovery router builds its route from, so a challenge can never point at a 404.

See [MCP connectors](/guide/mcp#the-discovery-chain).

## Notes

- Mount it **after** your body parser and anything else the downstream router
  needs. `protect()` does not parse bodies.
- It does not touch the host session. A protected API is reached with a token,
  never a cookie.
- It is not rate limited. Rate limiting a resource server is your call, and the
  package's three buckets cover the authorization endpoints only.
- One middleware per resource. If an app serves two resources, mount two
  `protect()`s with explicit `resource` options.

## Related

- [MCP connectors](/guide/mcp)
- [Routers](/reference/routers)
- [`OAuthRequestContext`](/reference/types#oauthrequestcontext)
