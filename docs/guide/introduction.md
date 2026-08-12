# Introduction

## The problem this solves

You have an Express + Mongoose app with users in it. You want a user to be able
to open Claude or ChatGPT, add your API as a custom connector, click through a
consent screen that looks like your product, and have the assistant call your
API as *them* — with the scopes they approved, revocable from your settings
page, and dead the moment they change their password.

That is an OAuth 2.1 authorization server with OpenID Connect on top, and the
MCP authorization spec pins down the parts that are usually optional: PKCE is
mandatory, tokens are audience-bound to a named resource (RFC 8707), and the
client discovers where to authorize by reading a `WWW-Authenticate` challenge
off a 401 from your API (RFC 9728). Get any of those wrong and the connector
fails in a way the client reports as "could not connect", with nothing in your
logs to point at.

`@jeffjassky/oauth-host` is that server, as two Express routers and seven Mongo
collections inside the app you already run. It is not a service, does not listen
on a port, and does not authenticate anybody — your session middleware already
did that, and the package asks it who is calling through one adapter function.

The degenerate case is the whole point. Here is a complete host, the same
configuration the build plan's paper test uses:

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

  consentUrl: '/settings/authorize',            // host's own page
  loginUrl:   '/login',
  returnParam: 'next',

  userAdapter,                                  // default reads req.user (passport)
  // grantContext omitted  → single-subject mode, no picker
  // claims omitted        → profile/email derived from userAdapter fields
})

app.use(oauth.routes.discovery)                 // at origin root, not under /oauth
app.use('/oauth', express.json(), oauth.routes.oauth)
app.use('/mcp', oauth.protect('contacts.read'), mcpRouter)
```

Everything the package generalizes — multiple resources, organization-scoped
grants, pairwise subjects, custom claims — costs one config line and zero
runtime branches when you do not use it.

## What it is

Two Express routers and a programmatic admin API.

| | |
|---|---|
| `oauth.routes.discovery` | `/.well-known/*` metadata. Mounted at the **origin root** — those paths are not relocatable. |
| `oauth.routes.oauth` | `/authorize`, `/consent/:requestId`, `/token`, `/revoke`, `/userinfo`, `/jwks`, `/me/grants`. Mounted wherever you like, conventionally `/oauth`. |
| `oauth.protect(scopes)` | Resource-server middleware. Verifies the bearer token, enforces audience and scope, sets `req.oauth`. |
| `oauth.clients` / `.grants` / `.users` / `.contexts` | The admin surface, as plain functions. There is no admin router. |

What it supports on the wire: `authorization_code` with mandatory PKCE (S256
only) and `refresh_token`, for **confidential** clients and — when you enable
[client ID metadata documents](/guide/cimd) — for **public** ones. Signed
`id_token` in ES256, `/userinfo`, a published JWKS with rotation, RFC 7009
revocation, RFC 9207 `iss` on every authorization response, RFC 8707 resource
indicators.

## What it is not

- **Not an app.** It exports routers. You mount them, you own the process, you
  mount your own body parser.
- **Not a login system.** Sessions, passwords, MFA, "remember me" — all yours.
  `/authorize` bounces a signed-out user to your `loginUrl` and that is the
  entire extent of its involvement.
- **Not a consent screen.** It serves the JSON that describes a pending
  authorization; you render it. See [The consent screen](/guide/consent-screen).
- **Not an admin dashboard.** See below.

## Non-goals

These are decided, not missing. Someone arriving expecting one of them should
find out here rather than after an afternoon of grepping:

> Dynamic client registration (RFC 7591) · admin dashboard UI · consent screen
> markup · login, sessions, password reset, MFA · first-party clients (consent
> is never skipped) · `client_credentials` · device authorization · token
> exchange (RFC 8693) · token introspection (RFC 7662) · JWT access tokens ·
> SAML · upstream federation / social login · RP-initiated or back-channel
> logout · session management · CIBA · request objects (JAR/PAR) · OpenID
> certification · per-client quota/billing · storage adapter for logo uploads ·
> email notification on new connection (your job, via `track`).

Three of the harder omissions are worth their reasoning:

**Dynamic client registration (RFC 7591).** Not implemented, and not planned.
There is no registration endpoint, no registration access token, and no
admin-approval queue.

This is not only a scope decision. **Anthropic recommends against DCR for
high-traffic connectors and points at CIMD instead**, because a DCR client
re-registers itself on every fresh connection — so a popular connector writes a
new client row per install, per reinstall, per cleared cache, and the
registration table becomes the busiest write path in the server. Declining to
implement it puts this package on the same side as the vendor's own advice
rather than one feature short of it.

There are three ways a client gets registered instead.

The default is **manual and confidential**: you call
[`oauth.clients.create()`](/reference/admin-api) once from a script or your own
admin route and paste the returned `clientId` / `clientSecret` into the
connector setup. Both Claude's and ChatGPT's custom-connector UIs accept manual
credentials today.

The second is **manual and public** — `create({ type: 'public' })`. No secret is
generated; the client authenticates with `client_id` plus PKCE. This is the path
for a client that takes a client id and nothing else and publishes no metadata
document, which is exactly Codex CLI's MCP login.

The third is [client ID metadata documents](/guide/cimd), added after v1 and
**off by default**. A client whose `client_id` is an `https://` URL serving a
JSON document describing itself is registered by that document, fetched from a
host you allowlisted. Both Claude and ChatGPT prefer it over DCR, and it is what
turns "every install is a support interaction" into "it connects". It also means
the server makes an outbound request driven by a request parameter, which is why
it is opt-in, host-allowlisted, and has [a page of its
own](/guide/cimd#what-this-costs-ssrf).

**Public clients** are consequently no longer a non-goal either. Note that
public and CIMD are [orthogonal](/guide/cimd#public-clients): CIMD is how a
registration is *discovered*, public vs confidential is how a client
*authenticates*. A confidential client still cannot downgrade itself by omitting
its secret.

**An admin dashboard.** The admin API exists in v1 with no caller precisely so a
dashboard can be built on it later with no server changes. Shipping it as a
plain module export rather than a router is also the strongest available form of
the house rule that `isAdmin` gates nothing: there is no admin router for a host
to forget to guard. If you put these behind HTTP, the guard is yours.

**JWT access tokens / introspection.** Access tokens are opaque random strings
checked against the database on every call. That is what makes revocation
instant. A second resource server that cannot reach this database would need
introspection; there isn't one yet, so it isn't built.

## Requirements

| | |
|---|---|
| Node | 20+ |
| Express | 4.18+ or 5 |
| Mongoose | 7, 8, or 9 — all three run the full suite in CI |

Both are **peer dependencies**. The package uses the copy you already have,
which is the only way the Mongoose model registry stays coherent.

## Next

- [Quickstart](/guide/quickstart) — mounted, a client registered, a flow completed
- [The consent screen](/guide/consent-screen) — the page you have to write
- [MCP connectors](/guide/mcp) — `protect()`, discovery, and connecting Claude
- [Client ID metadata](/guide/cimd) — registration without a registration endpoint
