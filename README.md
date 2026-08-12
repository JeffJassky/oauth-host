# @jeffjassky/oauth-host

OAuth 2.1 + OpenID Connect authorization server for an Express/Mongoose app you
already have. Built for the case where a user connects your API to Claude or
ChatGPT as an MCP connector.

```bash
npm install @jeffjassky/oauth-host
```

Full docs: **https://jeffjassky.github.io/oauth-host/**

## Quick start

```js
import express from 'express';
import mongoose from 'mongoose';
import { createOAuthHost } from '@jeffjassky/oauth-host';

await mongoose.connect(process.env.MONGO_URL);

const oauth = createOAuthHost({
  connection: mongoose,
  issuer: 'https://api.example.com',                    // the PUBLIC origin
  resources: [{ id: 'https://api.example.com/mcp', label: 'MCP server' }],
  scopes: [
    { id: 'openid',        label: 'Sign you in' },
    { id: 'contacts.read', label: 'Read your contacts' },
    { id: 'contacts.write', label: 'Create and edit contacts', sensitive: true },
  ],
  consentUrl: '/settings/authorize',                    // your page
  loginUrl: '/login',
  resolveUser: (req) => req.user && { id: req.user._id, email: req.user.email },
  loadUser: async (id) => User.findById(id).lean(),
  signing: { keys: [{ kid: 'prod-1', privateKeyPem: process.env.OAUTH_KEY }] },
});

await oauth.syncIndexes();                              // before the first write

const app = express();
app.use(express.json());                                // yours, not ours

app.use(oauth.routes.discovery);                        // ORIGIN ROOT
app.use('/oauth', oauth.routes.oauth);
app.use('/mcp', oauth.protect('contacts.read'), mcpRouter);
```

Register each client once — there is no RFC 7591 dynamic client registration:

```js
const { clientId, clientSecret } = await oauth.clients.create({
  name: 'Claude',
  redirectUris: ['<Claude connector callback, from their docs>'],
  allowedScopes: ['openid', 'contacts.read'],
  branding: { publisher: 'Anthropic' },
});   // secret returned once, never again
```

Or let Claude and ChatGPT register themselves with a [client ID metadata
document](https://jeffjassky.github.io/oauth-host/guide/cimd) — their
`client_id` is an `https://` URL serving a JSON description of themselves, and
there is no secret to paste. Off by default; it means an outbound fetch driven
by a request parameter, so it is opt-in and host-allowlisted:

```js
clientIdMetadata: { enabled: true, allowedHosts: ['claude.ai', 'chatgpt.com'] }
```

## What it does

`authorization_code` with mandatory PKCE (S256) and `refresh_token`, for
confidential clients and — with client ID metadata documents enabled — public
ones. Signed ES256 `id_token`, `/userinfo`, published JWKS with rotation, RFC
7009 revocation, RFC 9207 `iss`, RFC 8707 audience-bound tokens, and the RFC
9728 protected-resource metadata an MCP client needs to discover where to
authorize.

Rotating refresh tokens with reuse detection: a replayed authorization code or a
reused refresh token revokes the entire token family and audits it.

## The two things to get right

**You write the consent screen.** The package serves a JSON description of the
pending request at `GET /oauth/consent/:requestId` and takes a decision back at
`POST`. No markup ships. That payload is a versioned contract with no internal
ids in it. See the [consent screen
guide](https://jeffjassky.github.io/oauth-host/guide/consent-screen).

**`isAdmin` gates nothing.** There is no admin router — `oauth.clients`,
`.grants`, `.users` and `.contexts` are plain functions, so there is nothing for
you to leave unguarded. The moment you put one behind an Express route, the
guard is yours, and a test asserting a non-admin is refused belongs in your repo.

## Non-goals

Dynamic client registration (RFC 7591) · admin dashboard · consent screen markup
· login, sessions, MFA · first-party clients (consent is never skipped) ·
`client_credentials` · device authorization · token exchange · token
introspection · JWT access tokens · federation / social login · logout & session
management · JAR/PAR · OpenID certification. See
[the full list and the reasoning](https://jeffjassky.github.io/oauth-host/guide/introduction#non-goals).

## Requirements

Node 20+, Express 4.18+/5, Mongoose 7/8/9. Both are peer dependencies — all
three Mongoose majors run the full suite in CI.

## Development

```bash
npm install
npm run check-tracked   # run this FIRST — a global gitignore can eat source files
npm run typecheck       # types/ is hand-written; this is what keeps it honest
npm run build
npm test                # 148 tests: real HTTP, real Mongo, no mocks
npm run docs:build      # a dead internal link fails this build, on purpose

node examples/express/server.js   # imports dist/, so build first
```

The example boots an in-memory Mongo, registers a client, and prints an
authorization URL that walks the whole round trip a connector performs.

## License

MIT © Jeff Jassky
