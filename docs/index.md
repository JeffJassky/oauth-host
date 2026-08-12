---
layout: home

hero:
  name: oauth-host
  text: Be the authorization server
  tagline: OAuth 2.1 + OpenID Connect for an Express/Mongoose app you already have. Mount two routers and Claude, ChatGPT, or any other MCP client can connect to your API as a user.
  actions:
    - theme: brand
      text: Quickstart
      link: /guide/quickstart
    - theme: alt
      text: Connecting an MCP client
      link: /guide/mcp
    - theme: alt
      text: View on GitHub
      link: https://github.com/JeffJassky/oauth-host

features:
  - title: Built for MCP connectors
    details: 'Audience-bound tokens (RFC 8707), protected-resource metadata (RFC 9728), and a `WWW-Authenticate` challenge that carries `resource_metadata` — the discovery chain an MCP client walks from a cold 401 to an authorization it can complete.'
  - title: Your consent screen
    details: 'The package serves a JSON description of the pending request; you render it. No markup ships, no iframe, no redirect to somebody else. The payload is a versioned contract with no internal ids in it.'
  - title: Rotating refresh with reuse detection
    details: 'Every refresh rotates. A replayed authorization code or a reused refresh token revokes the entire token family and audits it, because a replay is an attack signal rather than a duplicate to dedupe.'
  - title: No UI, no dashboard, no DCR
    details: 'The admin surface is a plain module export, so there is no admin router for a host to leave unguarded. RFC 7591 registration is a non-goal — you register clients from a script, or turn on host-allowlisted client ID metadata documents and let Claude and ChatGPT register themselves.'
---

```js
import express from 'express';
import mongoose from 'mongoose';
import { createOAuthHost } from '@jeffjassky/oauth-host';

await mongoose.connect(process.env.MONGO_URL);

const oauth = createOAuthHost({
  connection: mongoose,
  issuer: 'https://api.example.com',
  resources: [{ id: 'https://api.example.com/mcp', label: 'MCP server' }],
  scopes: [
    { id: 'openid',        label: 'Sign you in' },
    { id: 'contacts.read', label: 'Read your contacts' },
  ],
  consentUrl: '/settings/authorize',
  loginUrl: '/login',
});

await oauth.syncIndexes();

const app = express();
app.use(express.json());              // yours, not ours

app.use(oauth.routes.discovery);      // origin root — /.well-known/* is fixed
app.use('/oauth', oauth.routes.oauth);
app.use('/mcp', oauth.protect('contacts.read'), mcpRouter);
```
