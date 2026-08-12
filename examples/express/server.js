/**
 * Runnable example — an in-memory Mongo, a fake session, a registered client,
 * a host-rendered consent screen, and a protected MCP-style API.
 *
 *   npm run build && node examples/express/server.js
 *
 * It prints a ready-made authorization URL. Open it, approve, and the redirect
 * lands on `/callback`, which completes the code exchange and prints the token
 * response — the whole round trip a Claude or ChatGPT connector performs.
 *
 * The consent page here is deliberately ugly. It is the HOST's, not the
 * package's: oauth-host serves the JSON that describes the request, and the
 * host renders whatever it likes. See plans/build-plan.md §8.
 */
import crypto from 'node:crypto';
import express from 'express';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
// The BUILT artifact, not `src/` — the source is TypeScript and this example
// runs under plain `node`. Importing dist also means the example exercises what
// a host actually installs. Run `npm run build` first.
import { createOAuthHost } from '../../dist/index.js';

const port = Number(process.env.PORT) || 3000;
const origin = `http://127.0.0.1:${port}`;

const mongod = await MongoMemoryServer.create();
await mongoose.connect(mongod.getUri(), { dbName: 'oauth-host-example' });

// A stand-in for a real account. A real host reads this from its session.
const ALICE = {
  id: new mongoose.Types.ObjectId(),
  email: 'alice@example.com',
  displayName: 'Alice',
  authTime: new Date(),
};

const oauth = createOAuthHost({
  connection: mongoose,
  issuer: origin,
  mountPath: '/oauth',
  resources: [{ id: `${origin}/mcp`, label: 'Example MCP server' }],
  scopes: [
    { id: 'openid', label: 'Sign you in' },
    { id: 'profile', label: 'Your name and avatar' },
    { id: 'email', label: 'Your email address' },
    { id: 'contacts.read', label: 'Read your contacts', description: 'Names and emails.' },
    { id: 'contacts.write', label: 'Create and edit contacts', sensitive: true },
  ],
  consentUrl: '/consent',
  loginUrl: '/login',
  returnParam: 'next',
  resolveUser: (req) => req.person ?? null,
  // The second inbound direction, and the reason the id_token below carries a
  // name and an email at all: `/userinfo` and the token endpoint are reached
  // with no host session, so `resolveUser` has nothing to read. A real host
  // looks the id up in its own user collection here.
  loadUser: (id) => (String(id) === String(ALICE.id) ? ALICE : null),
  // Development only: this puts the signing key in the same database as the
  // tokens it signs. Production supplies `signing.keys` from the environment.
  signing: { autoGenerate: true },
  logger: console,
});

// Before the first write, not after. See standards/traps.md #3.
await oauth.syncIndexes();

const app = express();

// The host mounts the body parser, not the package — traps #5. Note that
// `/token` and `/revoke` still accept form encoding: the package mounts
// `express.urlencoded` on those two routes only, because RFC 6749 requires it
// and no host mounts it for us.
app.use(express.json());

// Fake auth. Everything is Alice; `?anon=1` exercises the signed-out path.
app.use((req, _res, next) => {
  req.person = req.query.anon ? null : ALICE;
  next();
});

// `/.well-known/*` at the ORIGIN ROOT — those paths are fixed by RFC 8414 and
// RFC 9728 and cannot be relocated under a prefix.
app.use(oauth.routes.discovery);
app.use('/oauth', oauth.routes.oauth);

// A protected API. `protect()` is what an MCP server mounts behind.
app.use('/mcp', oauth.protect('contacts.read'), (req, res) => {
  res.json({
    ok: true,
    // The contract mcp-server consumes — plan §6.
    caller: req.oauth,
    contacts: [{ name: 'Bob', email: 'bob@example.com' }],
  });
});

app.get('/login', (_req, res) => res.status(200).send('<h1>Sign in</h1><p>This is the host\'s job.</p>'));

/**
 * The host's consent screen.
 *
 * All it does is fetch the package's JSON description of the pending request
 * and POST a decision back. Nothing about the OAuth protocol leaks into this
 * page — no code, no state, no redirect_uri.
 */
app.get('/consent', (req, res) => {
  const id = String(req.query.request_id ?? '');
  res.type('html').send(`<!doctype html><meta charset="utf-8">
<h1>Authorize</h1><div id="app">Loading…</div>
<script type="module">
  const id = ${JSON.stringify(id)};
  const r = await fetch('/oauth/consent/' + id).then((x) => x.json());
  document.getElementById('app').innerHTML =
    '<p><b>' + r.client.name + '</b> wants access to your account.</p><ul>'
    + r.scopes.map((s) => '<li>' + s.label + (s.sensitive ? ' (sensitive)' : '') + '</li>').join('')
    + '</ul><button id="y">Allow</button> <button id="n">Deny</button>';
  const decide = async (approve) => {
    const out = await fetch('/oauth/consent/' + id, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ approve, scopes: r.scopes.map((s) => s.id) }),
    }).then((x) => x.json());
    location.href = out.redirectTo;
  };
  document.getElementById('y').onclick = () => decide(true);
  document.getElementById('n').onclick = () => decide(false);
</script>`);
});

// Stands in for the third-party client's redirect endpoint.
let pending = null;
app.get('/callback', async (req, res) => {
  if (req.query.error) return res.status(400).json(req.query);
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: String(req.query.code),
    redirect_uri: `${origin}/callback`,
    code_verifier: pending.verifier,
    client_id: pending.clientId,
    client_secret: pending.clientSecret,
  });
  const tokens = await fetch(`${origin}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  }).then((r) => r.json());
  const api = await fetch(`${origin}/mcp`, {
    headers: { authorization: `Bearer ${tokens.access_token}` },
  }).then((r) => r.json());
  res.json({ tokens, api });
});

const server = app.listen(port, '127.0.0.1', async () => {
  const { clientId, clientSecret } = await oauth.clients.create({
    name: 'Example Connector',
    redirectUris: [`${origin}/callback`],
    allowedScopes: ['openid', 'profile', 'email', 'contacts.read'],
    branding: { publisher: 'Example Inc.' },
  });

  // PKCE, generated the way a real client would.
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  pending = { clientId, clientSecret, verifier };

  const url = new URL(`${origin}/oauth/authorize`);
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: `${origin}/callback`,
    scope: 'openid profile email contacts.read',
    resource: `${origin}/mcp`,
    state: crypto.randomBytes(8).toString('hex'),
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }).toString();

  console.log(`\noauth-host example on ${origin}`);
  console.log(`  discovery  ${origin}/.well-known/oauth-authorization-server`);
  console.log(`  protected  ${origin}/.well-known/oauth-protected-resource`);
  console.log(`\nOpen this to run the flow:\n  ${url}\n`);
});

// Honor PORT. A dev box usually has something on 3000 already, and on macOS a
// process bound to IPv6 `*:3000` does NOT stop node binding IPv4 0.0.0.0:3000 —
// so this listens "successfully" and every request goes to the other app. The
// symptom is a 404 on every route with no error anywhere.
server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${port} is taken. Try: PORT=3100 node examples/express/server.js`);
    process.exit(1);
  }
  throw err;
});
