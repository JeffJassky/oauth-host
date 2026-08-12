# Testing

## Testing the package

Vitest, `mongodb-memory-server`, and `supertest`. Real HTTP, real Mongo, no
mocks — 148 tests across six files.

```bash
npm test
npm run test:watch
npm run typecheck        # tsc --noEmit; types/ is hand-written, this keeps it honest
```

| File | Layer |
|---|---|
| `test/tokens.test.ts` | the token core in isolation — issue, rotate, family revoke, reuse detection |
| `test/consent.test.ts` | the redirect boundary, the consent payload as a contract, one-shot decisions |
| `test/flow.test.ts` | `/authorize` → consent → code → `/token`, over HTTP |
| `test/protect.test.ts` | the resource-server middleware, challenges, audience |
| `test/oidc.test.ts` | `id_token`, JWKS, subjects, `/userinfo` — signatures verified for real |
| `test/admin.test.ts` | the programmatic admin API |

Tests are named after the failure they prevent, not the feature they exercise:

```
✗  it('handles /me/grants')
✓  it('does not shadow /me/grants with the /me/grants/:id route')
```

Six months later the second one tells a reader why reordering the router broke
CI. Several tests here guard boundaries that are silent when they break — an
error redirected to an unvalidated `redirect_uri` is an open redirect that still
looks like a working server, and a `/token` that quietly needs
`express.urlencoded()` fails only for the clients that follow the spec exactly.

The OIDC tests parse the JWKS the package publishes and run `crypto.verify`
against it, because the failure they exist to prevent is an `id_token` that
looks perfect and that no client will accept: an ECDSA signature in Node's
default DER encoding rather than the fixed-width `r‖s` pair JWS requires.
Asserting "three dot-separated segments" would pass on that bug.

## Testing your integration

Three things the package's own suite cannot prove, because they live in your
repo.

### 1. Your consent page posts what it renders

The endpoint rejects any scope that was not part of the original request, so a
UI bug here is a `400`, not a privilege escalation. It is still worth a test,
because the failure mode is a consent screen that cannot be approved at all.

```ts
it('posts back only scopes the request actually carried', async () => {
  const { requestId } = await startAuthorization();
  const payload = await get(`/oauth/consent/${requestId}`);

  const res = await post(`/oauth/consent/${requestId}`, {
    approve: true,
    scopes: payload.scopes.map((s) => s.id),
  });
  expect(res.body.redirectTo).toContain('code=');
});
```

### 2. Your deletion path calls `users.forget`

The distinction between `forget` and `revokeAll` is only meaningful if the right
one is wired. Assert on the difference:

```ts
it('deletes oauth grants when an account is deleted, rather than revoking them', async () => {
  await connectAnApp(user);
  await request(app).delete('/account').set('Cookie', session(user));

  expect(await oauth.models.Grant.countDocuments({ userId: user._id })).toBe(0);
});

it('revokes but keeps the grant when the password changes', async () => {
  await connectAnApp(user);
  await request(app).post('/account/password').set('Cookie', session(user)).send({ … });

  const grant = await oauth.models.Grant.findOne({ userId: user._id });
  expect(grant).not.toBeNull();          // kept
  expect(grant.revokedAt).not.toBeNull(); // and dead
});
```

### 3. Any admin route you wrote is guarded

The package ships no admin router — the admin surface is a plain module export,
so there is nothing for it to leave unguarded. The moment you put
`oauth.clients.create` behind an Express route, that guard is yours and yours
alone. `isAdmin` from the user adapter gates nothing and never will.

```ts
it('refuses a non-admin on the client registration route', async () => {
  const res = await request(app)
    .post('/admin/oauth/clients')
    .set('Cookie', session(ordinaryUser))
    .send({ name: 'X', redirectUris: ['https://x.test/cb'], allowedScopes: ['openid'] });

  expect(res.status).toBe(403);
  expect(await oauth.models.Client.countDocuments({ name: 'X' })).toBe(0);
});
```

Assert the database, not just the status code. A guard that returns 403 after
doing the write is not a guard.

## Driving a full flow in your own tests

The shape, condensed from `test/helpers.ts`. Nothing here needs the package's
internals — it is what any client does.

```ts
import crypto from 'node:crypto';

const verifier = crypto.randomBytes(32).toString('base64url');
const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');

// 1. /authorize → 302 to your consent page, carrying request_id
const auth = await request(app).get('/oauth/authorize').query({
  response_type: 'code',
  client_id: clientId,
  redirect_uri: 'https://client.test/cb',
  scope: 'openid contacts.read',
  state: 'xyz-state',
  resource: 'https://api.example.com/mcp',
  code_challenge: challenge,
  code_challenge_method: 'S256',
});
const requestId = new URL(auth.headers.location, 'https://x.invalid')
  .searchParams.get('request_id');

// 2. consent payload, then the decision
await request(app).get(`/oauth/consent/${requestId}`);
const decision = await request(app)
  .post(`/oauth/consent/${requestId}`)
  .send({ approve: true });

const code = new URL(decision.body.redirectTo).searchParams.get('code');

// 3. the exchange — form-encoded, with client credentials
const tokens = await request(app)
  .post('/oauth/token')
  .type('form')
  .auth(clientId, clientSecret)
  .send({
    grant_type: 'authorization_code',
    code,
    redirect_uri: 'https://client.test/cb',
    code_verifier: verifier,
  });

// 4. the token works against the protected API
await request(app).get('/mcp')
  .set('Authorization', `Bearer ${tokens.body.access_token}`)
  .expect(200);
```

Two details that bite:

- **`.type('form')`.** `/token` and `/revoke` are form endpoints per RFC 6749.
  They work even though your app only mounts `express.json()`, because the
  package mounts `express.urlencoded()` on those two routes specifically.
- **`code_verifier` must be the verifier, not the challenge**, and must be 43–128
  characters from the RFC 7636 unreserved set. `randomBytes(32).toString('base64url')`
  is exactly 43 and satisfies both.

## Running the example end to end

```bash
npm run build && node examples/express/server.js
```

It boots an in-memory Mongo, registers a client, and prints a ready-made
authorization URL. Open it, approve, and the redirect lands on `/callback`,
which completes the exchange and prints the token response plus a call to the
protected API — the whole round trip a Claude or ChatGPT connector performs.

Set `PORT` if 3000 is taken. On macOS a process bound to IPv6 `*:3000` does not
stop Node binding IPv4 `0.0.0.0:3000`, so the example would "listen
successfully" while every request went to the other app.

## Peer matrix

CI runs the full suite against Mongoose 7, 8, and 9, and Express 4 and 5. Two
places in the source exist only because of that spread: the discovery router
matches `/.well-known/oauth-protected-resource/*` with a RegExp (Express 4 and 5
disagree about wildcard syntax), and the admin service types Mongo filters
loosely (`FilterQuery` is not exported across all three Mongoose majors).

If you add a test that touches either, run it against the matrix before
assuming it is green.
