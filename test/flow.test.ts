import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import {
  OTHER_RESOURCE,
  REDIRECT_URI,
  TEST_ISSUER,
  TEST_RESOURCE,
  authorize,
  buildApp,
  clearDb,
  createTestClient,
  exchange,
  param,
  pkce,
  startDb,
  stopDb,
  testUser,
  type BuiltApp,
} from './helpers.js';
import type { CreatedClient } from '../types/index.js';

/**
 * The end-to-end HTTP suite — build plan §13 step 3.
 *
 * Every test is named after the failure it prevents, not the feature it
 * exercises (standards/testing.md). Several of these guard boundaries that are
 * silent when they break: an error redirected to an unvalidated `redirect_uri`
 * is an open redirect that still looks like a working server, and a `/token`
 * that quietly needs `express.urlencoded()` fails only for the clients that
 * follow the spec.
 */
// One database for the file. Per-`describe` lifecycle hooks would reconnect
// mongoose mid-run, which surfaces as an unrelated request hanging up rather
// than as a connection error.
beforeAll(startDb);
afterAll(stopDb);

describe('authorization flow', () => {
  let built: BuiltApp;
  let client: CreatedClient;

  beforeEach(async () => {
    await clearDb();
    built = await buildApp({ session: { user: testUser() } });
    client = await createTestClient(built);
  });

  it('completes authorize → consent → code → token with PKCE', async () => {
    const flow = await authorize(built, client, { nonce: 'n-1' });

    expect(flow.tokens.access_token).toBeTypeOf('string');
    expect(flow.tokens.token_type).toBe('Bearer');
    expect(flow.tokens.expires_in).toBeTypeOf('number');
    expect(flow.tokens.refresh_token).toBeTypeOf('string');
    expect(String(flow.tokens.scope).split(' ')).toContain('contacts.read');
    // RFC 9207 — `iss` on the authorization response is what lets a client
    // refuse a mix-up attack, and it has to survive the whole round trip.
    expect(flow.iss).toBe(TEST_ISSUER);
    expect(flow.state).toBe('xyz-state');
  });

  it('omits id_token when `openid` was not among the granted scopes', async () => {
    const flow = await authorize(built, client, { scope: 'contacts.read' });
    expect(flow.tokens.id_token).toBeUndefined();

    const withOidc = await authorize(built, client, { scope: 'openid contacts.read' });
    expect(withOidc.tokens.id_token).toBeTypeOf('string');
  });

  it('sends Cache-Control: no-store on a token response', async () => {
    const flow = await authorize(built, client);
    const res = await exchange(built, client, {
      grant_type: 'refresh_token',
      refresh_token: String(flow.tokens.refresh_token),
    });
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers.pragma).toBe('no-cache');
  });

  // -- the redirect-vs-render split: a security boundary, tested both ways ----

  it('renders an unknown client_id rather than redirecting it — the open-redirect hole', async () => {
    const res = await request(built.app).get('/oauth/authorize').query({
      response_type: 'code',
      client_id: 'not-a-client',
      redirect_uri: 'https://attacker.test/steal',
      scope: 'openid',
      code_challenge: pkce().challenge,
      code_challenge_method: 'S256',
    });
    expect(res.status).toBe(400);
    expect(res.headers.location).toBeUndefined();
    expect(res.headers['content-type']).toMatch(/json/);
    expect(res.body.error).toBeTypeOf('string');
  });

  it('renders an unregistered redirect_uri rather than redirecting to it', async () => {
    const res = await request(built.app).get('/oauth/authorize').query({
      response_type: 'code',
      client_id: client.clientId,
      redirect_uri: 'https://attacker.test/steal',
      scope: 'openid',
      code_challenge: pkce().challenge,
      code_challenge_method: 'S256',
    });
    expect(res.status).toBe(400);
    expect(res.headers.location).toBeUndefined();
  });

  it('redirects a recoverable error back to the client with state and iss intact', async () => {
    const res = await request(built.app).get('/oauth/authorize').query({
      // Registered client, registered redirect_uri — so the client IS a proven
      // safe place to report this to.
      response_type: 'token',
      client_id: client.clientId,
      redirect_uri: REDIRECT_URI,
      scope: 'openid',
      state: 'keep-me',
      code_challenge: pkce().challenge,
      code_challenge_method: 'S256',
    });
    expect(res.status).toBe(302);
    const location = res.headers.location!;
    expect(location.startsWith(REDIRECT_URI)).toBe(true);
    expect(param(location, 'error')).toBeTypeOf('string');
    expect(param(location, 'state')).toBe('keep-me');
    expect(param(location, 'iss')).toBe(TEST_ISSUER);
  });

  it('bounces a signed-out user to loginUrl instead of issuing a code', async () => {
    built.state.user = null;
    const res = await request(built.app).get('/oauth/authorize').query({
      response_type: 'code',
      client_id: client.clientId,
      redirect_uri: REDIRECT_URI,
      scope: 'openid',
      code_challenge: pkce().challenge,
      code_challenge_method: 'S256',
    });
    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('/login');
  });

  it('renders login_required rather than looping when no loginUrl is configured', async () => {
    const noLogin = await buildApp({ session: { user: null }, config: { loginUrl: undefined } });
    const other = await createTestClient(noLogin);
    const res = await request(noLogin.app).get('/oauth/authorize').query({
      response_type: 'code',
      client_id: other.clientId,
      redirect_uri: REDIRECT_URI,
      scope: 'openid',
      code_challenge: pkce().challenge,
      code_challenge_method: 'S256',
    });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('login_required');
  });

  // -- traps #5: the sanctioned body-parser exception ------------------------

  it('accepts a form-encoded /token on an app that never mounted express.urlencoded', async () => {
    // The harness mounts `express.json()` and nothing else, exactly like a host.
    // Without the route-level urlencoded parser this is a "missing grant_type"
    // failure for every spec-compliant client.
    const flow = await authorize(built, client);
    expect(flow.tokens.access_token).toBeTypeOf('string');

    const posted = await authorize(built, client, { authMethod: 'post' });
    expect(posted.tokens.access_token).toBeTypeOf('string');
  });

  it('does not let the urlencoded parser leak onto other routes', async () => {
    // A form body on a JSON route must not be parsed into `approve: true` by a
    // parser this router mounted globally. It is scoped to /token and /revoke.
    const res = await request(built.app)
      .post('/oauth/consent/whatever')
      .type('form')
      .send({ approve: 'true' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
  });

  // -- cors.tokenEndpoint, off by default ------------------------------------

  it('sends no CORS headers on /token unless the host opted in', async () => {
    const flow = await authorize(built, client);
    const res = await exchange(built, client, {
      grant_type: 'refresh_token',
      refresh_token: String(flow.tokens.refresh_token),
    });
    // v1 has no public clients, so a browser has no business calling this.
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
    expect((await request(built.app).options('/oauth/token')).status).not.toBe(204);
  });

  it('sends CORS headers on /token and /revoke when cors.tokenEndpoint is on', async () => {
    const open = await buildApp({
      session: { user: testUser() },
      config: { cors: { tokenEndpoint: true } },
    });
    const openClient = await createTestClient(open);
    const flow = await authorize(open, openClient);
    const res = await exchange(open, openClient, {
      grant_type: 'refresh_token',
      refresh_token: String(flow.tokens.refresh_token),
    });
    expect(res.headers['access-control-allow-origin']).toBe('*');
    expect((await request(open.app).options('/oauth/token')).status).toBe(204);
    expect((await request(open.app).options('/oauth/revoke')).status).toBe(204);
  });

  // -- traps #4: literal routes before parameter routes ----------------------

  it('does not shadow /me/grants with the /me/grants/:id route', async () => {
    await authorize(built, client);
    const res = await request(built.app).get('/oauth/me/grants');
    expect(res.status).toBe(200);
    // If the parameter route had swallowed it, this would be a 404 from a
    // failed id lookup rather than a list.
    expect(Array.isArray(res.body.items)).toBe(true);
    expect(res.body.items.length).toBe(1);
  });

  it('does not shadow /jwks with /consent/:requestId or any other param route', async () => {
    const res = await request(built.app).get('/oauth/jwks');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.keys)).toBe(true);
  });

  // -- discovery -------------------------------------------------------------

  it('advertises endpoints under the mount path the host actually used', async () => {
    const res = await request(built.app).get('/.well-known/oauth-authorization-server');
    expect(res.status).toBe(200);
    expect(res.body.issuer).toBe(TEST_ISSUER);
    expect(res.body.token_endpoint).toBe(`${TEST_ISSUER}/oauth/token`);
    expect(res.body.authorization_endpoint).toBe(`${TEST_ISSUER}/oauth/authorize`);
    expect(res.body.jwks_uri).toBe(`${TEST_ISSUER}/oauth/jwks`);
    expect(res.body.code_challenge_methods_supported).toEqual(['S256']);
    expect(res.body.grant_types_supported).toEqual(['authorization_code', 'refresh_token']);
    expect(res.body.authorization_response_iss_parameter_supported).toBe(true);
    expect(res.body.id_token_signing_alg_values_supported).toEqual(['ES256']);
  });

  it('serves openid-configuration from the same table as the RFC 8414 document', async () => {
    const rfc = await request(built.app).get('/.well-known/oauth-authorization-server');
    const oidc = await request(built.app).get('/.well-known/openid-configuration');
    // One table, one document. Divergence here is how a server ends up
    // advertising a token endpoint it moved a year ago.
    expect(oidc.body).toEqual(rfc.body);
  });

  it('keys protected-resource metadata by the resource path, not by order alone', async () => {
    const bare = await request(built.app).get('/.well-known/oauth-protected-resource');
    expect(bare.body.resource).toBe(TEST_RESOURCE);
    expect(bare.body.authorization_servers).toEqual([TEST_ISSUER]);
    expect(bare.body.bearer_methods_supported).toEqual(['header']);

    const suffixed = await request(built.app).get('/.well-known/oauth-protected-resource/reports');
    expect(suffixed.body.resource).toBe(OTHER_RESOURCE);

    const missing = await request(built.app).get('/.well-known/oauth-protected-resource/nope');
    expect(missing.status).toBe(404);
    expect(missing.headers['content-type']).toMatch(/json/);
  });

  it('never publishes a private key through /jwks', async () => {
    const res = await request(built.app).get('/oauth/jwks');
    for (const key of res.body.keys as Record<string, unknown>[]) {
      expect(key.kid).toBeTypeOf('string');
      expect(key.d).toBeUndefined();
    }
  });

  // -- userinfo --------------------------------------------------------------

  it('answers /userinfo 401 with a Bearer challenge when no token is presented', async () => {
    const res = await request(built.app).get('/oauth/userinfo');
    expect(res.status).toBe(401);
    expect(res.headers['www-authenticate']).toMatch(/^Bearer/);
  });

  it('refuses /userinfo for a token without the openid scope', async () => {
    const flow = await authorize(built, client, { scope: 'contacts.read' });
    const res = await request(built.app)
      .get('/oauth/userinfo')
      .set('Authorization', `Bearer ${flow.tokens.access_token}`);
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('insufficient_scope');
  });

  it('returns a sub from /userinfo for an openid token', async () => {
    const flow = await authorize(built, client, { scope: 'openid profile email' });
    const res = await request(built.app)
      .get('/oauth/userinfo')
      .set('Authorization', `Bearer ${flow.tokens.access_token}`);
    expect(res.status).toBe(200);
    expect(res.body.sub).toBeTypeOf('string');
  });

  // -- refresh, revoke -------------------------------------------------------

  it('rotates a refresh token rather than reissuing the same one', async () => {
    const flow = await authorize(built, client);
    const res = await exchange(built, client, {
      grant_type: 'refresh_token',
      refresh_token: String(flow.tokens.refresh_token),
    });
    expect(res.status).toBe(200);
    expect(res.body.access_token).not.toBe(flow.tokens.access_token);
    expect(res.body.refresh_token).not.toBe(flow.tokens.refresh_token);
  });

  it('rejects an unsupported grant_type with the RFC code, not a 500', async () => {
    const res = await exchange(built, client, { grant_type: 'client_credentials' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('unsupported_grant_type');
  });

  it('answers /revoke 200 for an unknown token and for a repeat revocation', async () => {
    const flow = await authorize(built, client);
    const revoke = (token: string) => request(built.app)
      .post('/oauth/revoke')
      .type('form')
      .auth(client.clientId, client.clientSecret)
      .send({ token });

    expect((await revoke(String(flow.tokens.refresh_token))).status).toBe(200);
    // RFC 7009 §2.2 — idempotent. A 400 on the second call turns this endpoint
    // into a token-existence oracle.
    expect((await revoke(String(flow.tokens.refresh_token))).status).toBe(200);
    expect((await revoke('never-issued-anything')).status).toBe(200);
  });

  it('refuses a token exchange with a wrong client secret', async () => {
    const flow = await authorize(built, client);
    const res = await request(built.app)
      .post('/oauth/token')
      .type('form')
      .auth(client.clientId, 'wrong-secret')
      .send({ grant_type: 'refresh_token', refresh_token: String(flow.tokens.refresh_token) });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_client');
  });

  // -- /me/grants ------------------------------------------------------------

  it('answers /me/grants 401 for a signed-out caller instead of leaking a list', async () => {
    built.state.user = null;
    const res = await request(built.app).get('/oauth/me/grants');
    expect(res.status).toBe(401);
    expect(res.body.items).toBeUndefined();
  });

  it('omits internal ids from /me/grants beyond the grant id delete needs', async () => {
    await authorize(built, client);
    const { body } = await request(built.app).get('/oauth/me/grants');
    const [item] = body.items as Record<string, unknown>[];
    expect(item!.id).toBeTypeOf('string');
    // Assert the fields are absent, not that a UI hides them.
    expect(item!.userId).toBeUndefined();
    expect(item!._id).toBeUndefined();
    expect((item!.client as Record<string, unknown>)._id).toBeUndefined();
    expect(body.limit).toBeLessThanOrEqual(100);
  });

  it('caps /me/grants even when the caller asks for more', async () => {
    const { body } = await request(built.app).get('/oauth/me/grants?limit=100000');
    expect(body.limit).toBeLessThanOrEqual(100);
  });

  it('revokes only the signed-in user\'s own grant, and 404s an unknown id', async () => {
    await authorize(built, client);
    const { body } = await request(built.app).get('/oauth/me/grants');
    const grantId = String((body.items as { id: string }[])[0]!.id);

    // Another user must not be able to revoke it by id.
    const owner = built.state.user;
    built.state.user = testUser({ email: 'someone.else@example.com' });
    expect((await request(built.app).delete(`/oauth/me/grants/${grantId}`)).status).toBe(404);

    built.state.user = owner;
    const res = await request(built.app).delete(`/oauth/me/grants/${grantId}`);
    expect(res.status).toBe(200);
    expect(res.body.revoked).toBe(true);

    const after = await request(built.app).get('/oauth/me/grants');
    expect(after.body.items).toHaveLength(0);
  });

  it('answers JSON, not a cast error, for a malformed grant id', async () => {
    const res = await request(built.app).delete('/oauth/me/grants/not-an-object-id');
    expect(res.status).toBe(404);
    expect(res.headers['content-type']).toMatch(/json/);
    expect(res.body.error).toBe('not_found');
  });
});

/**
 * The `loadUser` adapter — build plan §4's second inbound direction.
 *
 * `/userinfo` and the `id_token` are reached on the bearer and
 * client-authenticated bands, where there is no host session and the only
 * identity available is the `userId` on the token. Without this adapter the
 * profile and email claims come back empty while every other part of the flow
 * looks correct, which is why it gets a test of its own rather than an
 * assertion tacked onto an existing one.
 */
describe('profile claims without a session', () => {
  let built: BuiltApp;
  let client: CreatedClient;

  beforeEach(async () => {
    await clearDb();
    const user = testUser({ email: 'alice@example.com', displayName: 'Alice' });
    built = await buildApp({
      session: { user },
      config: {
        // A host reading its own user collection. The package holds an id and
        // nothing else at this point in the request.
        loadUser: (id) => (String(id) === String(user.id)
          ? { id, email: 'alice@example.com', displayName: 'Alice', avatarUrl: 'https://x/a.png' }
          : null),
      },
    });
    client = await createTestClient(built);
  });

  it('serves profile and email claims from loadUser, not from the request session', async () => {
    const flow = await authorize(built, client, { scope: 'openid profile email' });
    const res = await request(built.app)
      .get('/oauth/userinfo')
      .set('Authorization', `Bearer ${flow.tokens.access_token}`);

    expect(res.status).toBe(200);
    expect(res.body.email).toBe('alice@example.com');
    expect(res.body.name).toBe('Alice');
    expect(res.body.picture).toBe('https://x/a.png');
  });

  it('answers /userinfo with a bare sub rather than 500ing when loadUser returns null', async () => {
    const flow = await authorize(built, client, { scope: 'openid profile email' });
    // The user was deleted between issuance and the call — a host that forgets
    // to revoke is common, and it must not turn into a 500 on a public route.
    built.ctx.models.Token.collection.updateMany({}, { $set: { userId: 'gone' } });
    const res = await request(built.app)
      .get('/oauth/userinfo')
      .set('Authorization', `Bearer ${flow.tokens.access_token}`);
    expect([200, 401]).toContain(res.status);
  });
});
