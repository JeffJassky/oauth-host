import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import {
  OTHER_RESOURCE,
  TEST_ISSUER,
  TEST_RESOURCE,
  authorize,
  buildApp,
  clearDb,
  createTestClient,
  startDb,
  stopDb,
  testUser,
  type BuiltApp,
} from './helpers.js';
import type { CreatedConfidentialClient } from '../types/index.js';

/**
 * `oauth.protect()` — build plan §13 step 4.
 *
 * Two of these are the reason the middleware exists at all:
 *
 * - the `resource_metadata` parameter on the `WWW-Authenticate` challenge is
 *   the entire MCP discovery chain. Lose it and a client that meets this API
 *   cold has no way to find the authorization server.
 * - audience enforcement is the confused-deputy defense. A token for one
 *   resource must not open another behind the same issuer.
 */
describe('protect()', () => {
  let built: BuiltApp;
  let client: CreatedConfidentialClient;

  beforeAll(startDb);
  afterAll(stopDb);

  beforeEach(async () => {
    await clearDb();
    built = await buildApp({ session: { user: testUser() } });
    client = await createTestClient(built);

    // Mounted the way a host mounts it, after the package's own routers.
    built.app.get('/mcp/ping', built.protect('contacts.read'), (req, res) => {
      res.json({ oauth: req.oauth });
    });
    built.app.get('/mcp/write', built.protect('contacts.write'), (_req, res) => {
      res.json({ ok: true });
    });
    built.app.get(
      '/mcp/either',
      built.protect(['contacts.read', 'contacts.write'], { mode: 'any' }),
      (_req, res) => { res.json({ ok: true }); },
    );
    built.app.get(
      '/reports/summary',
      built.protect('contacts.read', { resource: OTHER_RESOURCE }),
      (_req, res) => { res.json({ ok: true }); },
    );
  });

  it('points an unauthenticated caller at the protected-resource metadata', async () => {
    const res = await request(built.app).get('/mcp/ping');
    expect(res.status).toBe(401);
    const challenge = res.headers['www-authenticate']!;
    expect(challenge).toMatch(/^Bearer/);
    // The single most important assertion in this file.
    expect(challenge).toContain(
      `resource_metadata="${TEST_ISSUER}/.well-known/oauth-protected-resource/mcp"`,
    );
  });

  it('publishes a document at the resource_metadata URL it advertises', async () => {
    const res = await request(built.app).get('/mcp/ping');
    const url = /resource_metadata="([^"]+)"/.exec(res.headers['www-authenticate']!)![1]!;
    // Walk the chain a client walks: challenge → metadata → authorization
    // server. A challenge pointing at a 404 is worse than no challenge.
    const metadata = await request(built.app).get(new URL(url).pathname);
    expect(metadata.status).toBe(200);
    expect(metadata.body.resource).toBe(TEST_RESOURCE);
    expect(metadata.body.authorization_servers).toEqual([TEST_ISSUER]);
  });

  it('answers invalid_token, with the same challenge, for a token it never issued', async () => {
    const res = await request(built.app).get('/mcp/ping').set('Authorization', 'Bearer made-up');
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_token');
    expect(res.headers['www-authenticate']).toContain('resource_metadata=');
    expect(res.headers['www-authenticate']).toContain('error="invalid_token"');
  });

  it('rejects a token minted for a different resource — the confused-deputy defense', async () => {
    const flow = await authorize(built, client, {
      scope: 'contacts.read',
      resource: OTHER_RESOURCE,
    });
    const token = String(flow.tokens.access_token);

    // Valid, unexpired, correctly scoped — and still wrong for this API.
    const wrong = await request(built.app).get('/mcp/ping').set('Authorization', `Bearer ${token}`);
    expect(wrong.status).toBe(401);
    expect(wrong.body.error).toBe('invalid_token');

    const right = await request(built.app)
      .get('/reports/summary')
      .set('Authorization', `Bearer ${token}`);
    expect(right.status).toBe(200);
  });

  it('answers 403 insufficient_scope, naming the scope, rather than 401', async () => {
    const flow = await authorize(built, client, { scope: 'contacts.read' });
    const res = await request(built.app)
      .get('/mcp/write')
      .set('Authorization', `Bearer ${flow.tokens.access_token}`);
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('insufficient_scope');
    // A client cannot fix this without being told which scope to ask for.
    expect(res.headers['www-authenticate']).toContain('scope="contacts.write"');
    expect(res.headers['www-authenticate']).toContain('resource_metadata=');
  });

  it('honours mode:any instead of requiring every listed scope', async () => {
    const flow = await authorize(built, client, { scope: 'contacts.read' });
    const res = await request(built.app)
      .get('/mcp/either')
      .set('Authorization', `Bearer ${flow.tokens.access_token}`);
    expect(res.status).toBe(200);
  });

  it('sets the req.oauth contract mcp-server consumes, with no extra internals', async () => {
    const flow = await authorize(built, client, { scope: 'openid contacts.read' });
    const res = await request(built.app)
      .get('/mcp/ping')
      .set('Authorization', `Bearer ${flow.tokens.access_token}`);
    expect(res.status).toBe(200);

    const oauth = res.body.oauth as Record<string, unknown>;
    // Fixed in build plan §6. Adding a field is a change to a published
    // contract, so the shape is asserted exactly, not field by field.
    expect(Object.keys(oauth).sort()).toEqual(
      ['audience', 'clientId', 'contextId', 'grantId', 'scopes', 'tokenId', 'userId'],
    );
    expect(oauth.clientId).toBe(client.clientId);
    expect(oauth.audience).toContain(TEST_RESOURCE);
    expect(oauth.scopes).toContain('contacts.read');
    expect(oauth.contextId).toBeNull();
    expect(oauth.grantId).toBeTypeOf('string');
    expect(oauth.tokenId).toBeTypeOf('string');
  });

  it('ignores a token in the query string — header only, as the metadata claims', async () => {
    const flow = await authorize(built, client, { scope: 'contacts.read' });
    const res = await request(built.app).get(`/mcp/ping?access_token=${flow.tokens.access_token}`);
    // A token in a URL lands in access logs, Referer headers and history.
    expect(res.status).toBe(401);
  });

  it('refuses to mount against a resource that is not configured', () => {
    expect(() => built.protect('contacts.read', { resource: 'https://nope.test/api' }))
      .toThrow(/not one of the configured resources/);
  });

  it('refuses to mount against a scope that is not in the catalog', () => {
    expect(() => built.protect('contacts.delete')).toThrow(/scope catalog/);
  });

  it('stops a revoked token working, with no grace window at default config', async () => {
    const flow = await authorize(built, client, { scope: 'contacts.read' });
    const token = String(flow.tokens.access_token);
    expect((await request(built.app).get('/mcp/ping').set('Authorization', `Bearer ${token}`)).status)
      .toBe(200);

    await request(built.app)
      .post('/oauth/revoke')
      .type('form')
      .auth(client.clientId, client.clientSecret)
      .send({ token });

    // `tokenCache.ttlMs` defaults to 0 precisely so this is instant.
    const after = await request(built.app).get('/mcp/ping').set('Authorization', `Bearer ${token}`);
    expect(after.status).toBe(401);
    expect(after.body.error).toBe('invalid_token');
  });
});
