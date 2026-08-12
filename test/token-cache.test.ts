import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import {
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
 * `tokenCache.ttlMs` — the one config key whose value is a security tradeoff
 * rather than a tuning knob.
 *
 * These tests exist to hold BOTH halves of the documented bargain: that a
 * non-zero TTL really does serve a stale answer (otherwise the key is a lie),
 * and that the default of 0 really does mean revocation is instant (otherwise
 * the docs are a lie). A cache that quietly did nothing would pass every other
 * test in this suite.
 */
describe('introspection cache', () => {
  let built: BuiltApp;
  let client: CreatedConfidentialClient;

  beforeAll(startDb);
  afterAll(stopDb);

  const withCache = async (ttlMs: number): Promise<void> => {
    built = await buildApp({
      session: { user: testUser() },
      config: { tokenCache: { ttlMs } },
    });
    client = await createTestClient(built);
  };

  const callProtected = (token: string) => request(
    (() => {
      const app = built.app;
      app.get('/guarded', built.protect('contacts.read', { resource: TEST_RESOURCE }), (_req, res) => {
        res.json({ ok: true });
      });
      return app;
    })(),
  ).get('/guarded').set('Authorization', `Bearer ${token}`);

  beforeEach(clearDb);

  it('is off by default, so revoking a grant kills an access token immediately', async () => {
    await withCache(0);
    const flow = await authorize(built, client, { scope: 'contacts.read' });
    const token = String(flow.tokens.access_token);

    expect((await callProtected(token)).status).toBe(200);

    await built.ctx.models.Grant.updateMany({}, { $set: { revokedAt: new Date() } });
    expect((await callProtected(token)).status).toBe(401);
  });

  it('serves a revoked token for the length of the TTL when one is configured', async () => {
    // This is the cost of the key, asserted rather than described. A host that
    // finds this test surprising should be leaving `tokenCache.ttlMs` at 0.
    await withCache(60_000);
    const flow = await authorize(built, client, { scope: 'contacts.read' });
    const token = String(flow.tokens.access_token);

    expect((await callProtected(token)).status).toBe(200);

    await built.ctx.models.Grant.updateMany({}, { $set: { revokedAt: new Date() } });
    expect((await callProtected(token)).status).toBe(200);
  });

  it('evicts on /revoke, so an explicit revocation is instant even with a cache', async () => {
    // The cache may lag a database change it cannot see. It must never lag a
    // revocation that came through this server.
    await withCache(60_000);
    const flow = await authorize(built, client, { scope: 'contacts.read' });
    const token = String(flow.tokens.access_token);
    expect((await callProtected(token)).status).toBe(200);

    const revoked = await request(built.app)
      .post('/oauth/revoke')
      .auth(client.clientId, client.clientSecret)
      .type('form')
      .send({ token });
    expect(revoked.status).toBe(200);

    expect((await callProtected(token)).status).toBe(401);
  });
});
