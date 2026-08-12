import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import type { Request } from 'express';
import { resolveConfig } from '../src/server/config.js';
import type { ResolvedContext } from '../src/server/config.js';
import {
  authenticateClient,
  createClientsApi,
  createContextsApi,
  createGrantsApi,
  createUsersApi,
} from '../src/server/services/admin.js';
import { OAuthError } from '../src/server/errors.js';
import type { OAuthEvent } from '../types/index.js';

/**
 * The programmatic admin API.
 *
 * Every test is named after the failure it prevents. The failures worth having
 * a test for here are the quiet ones: a secret that can be read back, a
 * redirect URI that was accepted and only misbehaves at a partner's first real
 * authorization, a rotation that took the old secret down with it, an erasure
 * that left a pseudonym behind in a client document.
 *
 * `test/helpers.ts` is owned elsewhere and is being rewritten, so this file
 * builds its own context rather than depending on its current shape.
 */

let mongod: MongoMemoryServer;
let ctx: ResolvedContext;
let events: OAuthEvent[];
let clients: ReturnType<typeof createClientsApi>;
let grants: ReturnType<typeof createGrantsApi>;
let users: ReturnType<typeof createUsersApi>;
let contexts: ReturnType<typeof createContextsApi>;

/** Distinct model + collection names: vitest runs every suite in ONE fork, and
 *  mongoose's model registry is process-global — traps #2. */
const NAMES = {
  client: 'AdminTestClient',
  grant: 'AdminTestGrant',
  code: 'AdminTestCode',
  token: 'AdminTestToken',
  request: 'AdminTestRequest',
  key: 'AdminTestKey',
  audit: 'AdminTestAudit',
};

const RESOURCE = 'https://api.example.com/mcp';
const OTHER_RESOURCE = 'https://api.example.com/v1';

function buildContext(extra: Record<string, unknown> = {}): ResolvedContext {
  return resolveConfig({
    connection: mongoose,
    issuer: 'https://api.example.com',
    resources: [{ id: RESOURCE }, { id: OTHER_RESOURCE }],
    scopes: [
      { id: 'openid' },
      { id: 'contacts.read', label: 'Read your contacts', description: 'View names and emails.' },
      { id: 'contacts.write', label: 'Edit your contacts', sensitive: true },
    ],
    consentUrl: '/settings/authorize',
    modelNames: NAMES,
    collectionPrefix: 'admintest_',
    track: (event) => events.push(event),
    ...extra,
  });
}

/** A request-shaped stand-in. Only `headers` and `body` are read. */
function req(init: { headers?: Record<string, string>; body?: unknown }): Request {
  return { headers: init.headers ?? {}, body: init.body } as unknown as Request;
}

/**
 * Assert the call failed and hand back the error, narrowed.
 *
 * `authenticateClient` resolves to a client document, so a bare `.catch(e => e)`
 * leaves a union that hides exactly the fields these tests are here to compare.
 */
async function authError(promise: Promise<unknown>): Promise<OAuthError> {
  const result = await promise.then(() => null, (err: unknown) => err);
  expect(result).toBeInstanceOf(OAuthError);
  return result as OAuthError;
}

function basicHeader(id: string, secret: string): Record<string, string> {
  // RFC 6749 §2.3.1 — form-urlencode each half before base64.
  const encoded = `${encodeURIComponent(id)}:${encodeURIComponent(secret)}`;
  return { authorization: `Basic ${Buffer.from(encoded, 'utf8').toString('base64')}` };
}

async function newClient(overrides: Record<string, unknown> = {}) {
  return clients.create({
    name: 'Claude',
    redirectUris: ['https://claude.ai/api/mcp/auth_callback'],
    allowedScopes: ['openid', 'contacts.read'],
    ...overrides,
  });
}

async function newGrant(userId: mongoose.Types.ObjectId, clientId: string, contextId: string | null = null) {
  return ctx.models.Grant.create({
    userId,
    clientId,
    contextId,
    scopes: ['openid', 'contacts.read'],
    resources: [RESOURCE],
  });
}

async function newToken(
  userId: mongoose.Types.ObjectId,
  clientId: string,
  grantId: mongoose.Types.ObjectId,
  contextId: string | null = null,
) {
  return ctx.models.Token.create({
    kind: 'access',
    tokenHash: Math.random().toString(36).slice(2),
    clientId,
    userId,
    grantId,
    contextId,
    scopes: ['contacts.read'],
    audience: [RESOURCE],
    familyId: 'fam',
    expiresAt: new Date(Date.now() + 3600_000),
  });
}

beforeAll(async () => {
  mongod = await MongoMemoryServer.create();
  await mongoose.connect(mongod.getUri(), { dbName: 'oauth-host-admin-test' });
  events = [];
  ctx = buildContext();
  clients = createClientsApi(ctx);
  grants = createGrantsApi(ctx);
  users = createUsersApi(ctx);
  contexts = createContextsApi(ctx);
  await Promise.all(Object.values(ctx.models).map((m) => m.init()));
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongod.stop();
});

beforeEach(async () => {
  events = [];
  await Promise.all(Object.values(ctx.models).map((m) => m.deleteMany({})));
});

// ---------------------------------------------------------------------------

describe('clients.create', () => {
  it('never lets the raw secret be read back after it is returned once', async () => {
    const created = await newClient();
    expect(created.clientSecret).toMatch(/^[A-Za-z0-9_-]{20,}$/);

    // The projection carries no secret material at all.
    expect(created.client).not.toHaveProperty('secrets');
    expect(created.client).not.toHaveProperty('clientSecret');
    expect(await clients.get(created.clientId)).not.toHaveProperty('secrets');
    const [listed] = (await clients.list()).items;
    expect(listed).not.toHaveProperty('secrets');

    // And what IS stored is a digest, not the value.
    const doc = await ctx.models.Client.findOne({ clientId: created.clientId }).lean();
    expect(doc?.secrets).toHaveLength(1);
    expect(doc?.secrets[0]?.hash).not.toBe(created.clientSecret);
    expect(JSON.stringify(doc)).not.toContain(created.clientSecret);
  });

  it('rejects a non-https redirect uri and names the offending value', async () => {
    await expect(newClient({ redirectUris: ['http://evil.example.com/cb'] }))
      .rejects.toThrow('http://evil.example.com/cb');
  });

  it('rejects a relative redirect uri rather than storing something /authorize can never match', async () => {
    await expect(newClient({ redirectUris: ['/callback'] })).rejects.toThrow('/callback');
  });

  it('rejects a redirect uri carrying a fragment', async () => {
    await expect(newClient({ redirectUris: ['https://app.example.com/cb#/done'] }))
      .rejects.toThrow(/fragment/);
  });

  it('allows http on loopback, because connector development needs it', async () => {
    const local = await newClient({ redirectUris: ['http://localhost:3000/cb', 'http://127.0.0.1:3000/cb'] });
    expect(local.client.redirectUris).toHaveLength(2);
  });

  it('rejects a scope that is not in the configured catalog and names it', async () => {
    await expect(newClient({ allowedScopes: ['openid', 'billing.write'] }))
      .rejects.toThrow('billing.write');
  });

  it('rejects a resource that is not configured and names it', async () => {
    await expect(newClient({ allowedResources: ['https://other.example.com/api'] }))
      .rejects.toThrow('https://other.example.com/api');
  });

  it('defaults allowedResources to every configured resource rather than leaving it empty', async () => {
    const created = await newClient();
    expect(created.client.allowedResources).toEqual([RESOURCE, OTHER_RESOURCE]);
  });
});

describe('clients.rotateSecret', () => {
  it('leaves two working secrets so the rotation can be deployed without downtime', async () => {
    const first = await newClient();
    const second = await clients.rotateSecret(first.clientId, { retireAfter: 10_000 });

    const viaOld = await authenticateClient(ctx, req({ headers: basicHeader(first.clientId, first.clientSecret) }));
    const viaNew = await authenticateClient(ctx, req({ headers: basicHeader(first.clientId, second.clientSecret) }));
    expect(viaOld.clientId).toBe(first.clientId);
    expect(viaNew.clientId).toBe(first.clientId);
  });

  it('stops accepting a secret once retiresAt has passed', async () => {
    const first = await newClient();
    const second = await clients.rotateSecret(first.clientId, { retireAfter: 10_000 });
    // Default retireAfter is 0 — immediate. Both earlier secrets die here.
    const third = await clients.rotateSecret(first.clientId);

    await expect(authenticateClient(ctx, req({ body: { client_id: first.clientId, client_secret: first.clientSecret } })))
      .rejects.toThrow(OAuthError);
    await expect(authenticateClient(ctx, req({ body: { client_id: first.clientId, client_secret: second.clientSecret } })))
      .rejects.toThrow(OAuthError);
    const ok = await authenticateClient(ctx, req({ body: { client_id: first.clientId, client_secret: third.clientSecret } }));
    expect(ok.clientId).toBe(first.clientId);
  });

  it('does not push an already-scheduled retirement further out', async () => {
    const first = await newClient();
    await clients.rotateSecret(first.clientId, { retireAfter: 1_000 });
    await clients.rotateSecret(first.clientId, { retireAfter: 10_000 });

    const doc = await ctx.models.Client.findOne({ clientId: first.clientId }).lean();
    const original = doc?.secrets[0];
    expect(original?.retiresAt?.getTime()).toBeLessThan(Date.now() + 5_000);
  });

  it('emits the rotation event and an audit row an operator can find later', async () => {
    const first = await newClient();
    await clients.rotateSecret(first.clientId);
    expect(events.map((e) => e.type)).toContain('oauth.client_secret_rotated');
    expect(await ctx.models.Audit.countDocuments({ type: 'oauth.client_secret_rotated' })).toBe(1);
  });
});

describe('authenticateClient', () => {
  it('accepts client_secret_basic with the credentials form-urlencoded per RFC 6749 §2.3.1', async () => {
    const created = await newClient();
    const doc = await authenticateClient(ctx, req({ headers: basicHeader(created.clientId, created.clientSecret) }));
    expect(doc.clientId).toBe(created.clientId);
  });

  it('accepts client_secret_post from the body', async () => {
    const created = await newClient();
    const doc = await authenticateClient(
      ctx,
      req({ body: { client_id: created.clientId, client_secret: created.clientSecret } }),
    );
    expect(doc.clientId).toBe(created.clientId);
  });

  it('fails a wrong secret identically to an unknown client id, so it is not an id oracle', async () => {
    const created = await newClient();
    const wrongSecret = await authError(
      authenticateClient(ctx, req({ body: { client_id: created.clientId, client_secret: 'not-the-secret' } })),
    );
    const wrongId = await authError(
      authenticateClient(ctx, req({ body: { client_id: 'no-such-client', client_secret: created.clientSecret } })),
    );

    expect(wrongSecret.status).toBe(401);
    expect(wrongSecret.code).toBe('invalid_client');
    // The bodies must be byte-identical, not merely both failures.
    expect(wrongSecret.toBody()).toEqual(wrongId.toBody());
  });

  it('carries a WWW-Authenticate challenge when the credentials came in as Basic', async () => {
    const created = await newClient();
    const viaBasic = await authError(
      authenticateClient(ctx, req({ headers: basicHeader(created.clientId, 'wrong') })),
    );
    const viaPost = await authError(
      authenticateClient(ctx, req({ body: { client_id: created.clientId, client_secret: 'wrong' } })),
    );

    expect(viaBasic.headers?.['WWW-Authenticate']).toMatch(/^Basic/);
    expect(viaPost.headers?.['WWW-Authenticate']).toBeUndefined();
  });

  it('refuses a disabled client even with the correct secret', async () => {
    const created = await newClient();
    await clients.disable(created.clientId);
    await expect(
      authenticateClient(ctx, req({ body: { client_id: created.clientId, client_secret: created.clientSecret } })),
    ).rejects.toThrow(OAuthError);
  });

  it('stamps lastUsedAt on the secret that matched, so an operator can finish a rotation', async () => {
    const first = await newClient();
    const second = await clients.rotateSecret(first.clientId, { retireAfter: 10_000 });
    await authenticateClient(ctx, req({ body: { client_id: first.clientId, client_secret: second.clientSecret } }));

    const doc = await ctx.models.Client.findOne({ clientId: first.clientId }).lean();
    expect(doc?.secrets[0]?.lastUsedAt).toBeUndefined();
    expect(doc?.secrets[1]?.lastUsedAt).toBeInstanceOf(Date);
  });

  it('rejects a Basic header with no colon rather than treating the whole string as an id', async () => {
    await expect(
      authenticateClient(ctx, req({ headers: { authorization: `Basic ${Buffer.from('nocolon').toString('base64')}` } })),
    ).rejects.toThrow(OAuthError);
  });
});

describe('clients.disable', () => {
  it('revokes every grant and token the client holds, not just its future ones', async () => {
    const created = await newClient();
    const userId = new mongoose.Types.ObjectId();
    const grant = await newGrant(userId, created.clientId);
    await newToken(userId, created.clientId, grant._id);
    await newToken(userId, created.clientId, grant._id);

    const result = await clients.disable(created.clientId);
    expect(result).toEqual({ grantsRevoked: 1, tokensRevoked: 2 });

    expect(await ctx.models.Grant.countDocuments({ revokedAt: null })).toBe(0);
    expect(await ctx.models.Token.countDocuments({ revokedAt: null })).toBe(0);
    expect((await clients.get(created.clientId))?.status).toBe('disabled');
  });
});

describe('clients.list', () => {
  it('caps the page size at the ceiling even when the caller asks for more', async () => {
    await newClient();
    await newClient({ name: 'ChatGPT' });

    const res = await clients.list({ limit: 100_000 });
    // Assert the cap. Do not assume it.
    expect(res.limit).toBeLessThanOrEqual(200);
    expect(res.items.length).toBeLessThanOrEqual(res.limit);
  });

  it('does not let a zero or negative limit turn into an unbounded read', async () => {
    await newClient();
    expect((await clients.list({ limit: 0 })).limit).toBe(1);
    expect((await clients.list({ limit: -5 })).limit).toBe(1);
  });

  it('filters by status without leaking disabled clients into the active page', async () => {
    const a = await newClient();
    await newClient({ name: 'ChatGPT' });
    await clients.disable(a.clientId);

    const active = await clients.list({ status: 'active' });
    expect(active.items.map((c) => c.name)).toEqual(['ChatGPT']);
  });
});

describe('grants.list', () => {
  it('hydrates the client branding and the scope descriptions a connected-apps screen renders', async () => {
    const created = await newClient({ branding: { logoUrl: 'https://x/logo.png', publisher: 'Anthropic' } });
    const userId = new mongoose.Types.ObjectId();
    await newGrant(userId, created.clientId);

    const { items } = await grants.list({ userId });
    expect(items).toHaveLength(1);
    expect(items[0]?.client.name).toBe('Claude');
    expect(items[0]?.client.branding.publisher).toBe('Anthropic');
    expect(items[0]?.scopes.find((s) => s.id === 'contacts.read')?.description)
      .toBe('View names and emails.');
  });

  it('omits the context key entirely when no grantContext adapter is configured', async () => {
    const created = await newClient();
    const userId = new mongoose.Types.ObjectId();
    await newGrant(userId, created.clientId, 'org_1');

    const { items } = await grants.list({ userId });
    // Absent, not undefined — a host that never configured contexts should
    // never see the word in a payload built from this.
    expect(Object.prototype.hasOwnProperty.call(items[0] ?? {}, 'context')).toBe(false);
  });

  it('resolves the context label from the adapter when one is configured', async () => {
    const created = await newClient();
    const userId = new mongoose.Types.ObjectId();
    await newGrant(userId, created.clientId, 'org_1');

    const withContext = createGrantsApi({
      ...ctx,
      grantContext: {
        list: () => [{ id: 'org_1', label: 'Acme Inc' }],
        verify: () => true,
      },
    });
    const { items } = await withContext.list({ userId });
    expect(items[0]?.context).toEqual({ id: 'org_1', label: 'Acme Inc' });
  });

  it('caps the page size at the ceiling even when the caller asks for more', async () => {
    const created = await newClient();
    const userId = new mongoose.Types.ObjectId();
    await newGrant(userId, created.clientId);
    expect((await grants.list({ userId, limit: 100_000 })).limit).toBeLessThanOrEqual(200);
  });

  it('does not list a revoked grant as a live connection', async () => {
    const created = await newClient();
    const userId = new mongoose.Types.ObjectId();
    const grant = await newGrant(userId, created.clientId);
    await grants.revoke(String(grant._id));
    expect((await grants.list({ userId })).items).toHaveLength(0);
  });
});

describe('grants.revoke', () => {
  it('revokes the grant and its tokens and records who did it', async () => {
    const created = await newClient();
    const userId = new mongoose.Types.ObjectId();
    const grant = await newGrant(userId, created.clientId);
    await newToken(userId, created.clientId, grant._id);

    const { tokensRevoked } = await grants.revoke(String(grant._id), { by: 'user' });
    expect(tokensRevoked).toBe(1);

    const after = await ctx.models.Grant.findById(grant._id).lean();
    expect(after?.revokedAt).toBeInstanceOf(Date);
    expect(after?.revokedBy).toBe('user');
    expect(events.filter((e) => e.type === 'oauth.grant_revoked')).toHaveLength(1);
  });

  it('is idempotent — a second call neither moves revokedAt nor double-audits', async () => {
    const created = await newClient();
    const userId = new mongoose.Types.ObjectId();
    const grant = await newGrant(userId, created.clientId);

    await grants.revoke(String(grant._id));
    const firstRevokedAt = (await ctx.models.Grant.findById(grant._id).lean())?.revokedAt;
    await grants.revoke(String(grant._id));
    const secondRevokedAt = (await ctx.models.Grant.findById(grant._id).lean())?.revokedAt;

    expect(secondRevokedAt?.getTime()).toBe(firstRevokedAt?.getTime());
    expect(await ctx.models.Audit.countDocuments({ type: 'oauth.grant_revoked' })).toBe(1);
  });

  it('treats an unknown grant id as a no-op, because forget() may already have deleted it', async () => {
    await expect(grants.revoke(String(new mongoose.Types.ObjectId()))).resolves.toEqual({ tokensRevoked: 0 });
    await expect(grants.revoke('not-an-object-id')).resolves.toEqual({ tokensRevoked: 0 });
  });
});

describe('users.forget', () => {
  it('deletes grants, tokens, codes and pending requests for the user', async () => {
    const created = await newClient();
    const userId = new mongoose.Types.ObjectId();
    const other = new mongoose.Types.ObjectId();
    const grant = await newGrant(userId, created.clientId);
    await newToken(userId, created.clientId, grant._id);
    const otherGrant = await newGrant(other, created.clientId);
    await newToken(other, created.clientId, otherGrant._id);

    const result = await users.forget(userId);
    expect(result).toEqual({ grants: 1, tokens: 1 });
    // The other user is untouched — erasure is scoped, not a truncate.
    expect(await ctx.models.Grant.countDocuments({ userId: other })).toBe(1);
    expect(await ctx.models.Token.countDocuments({ userId: other })).toBe(1);
  });

  it('removes the user from every client pairwiseSubjects map', async () => {
    const created = await newClient();
    const userId = new mongoose.Types.ObjectId();
    await ctx.models.Client.updateOne(
      { clientId: created.clientId },
      { $set: { [`pairwiseSubjects.${String(userId)}`]: 'pseudonym-abc' } },
    );

    await users.forget(userId);

    const doc = await ctx.models.Client.findOne({ clientId: created.clientId }).lean();
    // The pseudonym is the one identifier a partner stored. Leaving it behind
    // means the erased user is still addressable.
    expect(JSON.stringify(doc?.pairwiseSubjects ?? {})).not.toContain('pseudonym-abc');
  });

  it('writes one audit tombstone that names no personal data', async () => {
    const created = await newClient();
    const userId = new mongoose.Types.ObjectId();
    await newGrant(userId, created.clientId);

    await users.forget(userId);

    const rows = await ctx.models.Audit.find({}).lean();
    const tombstones = rows.filter((r) => r.type === 'oauth.user_forgotten');
    expect(tombstones).toHaveLength(1);
    expect(tombstones[0]?.userId).toBeUndefined();
    expect(tombstones[0]?.clientId).toBeUndefined();
    // Nothing left anywhere in the audit log points back at the erased user.
    expect(JSON.stringify(rows)).not.toContain(String(userId));
  });

  it('is idempotent — the second call removes nothing and still succeeds', async () => {
    const created = await newClient();
    const userId = new mongoose.Types.ObjectId();
    const grant = await newGrant(userId, created.clientId);
    await newToken(userId, created.clientId, grant._id);

    expect(await users.forget(userId)).toEqual({ grants: 1, tokens: 1 });
    expect(await users.forget(userId)).toEqual({ grants: 0, tokens: 0 });
  });
});

describe('users.revokeAll', () => {
  it('keeps the grant documents and the audit trail that forget() destroys', async () => {
    const created = await newClient();
    const userId = new mongoose.Types.ObjectId();
    const grant = await newGrant(userId, created.clientId);
    await newToken(userId, created.clientId, grant._id);

    const result = await users.revokeAll(userId, { reason: 'password_changed' });
    expect(result).toEqual({ grantsRevoked: 1, tokensRevoked: 1 });

    // The grant survives, revoked — this is the whole difference from forget().
    const after = await ctx.models.Grant.findById(grant._id).lean();
    expect(after).not.toBeNull();
    expect(after?.revokedAt).toBeInstanceOf(Date);
    expect(await ctx.models.Token.countDocuments({ userId, revokedAt: null })).toBe(0);

    const audit = await ctx.models.Audit.findOne({ type: 'oauth.user_access_revoked' }).lean();
    expect(audit?.meta?.reason).toBe('password_changed');
    expect(String(audit?.userId)).toBe(String(userId));
  });

  it('is idempotent — a second call revokes nothing further', async () => {
    const created = await newClient();
    const userId = new mongoose.Types.ObjectId();
    await newGrant(userId, created.clientId);

    await users.revokeAll(userId);
    expect(await users.revokeAll(userId)).toEqual({ grantsRevoked: 0, tokensRevoked: 0 });
  });
});

describe('contexts.revoked', () => {
  it('kills only the grants made for the ended membership, not the user other connections', async () => {
    const created = await newClient();
    const userId = new mongoose.Types.ObjectId();
    const gone = await newGrant(userId, created.clientId, 'org_1');
    const kept = await newGrant(userId, created.clientId, 'org_2');
    await newToken(userId, created.clientId, gone._id, 'org_1');
    await newToken(userId, created.clientId, kept._id, 'org_2');

    const result = await contexts.revoked(userId, 'org_1');
    expect(result).toEqual({ grantsRevoked: 1, tokensRevoked: 1 });

    expect((await ctx.models.Grant.findById(gone._id).lean())?.revokedAt).toBeInstanceOf(Date);
    expect((await ctx.models.Grant.findById(kept._id).lean())?.revokedAt).toBeNull();
    expect(await ctx.models.Token.countDocuments({ contextId: 'org_2', revokedAt: null })).toBe(1);
  });

  it('is idempotent — a membership that ended twice revokes nothing the second time', async () => {
    const created = await newClient();
    const userId = new mongoose.Types.ObjectId();
    await newGrant(userId, created.clientId, 'org_1');

    await contexts.revoked(userId, 'org_1');
    expect(await contexts.revoked(userId, 'org_1')).toEqual({ grantsRevoked: 0, tokensRevoked: 0 });
  });
});
