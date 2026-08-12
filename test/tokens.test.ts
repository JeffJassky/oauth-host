import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { resolveConfig } from '../src/server/config.js';
import type { ResolvedContext } from '../src/server/config.js';
import { syncModelIndexes } from '../src/server/models.js';
import { randomToken, sha256 } from '../src/server/crypto.js';
import { OAuthError } from '../src/server/errors.js';
import {
  consumeCode,
  introspectAccessToken,
  issueForCode,
  revokeFamily,
  revokeGrantTokens,
  revokeToken,
  rotateRefresh,
} from '../src/server/services/tokens.js';
import type { CreateOAuthHostConfig, OAuthEvent, PackageUser } from '../types/index.js';

/**
 * The token core, tested before any HTTP exists — build plan §13 step 2.
 *
 * Every test here is named after the failure it prevents, and most of those
 * failures are silent: a code that can be redeemed twice, a refresh token that
 * outlives its family's ceiling, a revoked grant whose access token still
 * opens the API. None of them throw on their own.
 *
 * `test/helpers.ts` is the HTTP-level harness and boots the whole package;
 * these run against a `ResolvedContext` directly, so the DB plumbing is local.
 */

let mongod: MongoMemoryServer;

const REDIRECT = 'https://claude.ai/api/mcp/auth_callback';
const RESOURCE = 'https://api.example.com/mcp';
const OTHER_RESOURCE = 'https://api.example.com/other';

let suffix = 0;

interface TestContext extends ResolvedContext {
  events: OAuthEvent[];
}

async function makeCtx(overrides: Partial<CreateOAuthHostConfig> = {}): Promise<TestContext> {
  suffix += 1;
  const tag = `Tok${suffix}`;
  const events: OAuthEvent[] = [];
  const ctx = resolveConfig({
    connection: mongoose,
    issuer: 'https://api.example.com',
    resources: [{ id: RESOURCE }, { id: OTHER_RESOURCE }],
    scopes: ['openid', 'profile', 'contacts.read', 'contacts.write'],
    consentUrl: '/settings/authorize',
    // A fresh model name and collection per context: mongoose's registry is
    // process-global (traps #2) and vitest runs both suites in one fork.
    modelNames: {
      client: `${tag}Client`,
      grant: `${tag}Grant`,
      code: `${tag}Code`,
      token: `${tag}Token`,
      request: `${tag}Request`,
      key: `${tag}Key`,
      audit: `${tag}Audit`,
    },
    collectionPrefix: `oauth_${tag.toLowerCase()}_`,
    track: (e) => events.push(e),
    ...overrides,
  });
  await syncModelIndexes(ctx.models);
  return Object.assign(ctx, { events });
}

interface Seed {
  clientId: string;
  userId: mongoose.Types.ObjectId;
  grantId: mongoose.Types.ObjectId;
  rawCode: string;
  verifier: string;
}

async function seed(
  ctx: ResolvedContext,
  opts: { scopes?: string[]; contextId?: string | null; resources?: string[] } = {},
): Promise<Seed> {
  const clientId = `cid-${randomToken(8)}`;
  const scopes = opts.scopes ?? ['openid', 'profile', 'contacts.read'];
  const resources = opts.resources ?? [RESOURCE];
  const contextId = opts.contextId ?? null;

  await ctx.models.Client.create({
    clientId,
    name: 'Claude',
    redirectUris: [REDIRECT],
    allowedScopes: scopes,
    allowedResources: [RESOURCE, OTHER_RESOURCE],
  });
  const userId = new mongoose.Types.ObjectId();
  const grant = await ctx.models.Grant.create({
    userId, clientId, contextId, scopes, resources,
  });

  const rawCode = randomToken();
  const verifier = randomToken();
  await ctx.models.Code.create({
    codeHash: sha256(rawCode),
    clientId,
    userId,
    grantId: grant._id,
    contextId,
    scopes,
    resources,
    redirectUri: REDIRECT,
    codeChallenge: sha256(verifier),
    expiresAt: new Date(Date.now() + 60_000),
  });

  return { clientId, userId, grantId: grant._id, rawCode, verifier };
}

const redeem = (ctx: ResolvedContext, s: Seed) =>
  consumeCode(ctx, s.rawCode, {
    clientId: s.clientId,
    redirectUri: REDIRECT,
    codeVerifier: s.verifier,
  });

/** Assert the RFC token, not the message — clients switch on `error`. */
async function expectOAuthCode(promise: Promise<unknown>, code: string): Promise<OAuthError> {
  const err = await promise.then(
    () => { throw new Error(`expected ${code}, got success`); },
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(OAuthError);
  expect((err as OAuthError).code).toBe(code);
  return err as OAuthError;
}

describe('token core', () => {
  beforeAll(async () => {
    mongod = await MongoMemoryServer.create();
    await mongoose.connect(mongod.getUri(), { dbName: 'oauth-host-tokens' });
  });
  afterAll(async () => {
    await mongoose.disconnect();
    await mongod.stop();
  });

  it('issues, then rotates twice, keeping the family and killing each spent refresh token', async () => {
    const ctx = await makeCtx();
    const s = await seed(ctx);

    const first = await issueForCode(ctx, await redeem(ctx, s));
    expect(first.expiresIn).toBe(3600);
    expect(first.audience).toEqual([RESOURCE]);
    expect(await introspectAccessToken(ctx, first.accessToken)).not.toBeNull();

    const second = await rotateRefresh(ctx, first.refreshToken!, { clientId: s.clientId });
    const third = await rotateRefresh(ctx, second.refreshToken!, { clientId: s.clientId });

    expect(second.familyId).toBe(first.familyId);
    expect(third.familyId).toBe(first.familyId);
    expect(third.refreshToken).not.toBe(second.refreshToken);
    expect(await introspectAccessToken(ctx, third.accessToken)).not.toBeNull();

    // The chain is stored, or reuse detection has nothing to walk.
    const refreshes = await ctx.models.Token.find({ familyId: first.familyId, kind: 'refresh' });
    expect(refreshes).toHaveLength(3);
    expect(refreshes.filter((t) => t.parentId).length).toBe(2);

    expect(ctx.events.map((e) => e.type)).toEqual([
      'oauth.token_issued', 'oauth.token_refreshed', 'oauth.token_refreshed',
    ]);
  });

  it('revokes the whole family when an authorization code is redeemed a second time', async () => {
    const ctx = await makeCtx();
    const s = await seed(ctx);
    const issued = await issueForCode(ctx, await redeem(ctx, s));

    await expectOAuthCode(redeem(ctx, s), 'invalid_grant');

    // Not a silent dedupe: the tokens the first redemption produced are dead.
    expect(await introspectAccessToken(ctx, issued.accessToken)).toBeNull();
    await expectOAuthCode(
      rotateRefresh(ctx, issued.refreshToken!, { clientId: s.clientId }),
      'invalid_grant',
    );
    const audit = await ctx.models.Audit.findOne({ type: 'code_replay' });
    expect(audit).not.toBeNull();
  });

  it('revokes the whole family when a rotated refresh token is presented again', async () => {
    const ctx = await makeCtx();
    const s = await seed(ctx);
    const first = await issueForCode(ctx, await redeem(ctx, s));
    const second = await rotateRefresh(ctx, first.refreshToken!, { clientId: s.clientId });

    await expectOAuthCode(
      rotateRefresh(ctx, first.refreshToken!, { clientId: s.clientId }),
      'invalid_grant',
    );

    // The current token loses too — which of the two holders is the thief is
    // unknowable, so neither keeps access.
    expect(await introspectAccessToken(ctx, second.accessToken)).toBeNull();
    await expectOAuthCode(
      rotateRefresh(ctx, second.refreshToken!, { clientId: s.clientId }),
      'invalid_grant',
    );
    expect(ctx.events.some((e) => e.type === 'oauth.refresh_reuse_detected')).toBe(true);
    expect(await ctx.models.Audit.findOne({ type: 'refresh_reuse_detected' })).not.toBeNull();
  });

  it('refuses to refresh past the family absolute ceiling however often it was rotated', async () => {
    const ctx = await makeCtx();
    const s = await seed(ctx);
    const first = await issueForCode(ctx, await redeem(ctx, s));
    const second = await rotateRefresh(ctx, first.refreshToken!, { clientId: s.clientId });

    // The ceiling is copied onto every rotation, so backdating it on the family
    // is exactly what 180 days of sliding refreshes would produce.
    await ctx.models.Token.updateMany(
      { familyId: first.familyId },
      { $set: { familyExpiresAt: new Date(Date.now() - 1000) } },
    );

    const err = await expectOAuthCode(
      rotateRefresh(ctx, second.refreshToken!, { clientId: s.clientId }),
      'invalid_grant',
    );
    expect(err.description).toMatch(/absolute lifetime/);
  });

  it('carries the absolute ceiling unchanged across a rotation instead of sliding it', async () => {
    const ctx = await makeCtx();
    const s = await seed(ctx);
    const first = await issueForCode(ctx, await redeem(ctx, s));
    const before = await ctx.models.Token.findOne({ tokenHash: sha256(first.refreshToken!) });
    const second = await rotateRefresh(ctx, first.refreshToken!, { clientId: s.clientId });
    const after = await ctx.models.Token.findOne({ tokenHash: sha256(second.refreshToken!) });

    expect(after!.familyExpiresAt!.getTime()).toBe(before!.familyExpiresAt!.getTime());
    // …while the sliding window does move.
    expect(after!.expiresAt.getTime()).toBeGreaterThanOrEqual(before!.expiresAt.getTime());
  });

  it('allows a refresh to narrow the scope set but never to widen it', async () => {
    const ctx = await makeCtx();
    const s = await seed(ctx, { scopes: ['openid', 'profile', 'contacts.read'] });
    const first = await issueForCode(ctx, await redeem(ctx, s));

    const narrowed = await rotateRefresh(ctx, first.refreshToken!, {
      clientId: s.clientId,
      scope: 'contacts.read',
    });
    expect(narrowed.scopes).toEqual(['contacts.read']);

    await expectOAuthCode(
      rotateRefresh(ctx, narrowed.refreshToken!, {
        clientId: s.clientId,
        scope: 'contacts.read profile',
      }),
      'invalid_scope',
    );
  });

  it('rejects a scope the grant never carried rather than issuing it', async () => {
    const ctx = await makeCtx();
    const s = await seed(ctx);
    const first = await issueForCode(ctx, await redeem(ctx, s));
    await expectOAuthCode(
      rotateRefresh(ctx, first.refreshToken!, { clientId: s.clientId, scope: 'contacts.write' }),
      'invalid_scope',
    );
  });

  it('rejects a resource the authorization is not bound to', async () => {
    const ctx = await makeCtx();
    const s = await seed(ctx);
    const first = await issueForCode(ctx, await redeem(ctx, s));
    await expectOAuthCode(
      rotateRefresh(ctx, first.refreshToken!, { clientId: s.clientId, resources: [OTHER_RESOURCE] }),
      'invalid_target',
    );
  });

  it('rejects a code redemption whose PKCE verifier does not match the challenge', async () => {
    const ctx = await makeCtx();
    const s = await seed(ctx);
    await expectOAuthCode(
      consumeCode(ctx, s.rawCode, {
        clientId: s.clientId,
        redirectUri: REDIRECT,
        codeVerifier: randomToken(),
      }),
      'invalid_grant',
    );
  });

  it('rejects a redirect_uri that only prefixes the one the code was issued for', async () => {
    const ctx = await makeCtx();
    const s = await seed(ctx);
    await expectOAuthCode(
      consumeCode(ctx, s.rawCode, {
        clientId: s.clientId,
        redirectUri: `${REDIRECT}/../evil`,
        codeVerifier: s.verifier,
      }),
      'invalid_grant',
    );
  });

  it('rejects a code presented by a client it was not issued to', async () => {
    const ctx = await makeCtx();
    const s = await seed(ctx);
    await expectOAuthCode(
      consumeCode(ctx, s.rawCode, {
        clientId: 'someone-else',
        redirectUri: REDIRECT,
        codeVerifier: s.verifier,
      }),
      'invalid_grant',
    );
  });

  it('rejects an expired code even though the document has not been reaped yet', async () => {
    const ctx = await makeCtx();
    const s = await seed(ctx);
    await ctx.models.Code.updateOne(
      { codeHash: sha256(s.rawCode) },
      { $set: { expiresAt: new Date(Date.now() - 1000) } },
    );
    await expectOAuthCode(redeem(ctx, s), 'invalid_grant');
  });

  it('answers null from introspection once the parent grant is revoked', async () => {
    const ctx = await makeCtx();
    const s = await seed(ctx);
    const issued = await issueForCode(ctx, await redeem(ctx, s));
    expect(await introspectAccessToken(ctx, issued.accessToken)).not.toBeNull();

    // Revoke ONLY the grant. The access token document is untouched and
    // unexpired — if introspection trusted it, revocation would take an hour.
    await ctx.models.Grant.updateOne({ _id: s.grantId }, { $set: { revokedAt: new Date() } });
    expect(await introspectAccessToken(ctx, issued.accessToken)).toBeNull();
    await expectOAuthCode(
      rotateRefresh(ctx, issued.refreshToken!, { clientId: s.clientId }),
      'invalid_grant',
    );
  });

  it('answers null from introspection for an unknown or revoked token instead of throwing', async () => {
    const ctx = await makeCtx();
    const s = await seed(ctx);
    const issued = await issueForCode(ctx, await redeem(ctx, s));
    expect(await introspectAccessToken(ctx, 'not-a-token')).toBeNull();
    await revokeFamily(ctx, issued.familyId, 'test');
    expect(await introspectAccessToken(ctx, issued.accessToken)).toBeNull();
  });

  it('revokeGrantTokens kills the live tokens under a grant and counts only those', async () => {
    const ctx = await makeCtx();
    const s = await seed(ctx);
    const issued = await issueForCode(ctx, await redeem(ctx, s));
    expect(await revokeGrantTokens(ctx, s.grantId)).toBe(2);
    // Idempotent in the only sense that matters: nothing left to revoke.
    expect(await revokeGrantTokens(ctx, s.grantId)).toBe(0);
    expect(await introspectAccessToken(ctx, issued.accessToken)).toBeNull();
  });

  it('revokeToken is idempotent and stays silent about tokens it does not own', async () => {
    const ctx = await makeCtx();
    const s = await seed(ctx);
    const issued = await issueForCode(ctx, await redeem(ctx, s));

    // Unknown token: no throw, nothing to do (RFC 7009 §2.2).
    await expect(revokeToken(ctx, 'never-issued', s.clientId)).resolves.toBeUndefined();

    // Another client's token: 200-shaped, and NOT revoked.
    await revokeToken(ctx, issued.accessToken, 'a-different-client');
    expect(await introspectAccessToken(ctx, issued.accessToken)).not.toBeNull();

    await revokeToken(ctx, issued.refreshToken!, s.clientId);
    await revokeToken(ctx, issued.refreshToken!, s.clientId);
    // A refresh token revokes the family, so the access token dies with it.
    expect(await introspectAccessToken(ctx, issued.accessToken)).toBeNull();
  });

  it('revokes the family when a refresh token is presented by the wrong client', async () => {
    const ctx = await makeCtx();
    const s = await seed(ctx);
    const issued = await issueForCode(ctx, await redeem(ctx, s));
    await expectOAuthCode(
      rotateRefresh(ctx, issued.refreshToken!, { clientId: 'attacker' }),
      'invalid_grant',
    );
    expect(await introspectAccessToken(ctx, issued.accessToken)).toBeNull();
  });

  it('re-checks grantContext.verify on every refresh, not only at consent', async () => {
    let member = true;
    const ctx = await makeCtx({
      grantContext: {
        list: () => [{ id: 'org_1', label: 'Acme' }],
        verify: () => member,
      },
    });
    const s = await seed(ctx, { contextId: 'org_1' });
    const first = await issueForCode(ctx, await redeem(ctx, s));
    const second = await rotateRefresh(ctx, first.refreshToken!, { clientId: s.clientId });
    expect(second.contextId).toBe('org_1');

    member = false;
    await expectOAuthCode(
      rotateRefresh(ctx, second.refreshToken!, { clientId: s.clientId }),
      'invalid_grant',
    );

    // Membership ending kills the grant itself, not just the live tokens.
    const grant = await ctx.models.Grant.findById(s.grantId);
    expect(grant!.revokedAt).toBeInstanceOf(Date);
    expect(await introspectAccessToken(ctx, second.accessToken)).toBeNull();
  });

  it('hands grantContext.verify the loaded user on refresh, not a bare { id }', async () => {
    // The reported rule is "a member of this account OR an admin", and admins
    // hold no membership row — so an id alone forces the host to re-read the
    // same user from Mongo on every single refresh just to see a flag. The
    // package already has `loadUser` and already calls it for /userinfo.
    const seen: PackageUser[] = [];
    const ctx = await makeCtx({
      loadUser: (id) => ({ id, email: 'ada@example.test', displayName: 'Ada', isAdmin: true }),
      grantContext: {
        list: () => [{ id: 'org_1', label: 'Acme' }],
        verify: (u) => {
          seen.push(u);
          return Boolean(u.isAdmin);
        },
      },
    });
    const s = await seed(ctx, { contextId: 'org_1' });
    const first = await issueForCode(ctx, await redeem(ctx, s));
    await rotateRefresh(ctx, first.refreshToken!, { clientId: s.clientId });

    expect(seen).toHaveLength(1);
    expect(String(seen[0]!.id)).toBe(String(s.userId));
    expect(seen[0]!.email).toBe('ada@example.test');
    expect(seen[0]!.isAdmin).toBe(true);
  });

  it('still calls grantContext.verify with { id } when no loadUser is configured', async () => {
    // `loadUser` is optional and this path must not start requiring it —
    // `ctx.loadUser` falls back to `{ id }`, so the contract is unchanged for a
    // host that never configured one.
    const seen: PackageUser[] = [];
    const ctx = await makeCtx({
      grantContext: {
        list: () => [{ id: 'org_1', label: 'Acme' }],
        verify: (u) => {
          seen.push(u);
          return true;
        },
      },
    });
    const s = await seed(ctx, { contextId: 'org_1' });
    const first = await issueForCode(ctx, await redeem(ctx, s));
    await rotateRefresh(ctx, first.refreshToken!, { clientId: s.clientId });

    expect(String(seen[0]!.id)).toBe(String(s.userId));
    expect(seen[0]!.email).toBeUndefined();
  });

  it('never calls grantContext.verify when the adapter is absent and contextId is null', async () => {
    const ctx = await makeCtx();
    const s = await seed(ctx);
    const first = await issueForCode(ctx, await redeem(ctx, s));
    const second = await rotateRefresh(ctx, first.refreshToken!, { clientId: s.clientId });
    expect(second.contextId).toBeNull();
  });

  it('stores nothing that can be replayed — only hashes reach the database', async () => {
    const ctx = await makeCtx();
    const s = await seed(ctx);
    const issued = await issueForCode(ctx, await redeem(ctx, s));

    expect(await ctx.models.Token.findOne({ tokenHash: issued.accessToken })).toBeNull();
    expect(await ctx.models.Token.findOne({ tokenHash: sha256(issued.accessToken) })).not.toBeNull();
    const raw = JSON.stringify(await ctx.models.Token.find({ familyId: issued.familyId }));
    expect(raw).not.toContain(issued.accessToken);
    expect(raw).not.toContain(issued.refreshToken);
  });
});
