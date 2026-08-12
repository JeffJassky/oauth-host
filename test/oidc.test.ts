import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createHash, createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { resolveConfig } from '../src/server/config.js';
import type { ResolvedContext } from '../src/server/config.js';
import { syncModelIndexes } from '../src/server/models.js';
import { randomToken } from '../src/server/crypto.js';
import { createKeyManager } from '../src/server/keys.js';
import { buildIdToken, buildUserInfo, subjectFor } from '../src/server/services/oidc.js';
import type {
  CreateOAuthHostConfig,
  OAuthClientDoc,
  PackageUser,
} from '../types/index.js';

/**
 * The OIDC layer, verified for real rather than by shape.
 *
 * The `id_token` tests parse the JWKS this package publishes and run
 * `crypto.verify` against it, because the failure this file exists to prevent
 * is a token that looks perfect and that no client will accept — an ECDSA
 * signature in Node's default DER encoding instead of the fixed-width pair JWS
 * requires. Asserting three dot-separated segments would pass on that bug.
 */

let mongod: MongoMemoryServer;
let suffix = 0;

const RESOURCE = 'https://api.example.com/mcp';

async function makeCtx(overrides: Partial<CreateOAuthHostConfig> = {}): Promise<ResolvedContext> {
  suffix += 1;
  const tag = `Oidc${suffix}`;
  const ctx = resolveConfig({
    connection: mongoose,
    issuer: 'https://api.example.com',
    resources: [{ id: RESOURCE }],
    scopes: ['openid', 'profile', 'email', 'contacts.read'],
    consentUrl: '/settings/authorize',
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
    signing: { autoGenerate: true },
    ...overrides,
  });
  await syncModelIndexes(ctx.models);
  return ctx;
}

async function makeClient(ctx: ResolvedContext, name = 'Claude'): Promise<OAuthClientDoc> {
  const client = await ctx.models.Client.create({
    clientId: `cid-${randomToken(8)}`,
    name,
    redirectUris: ['https://claude.ai/cb'],
    allowedScopes: ['openid', 'profile', 'email', 'contacts.read'],
    allowedResources: [RESOURCE],
  });
  return client;
}

const user = (): PackageUser => ({
  id: new mongoose.Types.ObjectId(),
  email: 'ada@example.com',
  displayName: 'Ada Lovelace',
  avatarUrl: 'https://cdn.example.com/ada.png',
});

interface Verified {
  ok: boolean;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: Buffer;
}

/** Verify a compact JWS against a JWK Set exactly as a client would. */
function verifyAgainstJwks(token: string, jwks: { keys: Record<string, unknown>[] }): Verified {
  const [h, p, s] = token.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url').toString()) as Record<string, unknown>;
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error(`no JWK published for kid ${String(header.kid)}`);
  const signature = Buffer.from(s, 'base64url');
  const ok = verify(
    'sha256',
    Buffer.from(`${h}.${p}`),
    { key: createPublicKey({ key: jwk as never, format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
    signature,
  );
  return { ok, header, payload: JSON.parse(Buffer.from(p, 'base64url').toString()), signature };
}

describe('oidc', () => {
  beforeAll(async () => {
    mongod = await MongoMemoryServer.create();
    await mongoose.connect(mongod.getUri(), { dbName: 'oauth-host-oidc' });
  });
  afterAll(async () => {
    await mongoose.disconnect();
    await mongod.stop();
  });

  // -- keys -----------------------------------------------------------------

  it('names signing.autoGenerate when there is no key, instead of inventing one per boot', async () => {
    const ctx = await makeCtx({ signing: {} });
    await expect(createKeyManager(ctx).getSigningKey()).rejects.toThrow(/signing\.autoGenerate/);
  });

  it('reuses the auto-generated key across restarts rather than orphaning every id_token', async () => {
    const ctx = await makeCtx();
    const first = await createKeyManager(ctx).getSigningKey();
    // A second manager is what a second process — or a restart — looks like.
    const second = await createKeyManager(ctx).getSigningKey();
    expect(second.kid).toBe(first.kid);
    expect(await ctx.models.Key.countDocuments({})).toBe(1);
  });

  it('never publishes the private scalar in the JWK Set', async () => {
    const ctx = await makeCtx();
    const keys = createKeyManager(ctx);
    await keys.getSigningKey();
    const { keys: published } = await keys.jwks();
    expect(published).toHaveLength(1);
    expect(published[0]!.d).toBeUndefined();
    expect(published[0]).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig' });
  });

  it('keeps publishing a retiring key so tokens it already signed still validate', async () => {
    const ctx = await makeCtx();
    const keys = createKeyManager(ctx);
    const active = await keys.getSigningKey();
    const idToken = await buildIdToken(ctx, keys, {
      client: await makeClient(ctx), user: user(), scopes: ['openid'], contextId: null,
    });

    await ctx.models.Key.updateOne({ kid: active.kid }, { $set: { status: 'retiring' } });
    const { keys: published } = await keys.jwks();
    expect(published.map((k) => k.kid)).toContain(active.kid);
    expect(verifyAgainstJwks(idToken, { keys: published }).ok).toBe(true);
  });

  it('signs with a configured PEM in preference to anything in the database', async () => {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    const ctx = await makeCtx({
      signing: { autoGenerate: true, keys: [{ kid: 'env-1', privateKeyPem: pem }] },
    });
    const keys = createKeyManager(ctx);
    expect((await keys.getSigningKey()).kid).toBe('env-1');
    // Nothing was persisted: the production key does not live beside the data.
    expect(await ctx.models.Key.countDocuments({})).toBe(0);

    const idToken = await buildIdToken(ctx, keys, {
      client: await makeClient(ctx), user: user(), scopes: ['openid'], contextId: null,
    });
    expect(verifyAgainstJwks(idToken, await keys.jwks()).ok).toBe(true);
  });

  it('rejects a non-P-256 signing key at boot rather than at the first id_token', async () => {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    const ctx = await makeCtx({ signing: { keys: [{ kid: 'wrong-curve', privateKeyPem: pem }] } });
    expect(() => createKeyManager(ctx)).toThrow(/P-256/);
  });

  // -- id_token -------------------------------------------------------------

  it('issues an id_token that verifies against the published JWKS', async () => {
    const ctx = await makeCtx();
    const keys = createKeyManager(ctx);
    const client = await makeClient(ctx);
    const u = user();

    const idToken = await buildIdToken(ctx, keys, {
      client, user: u, scopes: ['openid', 'profile', 'email'], contextId: null,
    });
    const { ok, header, payload } = verifyAgainstJwks(idToken, await keys.jwks());

    expect(ok).toBe(true);
    expect(header).toMatchObject({ alg: 'ES256', typ: 'JWT' });
    expect(payload.iss).toBe('https://api.example.com');
    expect(payload.aud).toBe(client.clientId);
    expect(payload.sub).toBe(String(u.id));
    expect(payload.exp as number).toBeGreaterThan(payload.iat as number);
    expect(payload.nbf as number).toBeLessThanOrEqual(payload.iat as number);
  });

  it('signs ES256 as the fixed-width r‖s pair, not Node default DER', async () => {
    const ctx = await makeCtx();
    const keys = createKeyManager(ctx);
    const idToken = await buildIdToken(ctx, keys, {
      client: await makeClient(ctx), user: user(), scopes: ['openid'], contextId: null,
    });
    // RFC 7518 §3.4 — exactly 64 bytes for P-256. A DER signature is 70-72 and
    // verifies nowhere, silently.
    expect(verifyAgainstJwks(idToken, await keys.jwks()).signature).toHaveLength(64);
  });

  it('fails verification when a single payload byte is altered', async () => {
    const ctx = await makeCtx();
    const keys = createKeyManager(ctx);
    const idToken = await buildIdToken(ctx, keys, {
      client: await makeClient(ctx), user: user(), scopes: ['openid'], contextId: null,
    });
    const [h, p, s] = idToken.split('.');
    const tampered = JSON.parse(Buffer.from(p!, 'base64url').toString()) as Record<string, unknown>;
    tampered.sub = 'someone-else';
    const forged = `${h}.${Buffer.from(JSON.stringify(tampered)).toString('base64url')}.${s}`;
    expect(verifyAgainstJwks(forged, await keys.jwks()).ok).toBe(false);
  });

  it('binds at_hash to the access token it was issued with', async () => {
    const ctx = await makeCtx();
    const keys = createKeyManager(ctx);
    const accessToken = randomToken();
    const idToken = await buildIdToken(ctx, keys, {
      client: await makeClient(ctx), user: user(), scopes: ['openid'], contextId: null, accessToken,
    });
    const { payload } = verifyAgainstJwks(idToken, await keys.jwks());

    // OIDC Core §3.1.3.6 — left-most half of the SHA-256, base64url.
    const digest = createHash('sha256').update(accessToken, 'ascii').digest();
    expect(payload.at_hash).toBe(digest.subarray(0, 16).toString('base64url'));
  });

  it('omits at_hash and nonce when neither was supplied, rather than emitting null', async () => {
    const ctx = await makeCtx();
    const keys = createKeyManager(ctx);
    const idToken = await buildIdToken(ctx, keys, {
      client: await makeClient(ctx), user: user(), scopes: ['openid'], contextId: null,
    });
    const { payload } = verifyAgainstJwks(idToken, await keys.jwks());
    expect('at_hash' in payload).toBe(false);
    expect('nonce' in payload).toBe(false);
    expect('auth_time' in payload).toBe(false);
  });

  it('echoes the nonce and the session auth_time when the host knows them', async () => {
    const ctx = await makeCtx();
    const keys = createKeyManager(ctx);
    const authTime = new Date('2026-08-12T10:00:00Z');
    const idToken = await buildIdToken(ctx, keys, {
      client: await makeClient(ctx),
      user: { ...user(), authTime },
      scopes: ['openid'],
      contextId: null,
      nonce: 'n-0S6_WzA2Mj',
    });
    const { payload } = verifyAgainstJwks(idToken, await keys.jwks());
    expect(payload.nonce).toBe('n-0S6_WzA2Mj');
    expect(payload.auth_time).toBe(Math.floor(authTime.getTime() / 1000));
  });

  it('withholds profile and email claims from a token that was not granted those scopes', async () => {
    const ctx = await makeCtx();
    const keys = createKeyManager(ctx);
    const idToken = await buildIdToken(ctx, keys, {
      client: await makeClient(ctx), user: user(), scopes: ['openid', 'contacts.read'], contextId: null,
    });
    const { payload } = verifyAgainstJwks(idToken, await keys.jwks());
    expect(payload.email).toBeUndefined();
    expect(payload.name).toBeUndefined();
    expect(payload.picture).toBeUndefined();
  });

  it('does not let host claims overwrite iss, sub, aud, exp or iat', async () => {
    const u = user();
    const ctx = await makeCtx({
      claims: () => ({
        iss: 'https://evil.example.com',
        sub: 'root',
        aud: 'another-client',
        exp: 9_999_999_999,
        iat: 0,
        nonce: 'forged',
        department: 'analytical engines',
      }),
    });
    const keys = createKeyManager(ctx);
    const client = await makeClient(ctx);
    const idToken = await buildIdToken(ctx, keys, {
      client, user: u, scopes: ['openid'], contextId: null, nonce: 'real',
    });
    const { payload } = verifyAgainstJwks(idToken, await keys.jwks());

    expect(payload.iss).toBe('https://api.example.com');
    expect(payload.sub).toBe(String(u.id));
    expect(payload.aud).toBe(client.clientId);
    expect(payload.exp).not.toBe(9_999_999_999);
    expect(payload.iat).not.toBe(0);
    expect(payload.nonce).toBe('real');
    // Everything else the host asked for is still there — this is a guard, not a filter.
    expect(payload.department).toBe('analytical engines');
  });

  it('passes the contextId to the claims adapter so a host can project per-context data', async () => {
    let seen: unknown;
    const ctx = await makeCtx({
      claims: (_u, args) => { seen = args.contextId; return { org: args.contextId }; },
    });
    const keys = createKeyManager(ctx);
    const idToken = await buildIdToken(ctx, keys, {
      client: await makeClient(ctx), user: user(), scopes: ['openid'], contextId: 'org_1',
    });
    expect(seen).toBe('org_1');
    expect(verifyAgainstJwks(idToken, await keys.jwks()).payload.org).toBe('org_1');
  });

  it('hands the claims adapter a client with no secrets on it', async () => {
    let seen: Record<string, unknown> | undefined;
    const ctx = await makeCtx({
      claims: (_u, args) => { seen = args.client as unknown as Record<string, unknown>; return {}; },
    });
    const client = await ctx.models.Client.create({
      clientId: `cid-${randomToken(8)}`,
      name: 'Claude',
      secrets: [{ hash: 'super-secret-hash', createdAt: new Date() }],
      redirectUris: ['https://claude.ai/cb'],
      allowedScopes: ['openid'],
      allowedResources: [RESOURCE],
    });
    await buildIdToken(ctx, createKeyManager(ctx), {
      client, user: user(), scopes: ['openid'], contextId: null,
    });
    expect(seen!.secrets).toBeUndefined();
    expect(JSON.stringify(seen)).not.toContain('super-secret-hash');
  });

  // -- subjects -------------------------------------------------------------

  it('uses the host user id as sub in public mode', async () => {
    const ctx = await makeCtx();
    const u = user();
    expect(await subjectFor(ctx, await makeClient(ctx), u.id)).toBe(String(u.id));
  });

  it('keeps a pairwise sub stable per client and unlinkable across clients', async () => {
    const ctx = await makeCtx({ subjectMode: 'pairwise', pairwiseSalt: 'a-permanent-salt' });
    const u = user();
    const a = await makeClient(ctx, 'Claude');
    const b = await makeClient(ctx, 'ChatGPT');

    const first = await subjectFor(ctx, a, u.id);
    const second = await subjectFor(ctx, await ctx.models.Client.findOne({ clientId: a.clientId }) as OAuthClientDoc, u.id);
    const other = await subjectFor(ctx, b, u.id);

    expect(second).toBe(first);
    expect(other).not.toBe(first);
    expect(first).not.toBe(String(u.id));
  });

  it('persists the pairwise sub so it survives anything that changes the derivation', async () => {
    const ctx = await makeCtx({ subjectMode: 'pairwise', pairwiseSalt: 'salt-one' });
    const u = user();
    const client = await makeClient(ctx);
    const issued = await subjectFor(ctx, client, u.id);

    const stored = await ctx.models.Client.findOne({ clientId: client.clientId });
    expect(stored!.pairwiseSubjects!.get(String(u.id))).toBe(issued);

    // The partner stores this value as their primary key. A rotated salt must
    // not silently re-identify their user as somebody new.
    const rotated = await makeCtx({ subjectMode: 'pairwise', pairwiseSalt: 'salt-two' });
    Object.assign(rotated, { models: ctx.models });
    expect(await subjectFor(rotated, stored as OAuthClientDoc, u.id)).toBe(issued);
  });

  // -- userinfo -------------------------------------------------------------

  it('returns a userinfo sub that matches the id_token sub', async () => {
    const ctx = await makeCtx({ subjectMode: 'pairwise', pairwiseSalt: 'a-permanent-salt' });
    const keys = createKeyManager(ctx);
    const client = await makeClient(ctx);
    const u = user();

    const idToken = await buildIdToken(ctx, keys, {
      client, user: u, scopes: ['openid', 'email'], contextId: null,
    });
    const info = await buildUserInfo(ctx, { client, user: u, scopes: ['openid', 'email'], contextId: null });

    expect(info.sub).toBe(verifyAgainstJwks(idToken, await keys.jwks()).payload.sub);
    expect(info.email).toBe('ada@example.com');
  });

  it('does not let a host claims adapter rewrite the userinfo sub', async () => {
    const ctx = await makeCtx({ claims: () => ({ sub: 'root', title: 'Countess' }) });
    const u = user();
    const info = await buildUserInfo(ctx, {
      client: await makeClient(ctx), user: u, scopes: ['openid'], contextId: null,
    });
    expect(info.sub).toBe(String(u.id));
    expect(info.title).toBe('Countess');
  });

  it('withholds userinfo email and profile claims from a token without those scopes', async () => {
    const ctx = await makeCtx();
    const info = await buildUserInfo(ctx, {
      client: await makeClient(ctx), user: user(), scopes: ['openid'], contextId: null,
    });
    expect(info.email).toBeUndefined();
    expect(info.name).toBeUndefined();
  });
});
