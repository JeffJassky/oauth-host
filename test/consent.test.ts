import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { resolveConfig } from '../src/server/config.js';
import { syncModelIndexes } from '../src/server/models.js';
import { generateClientId } from '../src/server/crypto.js';
import { RedirectableAuthError, UnredirectableError } from '../src/server/errors.js';
import {
  consentRedirectUrl,
  createAuthorizationRequest,
  loginRedirectUrl,
  validateAuthorizationRequest,
} from '../src/server/services/authorize.js';
import { decideConsent, getConsentPayload } from '../src/server/services/consent.js';
import type { ResolvedContext } from '../src/server/config.js';
import type {
  CreateOAuthHostConfig,
  GrantContextAdapter,
  OAuthClientDoc,
  OAuthEvent,
  PackageUser,
} from '../types/index.js';

/**
 * Service-level, no HTTP. The routes are another layer's tests; what is being
 * proven here is the redirect-vs-render split, PKCE enforcement, the shape of
 * the consent payload as a published contract, and that a decision is one-shot.
 *
 * `test/helpers.ts` covers the HTTP app; everything this file needs is local
 * because a service test has no app to build.
 */

const ISSUER = 'https://api.example.test';
const MCP = 'https://api.example.test/mcp';

let mongod: MongoMemoryServer;

const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

const user: PackageUser = {
  id: new mongoose.Types.ObjectId(),
  email: 'ada@example.test',
  displayName: 'Ada Lovelace',
  authTime: new Date('2026-08-12T09:00:00Z'),
};

const otherUser: PackageUser = { id: new mongoose.Types.ObjectId(), email: 'bob@example.test' };

/** Events the context recorded, so `track` can be asserted without a spy lib. */
let events: OAuthEvent[] = [];

function buildContext(overrides: Partial<CreateOAuthHostConfig> = {}): ResolvedContext {
  return resolveConfig({
    connection: mongoose,
    issuer: ISSUER,
    resources: [{ id: MCP, label: 'MCP server' }],
    scopes: [
      { id: 'openid', label: 'Sign you in', oidc: true },
      { id: 'profile', label: 'Your name and avatar', oidc: true },
      { id: 'contacts.read', label: 'Read your contacts', description: 'Names and emails.' },
      { id: 'contacts.write', label: 'Create and edit contacts', sensitive: true },
    ],
    consentUrl: '/settings/authorize?theme=dark',
    loginUrl: '/login?src=oauth',
    returnParam: 'next',
    resolveUser: () => user,
    track: (event) => events.push(event),
    ...overrides,
  });
}

async function makeClient(
  ctx: ResolvedContext,
  patch: Partial<OAuthClientDoc> = {},
): Promise<OAuthClientDoc> {
  return ctx.models.Client.create({
    clientId: generateClientId(),
    name: 'Claude',
    redirectUris: ['https://claude.ai/api/mcp/auth_callback'],
    allowedScopes: ['openid', 'profile', 'contacts.read'],
    allowedResources: [MCP],
    branding: { logoUrl: 'https://cdn.example.test/claude.png', publisher: 'Anthropic' },
    ...patch,
  });
}

function query(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    response_type: 'code',
    redirect_uri: 'https://claude.ai/api/mcp/auth_callback',
    scope: 'openid contacts.read',
    code_challenge: CHALLENGE,
    code_challenge_method: 'S256',
    state: 'st-123',
    resource: MCP,
    ...over,
  };
}

/** Walk /authorize through to a parked request id, the way the route does. */
async function pending(ctx: ResolvedContext, client: OAuthClientDoc, over: Record<string, unknown> = {}) {
  const validated = await validateAuthorizationRequest(
    ctx,
    query({ client_id: client.clientId, ...over }),
  );
  return createAuthorizationRequest(ctx, validated, user);
}

beforeAll(async () => {
  mongod = await MongoMemoryServer.create();
  await mongoose.connect(mongod.getUri(), { dbName: 'oauth-host-consent-test' });
  await syncModelIndexes(buildContext().models);
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongod.stop();
});

beforeEach(async () => {
  events = [];
  const { collections } = mongoose.connection;
  await Promise.all(Object.values(collections).map((c) => c.deleteMany({})));
});

// ---------------------------------------------------------------------------

describe('validateAuthorizationRequest — the redirect boundary', () => {
  it('never redirects an unregistered client', async () => {
    const ctx = buildContext();
    await expect(validateAuthorizationRequest(ctx, query({ client_id: 'nope' })))
      .rejects.toBeInstanceOf(UnredirectableError);
  });

  it('never redirects a missing client_id', async () => {
    const ctx = buildContext();
    await expect(validateAuthorizationRequest(ctx, query()))
      .rejects.toBeInstanceOf(UnredirectableError);
  });

  it('never redirects a disabled client', async () => {
    const ctx = buildContext();
    const client = await makeClient(ctx, { status: 'disabled' });
    await expect(validateAuthorizationRequest(ctx, query({ client_id: client.clientId })))
      .rejects.toBeInstanceOf(UnredirectableError);
  });

  it('never redirects an unregistered redirect_uri, however close', async () => {
    const ctx = buildContext();
    const client = await makeClient(ctx);
    // Prefix, extra query, and trailing slash are all rejected — the open
    // redirect lives in whichever of these a "close enough" match allows.
    for (const redirect_uri of [
      'https://claude.ai/api/mcp/auth_callback/../../evil',
      'https://claude.ai/api/mcp/auth_callback?x=1',
      'https://claude.ai/api/mcp/auth_callback/',
      'https://evil.test/cb',
    ]) {
      await expect(
        validateAuthorizationRequest(ctx, query({ client_id: client.clientId, redirect_uri })),
      ).rejects.toBeInstanceOf(UnredirectableError);
    }
  });

  it('redirects a missing or plain code_challenge back to the client', async () => {
    const ctx = buildContext();
    const client = await makeClient(ctx);

    const missing = validateAuthorizationRequest(
      ctx,
      query({ client_id: client.clientId, code_challenge: undefined }),
    );
    await expect(missing).rejects.toBeInstanceOf(RedirectableAuthError);

    const plain = await validateAuthorizationRequest(
      ctx,
      query({ client_id: client.clientId, code_challenge_method: 'plain' }),
    ).catch((e: unknown) => e);
    expect(plain).toBeInstanceOf(RedirectableAuthError);
    const url = new URL((plain as RedirectableAuthError).toRedirect(ISSUER));
    expect(url.searchParams.get('error')).toBe('invalid_request');
    expect(url.searchParams.get('state')).toBe('st-123');
    expect(url.searchParams.get('iss')).toBe(ISSUER);
  });

  it('redirects a scope outside the client allow-list', async () => {
    const ctx = buildContext();
    const client = await makeClient(ctx);
    const err = await validateAuthorizationRequest(
      ctx,
      // In the catalog, NOT in this client's allowedScopes.
      query({ client_id: client.clientId, scope: 'openid contacts.write' }),
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RedirectableAuthError);
    expect((err as RedirectableAuthError).code).toBe('invalid_scope');
    expect((err as RedirectableAuthError).description).toContain('contacts.write');
  });

  it('redirects a scope outside the catalog', async () => {
    const ctx = buildContext();
    const client = await makeClient(ctx, { allowedScopes: ['openid', 'billing.read'] });
    const err = await validateAuthorizationRequest(
      ctx,
      query({ client_id: client.clientId, scope: 'billing.read' }),
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RedirectableAuthError);
    expect((err as RedirectableAuthError).code).toBe('invalid_scope');
  });

  it('accepts a repeated resource parameter and rejects an undeclared one', async () => {
    const ctx = buildContext({
      resources: [{ id: MCP }, { id: 'https://api.example.test/v1' }],
    });
    const client = await makeClient(ctx, {
      allowedResources: [MCP, 'https://api.example.test/v1'],
    });

    const both = await validateAuthorizationRequest(
      ctx,
      query({ client_id: client.clientId, resource: [MCP, 'https://api.example.test/v1'] }),
    );
    expect(both.resources).toEqual([MCP, 'https://api.example.test/v1']);

    await expect(
      validateAuthorizationRequest(
        ctx,
        query({ client_id: client.clientId, resource: 'https://elsewhere.test/api' }),
      ),
    ).rejects.toBeInstanceOf(RedirectableAuthError);
  });

  it('defaults to the client first allowed resource', async () => {
    const ctx = buildContext();
    const client = await makeClient(ctx);
    const validated = await validateAuthorizationRequest(
      ctx,
      query({ client_id: client.clientId, resource: undefined }),
    );
    expect(validated.resources).toEqual([MCP]);
  });
});

describe('redirect helpers', () => {
  it('merges request_id into a consentUrl that already has a query', () => {
    const ctx = buildContext();
    expect(consentRedirectUrl(ctx, 'abc')).toBe('/settings/authorize?theme=dark&request_id=abc');
  });

  it('merges the return param into loginUrl, and is null without one', () => {
    const ctx = buildContext();
    expect(loginRedirectUrl(ctx, '/oauth/authorize?client_id=x&state=y')).toBe(
      '/login?src=oauth&next=%2Foauth%2Fauthorize%3Fclient_id%3Dx%26state%3Dy',
    );
    expect(loginRedirectUrl(buildContext({ loginUrl: undefined }), '/x')).toBeNull();
  });
});

describe('getConsentPayload — the versioned UI contract', () => {
  it('carries no internal ids', async () => {
    const ctx = buildContext();
    const client = await makeClient(ctx);
    const request = await pending(ctx, client);

    const payload = await getConsentPayload(ctx, request.requestId, user);
    const serialized = JSON.stringify(payload);

    expect(serialized).not.toContain('_id');
    expect(serialized).not.toContain('grantId');
    expect(serialized).not.toContain('userId');
    expect(serialized).not.toContain(String(user.id));
    expect(serialized).not.toContain(request.requestId);

    expect(payload.client).toEqual({
      name: 'Claude',
      logoUrl: 'https://cdn.example.test/claude.png',
      publisher: 'Anthropic',
    });
    expect(payload.scopes).toEqual([
      { id: 'openid', label: 'Sign you in', isNew: true },
      {
        id: 'contacts.read',
        label: 'Read your contacts',
        description: 'Names and emails.',
        isNew: true,
      },
    ]);
    expect(payload.user).toEqual({ displayName: 'Ada Lovelace', email: 'ada@example.test' });
  });

  it('omits `contexts` entirely in single-subject mode', async () => {
    const ctx = buildContext();
    const client = await makeClient(ctx);
    const request = await pending(ctx, client);
    const payload = await getConsentPayload(ctx, request.requestId, user);
    // Absent, not empty — an empty array says "no contexts to pick", which is a
    // different claim from "this host has no contexts at all".
    expect('contexts' in payload).toBe(false);
  });

  it('includes `contexts` from the adapter when one is configured', async () => {
    const grantContext: GrantContextAdapter = {
      list: () => [{ id: 'org_1', label: 'Acme', description: 'Your team' }],
      verify: (_u, id) => id === 'org_1',
    };
    const ctx = buildContext({ grantContext });
    const client = await makeClient(ctx);
    const request = await pending(ctx, client);
    const payload = await getConsentPayload(ctx, request.requestId, user);
    expect(payload.contexts).toEqual([{ id: 'org_1', label: 'Acme', description: 'Your team' }]);
  });

  it('marks re-consented scopes as not new', async () => {
    const ctx = buildContext();
    const client = await makeClient(ctx);
    const first = await pending(ctx, client, { scope: 'openid' });
    await decideConsent(ctx, first.requestId, user, { approve: true });

    const second = await pending(ctx, client);
    const payload = await getConsentPayload(ctx, second.requestId, user);
    expect(payload.scopes.map((s) => [s.id, s.isNew])).toEqual([
      ['openid', false],
      ['contacts.read', true],
    ]);
  });

  it('404s an unknown handle and 403s another user’s', async () => {
    const ctx = buildContext();
    const client = await makeClient(ctx);
    const request = await pending(ctx, client);

    await expect(getConsentPayload(ctx, 'no-such-handle', user)).rejects.toMatchObject({
      status: 404,
      code: 'invalid_request',
    });
    await expect(getConsentPayload(ctx, request.requestId, otherUser)).rejects.toMatchObject({
      status: 403,
      code: 'access_denied',
    });
  });
});

describe('decideConsent', () => {
  it('approves, mints a code, and returns code + state + iss', async () => {
    const ctx = buildContext();
    const client = await makeClient(ctx);
    const request = await pending(ctx, client);

    const { redirectTo } = await decideConsent(ctx, request.requestId, user, { approve: true });
    const url = new URL(redirectTo);
    expect(url.origin + url.pathname).toBe('https://claude.ai/api/mcp/auth_callback');
    expect(url.searchParams.get('code')).toBeTruthy();
    expect(url.searchParams.get('state')).toBe('st-123');
    expect(url.searchParams.get('iss')).toBe(ISSUER);

    // The code is stored only as a digest — nothing in the row can be replayed.
    const stored = await ctx.models.Code.findOne({}).lean();
    expect(stored?.codeHash).toBeTruthy();
    expect(stored?.codeHash).not.toBe(url.searchParams.get('code'));
    expect(stored?.scopes).toEqual(['openid', 'contacts.read']);
    expect(stored?.codeChallenge).toBe(CHALLENGE);
    expect(stored?.authTime?.toISOString()).toBe('2026-08-12T09:00:00.000Z');

    expect(events.map((e) => e.type)).toEqual([
      'oauth.authorization_requested',
      'oauth.consent_granted',
    ]);
    expect(await ctx.models.Audit.countDocuments({ type: 'oauth.consent_granted' })).toBe(1);
  });

  it('rejects an approved scope that was never requested', async () => {
    const ctx = buildContext();
    const client = await makeClient(ctx);
    const request = await pending(ctx, client, { scope: 'openid' });

    await expect(
      decideConsent(ctx, request.requestId, user, {
        approve: true,
        scopes: ['openid', 'contacts.read'],
      }),
    ).rejects.toMatchObject({ code: 'invalid_request' });

    // The rejected decision left the handle usable.
    expect(await ctx.models.Code.countDocuments({})).toBe(0);
    await expect(decideConsent(ctx, request.requestId, user, { approve: true })).resolves.toBeDefined();
  });

  it('honours a narrower approval', async () => {
    const ctx = buildContext();
    const client = await makeClient(ctx);
    const request = await pending(ctx, client);
    await decideConsent(ctx, request.requestId, user, { approve: true, scopes: ['openid'] });
    const grant = await ctx.models.Grant.findOne({}).lean();
    expect(grant?.scopes).toEqual(['openid']);
  });

  it('cannot be decided twice', async () => {
    const ctx = buildContext();
    const client = await makeClient(ctx);
    const request = await pending(ctx, client);

    await decideConsent(ctx, request.requestId, user, { approve: true });
    await expect(decideConsent(ctx, request.requestId, user, { approve: true }))
      .rejects.toMatchObject({ code: 'invalid_request' });
    expect(await ctx.models.Code.countDocuments({})).toBe(1);
  });

  it('unions scopes on re-consent and bumps version only when it grows', async () => {
    const ctx = buildContext();
    const client = await makeClient(ctx);

    await decideConsent(ctx, (await pending(ctx, client, { scope: 'openid' })).requestId, user, {
      approve: true,
    });
    let grant = await ctx.models.Grant.findOne({}).lean();
    expect(grant?.scopes).toEqual(['openid']);
    expect(grant?.version).toBe(1);

    // Same set again — no widening, so the version stands still.
    await decideConsent(ctx, (await pending(ctx, client, { scope: 'openid' })).requestId, user, {
      approve: true,
    });
    grant = await ctx.models.Grant.findOne({}).lean();
    expect(grant?.version).toBe(1);

    await decideConsent(ctx, (await pending(ctx, client)).requestId, user, { approve: true });
    grant = await ctx.models.Grant.findOne({}).lean();
    expect(grant?.scopes).toEqual(['openid', 'contacts.read']);
    expect(grant?.version).toBe(2);
    // Upserted, never duplicated — the partial unique index depends on it.
    expect(await ctx.models.Grant.countDocuments({})).toBe(1);
  });

  it('denies with error=access_denied, state and iss', async () => {
    const ctx = buildContext();
    const client = await makeClient(ctx);
    const request = await pending(ctx, client);

    const { redirectTo } = await decideConsent(ctx, request.requestId, user, { approve: false });
    const url = new URL(redirectTo);
    expect(url.searchParams.get('error')).toBe('access_denied');
    expect(url.searchParams.get('state')).toBe('st-123');
    expect(url.searchParams.get('iss')).toBe(ISSUER);
    expect(url.searchParams.get('code')).toBeNull();

    expect(await ctx.models.Grant.countDocuments({})).toBe(0);
    expect(await ctx.models.Code.countDocuments({})).toBe(0);
    expect((await ctx.models.Request.findOne({ requestId: request.requestId }))?.decision)
      .toBe('denied');
    expect(events.at(-1)?.type).toBe('oauth.consent_denied');
  });

  it('requires a verified contextId when grantContext is configured', async () => {
    const grantContext: GrantContextAdapter = {
      list: () => [{ id: 'org_1', label: 'Acme' }],
      verify: (_u, id) => id === 'org_1',
    };
    const ctx = buildContext({ grantContext });
    const client = await makeClient(ctx);

    const missing = await pending(ctx, client);
    await expect(decideConsent(ctx, missing.requestId, user, { approve: true }))
      .rejects.toMatchObject({ code: 'invalid_request' });

    await expect(
      decideConsent(ctx, missing.requestId, user, { approve: true, contextId: 'org_9' }),
    ).rejects.toMatchObject({ code: 'access_denied' });

    await decideConsent(ctx, missing.requestId, user, { approve: true, contextId: 'org_1' });
    expect((await ctx.models.Grant.findOne({}).lean())?.contextId).toBe('org_1');
  });

  it('refuses a contextId in single-subject mode and stores null', async () => {
    const ctx = buildContext();
    const client = await makeClient(ctx);
    const request = await pending(ctx, client);

    await expect(
      decideConsent(ctx, request.requestId, user, { approve: true, contextId: 'org_1' }),
    ).rejects.toMatchObject({ code: 'invalid_request' });

    await decideConsent(ctx, request.requestId, user, { approve: true });
    expect((await ctx.models.Grant.findOne({}).lean())?.contextId).toBeNull();
  });
});
