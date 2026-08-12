import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import {
  TEST_RESOURCE,
  buildApp,
  clearDb,
  param,
  pkce,
  startDb,
  stopDb,
  testUser,
  type BuiltApp,
  type Session,
} from './helpers.js';
import type { ClientIdMetadataConfig } from '../types/index.js';

/**
 * Client ID Metadata Documents.
 *
 * The network is stubbed at the `fetch` boundary and nowhere deeper, because
 * the boundary is the thing under test: half of these tests assert that no
 * outbound request happened at all, and a stub any further in would let a real
 * one through while still passing.
 *
 * Every test below is named after the failure it prevents. Most of those
 * failures are SSRF — this is the only file in the package where the server
 * makes an outbound request on an unauthenticated parameter.
 */

const CLIENT_ID = 'https://claude.ai/.well-known/oauth-client';
const CIMD_REDIRECT = 'https://claude.ai/api/mcp/auth_callback';

function metadataDocument(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    client_id: CLIENT_ID,
    client_name: 'Claude',
    redirect_uris: [CIMD_REDIRECT],
    token_endpoint_auth_method: 'none',
    logo_uri: 'https://claude.ai/logo.png',
    client_uri: 'https://claude.ai',
    scope: 'openid profile contacts.read',
    ...overrides,
  };
}

function jsonResponse(body: unknown, contentType = 'application/json'): Response {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  return new Response(text, { status: 200, headers: { 'content-type': contentType } });
}

let fetchStub: ReturnType<typeof vi.fn>;

/** An app with CIMD on and `claude.ai` allowlisted, signed in as a test user. */
async function cimdApp(
  cimd: Partial<ClientIdMetadataConfig> = {},
): Promise<{ built: BuiltApp; state: Session }> {
  const state: Session = { user: testUser() };
  const built = await buildApp({
    session: state,
    config: {
      clientIdMetadata: { enabled: true, allowedHosts: ['claude.ai'], ...cimd },
    },
  });
  return { built, state };
}

interface AuthorizeResult {
  status: number;
  location: string;
  body: Record<string, unknown>;
  verifier: string;
}

/** `/authorize` only — the half of the flow CIMD resolution lives in. */
async function startAuthorize(
  built: BuiltApp,
  opts: { clientId?: string; redirectUri?: string; scope?: string; challenge?: string | null } = {},
): Promise<AuthorizeResult> {
  const pair = pkce();
  const query: Record<string, string> = {
    response_type: 'code',
    client_id: opts.clientId ?? CLIENT_ID,
    redirect_uri: opts.redirectUri ?? CIMD_REDIRECT,
    scope: opts.scope ?? 'openid contacts.read',
    state: 'xyz-state',
    resource: TEST_RESOURCE,
  };
  if (opts.challenge !== null) {
    query.code_challenge = opts.challenge ?? pair.challenge;
    query.code_challenge_method = 'S256';
  }
  const res = await request(built.app).get('/oauth/authorize').query(query);
  return {
    status: res.status,
    location: res.headers.location ?? '',
    body: res.body as Record<string, unknown>,
    verifier: pair.verifier,
  };
}

/** `/authorize` → consent → approve. Returns the authorization code. */
async function authorizeToCode(built: BuiltApp): Promise<{ code: string; verifier: string }> {
  const started = await startAuthorize(built);
  expect(started.status).toBe(302);
  const requestId = param(started.location, 'request_id');
  expect(requestId).toBeTruthy();

  const decision = await request(built.app)
    .post(`/oauth/consent/${requestId}`)
    .send({ approve: true });
  expect(decision.status).toBe(200);

  const code = param(String(decision.body.redirectTo), 'code');
  expect(code).toBeTruthy();
  return { code: code as string, verifier: started.verifier };
}

beforeAll(startDb);
afterAll(stopDb);

beforeEach(async () => {
  await clearDb();
  fetchStub = vi.fn();
  vi.stubGlobal('fetch', fetchStub);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ---------------------------------------------------------------------------

describe('client id metadata documents', () => {
  it('completes an authorization for a secretless client whose client_id is a document URL', async () => {
    fetchStub.mockResolvedValue(jsonResponse(metadataDocument()));
    const { built } = await cimdApp();

    const { code, verifier } = await authorizeToCode(built);

    // No Authorization header and no client_secret anywhere: `client_id` alone,
    // with PKCE as the binding.
    const tokens = await request(built.app)
      .post('/oauth/token')
      .type('form')
      .send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: CIMD_REDIRECT,
        code_verifier: verifier,
        client_id: CLIENT_ID,
      });

    expect(tokens.status).toBe(200);
    expect(tokens.body.access_token).toBeTruthy();
    expect(tokens.body.token_type).toBe('Bearer');
    expect(String(tokens.body.scope).split(' ').sort()).toEqual(['contacts.read', 'openid']);

    const stored = await built.ctx.models.Client.findOne({ clientId: CLIENT_ID }).lean();
    expect(stored?.type).toBe('public');
    expect(stored?.registration).toBe('cimd');
    expect(stored?.secrets ?? []).toHaveLength(0);
  });

  it('serves the fetched client_name and logo to the consent screen', async () => {
    fetchStub.mockResolvedValue(jsonResponse(metadataDocument()));
    const { built } = await cimdApp();

    const started = await startAuthorize(built);
    const payload = await request(built.app)
      .get(`/oauth/consent/${param(started.location, 'request_id')}`);

    expect(payload.status).toBe(200);
    expect(payload.body.client).toMatchObject({
      name: 'Claude',
      logoUrl: 'https://claude.ai/logo.png',
      homepageUrl: 'https://claude.ai',
    });
  });

  // ── the allowlist ────────────────────────────────────────────────────────

  it('makes no outbound request for a host outside the allowlist', async () => {
    const { built } = await cimdApp();

    const res = await startAuthorize(built, { clientId: 'https://evil.test/doc.json' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_client');
    // The assertion that matters: the refusal happened before the socket.
    expect(fetchStub).not.toHaveBeenCalled();
  });

  it('does not let evilclaude.ai match an allowlist entry of claude.ai', async () => {
    const { built } = await cimdApp();

    const res = await startAuthorize(built, { clientId: 'https://evilclaude.ai/doc.json' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_client');
    expect(fetchStub).not.toHaveBeenCalled();
  });

  it('does not admit a subdomain unless the allowlist entry was written with a leading dot', async () => {
    const strict = await cimdApp();
    const sub = await startAuthorize(strict.built, { clientId: 'https://api.claude.ai/doc.json' });
    expect(sub.status).toBe(400);
    expect(fetchStub).not.toHaveBeenCalled();

    fetchStub.mockResolvedValue(jsonResponse(metadataDocument({
      client_id: 'https://api.claude.ai/doc.json',
      redirect_uris: [CIMD_REDIRECT],
    })));
    const loose = await cimdApp({ allowedHosts: ['.claude.ai'] });
    const admitted = await startAuthorize(loose.built, {
      clientId: 'https://api.claude.ai/doc.json',
    });
    expect(admitted.status).toBe(302);
  });

  it('refuses an http:// client_id before opening a connection', async () => {
    const { built } = await cimdApp({ allowedHosts: ['claude.ai'] });

    const res = await startAuthorize(built, { clientId: 'http://claude.ai/doc.json' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_client');
    expect(fetchStub).not.toHaveBeenCalled();
  });

  it('refuses a client_id carrying URL credentials', async () => {
    const { built } = await cimdApp();

    const res = await startAuthorize(built, { clientId: 'https://user:pw@claude.ai/doc.json' });

    expect(res.status).toBe(400);
    expect(fetchStub).not.toHaveBeenCalled();
  });

  it('refuses a non-default port the allowlist entry did not name', async () => {
    const { built } = await cimdApp();

    const res = await startAuthorize(built, { clientId: 'https://claude.ai:8443/doc.json' });

    expect(res.status).toBe(400);
    expect(fetchStub).not.toHaveBeenCalled();
  });

  // ── the fetch itself ─────────────────────────────────────────────────────

  it('treats a 302 from the metadata URL as a failure rather than a hop', async () => {
    fetchStub.mockResolvedValue(
      new Response(null, { status: 302, headers: { location: 'https://evil.test/doc.json' } }),
    );
    const { built } = await cimdApp();

    const res = await startAuthorize(built);

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_client');
    // One call, to the allowlisted URL. Following the redirect would be a
    // second call to a host that was never allowlisted.
    expect(fetchStub).toHaveBeenCalledTimes(1);
    expect(fetchStub.mock.calls[0]?.[0]).toBe(CLIENT_ID);
    expect((fetchStub.mock.calls[0]?.[1] as RequestInit).redirect).toBe('manual');
  });

  it('refuses a document larger than maxBytes instead of buffering it', async () => {
    const huge = metadataDocument({ client_name: 'C'.repeat(4_000) });
    fetchStub.mockResolvedValue(jsonResponse(huge));
    const { built } = await cimdApp({ maxBytes: 512 });

    const res = await startAuthorize(built);

    expect(res.status).toBe(400);
    expect(res.body.error_description).toMatch(/exceeds 512 bytes/);
  });

  it('refuses a metadata fetch that outruns fetchTimeoutMs', async () => {
    // Honour the abort signal rather than faking the rejection, so the test
    // exercises the real `AbortSignal.timeout` wiring.
    fetchStub.mockImplementation((_url: string, init: RequestInit) => new Promise((_ok, reject) => {
      init.signal?.addEventListener('abort', () => reject(init.signal?.reason));
    }));
    const { built } = await cimdApp({ fetchTimeoutMs: 25 });

    const res = await startAuthorize(built);

    expect(res.status).toBe(400);
    expect(res.body.error_description).toMatch(/timed out/);
  });

  it('refuses a metadata document served with a non-JSON content type', async () => {
    fetchStub.mockResolvedValue(jsonResponse(metadataDocument(), 'text/html'));
    const { built } = await cimdApp();

    const res = await startAuthorize(built);

    expect(res.status).toBe(400);
    expect(res.body.error_description).toMatch(/must be JSON/);
  });

  // ── document validation ──────────────────────────────────────────────────

  it('refuses a document whose inner client_id disagrees with the URL it came from', async () => {
    fetchStub.mockResolvedValue(
      jsonResponse(metadataDocument({ client_id: 'https://claude.ai/some-other-client' })),
    );
    const { built } = await cimdApp();

    const res = await startAuthorize(built);

    expect(res.status).toBe(400);
    expect(res.body.error_description).toMatch(/'client_id'/);
  });

  it('refuses a javascript: logo_uri before it can reach the consent screen', async () => {
    fetchStub.mockResolvedValue(
      // eslint-disable-next-line no-script-url
      jsonResponse(metadataDocument({ logo_uri: 'javascript:alert(1)' })),
    );
    const { built } = await cimdApp();

    const res = await startAuthorize(built);

    expect(res.status).toBe(400);
    expect(res.body.error_description).toMatch(/'logo_uri'/);
  });

  it('refuses a document with no client_name, which no user could consent to', async () => {
    fetchStub.mockResolvedValue(jsonResponse(metadataDocument({ client_name: '' })));
    const { built } = await cimdApp();

    const res = await startAuthorize(built);

    expect(res.status).toBe(400);
    expect(res.body.error_description).toMatch(/'client_name'/);
  });

  it('refuses a document with an empty or missing redirect_uris', async () => {
    fetchStub.mockResolvedValue(jsonResponse(metadataDocument({ redirect_uris: [] })));
    const { built } = await cimdApp();

    const res = await startAuthorize(built);

    expect(res.status).toBe(400);
    expect(res.body.error_description).toMatch(/'redirect_uris'/);
  });

  it('refuses a non-loopback http redirect_uri in a metadata document', async () => {
    fetchStub.mockResolvedValue(
      jsonResponse(metadataDocument({ redirect_uris: ['http://claude.ai/cb'] })),
    );
    const { built } = await cimdApp();

    const res = await startAuthorize(built);

    expect(res.status).toBe(400);
    expect(res.body.error_description).toMatch(/'redirect_uris'/);
  });

  it('refuses a token_endpoint_auth_method other than none', async () => {
    fetchStub.mockResolvedValue(
      jsonResponse(metadataDocument({ token_endpoint_auth_method: 'client_secret_post' })),
    );
    const { built } = await cimdApp();

    const res = await startAuthorize(built);

    expect(res.status).toBe(400);
    expect(res.body.error_description).toMatch(/'token_endpoint_auth_method'/);
  });

  it('drops a scope the host does not offer rather than failing the whole document', async () => {
    fetchStub.mockResolvedValue(
      jsonResponse(metadataDocument({ scope: 'openid contacts.read billing.admin' })),
    );
    const { built } = await cimdApp();

    const res = await startAuthorize(built);
    expect(res.status).toBe(302);

    const stored = await built.ctx.models.Client.findOne({ clientId: CLIENT_ID }).lean();
    expect([...(stored?.allowedScopes ?? [])].sort()).toEqual(['contacts.read', 'openid']);
  });

  it('narrows a document scope by clientIdMetadata.allowedScopes', async () => {
    fetchStub.mockResolvedValue(jsonResponse(metadataDocument()));
    const { built } = await cimdApp({ allowedScopes: ['openid'] });

    const res = await startAuthorize(built, { scope: 'openid' });
    expect(res.status).toBe(302);

    const stored = await built.ctx.models.Client.findOne({ clientId: CLIENT_ID }).lean();
    expect(stored?.allowedScopes).toEqual(['openid']);
  });

  // ── client authentication ────────────────────────────────────────────────

  it('refuses a public client that presents a client secret', async () => {
    fetchStub.mockResolvedValue(jsonResponse(metadataDocument()));
    const { built } = await cimdApp();
    const { code, verifier } = await authorizeToCode(built);

    const tokens = await request(built.app)
      .post('/oauth/token')
      .type('form')
      .send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: CIMD_REDIRECT,
        code_verifier: verifier,
        client_id: CLIENT_ID,
        client_secret: 'a-secret-this-client-does-not-have',
      });

    expect(tokens.status).toBe(401);
    expect(tokens.body.error).toBe('invalid_client');
  });

  it('refuses a confidential client that omits its secret, so it cannot downgrade to public', async () => {
    const { built } = await cimdApp();
    const confidential = await built.clients.create({
      name: 'Manual',
      redirectUris: ['https://client.test/cb'],
      allowedScopes: ['openid'],
    });

    const tokens = await request(built.app)
      .post('/oauth/token')
      .type('form')
      .send({
        grant_type: 'authorization_code',
        code: 'irrelevant',
        redirect_uri: 'https://client.test/cb',
        code_verifier: 'x'.repeat(43),
        client_id: confidential.clientId,
      });

    // Identical to every other client-auth failure — never an oracle for
    // whether that id names a public or a confidential client.
    expect(tokens.status).toBe(401);
    expect(tokens.body).toEqual({
      error: 'invalid_client',
      error_description: 'client authentication failed',
    });
  });

  it('refuses a CIMD authorization with no PKCE challenge, the only stand-in for a secret', async () => {
    fetchStub.mockResolvedValue(jsonResponse(metadataDocument()));
    const { built } = await cimdApp();

    const res = await startAuthorize(built, { challenge: null });

    // Redirectable: client_id and redirect_uri are both proven by this point.
    expect(res.status).toBe(302);
    expect(res.location.startsWith(CIMD_REDIRECT)).toBe(true);
    expect(param(res.location, 'error')).toBe('invalid_request');
    expect(param(res.location, 'error_description')).toMatch(/code_challenge/);
  });

  it('refuses to rotate a secret on a public client instead of silently doing nothing', async () => {
    fetchStub.mockResolvedValue(jsonResponse(metadataDocument()));
    const { built } = await cimdApp();
    await startAuthorize(built);

    await expect(built.clients.rotateSecret(CLIENT_ID)).rejects.toThrow(/public client/);
  });

  // ── caching ──────────────────────────────────────────────────────────────

  it('does not re-fetch a metadata document inside the cache TTL', async () => {
    fetchStub.mockResolvedValue(jsonResponse(metadataDocument()));
    const { built } = await cimdApp();

    await startAuthorize(built);
    await startAuthorize(built);

    expect(fetchStub).toHaveBeenCalledTimes(1);
  });

  it('does not re-fetch a failing metadata URL inside the negative cache window', async () => {
    fetchStub.mockResolvedValue(new Response('nope', { status: 500 }));
    const { built } = await cimdApp();

    const first = await startAuthorize(built);
    const second = await startAuthorize(built);

    expect(first.status).toBe(400);
    expect(second.status).toBe(400);
    // Without this the authorization endpoint is a traffic amplifier: one
    // replayed client_id becomes unbounded outbound load on a third party.
    expect(fetchStub).toHaveBeenCalledTimes(1);
  });

  it('reuses the cached registration when the document answers 304', async () => {
    fetchStub.mockResolvedValueOnce(
      new Response(JSON.stringify(metadataDocument()), {
        status: 200,
        headers: { 'content-type': 'application/json', etag: 'W/"v1"' },
      }),
    );
    const { built } = await cimdApp({ cacheTtlMs: 1 });

    await startAuthorize(built);
    fetchStub.mockResolvedValueOnce(new Response(null, { status: 304 }));
    const second = await startAuthorize(built);

    expect(second.status).toBe(302);
    expect(fetchStub).toHaveBeenCalledTimes(2);
    expect((fetchStub.mock.calls[1]?.[1] as RequestInit).headers)
      .toMatchObject({ 'if-none-match': 'W/"v1"' });
  });

  // ── revocation ───────────────────────────────────────────────────────────

  it('keeps a disabled CIMD client disabled across a re-fetch', async () => {
    fetchStub.mockResolvedValue(jsonResponse(metadataDocument()));
    // A TTL of 1ms means the next authorization is a guaranteed cache miss, so
    // the only thing that can keep this client disabled is the status check
    // running before the fetch — not the cache accidentally hiding it.
    const { built } = await cimdApp({ cacheTtlMs: 1 });

    await startAuthorize(built);
    expect(fetchStub).toHaveBeenCalledTimes(1);

    await built.clients.disable(CLIENT_ID);

    const afterDisable = await startAuthorize(built);
    expect(afterDisable.status).toBe(400);
    expect(afterDisable.body.error).toBe('invalid_client');
    expect(fetchStub).toHaveBeenCalledTimes(1);

    const stored = await built.ctx.models.Client.findOne({ clientId: CLIENT_ID }).lean();
    expect(stored?.status).toBe('disabled');
  });

  it('lists a CIMD client through the admin API alongside manual registrations', async () => {
    fetchStub.mockResolvedValue(jsonResponse(metadataDocument()));
    const { built } = await cimdApp();
    await built.clients.create({
      name: 'Manual',
      redirectUris: ['https://client.test/cb'],
      allowedScopes: ['openid'],
    });
    await startAuthorize(built);

    const { items } = await built.clients.list();
    const byRegistration = Object.fromEntries(items.map((c) => [c.registration, c]));

    expect(byRegistration.manual?.type).toBe('confidential');
    expect(byRegistration.cimd?.type).toBe('public');
    expect(byRegistration.cimd?.clientId).toBe(CLIENT_ID);
    expect(byRegistration.cimd?.metadataUrl).toBe(CLIENT_ID);
  });

  // ── off by default ───────────────────────────────────────────────────────

  it('makes no outbound request for a URL client_id when CIMD is disabled', async () => {
    const state: Session = { user: testUser() };
    const built = await buildApp({ session: state });

    const res = await startAuthorize(built);

    // Indistinguishable from any other unknown client — same status, same
    // error code, same single database read.
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_client');
    expect(fetchStub).not.toHaveBeenCalled();
  });

  it('advertises `none` and the CIMD flag only when CIMD is enabled', async () => {
    const off = await buildApp();
    const offMeta = await request(off.app).get('/.well-known/oauth-authorization-server');
    expect(offMeta.body.token_endpoint_auth_methods_supported).not.toContain('none');
    expect(offMeta.body.client_id_metadata_document_supported).toBeUndefined();

    const { built } = await cimdApp();
    const onMeta = await request(built.app).get('/.well-known/oauth-authorization-server');
    expect(onMeta.body.token_endpoint_auth_methods_supported).toContain('none');
    expect(onMeta.body.client_id_metadata_document_supported).toBe(true);
  });

  it('refuses to boot with CIMD enabled and no allowedHosts', async () => {
    await expect(buildApp({
      config: { clientIdMetadata: { enabled: true, allowedHosts: [] } },
    })).rejects.toThrow(/allowedHosts/);
  });

  it('refuses an allowedHosts entry written as a URL or a wildcard', async () => {
    await expect(buildApp({
      config: { clientIdMetadata: { enabled: true, allowedHosts: ['https://claude.ai/'] } },
    })).rejects.toThrow(/host, not a URL/);

    await expect(buildApp({
      config: { clientIdMetadata: { enabled: true, allowedHosts: ['*.claude.ai'] } },
    })).rejects.toThrow(/wildcard/);
  });
});
