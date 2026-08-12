import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import {
  REDIRECT_URI,
  TEST_ISSUER,
  TEST_RESOURCE,
  authorize,
  buildApp,
  clearDb,
  createPublicTestClient,
  createTestClient,
  exchange,
  param,
  pkce,
  startDb,
  stopDb,
  testUser,
  type BuiltApp,
} from './helpers.js';
import { CLAUDE_CODE_REDIRECT_URIS } from '../src/server/vendors.js';

/**
 * What the live clients require of this server.
 *
 * Every assertion here was learned by connecting a real product to a real
 * deployment — Claude on the web, Claude Code, and Codex CLI — rather than by
 * reading a spec. They are all satisfied today; the suite exists so that a
 * regression is caught here instead of by a partner, because each of these
 * fails in a way that looks like the client's bug from the server's side.
 *
 * Tests for requirements that already had one live where they belong and are
 * NOT duplicated here:
 *
 *   `code_challenge_methods_supported: ["S256"]`   test/flow.test.ts
 *   form-encoded POST /token with no host parser   test/flow.test.ts
 *   `WWW-Authenticate` carrying `resource_metadata` test/protect.test.ts
 *   CIMD's two metadata flags advertised together   test/cimd.test.ts
 */
beforeAll(startDb);
afterAll(stopDb);

describe('vendor requirements', () => {
  let built: BuiltApp;

  beforeEach(async () => {
    await clearDb();
    built = await buildApp({ session: { user: testUser() } });
  });

  // -- Codex CLI: a public client registered by hand --------------------------

  it('Codex CLI: a manually-registered public client completes authorization_code with PKCE and no client secret', async () => {
    // `codex mcp login` takes three settings — `oauth_client_id`,
    // `oauth_resource`, `bearer_token_env_var` — and there is no
    // `oauth_client_secret` among them. It cannot use CIMD either: CIMD needs
    // the CLIENT to publish a metadata document and Codex publishes none, so it
    // falls through to dynamic registration and stops with "Dynamic client
    // registration not supported". `clients.create({ type: 'public' })` is the
    // only path that exists for it.
    const codex = await createPublicTestClient(built, { name: 'Codex CLI' });
    expect(codex.type).toBe('public');
    expect(codex.clientSecret).toBeUndefined();
    expect(codex.client.type).toBe('public');
    expect(codex.client.registration).toBe('manual');

    // Not withheld from the return value — never written. A digest in the row
    // is a credential the token endpoint refuses but an operator could still
    // find and try to use.
    const doc = await built.ctx.models.Client.findOne({ clientId: codex.clientId }).lean();
    expect(doc!.secrets).toEqual([]);

    // `authorize()` sends `Basic base64(client_id:)` — an empty password, which
    // is the wire form of `token_endpoint_auth_method=none`.
    const flow = await authorize(built, codex, { scope: 'openid contacts.read' });
    expect(flow.tokens.access_token).toBeTypeOf('string');
    expect(flow.tokens.refresh_token).toBeTypeOf('string');
    expect(flow.tokens.id_token).toBeTypeOf('string');
  });

  it('Codex CLI: refuses that same public client the moment it presents a secret', async () => {
    // The symmetric half of the rule in `authenticateClient`. A secret sent for
    // a client that has none means the caller believes something false about
    // this registration, and the charitable reading — a copy-pasted
    // confidential config — still ends with an operator who thinks a secret is
    // protecting them.
    const codex = await createPublicTestClient(built, { name: 'Codex CLI' });
    const pair = pkce();

    const authRes = await request(built.app).get('/oauth/authorize').query({
      response_type: 'code',
      client_id: codex.clientId,
      redirect_uri: REDIRECT_URI,
      scope: 'openid',
      resource: TEST_RESOURCE,
      code_challenge: pair.challenge,
      code_challenge_method: 'S256',
    });
    const requestId = param(authRes.headers.location!, 'request_id')!;
    const decision = await request(built.app)
      .post(`/oauth/consent/${requestId}`)
      .send({ approve: true });
    const code = param(String(decision.body.redirectTo), 'code')!;

    const res = await request(built.app)
      .post('/oauth/token')
      .type('form')
      .auth(codex.clientId, 'a-secret-this-client-never-had')
      .send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: pair.verifier,
      });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_client');
  });

  it('Codex CLI: refuses to rotate a secret on a hand-registered public client rather than printing one', async () => {
    // `rotateSecret` gates on `type`, not on `registration`, so the CIMD case
    // and this one are the same check — asserted here anyway because the manual
    // path is the one a provisioning script reaches for.
    const codex = await createPublicTestClient(built, { name: 'Codex CLI' });
    await expect(built.clients.rotateSecret(codex.clientId)).rejects.toThrow(/public client/);
  });

  it('Codex CLI: carries a public client through consent, /me/grants and disable() unchanged', async () => {
    // Everything downstream of `/token` is client-type agnostic — `type` is
    // read in `authenticateClient` and `rotateSecret` and nowhere else. That is
    // a claim about code that could quietly stop being true, so it is asserted
    // rather than assumed.
    const codex = await createPublicTestClient(built, {
      name: 'Codex CLI',
      branding: { publisher: 'OpenAI' },
    });
    const flow = await authorize(built, codex, { scope: 'openid contacts.read' });

    // The consent payload is a published contract and names no client type.
    expect(flow.consent.client).toEqual({ name: 'Codex CLI', publisher: 'OpenAI' });

    const listed = await request(built.app).get('/oauth/me/grants');
    expect(listed.status).toBe(200);
    expect(listed.body.items).toHaveLength(1);
    expect(listed.body.items[0].client.clientId).toBe(codex.clientId);

    const { grantsRevoked, tokensRevoked } = await built.clients.disable(codex.clientId);
    expect(grantsRevoked).toBe(1);
    expect(tokensRevoked).toBeGreaterThan(0);

    // A disabled client cannot refresh, whatever it authenticates with.
    const refused = await exchange(built, codex, {
      grant_type: 'refresh_token',
      refresh_token: String(flow.tokens.refresh_token),
    });
    expect(refused.status).toBe(401);
    expect(refused.body.error).toBe('invalid_client');
  });

  // -- Claude Code: RFC 8252 §7.3, the loopback port varies -------------------

  it('Claude Code: completes a whole flow from an ephemeral loopback port against the portless registration it ships with', async () => {
    // Claude Code registers `http://localhost/callback` and
    // `http://127.0.0.1/callback`, then binds an ephemeral port per session and
    // connects from it. Byte-exact comparison makes every authorization an
    // unredirectable `invalid_request` that reads as the client's bug, and
    // nothing about the failure points back at the registration. Verified
    // working against a live deployment at `http://localhost:3118/callback`.
    const claudeCode = await createTestClient(built, {
      name: 'Claude Code',
      redirectUris: [...CLAUDE_CODE_REDIRECT_URIS],
    });

    // Both registered hosts, both with a port the registration never named.
    // `localhost` and `127.0.0.1` stay separate registrations on purpose, so a
    // client that wants both has to register both — which Claude Code does.
    for (const ephemeral of ['http://localhost:3118/callback', 'http://127.0.0.1:54321/callback']) {
      const pair = pkce();
      const authRes = await request(built.app).get('/oauth/authorize').query({
        response_type: 'code',
        client_id: claudeCode.clientId,
        redirect_uri: ephemeral,
        scope: 'openid contacts.read',
        resource: TEST_RESOURCE,
        code_challenge: pair.challenge,
        code_challenge_method: 'S256',
      });
      expect(authRes.status).toBe(302);

      const requestId = param(authRes.headers.location!, 'request_id')!;
      const decision = await request(built.app)
        .post(`/oauth/consent/${requestId}`)
        .send({ approve: true });
      expect(decision.status).toBe(200);
      // The code comes back to the port the browser actually used, not to the
      // registered one — the redirect is rebuilt from the request.
      expect(String(decision.body.redirectTo).startsWith(ephemeral)).toBe(true);

      // And `/token` has to agree with `/authorize`, or the flow dies one step
      // later than it used to and looks like a PKCE failure instead.
      const tokens = await exchange(built, claudeCode, {
        grant_type: 'authorization_code',
        code: param(String(decision.body.redirectTo), 'code')!,
        redirect_uri: ephemeral,
        code_verifier: pair.verifier,
      });
      expect(tokens.status).toBe(200);
      expect(tokens.body.access_token).toBeTypeOf('string');
    }
  });

  // -- the error code clients switch on to re-authenticate --------------------

  it('answers invalid_grant, not invalid_request, for a refresh token that is already dead', async () => {
    // Clients branch on this code: `invalid_grant` means "start a new
    // authorization", anything else means "something is broken, stop". A dead
    // refresh token reported as `invalid_request` strands the user in a
    // connector that will never reconnect itself.
    const client = await createTestClient(built);
    const flow = await authorize(built, client);
    const refresh = String(flow.tokens.refresh_token);

    const rotated = await exchange(built, client, { grant_type: 'refresh_token', refresh_token: refresh });
    expect(rotated.status).toBe(200);

    // The spent one, replayed.
    const replayed = await exchange(built, client, { grant_type: 'refresh_token', refresh_token: refresh });
    expect(replayed.status).toBe(400);
    expect(replayed.body.error).toBe('invalid_grant');

    // And one this server never issued at all.
    const unknown = await exchange(built, client, {
      grant_type: 'refresh_token',
      refresh_token: 'never-issued-anything',
    });
    expect(unknown.status).toBe(400);
    expect(unknown.body.error).toBe('invalid_grant');
  });

  it('rotates the refresh token on every refresh, including for a public client that has no other protection', async () => {
    // Rotation plus reuse detection is the ONLY thing standing behind a public
    // client's refresh token: there is no secret an attacker would also need.
    // A server that reissued the same value would hand a leaked token an
    // unlimited lifetime and nothing would ever notice.
    const codex = await createPublicTestClient(built, { name: 'Codex CLI' });
    const flow = await authorize(built, codex);

    let current = String(flow.tokens.refresh_token);
    const seen = new Set([current]);
    for (let i = 0; i < 3; i += 1) {
      const res = await exchange(built, codex, { grant_type: 'refresh_token', refresh_token: current });
      expect(res.status).toBe(200);
      const next = String(res.body.refresh_token);
      expect(seen.has(next)).toBe(false);
      seen.add(next);
      current = next;
    }

    // The first token in the family, replayed after three rotations, kills the
    // family rather than working.
    const reuse = await exchange(built, codex, {
      grant_type: 'refresh_token',
      refresh_token: String(flow.tokens.refresh_token),
    });
    expect(reuse.status).toBe(400);
    expect(reuse.body.error).toBe('invalid_grant');

    const dead = await exchange(built, codex, { grant_type: 'refresh_token', refresh_token: current });
    expect(dead.status).toBe(400);
    expect(dead.body.error).toBe('invalid_grant');
  });

  // -- what a client checks before it starts ---------------------------------

  it('advertises `none` for a hand-registered public client only when CIMD is on, which Codex does not need', async () => {
    // The gap worth naming: `token_endpoint_auth_methods_supported` is keyed to
    // CIMD, not to whether any public client is registered. A public client
    // that reads the metadata and refuses to proceed without `none` therefore
    // needs CIMD enabled too. Codex does not read it — it is configured with a
    // `client_id` and posts — so this is recorded rather than changed.
    const off = await request(built.app).get('/.well-known/oauth-authorization-server');
    expect(off.body.token_endpoint_auth_methods_supported).not.toContain('none');
    expect(off.body.issuer).toBe(TEST_ISSUER);

    const codex = await createPublicTestClient(built, { name: 'Codex CLI' });
    const flow = await authorize(built, codex);
    // Unadvertised, and still accepted. The metadata is a hint to clients that
    // read it, never the gate.
    expect(flow.tokens.access_token).toBeTypeOf('string');
  });
});
