import express from 'express';
import mongoose from 'mongoose';
import type { NextFunction, Request, RequestHandler, Response, Router } from 'express';
import { OAuthError, RedirectableAuthError, invalidRequest, unsupportedGrantType, wrap } from '../errors.js';
import { rateLimit } from '../rate-limit.js';
import { createKeyManager } from '../keys.js';
import { authenticateClient } from '../services/admin.js';
import {
  consentRedirectUrl,
  createAuthorizationRequest,
  loginRedirectUrl,
  validateAuthorizationRequest,
} from '../services/authorize.js';
import { decideConsent, getConsentPayload } from '../services/consent.js';
import { buildIdToken, buildUserInfo } from '../services/oidc.js';
import {
  consumeCode,
  introspectAccessToken,
  issueForCode,
  revokeToken,
  rotateRefresh,
} from '../services/tokens.js';
import type { ResolvedContext } from '../config.js';
import type { PackageUser } from '../../../types/index.js';

/**
 * The protocol router.
 *
 * **Three trust bands share this mount, and each handler states its own.**
 * There is deliberately no shared "authenticated" middleware here, because the
 * bands authenticate different principals with different credentials:
 *
 *   host session   GET /authorize, /consent/:id, POST /consent/:id, /me/grants
 *                  → `ctx.resolveUser(req)` — a browser cookie the HOST issued
 *   client         POST /token, POST /revoke
 *                  → `authenticateClient` — a client id and secret
 *   bearer         GET /userinfo
 *                  → an access token this server minted
 *   public         GET /jwks
 *
 * A `router.use(requireSomething)` covering all of them is how a session cookie
 * ends up being sufficient to exchange somebody else's authorization code.
 */
export function createOAuthRouter(ctx: ResolvedContext): Router {
  const router = express.Router();
  const w = (h: Parameters<typeof wrap>[1]): RequestHandler => wrap(ctx.logger, h);
  const keys = createKeyManager(ctx);

  /**
   * The sanctioned body-parser exception — standards/traps.md #5.
   *
   * A library router must not mount a body parser, because it silently changes
   * parsing for everything mounted after it. RFC 6749 §4.1.3 nonetheless
   * REQUIRES `/token` (and RFC 7009 `/revoke`) to accept
   * `application/x-www-form-urlencoded`, and hosts mount `express.json()` only
   * — so a client following the spec exactly would get "missing grant_type"
   * forever. Route-level, on these two routes and nowhere else, never
   * `router.use()`. `test/flow.test.ts` asserts a form POST works on an app
   * that never mounted a urlencoded parser.
   */
  const form = express.urlencoded({ extended: false, limit: '10kb' });

  const ipKey = (req: Request): string => req.ip ?? 'unknown';
  const clientKey = (req: Request): string => clientIdFromRequest(req) ?? ipKey(req);
  const cors = corsMiddleware(ctx);

  /**
   * Fail closed until `syncIndexes()` has resolved — but only on the routes
   * that WRITE.
   *
   * `syncIndexes()` is host-called, and the reported integration calls it inside
   * the `app.listen` callback, after mounting: even done correctly there is a
   * window in which these routes would serve. The unique partial index on grants
   * is what stops one user holding two live grants for one client, permanently,
   * and mongoose builds indexes in the background — so a write that lands in
   * that window is not recoverable later.
   *
   * Read-only surfaces (discovery, `/jwks`, `/userinfo`, `protect()`) are
   * deliberately NOT gated. They create nothing that could violate an index, and
   * taking them down would turn a boot-order mistake into a total outage of an
   * API that was already serving.
   */
  const requireIndexes: RequestHandler = w((_req, _res, next) => {
    if (ctx.indexes.ready) return next();
    // Thrown rather than passed to `next(err)`: `wrap` is what renders JSON, and
    // Express's default handler answers HTML — traps #6.
    throw new OAuthError(
      503,
      'server_error',
      'This authorization server is not ready: `syncIndexes()` has not resolved yet. '
      + 'Await `oauth.syncIndexes()` at boot, before mounting the routers.',
    );
  });

  // -------------------------------------------------------------------------
  // Literal paths FIRST. `/consent/:requestId` and `/me/grants/:id` are the
  // parameter routes in this file and they live at the bottom, because a
  // parameter segment will happily swallow a literal declared after it. Keep
  // the test named after that failure so nobody reorders this file back.
  // See standards/traps.md #4.
  // -------------------------------------------------------------------------

  // ---- host-session band ----

  router.get(
    '/authorize',
    requireIndexes,
    rateLimit(ctx, 'authorize', ipKey),
    w(async (req, res) => {
      let validated;
      try {
        validated = await validateAuthorizationRequest(ctx, req.query as Record<string, unknown>);
      } catch (err) {
        // The redirect-vs-render split is a security boundary, not formatting.
        // A RedirectableAuthError means `client_id` and `redirect_uri` were both
        // validated against the registration, so the client is a proven-safe
        // place to send the error. An UnredirectableError means they were not,
        // and redirecting anyway is the open-redirect hole — it falls through
        // to `wrap`, which renders JSON.
        if (err instanceof RedirectableAuthError) {
          return res.redirect(302, err.toRedirect(ctx.issuer));
        }
        throw err;
      }

      const user = await ctx.resolveUser(req);
      if (!user) {
        // `/authorize` is a package route a signed-out user lands on directly,
        // so the sign-in bounce is ours to perform — standards/adapters.md.
        const to = loginRedirectUrl(ctx, `${ctx.issuer}${req.originalUrl}`);
        if (!to) {
          // No `loginUrl` configured. Rendering the error is the only honest
          // answer; redirecting to `/authorize` itself would loop forever.
          throw new OAuthError(
            401,
            'login_required',
            'No user is signed in and no `loginUrl` is configured to send them to',
          );
        }
        return res.redirect(302, to);
      }

      const request = await createAuthorizationRequest(ctx, validated, user);
      return res.redirect(302, consentRedirectUrl(ctx, request.requestId));
    }),
  );

  router.get(
    '/me/grants',
    w(async (req, res) => {
      const user = await requireUser(ctx, req);
      // Capped and paginated even though a realistic user has under twenty —
      // the cap is what stops a host with one pathological account from
      // discovering the limit in production. See standards/traps.md #18.
      const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 100);
      const skip = Math.max(Number(req.query.skip) || 0, 0);

      const grants = await ctx.models.Grant
        .find({ userId: user.id, revokedAt: null })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean();

      const clients = await ctx.models.Client
        .find({ clientId: { $in: grants.map((g) => g.clientId) } })
        .lean();
      const byId = new Map(clients.map((c) => [c.clientId, c]));

      res.json({
        limit,
        items: grants.map((g) => ({
          // The grant id is the ONLY identifier that leaves: the DELETE below
          // needs it. No user id, no client _id, no token ids.
          id: String(g._id),
          client: {
            clientId: g.clientId,
            name: byId.get(g.clientId)?.name ?? g.clientId,
            branding: byId.get(g.clientId)?.branding ?? {},
          },
          scopes: g.scopes.map((id) => ctx.scopeIndex.get(id) ?? { id, label: id }),
          ...(g.contextId ? { contextId: g.contextId } : {}),
          createdAt: g.createdAt,
          lastUsedAt: g.lastUsedAt,
        })),
      });
    }),
  );

  // ---- client-authenticated band ----

  router.post(
    '/token',
    cors,
    requireIndexes,
    form,
    rateLimit(ctx, 'token', clientKey),
    w(async (req, res) => {
      // RFC 6749 §5.1 — a token response must never be cached. Set before any
      // branch so an error answer carries it too.
      res.set('Cache-Control', 'no-store');
      res.set('Pragma', 'no-cache');

      const client = await authenticateClient(ctx, req);
      const body = (req.body ?? {}) as Record<string, unknown>;
      const grantType = str(body.grant_type);

      if (grantType === 'authorization_code') {
        const code = await consumeCode(ctx, str(body.code), {
          clientId: client.clientId,
          redirectUri: str(body.redirect_uri),
          codeVerifier: str(body.code_verifier),
        });
        const issued = await issueForCode(ctx, code);
        const idToken = issued.scopes.includes('openid')
          ? await buildIdToken(ctx, keys, {
            client,
            user: await ctx.loadUser(issued.userId),
            scopes: issued.scopes,
            contextId: issued.contextId,
            nonce: code.nonce,
            authTime: code.authTime,
            accessToken: issued.accessToken,
          })
          : undefined;
        return res.json(tokenResponse(issued, idToken));
      }

      if (grantType === 'refresh_token') {
        const issued = await rotateRefresh(ctx, str(body.refresh_token), {
          clientId: client.clientId,
          scope: body.scope === undefined ? undefined : str(body.scope),
          resources: list(body.resource),
        });
        // No `nonce` on a refresh: it belongs to the authorization request that
        // is now long gone, and replaying it would let a client bind a fresh
        // id_token to a stale request.
        const idToken = issued.scopes.includes('openid')
          ? await buildIdToken(ctx, keys, {
            client,
            user: await ctx.loadUser(issued.userId),
            scopes: issued.scopes,
            contextId: issued.contextId,
            accessToken: issued.accessToken,
          })
          : undefined;
        return res.json(tokenResponse(issued, idToken));
      }

      throw unsupportedGrantType(
        `'${grantType}' is not supported. This server issues authorization_code and refresh_token only.`,
      );
    }),
  );

  router.post(
    '/revoke',
    cors,
    form,
    rateLimit(ctx, 'token', clientKey),
    w(async (req, res) => {
      res.set('Cache-Control', 'no-store');
      const client = await authenticateClient(ctx, req);
      const body = (req.body ?? {}) as Record<string, unknown>;
      await revokeToken(ctx, str(body.token), client.clientId);
      // RFC 7009 §2.2 — an unknown, expired or already-revoked token is a 200.
      // The client's goal ("this token must not work") is satisfied either way,
      // and answering 400 turns revocation into a token-existence oracle.
      res.status(200).json({});
    }),
  );

  // ---- bearer band ----

  router.get(
    '/userinfo',
    w(async (req, res) => {
      const raw = /^Bearer +([^\s]+)$/i.exec(req.headers.authorization ?? '')?.[1];
      if (!raw) throw bearerChallenge('invalid_request', 'A bearer access token is required');

      const token = await introspectAccessToken(ctx, raw);
      if (!token) throw bearerChallenge('invalid_token', 'The access token is expired, revoked or unknown');
      if (!token.scopes.includes('openid')) {
        throw new OAuthError(403, 'insufficient_scope', 'The `openid` scope is required', {
          headers: { 'WWW-Authenticate': 'Bearer error="insufficient_scope", scope="openid"' },
        });
      }

      const client = await ctx.models.Client.findOne({ clientId: token.clientId });
      if (!client) throw bearerChallenge('invalid_token', 'The client this token was issued to no longer exists');

      res.set('Cache-Control', 'no-store');
      res.json(await buildUserInfo(ctx, {
        client,
        user: await ctx.loadUser(token.userId),
        scopes: token.scopes,
        contextId: token.contextId,
      }));
    }),
  );

  // ---- public ----

  router.get('/jwks', w(async (_req, res) => {
    // Public keys, and public keys only. Cacheable on purpose: a client
    // refetching JWKS on every token validation is a self-inflicted DoS.
    res.set('Cache-Control', 'public, max-age=300');
    res.json(await keys.jwks());
  }));

  if (ctx.cors.tokenEndpoint) {
    router.options('/token', cors, (_req, res) => { res.sendStatus(204); });
    router.options('/revoke', cors, (_req, res) => { res.sendStatus(204); });
  }

  // ---- parameter paths LAST ----

  router.get(
    '/consent/:requestId',
    rateLimit(ctx, 'consent', ipKey),
    w(async (req, res) => {
      const user = await requireUser(ctx, req);
      res.json(await getConsentPayload(ctx, pathParam(req, 'requestId'), user));
    }),
  );

  router.post(
    '/consent/:requestId',
    requireIndexes,
    rateLimit(ctx, 'consent', ipKey),
    w(async (req, res) => {
      const user = await requireUser(ctx, req);
      // The host mounts `express.json()`; this band is the host's own fetch
      // from its consent page, not a spec-mandated form post.
      const body = (req.body ?? {}) as Record<string, unknown>;
      if (typeof body.approve !== 'boolean') {
        throw invalidRequest('`approve` must be a boolean');
      }
      res.json(await decideConsent(ctx, pathParam(req, 'requestId'), user, {
        approve: body.approve,
        scopes: Array.isArray(body.scopes) ? body.scopes.map(String) : undefined,
        contextId: body.contextId === undefined ? undefined : String(body.contextId),
      }));
    }),
  );

  router.delete(
    '/me/grants/:id',
    w(async (req, res) => {
      const user = await requireUser(ctx, req);
      const id = pathParam(req, 'id');
      // Validate before querying: an unparseable id is a 404, not a cast error
      // surfacing as a 500.
      if (!mongoose.Types.ObjectId.isValid(id)) {
        throw new OAuthError(404, 'not_found', 'No such grant');
      }

      // Scoped to this user's own grants. Without the `userId` term this route
      // revokes anybody's grant for anyone who can guess an id.
      const grant = await ctx.models.Grant.findOneAndUpdate(
        { _id: id, userId: user.id, revokedAt: null },
        { $set: { revokedAt: new Date(), revokedBy: 'user' } },
      );
      if (!grant) throw new OAuthError(404, 'not_found', 'No such grant');

      const { modifiedCount } = await ctx.models.Token.updateMany(
        { grantId: grant._id, revokedAt: null },
        { $set: { revokedAt: new Date() } },
      );
      ctx.track({ type: 'oauth.grant_revoked', userId: user.id, clientId: grant.clientId, grantId: String(grant._id) });
      void ctx.audit({ type: 'oauth.grant_revoked', actor: 'user', userId: user.id, clientId: grant.clientId, grantId: grant._id });
      res.json({ revoked: true, tokensRevoked: modifiedCount ?? 0 });
    }),
  );

  return router;
}

// ---------------------------------------------------------------------------

async function requireUser(ctx: ResolvedContext, req: Request): Promise<PackageUser> {
  const user = await ctx.resolveUser(req);
  if (!user) {
    throw new OAuthError(401, 'login_required', 'No user is signed in for this request');
  }
  return user;
}

function bearerChallenge(code: string, description: string): OAuthError {
  return new OAuthError(401, code, description, {
    headers: { 'WWW-Authenticate': `Bearer error="${code}", error_description="${description}"` },
  });
}

interface IssuedLike {
  accessToken: string;
  refreshToken?: string;
  expiresIn: number;
  scopes: string[];
}

function tokenResponse(issued: IssuedLike, idToken?: string): Record<string, unknown> {
  return {
    access_token: issued.accessToken,
    token_type: 'Bearer',
    expires_in: issued.expiresIn,
    ...(issued.refreshToken ? { refresh_token: issued.refreshToken } : {}),
    scope: issued.scopes.join(' '),
    // Only when `openid` was granted. Minting one unasked hands a client an
    // identity assertion it never requested consent for.
    ...(idToken ? { id_token: idToken } : {}),
  };
}

/**
 * A path parameter as a string.
 *
 * Express 5's types widen `req.params` values to `string | string[]` because a
 * wildcard segment can repeat. None of the parameters here can, so the coercion
 * is a type narrowing rather than a behavioural one.
 */
function pathParam(req: Request, name: string): string {
  const value = (req.params as Record<string, string | string[] | undefined>)[name];
  return Array.isArray(value) ? (value[0] ?? '') : (value ?? '');
}

/** A form field, coerced to the string the services expect. */
function str(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

/** `resource` may legally repeat (RFC 8707 §2), so it is always a list here. */
function list(value: unknown): string[] | undefined {
  if (value === undefined) return undefined;
  return Array.isArray(value) ? value.map(String) : [String(value)];
}

/** The client id as it arrives — Basic credentials or a form field. */
function clientIdFromRequest(req: Request): string | null {
  const header = req.headers.authorization;
  if (header?.startsWith('Basic ')) {
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    const id = decoded.split(':')[0];
    if (id) return decodeURIComponent(id);
  }
  const body = (req.body ?? {}) as Record<string, unknown>;
  return typeof body.client_id === 'string' ? body.client_id : null;
}

/**
 * CORS on `/token` and `/revoke`, off by default.
 *
 * v1 has no public clients, so a browser has no business calling either — this
 * ships as a documented flag rather than an assumption. When it is off the
 * middleware is a passthrough, not a header-stripper: the host may have its own
 * CORS layer and this router does not get to override it.
 */
function corsMiddleware(ctx: ResolvedContext): RequestHandler {
  if (!ctx.cors.tokenEndpoint) return (_req, _res, next) => next();

  const allowed = new Set(ctx.cors.origins);
  return (req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin;
    if (allowed.size === 0) {
      res.set('Access-Control-Allow-Origin', '*');
    } else if (origin && allowed.has(origin)) {
      res.set('Access-Control-Allow-Origin', origin);
      // Without `Vary` a shared cache can hand one origin another's answer.
      res.set('Vary', 'Origin');
    }
    res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.set('Access-Control-Max-Age', '600');
    next();
  };
}
