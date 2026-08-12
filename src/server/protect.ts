import type { Request, RequestHandler, Response } from 'express';
import { wrap } from './errors.js';
import { protectedResourceMetadataUrl } from './routes/discovery.js';
import { introspectAccessToken } from './services/tokens.js';
import type { ResolvedContext } from './config.js';
import type { OAuthHostInstance, ProtectOptions } from '../../types/index.js';

/**
 * The resource-server middleware.
 *
 *   app.use('/mcp', oauth.protect('contacts.read'), mcpRouter)
 *
 * Two things in here are load-bearing beyond "check a token":
 *
 * 1. **The `WWW-Authenticate` challenge carries `resource_metadata`.** That is
 *    how an MCP client that has never heard of this server discovers where to
 *    authorize: it calls the API, gets a 401, reads the metadata URL out of the
 *    challenge, and walks from there to the authorization server. Without that
 *    parameter the whole discovery chain is a dead end and the only fix is
 *    out-of-band configuration. It is the single most important line here.
 *
 * 2. **Audience is enforced, not merely recorded.** A token minted for another
 *    resource is rejected even though it is perfectly valid — the confused-deputy
 *    defense RFC 8707 and the MCP authorization spec both require. Skipping it
 *    turns every resource behind one issuer into a proxy for all the others.
 */
export function createProtect(ctx: ResolvedContext): OAuthHostInstance['protect'] {
  const declared = new Set(ctx.resources.map((r) => r.id));

  return function protect(scopes?: string | string[], opts: ProtectOptions = {}): RequestHandler {
    const required = scopes === undefined ? [] : Array.isArray(scopes) ? scopes : [scopes];
    const resource = opts.resource ?? ctx.resources[0]!.id;
    const mode = opts.mode ?? 'all';

    // Fail at mount, not on the first request. A typo'd resource here means
    // every token is the wrong audience, and the symptom (universal 401s) does
    // not point at the guard that caused it.
    if (!declared.has(resource)) {
      throw new TypeError(
        `oauth-host: protect({ resource: '${resource}' }) is not one of the configured resources `
        + `(${[...declared].join(', ')})`,
      );
    }
    for (const s of required) {
      if (!ctx.scopeIndex.has(s)) {
        throw new TypeError(`oauth-host: protect() requires scope '${s}', which is not in the scope catalog`);
      }
    }

    const metadataUrl = protectedResourceMetadataUrl(ctx.issuer, resource);

    return wrap(ctx.logger, async (req, res, next) => {
      const raw = bearerFromHeader(req);
      // RFC 6750 §3.1: a request with no credentials at all gets the bare
      // challenge — no `error`, because nothing was wrong with what was sent.
      if (!raw) return challenge(res, 401, metadataUrl);

      const token = await introspectAccessToken(ctx, raw);
      if (!token) {
        return challenge(res, 401, metadataUrl, {
          error: 'invalid_token',
          error_description: 'The access token is expired, revoked or unknown',
        });
      }

      if (!token.audience.includes(resource)) {
        // Deliberately `invalid_token` and not `insufficient_scope`: from this
        // resource's point of view the token is not addressed to it at all, and
        // saying "wrong audience" out loud would confirm the token is otherwise
        // good to a caller who stole it for a different API.
        return challenge(res, 401, metadataUrl, {
          error: 'invalid_token',
          error_description: 'The access token was not issued for this resource',
        });
      }

      const held = new Set(token.scopes);
      const ok = mode === 'any'
        ? required.length === 0 || required.some((s) => held.has(s))
        : required.every((s) => held.has(s));
      if (!ok) {
        return challenge(res, 403, metadataUrl, {
          error: 'insufficient_scope',
          error_description: `Requires ${mode === 'any' ? 'one of' : 'all of'}: ${required.join(' ')}`,
          scope: required.join(' '),
        });
      }

      // The contract `mcp-server` consumes — fixed in the build plan §6. Ids are
      // stringified here so a consumer never has to know they were ObjectIds.
      req.oauth = {
        userId: token.userId,
        clientId: token.clientId,
        contextId: token.contextId ?? null,
        scopes: token.scopes,
        grantId: String(token.grantId),
        tokenId: String(token._id),
        audience: token.audience,
      };
      return next();
    });
  };
}

/**
 * The header, and only the header.
 *
 * RFC 6750 also describes a form body and a query parameter; both are
 * deliberately unsupported. A token in a query string lands in access logs,
 * `Referer` headers and browser history, and the protected-resource metadata
 * this package publishes says `bearer_methods_supported: ["header"]`.
 */
function bearerFromHeader(req: Request): string | null {
  const header = req.headers.authorization;
  if (!header) return null;
  const match = /^Bearer +([^\s]+)$/i.exec(header);
  return match ? match[1]! : null;
}

function challenge(
  res: Response,
  status: number,
  metadataUrl: string,
  params: { error?: string; error_description?: string; scope?: string } = {},
): Response {
  const parts = [
    ...Object.entries(params).map(([k, v]) => `${k}="${String(v).replace(/"/g, '')}"`),
    `resource_metadata="${metadataUrl}"`,
  ];
  res.set('WWW-Authenticate', `Bearer ${parts.join(', ')}`);
  // The challenge omits `error` when nothing was presented, but the body still
  // has to say something a JSON client can switch on.
  return res.status(status).json({
    error: params.error ?? 'invalid_request',
    error_description: params.error_description ?? 'Missing bearer token',
  });
}
