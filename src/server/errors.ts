import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { Logger } from '../../types/index.js';

/**
 * Errors here are spec-shaped and loud — the opposite of the "reject junk
 * quietly" rule that governs a public ingest path.
 *
 * An authorization server that swallows bad input teaches an integrator
 * nothing and hides an attack. Every failure answers `{ error,
 * error_description }` with the RFC-mandated token, because clients switch on
 * `error` and a made-up code is indistinguishable from a broken server.
 * Volume is absorbed by rate limiting, not by silent drops.
 *
 * See standards/traps.md §19 (inverted for this package) and #6 — JSON on
 * throw, never Express's default HTML.
 */
export class OAuthError extends Error {
  status: number;

  code: string;

  description?: string;

  /** e.g. `WWW-Authenticate` on a 401 from the resource server. */
  headers?: Record<string, string>;

  constructor(
    status: number,
    code: string,
    description?: string,
    opts?: { headers?: Record<string, string> },
  ) {
    super(description ? `${code}: ${description}` : code);
    this.name = 'OAuthError';
    this.status = status;
    this.code = code;
    this.description = description;
    this.headers = opts?.headers;
  }

  toBody(): { error: string; error_description?: string } {
    return {
      error: this.code,
      ...(this.description ? { error_description: this.description } : {}),
    };
  }
}

/** RFC 6749 §5.2 — `invalid_client` is a 401 and carries no redirect. */
export const invalidClient = (d?: string) => new OAuthError(401, 'invalid_client', d);
export const invalidRequest = (d?: string) => new OAuthError(400, 'invalid_request', d);
export const invalidGrant = (d?: string) => new OAuthError(400, 'invalid_grant', d);
export const invalidScope = (d?: string) => new OAuthError(400, 'invalid_scope', d);
export const unsupportedGrantType = (d?: string) =>
  new OAuthError(400, 'unsupported_grant_type', d);
export const accessDenied = (d?: string) => new OAuthError(403, 'access_denied', d);
export const serverError = (d?: string) => new OAuthError(500, 'server_error', d);

/**
 * An authorization-endpoint failure that must NOT be redirected back.
 *
 * The redirect-vs-render split is a security boundary, not a formatting
 * choice: an unrecognised `client_id` or an unregistered `redirect_uri` means
 * we have no proven-safe place to send the user, and redirecting anyway is the
 * open-redirect hole. Everything else redirects with `state` and `iss` intact.
 */
export class UnredirectableError extends OAuthError {
  constructor(code: string, description?: string) {
    super(400, code, description);
    this.name = 'UnredirectableError';
  }
}

/**
 * An authorization-endpoint failure the client IS allowed to be told about,
 * because `client_id` and `redirect_uri` have both already been validated
 * against the registration. RFC 6749 §4.1.2.1 — return it to `redirect_uri`
 * with `state` and, per RFC 9207, `iss`.
 */
export class RedirectableAuthError extends OAuthError {
  redirectUri: string;

  state?: string;

  constructor(code: string, description: string | undefined, redirectUri: string, state?: string) {
    super(400, code, description);
    this.name = 'RedirectableAuthError';
    this.redirectUri = redirectUri;
    this.state = state;
  }

  /** The full `redirect_uri` to 302 to, error parameters attached. */
  toRedirect(issuer: string): string {
    const url = new URL(this.redirectUri);
    url.searchParams.set('error', this.code);
    if (this.description) url.searchParams.set('error_description', this.description);
    if (this.state !== undefined) url.searchParams.set('state', this.state);
    url.searchParams.set('iss', issuer);
    return url.toString();
  }
}

export type RawHandler = (
  req: Request,
  res: Response,
  next: NextFunction,
) => unknown | Promise<unknown>;

/**
 * Async handler wrapper.
 *
 * Without it a rejected promise reaches Express's default error handler, which
 * answers HTML. Every route in this package answers JSON, including on failure,
 * so a client that only knows how to parse `{ error }` never has to
 * special-case a 500. Test it by injecting a model whose method throws.
 * See standards/traps.md #6.
 */
export function wrap(logger: Logger, handler: RawHandler): RequestHandler {
  return async (req, res, next) => {
    try {
      await handler(req, res, next);
    } catch (err) {
      if (err instanceof OAuthError) {
        // Headers already flushed means we're mid-response — nothing useful
        // left to say, hand it to the host's handler to close out.
        if (res.headersSent) return next(err);
        if (err.headers) res.set(err.headers);
        return res.status(err.status).json(err.toBody());
      }
      logger.error?.({ err, path: req.originalUrl }, 'oauth-host: request failed');
      if (res.headersSent) return next(err);
      res.status(500).json({ error: 'server_error' });
    }
  };
}
