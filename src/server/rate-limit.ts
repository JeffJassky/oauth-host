import type { Request, RequestHandler } from 'express';
import type { ResolvedContext } from './config.js';

/**
 * A thin middleware over `ctx.rateLimits`.
 *
 * Brute force on `/token` is the classic authorization-server failure, and the
 * counter itself lives in config so a host can make it Redis. All this file
 * does is turn a rule into an HTTP answer — which is why `false` (the "no limit
 * here" value) short-circuits to a passthrough rather than to a rule with an
 * infinite `max`: a disabled bucket should cost nothing per request.
 *
 * The key is supplied by the caller because the useful key differs per bucket:
 * `/token` limits per client, `/authorize` per IP. A single built-in key would
 * mean one client's traffic throttles another's.
 */
export function rateLimit(
  ctx: ResolvedContext,
  bucket: 'token' | 'authorize' | 'consent',
  keyOf: (req: Request) => string,
): RequestHandler {
  const rule = ctx.rateLimits[bucket];
  if (rule === false) return (_req, _res, next) => next();

  return (req, res, next) => {
    void (async () => {
      let hit: { count: number; resetAt: number };
      try {
        hit = await ctx.rateLimits.hit(`${bucket}:${keyOf(req)}`, rule.windowMs);
      } catch (err) {
        // Fail open, loudly. The store may be the host's Redis; a transient
        // failure there must not take every token exchange down with it. The
        // cost of the other choice — a total auth outage because a counter is
        // unreachable — is worse than a window with no limiting.
        ctx.logger.error?.({ err, bucket }, 'oauth-host: rate limit store failed, allowing request');
        next();
        return;
      }

      if (hit.count <= rule.max) {
        next();
        return;
      }

      const retryAfter = Math.max(1, Math.ceil((hit.resetAt - Date.now()) / 1000));
      res.set('Retry-After', String(retryAfter));
      // JSON, like every other failure in this package — a client that only
      // knows how to parse `{ error }` should not meet HTML at the one moment
      // it is being told to back off. See standards/traps.md #6.
      res.status(429).json({
        error: 'too_many_requests',
        error_description: `Rate limit exceeded for ${bucket}. Retry in ${retryAfter}s.`,
      });
    })();
  };
}
