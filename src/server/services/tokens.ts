import { OAuthError, invalidGrant, invalidScope } from '../errors.js';
import { randomToken, sha256, verifyPkce } from '../crypto.js';
import type { ResolvedContext } from '../config.js';
import type {
  OAuthCodeDoc,
  OAuthGrantDoc,
  OAuthTokenDoc,
  UserId,
} from '../../../types/index.js';

/**
 * The token core — the security surface of this package, and the reason it is
 * unit-tested before any HTTP exists (build plan §13 step 2).
 *
 * Three invariants everything here exists to hold:
 *
 * 1. **Nothing replayable is stored.** Codes and tokens are 256-bit CSPRNG
 *    strings; only their SHA-256 is written, and every lookup is by hash. The
 *    raw value exists in one place: the return value of the call that minted it.
 * 2. **Single use is enforced by the database, not by a read-then-write.**
 *    `findOneAndUpdate({ consumedAt: null })` is atomic; an `if (doc.consumedAt)`
 *    check is a race two concurrent redemptions win.
 * 3. **A replay is an attack signal, not a duplicate to dedupe.** This is the
 *    one place the house "idempotency" rule inverts (traps §16): a second
 *    redemption of a code, or a second use of a rotated refresh token, means
 *    the credential leaked. The correct response is to revoke every token
 *    descended from it and say so loudly — silently returning the same tokens
 *    hands the attacker exactly what they asked for.
 */

export interface IssuedTokens {
  accessToken: string;
  refreshToken?: string;
  expiresIn: number;
  scopes: string[];
  audience: string[];
  grantId: string;
  familyId: string;
  userId: UserId;
  contextId: string | null;
}

/**
 * The family id is derived from the code, not random.
 *
 * A replayed code arrives with nothing but its own hash, and the family it
 * spawned has to be revocable from that alone. Deriving instead of storing a
 * back-reference means the link cannot go missing. It stays unguessable because
 * the input is a hash of 256 bits of CSPRNG output.
 */
function familyFor(codeHash: string): string {
  return sha256(`family:${codeHash}`);
}

const parseScopes = (scope?: string): string[] =>
  (scope ?? '').split(/\s+/).filter(Boolean);

/** RFC 8707 §2 — the code for a resource the token may not be bound to. */
const invalidTarget = (d: string) => new OAuthError(400, 'invalid_target', d);

async function liveGrant(
  ctx: ResolvedContext,
  grantId: OAuthCodeDoc['grantId'],
): Promise<OAuthGrantDoc> {
  const grant = await ctx.models.Grant.findById(grantId);
  if (!grant || grant.revokedAt) {
    throw invalidGrant('the authorization behind this token has been revoked');
  }
  return grant;
}

/**
 * Atomically consume a code.
 *
 * Consumption happens BEFORE validation, deliberately. A code that fails its
 * `redirect_uri` or PKCE check has still been presented, and leaving it live
 * for a second attempt is what turns a failed injection into a retried one.
 * The cost is that a client bug burns the code — which is the behaviour the
 * spec asks for anyway.
 */
export async function consumeCode(
  ctx: ResolvedContext,
  rawCode: string,
  opts: { clientId: string; redirectUri: string; codeVerifier: string },
): Promise<OAuthCodeDoc> {
  const codeHash = sha256(rawCode);
  const now = new Date();

  const code = await ctx.models.Code.findOneAndUpdate(
    { codeHash, consumedAt: null },
    { $set: { consumedAt: now } },
    { returnDocument: 'after' },
  );

  if (!code) {
    const replayed = await ctx.models.Code.findOne({ codeHash });
    if (replayed) {
      const familyId = familyFor(codeHash);
      const revoked = await revokeFamily(ctx, familyId, 'code_replay');
      await ctx.audit({
        type: 'code_replay',
        actor: 'client',
        clientId: opts.clientId,
        userId: replayed.userId,
        grantId: replayed.grantId,
        meta: { familyId, tokensRevoked: revoked },
      });
      ctx.logger.warn?.(
        { clientId: opts.clientId, familyId },
        'oauth-host: authorization code replayed — family revoked',
      );
    }
    // Same answer either way: an attacker must not learn whether the code was
    // real-but-spent or never existed.
    throw invalidGrant('authorization code is invalid, expired, or already used');
  }

  if (code.expiresAt.getTime() <= now.getTime()) {
    throw invalidGrant('authorization code has expired');
  }
  if (code.clientId !== opts.clientId) {
    throw invalidGrant('authorization code was issued to a different client');
  }
  // RFC 6749 §4.1.3 — exact match against the value bound at /authorize. A
  // prefix or origin comparison here is the classic redirect-hijack hole.
  if (code.redirectUri !== opts.redirectUri) {
    throw invalidGrant('redirect_uri does not match the one the code was issued for');
  }
  if (!verifyPkce(opts.codeVerifier ?? '', code.codeChallenge)) {
    throw invalidGrant('PKCE verification failed');
  }

  return code;
}

async function mintPair(
  ctx: ResolvedContext,
  args: {
    grant: OAuthGrantDoc;
    clientId: string;
    userId: UserId;
    contextId: string | null;
    scopes: string[];
    audience: string[];
    familyId: string;
    familyExpiresAt: Date;
    parentId?: OAuthTokenDoc['_id'] | null;
  },
): Promise<IssuedTokens> {
  const now = Date.now();
  const accessToken = randomToken();
  const refreshToken = randomToken();
  const common = {
    clientId: args.clientId,
    userId: args.userId,
    grantId: args.grant._id,
    contextId: args.contextId,
    scopes: args.scopes,
    audience: args.audience,
    familyId: args.familyId,
  };

  await ctx.models.Token.create({
    ...common,
    kind: 'access',
    tokenHash: sha256(accessToken),
    expiresAt: new Date(now + ctx.ttl.accessToken * 1000),
  });
  await ctx.models.Token.create({
    ...common,
    kind: 'refresh',
    tokenHash: sha256(refreshToken),
    parentId: args.parentId ?? null,
    // `expiresAt` is the SLIDING window and is what the TTL index reaps;
    // `familyExpiresAt` is the absolute ceiling and is copied unchanged onto
    // every rotation, so no amount of refreshing extends it.
    expiresAt: new Date(now + ctx.ttl.refreshToken * 1000),
    familyExpiresAt: args.familyExpiresAt,
  });

  await ctx.models.Grant.updateOne({ _id: args.grant._id }, { $set: { lastUsedAt: new Date(now) } });

  return {
    accessToken,
    refreshToken,
    expiresIn: ctx.ttl.accessToken,
    scopes: args.scopes,
    audience: args.audience,
    grantId: String(args.grant._id),
    familyId: args.familyId,
    userId: args.userId,
    contextId: args.contextId,
  };
}

export async function issueForCode(
  ctx: ResolvedContext,
  code: OAuthCodeDoc,
): Promise<IssuedTokens> {
  const grant = await liveGrant(ctx, code.grantId);
  const issued = await mintPair(ctx, {
    grant,
    clientId: code.clientId,
    userId: code.userId,
    contextId: code.contextId,
    scopes: code.scopes,
    // Audience comes from the resources bound at /authorize, which were already
    // checked against the client's registration. Never from the token request.
    audience: code.resources,
    familyId: familyFor(code.codeHash),
    familyExpiresAt: new Date(Date.now() + ctx.ttl.refreshAbsolute * 1000),
  });

  ctx.track({
    type: 'oauth.token_issued',
    userId: issued.userId,
    clientId: code.clientId,
    grantId: issued.grantId,
    contextId: issued.contextId ?? undefined,
    scopes: issued.scopes,
  });
  await ctx.audit({
    type: 'token_issued',
    actor: 'client',
    clientId: code.clientId,
    userId: code.userId,
    grantId: grant._id,
    meta: { familyId: issued.familyId, scopes: issued.scopes, audience: issued.audience },
  });
  return issued;
}

/**
 * Rotating refresh with reuse detection.
 *
 * Rotation is what makes theft detectable: because the old token is consumed
 * the instant a new one is minted, the *second* presentation can only come from
 * someone who is not the holder of the current one. Which of the two is the
 * attacker is unknowable, so both lose — the whole family dies.
 */
export async function rotateRefresh(
  ctx: ResolvedContext,
  rawRefresh: string,
  opts: { clientId: string; scope?: string; resources?: string[] },
): Promise<IssuedTokens> {
  const tokenHash = sha256(rawRefresh);
  const now = new Date();

  const token = await ctx.models.Token.findOneAndUpdate(
    { tokenHash, kind: 'refresh', consumedAt: null, revokedAt: null },
    { $set: { consumedAt: now } },
    { returnDocument: 'after' },
  );

  if (!token) {
    const known = await ctx.models.Token.findOne({ tokenHash, kind: 'refresh' });
    if (known?.consumedAt) {
      const revoked = await revokeFamily(ctx, known.familyId, 'refresh_reuse_detected');
      ctx.track({
        type: 'oauth.refresh_reuse_detected',
        userId: known.userId,
        clientId: known.clientId,
        grantId: String(known.grantId),
        contextId: known.contextId ?? undefined,
        scopes: known.scopes,
        meta: { familyId: known.familyId, tokensRevoked: revoked },
      });
      await ctx.audit({
        type: 'refresh_reuse_detected',
        actor: 'client',
        clientId: known.clientId,
        userId: known.userId,
        grantId: known.grantId,
        meta: { familyId: known.familyId, tokensRevoked: revoked },
      });
      ctx.logger.warn?.(
        { clientId: known.clientId, familyId: known.familyId },
        'oauth-host: rotated refresh token reused — family revoked',
      );
    }
    throw invalidGrant('refresh token is invalid, expired, or already used');
  }

  if (token.clientId !== opts.clientId) {
    // A refresh token presented by a client it was not issued to is theft, not
    // a mistake — there is no flow that produces it.
    await revokeFamily(ctx, token.familyId, 'refresh_wrong_client');
    await ctx.audit({
      type: 'refresh_wrong_client',
      actor: 'client',
      clientId: opts.clientId,
      userId: token.userId,
      grantId: token.grantId,
      meta: { familyId: token.familyId, issuedTo: token.clientId },
    });
    throw invalidGrant('refresh token was issued to a different client');
  }
  if (token.expiresAt.getTime() <= now.getTime()) {
    throw invalidGrant('refresh token has expired');
  }
  if (token.familyExpiresAt && token.familyExpiresAt.getTime() <= now.getTime()) {
    // The ceiling exists so a compromised-but-actively-refreshed token cannot
    // live forever. Past it, re-consent is the only way back.
    await revokeFamily(ctx, token.familyId, 'family_absolute_expiry');
    throw invalidGrant('refresh token family has reached its absolute lifetime; re-authorization is required');
  }

  const grant = await liveGrant(ctx, token.grantId);

  // Re-checked on EVERY refresh, not just at consent: a grant made as an
  // employee has to die when the employment does, and the only moment we are
  // guaranteed to be asked again is this one. `verify` gets the identity the
  // package holds — there is no request here to resolve a fuller user from.
  if (ctx.grantContext && token.contextId !== null) {
    const stillAllowed = await ctx.grantContext.verify({ id: token.userId }, token.contextId);
    if (!stillAllowed) {
      await ctx.models.Grant.updateOne(
        { _id: grant._id, revokedAt: null },
        { $set: { revokedAt: now, revokedBy: 'system' } },
      );
      await revokeFamily(ctx, token.familyId, 'context_membership_ended');
      await ctx.audit({
        type: 'grant_revoked',
        actor: 'system',
        clientId: token.clientId,
        userId: token.userId,
        grantId: token.grantId,
        meta: { reason: 'context_membership_ended', contextId: token.contextId },
      });
      throw invalidGrant('the context this authorization was granted for is no longer available');
    }
  }

  // Downscoping only (RFC 6749 §6). The ceiling is the intersection of what
  // this token carries and what the grant still says — a grant narrowed after
  // issuance must not be widened back by a refresh.
  const ceiling = token.scopes.filter((s) => grant.scopes.includes(s));
  const requested = parseScopes(opts.scope);
  const scopes = requested.length ? requested : ceiling;
  for (const s of scopes) {
    if (!ceiling.includes(s)) {
      throw invalidScope(`scope '${s}' was not granted; a refresh may only narrow the scope set`);
    }
  }

  const audience = opts.resources?.length ? opts.resources : token.audience;
  for (const r of audience) {
    if (!token.audience.includes(r)) {
      throw invalidTarget(`resource '${r}' is not one this authorization is bound to`);
    }
  }

  const issued = await mintPair(ctx, {
    grant,
    clientId: token.clientId,
    userId: token.userId,
    contextId: token.contextId,
    scopes,
    audience,
    familyId: token.familyId,
    familyExpiresAt: token.familyExpiresAt ?? new Date(now.getTime() + ctx.ttl.refreshAbsolute * 1000),
    parentId: token._id,
  });

  ctx.track({
    type: 'oauth.token_refreshed',
    userId: issued.userId,
    clientId: token.clientId,
    grantId: issued.grantId,
    contextId: issued.contextId ?? undefined,
    scopes: issued.scopes,
  });
  return issued;
}

/** Kill every token descended from one authorization code. Returns the count. */
export async function revokeFamily(
  ctx: ResolvedContext,
  familyId: string,
  reason: string,
): Promise<number> {
  const { modifiedCount = 0 } = await ctx.models.Token.updateMany(
    { familyId, revokedAt: null },
    { $set: { revokedAt: new Date() } },
  );
  if (modifiedCount) {
    ctx.logger.info?.({ familyId, reason, tokensRevoked: modifiedCount }, 'oauth-host: token family revoked');
  }
  return modifiedCount;
}

/**
 * Kill every token issued under a grant.
 *
 * The grant is the consent record and outlives its tokens, so revoking it has
 * to reach them explicitly — otherwise "revoke access" means "expire in an
 * hour". `introspectAccessToken` re-checks the grant for the same reason.
 */
export async function revokeGrantTokens(ctx: ResolvedContext, grantId: unknown): Promise<number> {
  const { modifiedCount = 0 } = await ctx.models.Token.updateMany(
    { grantId: grantId as never, revokedAt: null },
    { $set: { revokedAt: new Date() } },
  );
  return modifiedCount;
}

/**
 * Resource-server lookup. Null means "do not serve this request" — unknown,
 * expired, revoked, or belonging to a grant that has since been revoked.
 */
/**
 * The opt-in introspection cache.
 *
 * Keyed by token hash, never by the raw token — a cache key is the easiest
 * thing in a process to end up in a heap dump or a log line. Disabled at
 * `tokenCacheTtlMs === 0`, which is the default, because every millisecond of
 * TTL is a millisecond in which a revoked token still opens the door. Sized
 * against the number of tokens in flight rather than left unbounded: the key
 * space is attacker-influenced.
 */
const CACHE_MAX_ENTRIES = 10_000;
const introspectionCache = new Map<string, { doc: OAuthTokenDoc; until: number }>();

function cacheGet(ctx: ResolvedContext, hash: string): OAuthTokenDoc | null {
  if (ctx.tokenCacheTtlMs <= 0) return null;
  const hit = introspectionCache.get(hash);
  if (!hit) return null;
  if (hit.until <= Date.now()) {
    introspectionCache.delete(hash);
    return null;
  }
  return hit.doc;
}

function cachePut(ctx: ResolvedContext, hash: string, doc: OAuthTokenDoc): void {
  if (ctx.tokenCacheTtlMs <= 0) return;
  if (introspectionCache.size >= CACHE_MAX_ENTRIES) {
    // Cheapest bounded eviction that cannot be gamed into keeping a revoked
    // token alive: drop the oldest insertion. Map preserves insertion order.
    const oldest = introspectionCache.keys().next().value;
    if (oldest !== undefined) introspectionCache.delete(oldest);
  }
  // Never cache past the token's own expiry — a 60s cache on a token with 5s
  // left would extend it.
  const until = Math.min(Date.now() + ctx.tokenCacheTtlMs, doc.expiresAt.getTime());
  introspectionCache.set(hash, { doc, until });
}

/** Drop a token from the cache the moment it is revoked, so revocation stays instant. */
export function forgetCachedToken(tokenHash: string): void {
  introspectionCache.delete(tokenHash);
}

export async function introspectAccessToken(
  ctx: ResolvedContext,
  raw: string,
): Promise<OAuthTokenDoc | null> {
  const hash = sha256(raw);
  const cached = cacheGet(ctx, hash);
  if (cached) return cached;

  const token = await ctx.models.Token.findOne({ tokenHash: hash, kind: 'access' });
  if (!token) return null;
  if (token.revokedAt) return null;
  if (token.expiresAt.getTime() <= Date.now()) return null;

  // A live token whose grant died must not work. Skipping this read is how
  // "revocation is instant" quietly becomes "revocation takes an hour".
  const grant = await ctx.models.Grant.findById(token.grantId, { revokedAt: 1 });
  if (!grant || grant.revokedAt) return null;

  cachePut(ctx, hash, token);
  return token;
}

/**
 * RFC 7009 — revocation is the one genuinely idempotent operation here.
 *
 * An unknown token is a 200: the client's goal (this credential does not work)
 * is already true, and answering 404 turns the endpoint into an oracle for
 * which tokens exist.
 */
export async function revokeToken(
  ctx: ResolvedContext,
  raw: string,
  clientId: string,
): Promise<void> {
  const token = await ctx.models.Token.findOne({ tokenHash: sha256(raw) });
  if (!token) return;
  forgetCachedToken(token.tokenHash);
  // RFC 7009 §2.1 — a client may not revoke another client's token. Still a
  // 200, still nothing revoked.
  if (token.clientId !== clientId) return;

  if (token.kind === 'refresh') {
    await revokeFamily(ctx, token.familyId, 'client_revocation');
  } else {
    await ctx.models.Token.updateOne(
      { _id: token._id, revokedAt: null },
      { $set: { revokedAt: new Date() } },
    );
  }
  await ctx.audit({
    type: 'token_revoked',
    actor: 'client',
    clientId,
    userId: token.userId,
    grantId: token.grantId,
    meta: { kind: token.kind, familyId: token.familyId },
  });
}
