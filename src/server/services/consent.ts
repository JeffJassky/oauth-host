import { randomToken, sha256 } from '../crypto.js';
import { OAuthError, accessDenied, invalidRequest } from '../errors.js';
import { toPublicClient } from './admin.js';
import { describeScopes } from './scopes.js';
import type { ResolvedContext } from '../config.js';
import type {
  OAuthGrantDoc,
  PackageUser,
} from '../../../types/index.js';

/**
 * Consent — the half of this package that has a human in front of it.
 *
 * The host renders the screen, so `getConsentPayload` IS the UI contract (plan
 * §8) and is versioned as strictly as any route: no `_id`, no grant id, no user
 * id, nothing the host's page has no business rendering. If a field here needs
 * an internal identifier to be useful, the design is wrong, not the rule.
 *
 * `decideConsent` is the write side and is one-shot by construction. An
 * authorization request that could be approved twice mints two codes from one
 * user decision.
 */

/** The consent screen's view of the request. Deliberately id-free. */
export interface ConsentPayload {
  client: {
    name: string;
    logoUrl?: string;
    publisher?: string;
    homepageUrl?: string;
    tosUrl?: string;
    privacyUrl?: string;
  };
  scopes: Array<{
    id: string;
    label: string;
    description?: string;
    sensitive?: boolean;
    isNew: boolean;
  }>;
  contexts?: Array<{ id: string; label: string; description?: string }>;
  /**
   * True when `grantContext.list()` returned more than `contexts` carries.
   *
   * Present exactly when `contexts` is. See `CONSENT_CONTEXT_LIMIT`.
   */
  contextsHasMore?: boolean;
  user: { displayName?: string | null; email?: string };
  expiresAt: Date;
}

/**
 * How many grant contexts the consent payload carries.
 *
 * Every other list in this package is clamped — the admin API defaults to 50
 * with a ceiling of 200 — and this one is on an interactive path, embedded whole
 * in a payload a browser renders. An admin of a host where `list()` answers
 * "every account in the system" was the reported case.
 *
 * Truncating silently would be worse than not clamping: account #501 would
 * simply be unconnectable, with nothing in the payload saying so. Hence
 * `contextsHasMore` — it is the flag that lets a consent UI offer search instead
 * of rendering a prefix and calling it the whole list.
 */
export const CONSENT_CONTEXT_LIMIT = 50;

/** Same user? Ids may be ObjectId or string depending on the host. */
function sameUser(a: PackageUser['id'], b: PackageUser['id']): boolean {
  return String(a) === String(b);
}

/**
 * Load a pending request, proving it belongs to the caller.
 *
 * Unknown and expired are the same 404 on purpose: distinguishing them turns
 * the endpoint into an oracle for whether a given handle ever existed.
 */
async function loadPending(ctx: ResolvedContext, requestId: string, user: PackageUser) {
  const request = await ctx.models.Request.findOne({ requestId }).exec();
  if (!request || request.expiresAt.getTime() <= Date.now() || request.decision) {
    throw new OAuthError(404, 'invalid_request', 'unknown or expired authorization request');
  }
  // A different user's handle is a distinct failure from a stale one — the
  // browser is signed in as somebody, just not the right somebody, and the
  // host's page needs to say so rather than restart the flow.
  if (!sameUser(request.userId, user.id)) {
    throw accessDenied('this authorization request belongs to another user');
  }

  const client = await ctx.models.Client.findOne({ clientId: request.clientId }).exec();
  if (!client || client.status !== 'active') {
    throw new OAuthError(404, 'invalid_request', 'unknown or expired authorization request');
  }

  return { request, client };
}

/**
 * Scopes this user has already given this client.
 *
 * Unioned across every live grant rather than read from one, because the
 * context is not chosen until the user picks it — and a scope already granted
 * under any context is not something to badge as new.
 */
async function alreadyGranted(
  ctx: ResolvedContext,
  clientId: string,
  userId: PackageUser['id'],
): Promise<string[]> {
  const grants = await ctx.models.Grant.find({ clientId, userId, revokedAt: null })
    .select('scopes')
    .lean()
    .exec();
  return [...new Set(grants.flatMap((g) => g.scopes))];
}

export async function getConsentPayload(
  ctx: ResolvedContext,
  requestId: string,
  user: PackageUser,
): Promise<ConsentPayload> {
  const { request, client } = await loadPending(ctx, requestId, user);
  const previouslyGranted = await alreadyGranted(ctx, request.clientId, request.userId);

  const branding = client.branding ?? {};
  const payload: ConsentPayload = {
    client: {
      name: client.name,
      ...(branding.logoUrl ? { logoUrl: branding.logoUrl } : {}),
      ...(branding.publisher ? { publisher: branding.publisher } : {}),
      ...(branding.homepageUrl ? { homepageUrl: branding.homepageUrl } : {}),
      ...(branding.tosUrl ? { tosUrl: branding.tosUrl } : {}),
      ...(branding.privacyUrl ? { privacyUrl: branding.privacyUrl } : {}),
    },
    scopes: describeScopes(ctx, request.scopes, { previouslyGranted }),
    user: {
      displayName: user.displayName ?? null,
      ...(user.email ? { email: user.email } : {}),
    },
    expiresAt: request.expiresAt,
  };

  // Absent must mean absent (plan §0.2). An empty array reads as "there are no
  // contexts to choose from", which is a different statement from "this host
  // does not have contexts" — and a UI that renders an empty picker for every
  // single-subject host is exactly the leak that generalization was supposed
  // to avoid.
  if (ctx.grantContext) {
    const all = await ctx.grantContext.list(user, {
      client: toPublicClient(client),
      scopes: request.scopes,
    });
    payload.contexts = all.slice(0, CONSENT_CONTEXT_LIMIT);
    payload.contextsHasMore = all.length > CONSENT_CONTEXT_LIMIT;
  }

  return payload;
}

export interface ConsentDecision {
  approve: boolean;
  /** What the user actually ticked. Defaults to everything requested. */
  scopes?: string[];
  /** Required exactly when `grantContext` is configured. */
  contextId?: string;
}

/** Every authorization response carries `iss` — RFC 9207, errors included. */
function authorizationResponse(
  ctx: ResolvedContext,
  redirectUri: string,
  state: string | undefined,
  params: Record<string, string>,
): string {
  const url = new URL(redirectUri);
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  if (state !== undefined) url.searchParams.set('state', state);
  url.searchParams.set('iss', ctx.issuer);
  return url.toString();
}

export async function decideConsent(
  ctx: ResolvedContext,
  requestId: string,
  user: PackageUser,
  decision: ConsentDecision,
): Promise<{ redirectTo: string }> {
  const { request, client } = await loadPending(ctx, requestId, user);

  // Validate everything BEFORE claiming the request. A rejected decision must
  // leave the handle usable — the host's UI can fix its payload and re-post.
  const approvedScopes = decision.approve
    ? [...new Set(decision.scopes ?? request.scopes)]
    : [];
  for (const id of approvedScopes) {
    // A host UI offering more than the client asked for is a bug in the host,
    // and honouring it would let the consent screen widen its own request.
    if (!request.scopes.includes(id)) {
      throw invalidRequest(`scope '${id}' was not part of this authorization request`);
    }
  }

  let contextId: string | null = null;
  if (decision.approve) {
    if (ctx.grantContext) {
      if (!decision.contextId) {
        throw invalidRequest('`contextId` is required — this host configured a grant context');
      }
      if (!(await ctx.grantContext.verify(user, decision.contextId))) {
        throw accessDenied(`not a member of context '${decision.contextId}'`);
      }
      contextId = decision.contextId;
    } else if (decision.contextId) {
      throw invalidRequest('`contextId` is not accepted — this host has no grant context');
    }
  }

  // The one-shot guard. Filtering on `decision: null` matches both the missing
  // and the explicitly-null field, and the update is the same round trip, so
  // two concurrent approvals cannot both mint a code.
  const claimed = await ctx.models.Request.findOneAndUpdate(
    { requestId, decision: null },
    { $set: { decision: decision.approve ? 'approved' : 'denied', decidedAt: new Date() } },
    { returnDocument: 'after' },
  ).exec();
  if (!claimed) {
    throw invalidRequest('this authorization request has already been decided');
  }

  if (!decision.approve) {
    ctx.track({
      type: 'oauth.consent_denied',
      userId: user.id,
      clientId: request.clientId,
      scopes: request.scopes,
    });
    await ctx.audit({
      type: 'oauth.consent_denied',
      actor: 'user',
      clientId: request.clientId,
      userId: user.id,
    });
    return {
      redirectTo: authorizationResponse(ctx, request.redirectUri, request.state, {
        error: 'access_denied',
        error_description: 'the user denied the request',
      }),
    };
  }

  const now = new Date();
  const existing = await ctx.models.Grant.findOne({
    clientId: request.clientId,
    userId: request.userId,
    contextId,
    revokedAt: null,
  }).exec();

  // Re-consent unions rather than replaces: a client that asks for a narrower
  // set on its second connect must not silently lose access it still holds a
  // live token for.
  const scopes = [...new Set([...(existing?.scopes ?? []), ...approvedScopes])];
  const resources = [...new Set([...(existing?.resources ?? []), ...request.resources])];
  // `version` is what makes "you already approved this" checkable later, so it
  // moves only when the user actually widened the grant.
  const grew = Boolean(existing) && scopes.length > (existing?.scopes.length ?? 0);

  const grant = (await ctx.models.Grant.findOneAndUpdate(
    { clientId: request.clientId, userId: request.userId, contextId, revokedAt: null },
    {
      $set: { scopes, resources, lastUsedAt: now },
      // Mongo rejects an update that touches one path through two operators,
      // even when only one of them can apply — and `grew` already implies an
      // existing document, so the two branches are genuinely exclusive.
      ...(grew ? { $inc: { version: 1 } } : { $setOnInsert: { version: 1 } }),
    },
    { returnDocument: 'after', upsert: true, setDefaultsOnInsert: true },
  ).exec()) as OAuthGrantDoc;

  // Only the digest is stored. The code itself exists in this function and in
  // the redirect, and nowhere else — a database read cannot replay it.
  const code = randomToken();
  await ctx.models.Code.create({
    codeHash: sha256(code),
    clientId: request.clientId,
    userId: request.userId,
    grantId: grant._id,
    contextId,
    // What was approved now, not the grant's union: the token issued from this
    // code answers for this authorization, not for the history of the grant.
    scopes: approvedScopes,
    resources: request.resources,
    redirectUri: request.redirectUri,
    codeChallenge: request.codeChallenge,
    codeChallengeMethod: 'S256',
    nonce: request.nonce,
    authTime: user.authTime,
    expiresAt: new Date(now.getTime() + ctx.ttl.code * 1000),
  });

  ctx.track({
    type: 'oauth.consent_granted',
    userId: user.id,
    clientId: request.clientId,
    grantId: String(grant._id),
    ...(contextId ? { contextId } : {}),
    scopes: approvedScopes,
  });
  await ctx.audit({
    type: 'oauth.consent_granted',
    actor: 'user',
    clientId: request.clientId,
    userId: user.id,
    grantId: grant._id,
    meta: { scopes: approvedScopes, contextId, version: grant.version },
  });

  return {
    redirectTo: authorizationResponse(ctx, request.redirectUri, request.state, { code }),
  };
}
