import { createHash, sign } from 'node:crypto';
import { pairwiseSubject } from '../crypto.js';
import { toPublicClient } from './admin.js';
import type { ResolvedContext } from '../config.js';
import type { KeyManager, SigningKey } from '../keys.js';
import type {
  OAuthClientDoc,
  PackageUser,
  UserId,
} from '../../../types/index.js';

/**
 * The OIDC layer: `sub`, the signed `id_token`, and the `/userinfo` projection.
 *
 * The JWS is written by hand against `node:crypto` rather than pulled from
 * `jose`. Thirty lines against a runtime dependency in an authorization
 * server's trusted computing base is a trade worth making once, and the peer
 * set stays express + mongoose.
 *
 * The one thing that must not be "cleaned up": `dsaEncoding: 'ieee-p1363'`.
 * Node's default for ECDSA is DER, JWS ES256 is the fixed-width r‖s pair, and
 * the failure mode is not an exception — it is a client silently rejecting
 * every token while the server logs nothing.
 */

const b64u = (value: string | Buffer): string =>
  Buffer.from(value as never).toString('base64url');

/**
 * Claims a host's `claims` adapter may not write.
 *
 * The first five are the token's identity and lifetime — letting host data
 * overwrite `sub` or `aud` turns a projection of profile fields into
 * impersonation. `nonce` and `at_hash` are the client's replay and
 * token-binding checks, and they are ours to compute for the same reason.
 */
const RESERVED_ID_TOKEN_CLAIMS = new Set(['iss', 'sub', 'aud', 'exp', 'iat', 'nonce', 'at_hash']);

function signJws(key: SigningKey, payload: Record<string, unknown>): string {
  const header = { alg: key.alg, typ: 'JWT', kid: key.kid };
  const data = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  const signature = sign('sha256', Buffer.from(data), {
    key: key.privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return `${data}.${signature.toString('base64url')}`;
}

/**
 * OIDC Core §3.1.3.6 — the left-most half of the SHA-256 of the ASCII access
 * token, base64url. It is what lets a client that received both over the same
 * channel prove they belong together.
 */
function atHash(accessToken: string): string {
  const digest = createHash('sha256').update(accessToken, 'ascii').digest();
  return digest.subarray(0, digest.length / 2).toString('base64url');
}

/**
 * The client as an adapter may see it — `toPublicClient` from `admin.ts`, not a
 * local copy. Three hand-maintained copies of one projection is how a field
 * added to `PublicClient` reaches two of the three places it belongs.
 */
const publicClient = toPublicClient;

/**
 * Read a value out of `pairwiseSubjects`, which is a `Map` on a hydrated
 * document and a plain object on a lean one. Both reach here.
 */
function storedSubject(client: OAuthClientDoc, key: string): string | undefined {
  const map = client.pairwiseSubjects as unknown;
  if (map instanceof Map) return map.get(key) as string | undefined;
  if (map && typeof map === 'object') return (map as Record<string, string>)[key];
  return undefined;
}

/**
 * The `sub` this client sees for this user.
 *
 * `pairwise` is computed from the salt, but it is also **persisted** on the
 * client: the partner stores this value as their primary key, so it has to
 * survive anything that could change the derivation, and "which subject did we
 * hand out" has to be answerable from the database rather than recomputed.
 * OIDC Core §8.1.
 */
export async function subjectFor(
  ctx: ResolvedContext,
  client: OAuthClientDoc,
  userId: UserId,
): Promise<string> {
  const key = String(userId);
  if (ctx.subjectMode !== 'pairwise') return key;
  if (!ctx.pairwiseSalt) {
    throw new Error('oauth-host: subjectMode is "pairwise" but no `pairwiseSalt` is configured');
  }

  const existing = storedSubject(client, key);
  if (existing) return existing;

  const subject = pairwiseSubject(key, client.clientId, ctx.pairwiseSalt);
  // `$setOnInsert` semantics by hand: only write when the field is still
  // absent, so a concurrent issuance cannot hand two subjects to one partner.
  await ctx.models.Client.updateOne(
    { clientId: client.clientId, [`pairwiseSubjects.${key}`]: { $exists: false } },
    { $set: { [`pairwiseSubjects.${key}`]: subject } },
  );
  const stored = await ctx.models.Client.findOne(
    { clientId: client.clientId },
    { pairwiseSubjects: 1 },
  );
  return (stored && storedSubject(stored, key)) || subject;
}

/** Standard claims derivable from the user adapter alone, gated by scope. */
function standardClaims(user: PackageUser, scopes: string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const granted = new Set(scopes);
  if (granted.has('profile')) {
    if (user.displayName) out.name = user.displayName;
    if (user.avatarUrl) out.picture = user.avatarUrl;
  }
  // No `email_verified`. The host never tells us, and asserting `false` is as
  // wrong as asserting `true` — clients branch on it.
  if (granted.has('email') && user.email) out.email = user.email;
  return out;
}

async function hostClaims(
  ctx: ResolvedContext,
  args: { client: OAuthClientDoc; user: PackageUser; scopes: string[]; contextId: string | null },
): Promise<Record<string, unknown>> {
  if (!ctx.claims) return {};
  return await ctx.claims(args.user, {
    scopes: args.scopes,
    contextId: args.contextId ?? undefined,
    client: publicClient(args.client),
  });
}

export async function buildIdToken(
  ctx: ResolvedContext,
  keys: KeyManager,
  args: {
    client: OAuthClientDoc;
    user: PackageUser;
    scopes: string[];
    contextId: string | null;
    nonce?: string;
    authTime?: Date;
    accessToken?: string;
  },
): Promise<string> {
  const key = await keys.getSigningKey();
  const now = Date.now();
  const skew = ctx.clockSkewMs;

  // Server time exclusively — never a client-supplied timestamp. `clockSkewMs`
  // widens the window at both ends rather than shifting it, so a client whose
  // clock is behind does not reject a token that is genuinely fresh. traps §15.
  const payload: Record<string, unknown> = {
    ...standardClaims(args.user, args.scopes),
    ...await hostClaims(ctx, args),
  };
  for (const claim of RESERVED_ID_TOKEN_CLAIMS) delete payload[claim];

  payload.iss = ctx.issuer;
  payload.sub = await subjectFor(ctx, args.client, args.user.id);
  payload.aud = args.client.clientId;
  payload.iat = Math.floor(now / 1000);
  payload.nbf = Math.floor((now - skew) / 1000);
  payload.exp = Math.floor((now + ctx.ttl.accessToken * 1000 + skew) / 1000);

  const authTime = args.authTime ?? args.user.authTime;
  if (authTime) payload.auth_time = Math.floor(authTime.getTime() / 1000);
  if (args.nonce) payload.nonce = args.nonce;
  if (args.accessToken) payload.at_hash = atHash(args.accessToken);

  return signJws(key, payload);
}

/**
 * The `/userinfo` body.
 *
 * Read live on every call, which is why access tokens carry no claims: there is
 * nothing cached to invalidate when the host's data changes.
 */
export async function buildUserInfo(
  ctx: ResolvedContext,
  args: {
    client: OAuthClientDoc;
    user: PackageUser;
    scopes: string[];
    contextId: string | null;
  },
): Promise<Record<string, unknown>> {
  const claims: Record<string, unknown> = {
    ...standardClaims(args.user, args.scopes),
    ...await hostClaims(ctx, args),
  };
  // `sub` is the one claim a host cannot supply: OIDC Core §5.3.2 requires it
  // to match the `id_token`, and a client that checks will reject a mismatch.
  delete claims.sub;
  return { sub: await subjectFor(ctx, args.client, args.user.id), ...claims };
}
