import type { Request } from 'express';
import { OAuthError } from '../errors.js';
import { generateClientId, generateClientSecret, safeEqual, sha256 } from '../crypto.js';
import type { ResolvedContext } from '../config.js';
import type {
  ClientBranding,
  ClientsApi,
  ContextsApi,
  CreateClientSpec,
  CreatedClient,
  CreatedConfidentialClient,
  CreatedPublicClient,
  GrantContext,
  GrantSummary,
  GrantsApi,
  OAuthClientDoc,
  OAuthGrantDoc,
  PackageUser,
  PublicClient,
  ScopeSpec,
  UserId,
  UsersApi,
} from '../../../types/index.js';

/**
 * The programmatic admin surface — client registration, grant revocation, and
 * the two outbound lifecycle hooks a host has to call.
 *
 * **There is no admin router here, deliberately.** `standards/adapters.md` says
 * `isAdmin` must not gate anything, because the package cannot know what admin
 * means in a host. Shipping these as plain module exports is the strongest
 * available form of that rule: there is no admin router for a host to forget to
 * guard. If a host wants HTTP admin it writes the route and owns the guard, and
 * `examples/` ships the test it is expected to copy.
 *
 * Everything that leaves this module goes through `toPublicClient`. A client
 * document carries secret digests and the pairwise-subject map; neither has any
 * business in a response, a log line, or a dashboard payload.
 *
 * Revocation in here is written as bulk `updateMany` rather than a loop over
 * per-grant helpers. A popular client can hold tens of thousands of grants, and
 * `disable()` has to stay one round trip per collection or it becomes the
 * outage it was called to prevent.
 */

/**
 * A mongo filter, loosely typed on purpose.
 *
 * `FilterQuery` is not exported across the whole supported mongoose range
 * (7/8/9), and a library that imports a type one peer major dropped fails the
 * matrix in a way that has nothing to do with its behaviour — traps #10.
 */
type Filter = Record<string, unknown>;

/** Hard ceiling on any list read, above whatever the caller asked for — traps #18. */
const MAX_LIST = 200;
const DEFAULT_LIST = 50;

function clampLimit(requested: unknown): number {
  const n = typeof requested === 'number' && Number.isFinite(requested) ? Math.floor(requested) : DEFAULT_LIST;
  if (n < 1) return 1;
  return Math.min(n, MAX_LIST);
}

function clampSkip(requested: unknown): number {
  const n = typeof requested === 'number' && Number.isFinite(requested) ? Math.floor(requested) : 0;
  return n > 0 ? n : 0;
}

/**
 * A programmatic failure, not a wire failure.
 *
 * These are thrown at a host's own admin script or route handler, so a plain
 * `Error` with a readable message is the right shape — an RFC token like
 * `invalid_client` means something specific on the wire and would be a lie here.
 */
function notFound(clientId: string): Error {
  return new Error(`oauth-host: no client registered with clientId '${clientId}'`);
}

// ---------------------------------------------------------------------------
// Projection
// ---------------------------------------------------------------------------

/** The client as anything outside the package may see it. Never the secrets. */
export function toPublicClient(doc: OAuthClientDoc): PublicClient {
  return {
    clientId: doc.clientId,
    name: doc.name,
    type: doc.type,
    // Defaulted rather than read straight through: rows written before the
    // field existed have no value, and `undefined` here would read as "unknown
    // provenance" on a client that plainly was registered by hand.
    registration: doc.registration ?? 'manual',
    ...(doc.metadataUrl ? { metadataUrl: doc.metadataUrl } : {}),
    trusted: Boolean(doc.trusted),
    redirectUris: [...(doc.redirectUris ?? [])],
    allowedScopes: [...(doc.allowedScopes ?? [])],
    allowedResources: [...(doc.allowedResources ?? [])],
    branding: { ...((doc.branding ?? {}) as ClientBranding) },
    status: doc.status,
    createdAt: doc.createdAt,
  };
}

// ---------------------------------------------------------------------------
// Registration validation
// ---------------------------------------------------------------------------

/**
 * Validate a redirect URI hard, at registration, with the offending value in
 * the message.
 *
 * This is the one field nothing downstream can rescue: `/authorize` compares
 * the incoming `redirect_uri` by exact string equality against this list, so a
 * typo registered today is a partner integration that half-works six weeks
 * later with no error pointing back here.
 *
 * `http` is allowed on loopback and nowhere else. That is not a relaxed rule —
 * real connector development runs against `http://localhost`, and a package
 * that forbids it gets worked around with a fake TLS proxy or, worse, by
 * registering the production client against a dev callback.
 */
function assertRedirectUri(value: unknown): string {
  if (typeof value !== 'string' || !value) {
    throw new TypeError(`oauth-host: every redirectUri must be a string (got ${JSON.stringify(value)})`);
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError(`oauth-host: redirectUri must be an absolute URI: '${value}'`);
  }
  const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    throw new TypeError(
      `oauth-host: redirectUri must be https (http is allowed only on localhost/127.0.0.1): '${value}'`,
    );
  }
  // RFC 6749 §3.1.2 — the endpoint URI MUST NOT include a fragment. The
  // authorization response appends its own parameters, and a fragment already
  // present makes what the client receives undefined.
  if (url.hash) {
    throw new TypeError(`oauth-host: redirectUri must not contain a fragment: '${value}'`);
  }
  return value;
}

function assertRedirectUris(input: unknown): string[] {
  if (!Array.isArray(input) || input.length === 0) {
    throw new TypeError('oauth-host: a client needs at least one redirectUri');
  }
  return input.map(assertRedirectUri);
}

/**
 * A client may only be granted scopes the host declared.
 *
 * The two gates in `scopes.ts` (catalog, then registration) both have to hold
 * at request time; this is the earlier one, applied where a human can still fix
 * it. Without it, registering a client would implicitly extend the catalog and
 * the consent screen would have no label to render for the scope.
 */
function assertScopes(ctx: ResolvedContext, input: unknown): string[] {
  if (!Array.isArray(input) || input.length === 0) {
    throw new TypeError('oauth-host: a client needs at least one entry in allowedScopes');
  }
  for (const id of input) {
    if (typeof id !== 'string' || !ctx.scopeIndex.has(id)) {
      throw new TypeError(
        `oauth-host: allowedScopes contains '${String(id)}', which is not in the configured scope catalog`,
      );
    }
  }
  return [...(input as string[])];
}

/** Defaults to every configured resource — a client bound to nothing gets no token. */
function assertResources(ctx: ResolvedContext, input: unknown): string[] {
  const declared = new Set(ctx.resources.map((r) => r.id));
  if (input === undefined) return ctx.resources.map((r) => r.id);
  if (!Array.isArray(input) || input.length === 0) {
    throw new TypeError('oauth-host: allowedResources, when given, must list at least one resource');
  }
  for (const id of input) {
    if (typeof id !== 'string' || !declared.has(id)) {
      throw new TypeError(
        `oauth-host: allowedResources contains '${String(id)}', which is not a configured resource`,
      );
    }
  }
  return [...(input as string[])];
}

/**
 * `confidential` unless the caller said otherwise.
 *
 * The default is the compatibility guarantee: every registration written before
 * this option existed, and every caller that does not know about it, keeps
 * getting a secret. Choosing `public` is a deliberate act, because it is the one
 * that produces a registration `/token` will accept with no credential.
 */
function assertClientType(value: unknown): 'confidential' | 'public' {
  if (value === undefined) return 'confidential';
  if (value !== 'confidential' && value !== 'public') {
    throw new TypeError(
      `oauth-host: client type must be 'confidential' or 'public' (got ${JSON.stringify(value)})`,
    );
  }
  return value;
}

function assertName(value: unknown): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new TypeError('oauth-host: a client needs a non-empty `name` — it is what the consent screen shows');
  }
  return value.trim();
}

// ---------------------------------------------------------------------------
// Bulk revocation, shared by every cascade below
// ---------------------------------------------------------------------------

async function revokeGrantsMatching(
  ctx: ResolvedContext,
  filter: Filter,
  by: 'user' | 'admin' | 'system' | 'client',
): Promise<{ grantsRevoked: number }> {
  const res = await ctx.models.Grant.updateMany(
    { ...filter, revokedAt: null },
    { $set: { revokedAt: new Date(), revokedBy: by } },
  );
  return { grantsRevoked: res.modifiedCount ?? 0 };
}

/**
 * Tokens carry `clientId`, `userId`, `contextId` and `grantId` denormalized
 * precisely so revocation is one indexed write rather than a join.
 */
async function revokeTokensMatching(
  ctx: ResolvedContext,
  filter: Filter,
): Promise<number> {
  const res = await ctx.models.Token.updateMany(
    { ...filter, revokedAt: null },
    { $set: { revokedAt: new Date() } },
  );
  return res.modifiedCount ?? 0;
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

export function createClientsApi(ctx: ResolvedContext): ClientsApi {
  // A function declaration rather than a method on the object literal, because
  // this is the one member of the API that is overloaded — the confidential
  // default has to keep returning `clientSecret: string` while a public
  // registration returns a shape with no secret in it at all.
  function create(spec: CreateClientSpec & { type: 'public' }): Promise<CreatedPublicClient>;
  function create(spec: CreateClientSpec & { type?: 'confidential' }): Promise<CreatedConfidentialClient>;
  function create(spec: CreateClientSpec): Promise<CreatedClient>;
  async function create(spec: CreateClientSpec): Promise<CreatedClient> {
    if (!spec || typeof spec !== 'object') {
      throw new TypeError('oauth-host: clients.create(spec) requires a spec object');
    }
    const name = assertName(spec.name);
    const type = assertClientType(spec.type);
    const redirectUris = assertRedirectUris(spec.redirectUris);
    const allowedScopes = assertScopes(ctx, spec.allowedScopes);
    const allowedResources = assertResources(ctx, spec.allowedResources);

    const clientId = spec.clientId ?? generateClientId();
    // Not generated and then withheld — never generated. A secret that exists
    // anywhere for a public client is a credential `authenticateClient` would
    // refuse and an operator could still find in a log.
    const clientSecret = type === 'confidential' ? generateClientSecret() : undefined;

    const doc = await ctx.models.Client.create({
      clientId,
      name,
      type,
      registration: 'manual',
      trusted: Boolean(spec.trusted),
      // Only the digest is stored. `clientSecret` below is the only time the
      // raw value exists outside the caller's variable. Empty for a public
      // client, which is the same shape a CIMD row is written with.
      secrets: clientSecret
        ? [{ hash: sha256(clientSecret), label: 'initial', createdAt: new Date() }]
        : [],
      redirectUris,
      allowedScopes,
      allowedResources,
      branding: spec.branding ?? {},
      status: 'active',
    });

    await ctx.audit({ type: 'oauth.client_created', actor: 'admin', clientId, meta: { type } });

    return clientSecret
      ? { client: toPublicClient(doc), clientId, type: 'confidential', clientSecret }
      : { client: toPublicClient(doc), clientId, type: 'public' };
  }

  return {
    create,

    async rotateSecret(clientId, opts = {}): Promise<CreatedConfidentialClient> {
      const doc = await ctx.models.Client.findOne({ clientId });
      if (!doc) throw notFound(clientId);
      // An error, not a no-op. A public client has no secret by construction,
      // and handing the caller one would be worse than useless: the token
      // endpoint refuses a public client that presents a secret, so a
      // provisioning script would happily print a credential that breaks the
      // client the moment it is used.
      if (doc.type === 'public') {
        throw new Error(
          `oauth-host: client '${clientId}' is a public client and has no secret to rotate. `
          + 'Public clients authenticate with client_id and PKCE.',
        );
      }

      const retireAfter =typeof opts.retireAfter === 'number' && opts.retireAfter > 0 ? opts.retireAfter : 0;
      const retiresAt = new Date(Date.now() + retireAfter);

      // Two live secrets at once is the whole point: the operator deploys the
      // new one, watches `lastUsedAt` move, and only then finishes the rotation.
      // Never push an existing retirement later — an operator who already
      // scheduled a secret to die at noon does not expect a second rotation to
      // resurrect it until midnight.
      for (const record of doc.secrets) {
        record.retiresAt = record.retiresAt && record.retiresAt < retiresAt ? record.retiresAt : retiresAt;
      }

      const clientSecret = generateClientSecret();
      doc.secrets.push({
        hash: sha256(clientSecret),
        label: opts.label ?? `rotated-${new Date().toISOString()}`,
        createdAt: new Date(),
      });
      doc.markModified('secrets');
      await doc.save();

      ctx.track({ type: 'oauth.client_secret_rotated', clientId });
      await ctx.audit({
        type: 'oauth.client_secret_rotated',
        actor: 'admin',
        clientId,
        meta: { retireAfter, retiresAt },
      });

      return { client: toPublicClient(doc), clientId, type: 'confidential', clientSecret };
    },

    async update(clientId, patch): Promise<PublicClient> {
      const doc = await ctx.models.Client.findOne({ clientId });
      if (!doc) throw notFound(clientId);

      // Same validators as `create`. A field is only writable through the gate
      // that proved it at registration, or the second write is the hole.
      if (patch.name !== undefined) doc.name = assertName(patch.name);
      if (patch.redirectUris !== undefined) doc.redirectUris = assertRedirectUris(patch.redirectUris);
      if (patch.allowedScopes !== undefined) doc.allowedScopes = assertScopes(ctx, patch.allowedScopes);
      if (patch.allowedResources !== undefined) {
        doc.allowedResources = assertResources(ctx, patch.allowedResources);
      }
      if (patch.branding !== undefined) doc.branding = patch.branding;
      if (patch.trusted !== undefined) doc.trusted = Boolean(patch.trusted);

      await doc.save();
      await ctx.audit({ type: 'oauth.client_updated', actor: 'admin', clientId });
      return toPublicClient(doc);
    },

    async list(query = {}) {
      // Clamped BEFORE it reaches the query, so no caller-supplied value ever
      // becomes the ceiling — traps #18.
      const limit = clampLimit(query.limit);
      const skip = clampSkip(query.skip);
      const filter: Filter = {};
      if (query.status) filter.status = query.status;

      const docs = await ctx.models.Client.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean<OAuthClientDoc[]>();

      return { items: docs.map(toPublicClient), limit };
    },

    async get(clientId) {
      const doc = await ctx.models.Client.findOne({ clientId }).lean<OAuthClientDoc | null>();
      return doc ? toPublicClient(doc) : null;
    },

    async disable(clientId) {
      const doc = await ctx.models.Client.findOne({ clientId });
      if (!doc) throw notFound(clientId);

      doc.status = 'disabled';
      await doc.save();

      // Disabling without the cascade would leave every issued access token
      // valid until its own expiry — "revoke access" would mean "in an hour".
      const { grantsRevoked } = await revokeGrantsMatching(ctx, { clientId }, 'admin');
      const tokensRevoked = await revokeTokensMatching(ctx, { clientId });
      // Outstanding authorization codes are live credentials too, and unlike
      // tokens there is no revoked flag to set — they are single-use by design.
      await ctx.models.Code.deleteMany({ clientId });
      await ctx.models.Request.deleteMany({ clientId });

      // One audit row, not one per grant: a popular client holds thousands, and
      // a revocation storm in the audit log buries the event that caused it.
      await ctx.audit({
        type: 'oauth.client_disabled',
        actor: 'admin',
        clientId,
        meta: { grantsRevoked, tokensRevoked },
      });

      return { grantsRevoked, tokensRevoked };
    },
  };
}

// ---------------------------------------------------------------------------
// Client authentication (RFC 6749 §2.3.1)
// ---------------------------------------------------------------------------

/**
 * RFC 6749 §2.3.1 encodes the userid and password with the
 * `application/x-www-form-urlencoded` rules before base64ing them, which means
 * `+` is a space and `%xx` is a byte. Our own ids and secrets are base64url and
 * contain neither, but a client that follows the RFC literally will encode
 * anyway, and a server that skips the decode rejects a correct credential.
 */
function formUrlDecode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    // A malformed escape is not a credential; let it fail the comparison rather
    // than throw a URIError out of the middle of authentication.
    return value;
  }
}

interface ClientCredentials {
  clientId: string;
  /** `null` means no secret was presented at all — which is a public client's whole story. */
  clientSecret: string | null;
  viaBasic: boolean;
}

function readCredentials(req: Request): ClientCredentials | null {
  const header = req.headers?.authorization;
  if (typeof header === 'string' && /^Basic /i.test(header)) {
    const decoded = Buffer.from(header.slice(6).trim(), 'base64').toString('utf8');
    // Split on the FIRST colon only: a userid may not contain one, a password may.
    const sep = decoded.indexOf(':');
    const clientId = formUrlDecode(sep < 0 ? decoded : decoded.slice(0, sep));
    const secret = sep < 0 ? '' : formUrlDecode(decoded.slice(sep + 1));
    // An empty password is "no secret", not "the empty secret". Some clients
    // send `Basic base64(client_id:)` for `token_endpoint_auth_method=none`.
    return { clientId, clientSecret: secret === '' ? null : secret, viaBasic: true };
  }

  const body = (req.body ?? {}) as { client_id?: unknown; client_secret?: unknown };
  if (typeof body.client_id === 'string' && body.client_id) {
    return {
      clientId: body.client_id,
      clientSecret: typeof body.client_secret === 'string' && body.client_secret
        ? body.client_secret
        : null,
      viaBasic: false,
    };
  }
  return null;
}

/**
 * One error for every failure mode.
 *
 * An unknown client id, a wrong secret, a retired secret and a disabled client
 * all produce this exact object. Distinguishing them turns the token endpoint
 * into a client-id oracle, and the extra detail helps an attacker strictly more
 * than it helps an integrator — who has the audit log.
 */
function authFailure(viaBasic: boolean): OAuthError {
  return new OAuthError(401, 'invalid_client', 'client authentication failed', {
    // RFC 6749 §5.2 — a 401 answering a Basic credential MUST carry the challenge.
    headers: viaBasic ? { 'WWW-Authenticate': 'Basic realm="oauth", charset="UTF-8"' } : {},
  });
}

/**
 * RFC 6749 §2.3.1 — `client_secret_basic` (the `Authorization` header) or
 * `client_secret_post` (the body). Basic wins when both are present, because a
 * client that sends both and disagrees with itself is a bug we should not
 * paper over by picking the one that happens to verify.
 *
 * **Public clients authenticate by presenting `client_id` alone**
 * (`token_endpoint_auth_method=none`), with PKCE standing in for the secret.
 * The two rules that make that safe are symmetric and neither is optional:
 *
 *   public       MUST NOT present a secret
 *   confidential MUST present one
 *
 * The second is the attack. If a confidential client could authenticate by
 * simply omitting its secret, every registration in the database would be
 * downgradeable to public by anyone who knows a `client_id` — which is a public
 * value. Both violations produce the identical failure object, so neither is an
 * oracle for which kind of client an id names.
 */
export async function authenticateClient(
  ctx: ResolvedContext,
  req: Request,
): Promise<OAuthClientDoc> {
  const creds = readCredentials(req);
  if (!creds || !creds.clientId) throw authFailure(Boolean(creds?.viaBasic));

  const client = await ctx.models.Client.findOne({ clientId: creds.clientId });
  if (!client || client.status !== 'active') throw authFailure(creds.viaBasic);

  if (client.type === 'public') {
    // Refused, not ignored. A secret presented for a client that has none means
    // the caller believes something false about this registration, and the
    // charitable reading (a copy-pasted confidential config) still ends with a
    // client whose operator thinks a secret is protecting them.
    if (creds.clientSecret !== null) throw authFailure(creds.viaBasic);
    return client;
  }

  if (creds.clientSecret === null) throw authFailure(creds.viaBasic);

  const now = Date.now();
  let matched: (typeof client.secrets)[number] | undefined;
  for (const record of client.secrets) {
    // A retired secret is gone the instant `retiresAt` passes. That is what
    // makes `rotateSecret` a real cutover rather than an extra key that lives
    // forever because nobody remembered to remove it.
    if (record.retiresAt && record.retiresAt.getTime() <= now) continue;
    // No early exit: the loop runs the same number of comparisons whichever
    // secret matches, so the response time does not say which one it was.
    if (safeEqual(sha256(creds.clientSecret), record.hash)) matched = record;
  }
  if (!matched) throw authFailure(creds.viaBasic);

  // The whole reason `lastUsedAt` exists: it is how an operator knows the new
  // secret is actually in use and the rotation is safe to finish. A targeted
  // positional update, not a full `save()` — this runs on every token request.
  const usedAt = new Date();
  matched.lastUsedAt = usedAt;
  await ctx.models.Client.updateOne(
    { clientId: client.clientId, 'secrets.hash': matched.hash },
    { $set: { 'secrets.$.lastUsedAt': usedAt } },
  );

  return client;
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

/** A grant references scope ids; a "connected apps" screen needs the catalog entry. */
function describeGrantScopes(ctx: ResolvedContext, ids: string[]): ScopeSpec[] {
  // A scope can leave the catalog while a live grant still references it. Fall
  // back to a bare spec rather than dropping the row — a connected-apps screen
  // missing a line understates what the client can still do.
  return ids.map((id) => ctx.scopeIndex.get(id) ?? { id, label: id });
}

export function createGrantsApi(ctx: ResolvedContext): GrantsApi {
  return {
    async list(query) {
      const limit = clampLimit(query?.limit);
      const skip = clampSkip(query?.skip);

      const filter: Filter = { revokedAt: null };
      if (query?.userId !== undefined) filter.userId = query.userId;
      if (query?.clientId !== undefined) filter.clientId = query.clientId;

      const grants = await ctx.models.Grant.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean<OAuthGrantDoc[]>();

      if (grants.length === 0) return { items: [], limit };

      // One query for the whole page. The alternative is a client lookup per
      // row, which is the N+1 that makes a twenty-row screen feel broken.
      const clientIds = [...new Set(grants.map((g) => g.clientId))];
      const clients = await ctx.models.Client.find({ clientId: { $in: clientIds } })
        .lean<OAuthClientDoc[]>();
      const byId = new Map(clients.map((c) => [c.clientId, toPublicClient(c)]));

      // Context labels come from the host's adapter, which is keyed by user and
      // client — so cache per pair rather than asking once per grant.
      const contextCache = new Map<string, GrantContext[]>();
      const items: GrantSummary[] = [];

      for (const grant of grants) {
        const client = byId.get(grant.clientId);
        const summary: GrantSummary = {
          id: String(grant._id),
          client: client
            ? { clientId: client.clientId, name: client.name, branding: client.branding }
            // A grant can outlive a hard-deleted client row. Naming the id beats
            // rendering a blank card the user cannot act on.
            : { clientId: grant.clientId, name: grant.clientId, branding: {} },
          scopes: describeGrantScopes(ctx, grant.scopes ?? []),
          createdAt: grant.createdAt,
          ...(grant.lastUsedAt ? { lastUsedAt: grant.lastUsedAt } : {}),
        };

        // Single-subject mode omits the key entirely — not `undefined`, absent.
        // A host that never configured `grantContext` should never see the word.
        if (ctx.grantContext && grant.contextId) {
          const cacheKey = `${String(grant.userId)}:${grant.clientId}`;
          let available = contextCache.get(cacheKey);
          if (!available) {
            // The adapter takes a user, and all we hold is the id the grant was
            // stored with. That is enough for a membership lookup; the package
            // has no user collection to hydrate from and must not grow one.
            const user = { id: grant.userId } as PackageUser;
            available = client
              ? await ctx.grantContext.list(user, { client, scopes: grant.scopes ?? [] })
              : [];
            contextCache.set(cacheKey, available);
          }
          summary.context = available.find((c) => c.id === grant.contextId)
            // Membership may already have ended, which is exactly when the user
            // most wants to see the row. Show the id rather than hiding it.
            ?? { id: grant.contextId, label: grant.contextId };
        }

        items.push(summary);
      }

      return { items, limit };
    },

    async revoke(grantId, opts = {}) {
      const by = opts.by ?? 'admin';
      const grant = await ctx.models.Grant.findById(grantId).catch(() => null);
      // Idempotent, and tolerant of an id that no longer resolves: `users.forget`
      // deletes grants outright, so a revoke arriving after an erasure is a
      // no-op rather than an error.
      if (!grant) return { tokensRevoked: 0 };

      const alreadyRevoked = Boolean(grant.revokedAt);
      if (!alreadyRevoked) {
        grant.revokedAt = new Date();
        grant.revokedBy = by;
        await grant.save();
      }

      // Run the token sweep even on a repeat call: a token issued in the window
      // between the first revocation and this one would otherwise survive it.
      const tokensRevoked = await revokeTokensMatching(ctx, { grantId: grant._id });

      if (!alreadyRevoked) {
        ctx.track({
          type: 'oauth.grant_revoked',
          userId: grant.userId,
          clientId: grant.clientId,
          grantId: String(grant._id),
          ...(grant.contextId ? { contextId: grant.contextId } : {}),
          scopes: grant.scopes,
        });
        await ctx.audit({
          type: 'oauth.grant_revoked',
          actor: by,
          clientId: grant.clientId,
          userId: grant.userId,
          grantId: grant._id,
          meta: { tokensRevoked },
        });
      }

      return { tokensRevoked };
    },
  };
}

// ---------------------------------------------------------------------------
// Users — the outbound direction of the user adapter
// ---------------------------------------------------------------------------

/**
 * A pairwise subject lives at `pairwiseSubjects.<userId>` inside the client
 * document, so erasing one means an `$unset` on a computed path. Mongo treats
 * `.` as a path separator and `$` as an operator prefix, so a host whose user
 * ids contain either would have us unset something else entirely.
 */
function pairwiseKey(userId: UserId): string | null {
  const key = String(userId);
  if (!key || key.includes('.') || key.startsWith('$')) return null;
  return key;
}

export function createUsersApi(ctx: ResolvedContext): UsersApi {
  return {
    /**
     * Erasure. The user is gone and every trace of them has to go with them.
     *
     * This is the destructive twin of `revokeAll`, and the difference is the
     * whole reason both exist: `forget` DELETES the grant documents and the
     * user's audit rows, `revokeAll` keeps both. A password change must leave a
     * history an operator can read; a deletion request must not.
     *
     * Idempotent — it will be called twice, by a retry or by a host that wires
     * it to both a soft-delete and a hard-delete hook.
     */
    async forget(userId) {
      const grantsResult = await ctx.models.Grant.deleteMany({ userId });
      const tokensResult = await ctx.models.Token.deleteMany({ userId });
      await ctx.models.Code.deleteMany({ userId });
      await ctx.models.Request.deleteMany({ userId });

      // The pairwise subject is a pseudonym for this user held inside a client's
      // document. Leaving it behind means the erased user is still addressable
      // by the one identifier a partner stored.
      const key = pairwiseKey(userId);
      if (key) {
        await ctx.models.Client.updateMany(
          { [`pairwiseSubjects.${key}`]: { $exists: true } },
          { $unset: { [`pairwiseSubjects.${key}`]: '' } },
        );
      }

      await ctx.models.Audit.deleteMany({ userId });

      const grants = grantsResult.deletedCount ?? 0;
      const tokens = tokensResult.deletedCount ?? 0;

      // ONE tombstone, naming no personal data — no userId, no client, no
      // scopes. It exists to prove the erasure ran, which is the only thing an
      // auditor may still ask after the subject is gone.
      await ctx.audit({ type: 'oauth.user_forgotten', actor: 'system', meta: { grants, tokens } });

      return { grants, tokens };
    },

    /**
     * Password change, deactivation, suspected compromise.
     *
     * Kills live access and KEEPS everything else: the grant documents stay so
     * the audit trail still resolves and so the user's connected apps remain
     * visible, and the audit rows stay because that is the record the operator
     * called this to create. See `forget` above for the destructive twin.
     */
    async revokeAll(userId, opts = {}) {
      // Read the ids first: the events below are per-grant, and a user's grant
      // count is bounded by how many apps they connected — a handful, not the
      // unbounded set `clients.disable` faces.
      const live = await ctx.models.Grant.find({ userId, revokedAt: null })
        .limit(MAX_LIST)
        .lean<OAuthGrantDoc[]>();

      const { grantsRevoked } = await revokeGrantsMatching(ctx, { userId }, 'system');
      const tokensRevoked = await revokeTokensMatching(ctx, { userId });
      // Codes are single-use credentials with no revoked flag to set.
      await ctx.models.Code.deleteMany({ userId });
      await ctx.models.Request.deleteMany({ userId });

      for (const grant of live) {
        ctx.track({
          type: 'oauth.grant_revoked',
          userId,
          clientId: grant.clientId,
          grantId: String(grant._id),
          ...(grant.contextId ? { contextId: grant.contextId } : {}),
          scopes: grant.scopes,
        });
      }

      await ctx.audit({
        type: 'oauth.user_access_revoked',
        actor: 'system',
        userId,
        meta: { grantsRevoked, tokensRevoked, ...(opts.reason ? { reason: opts.reason } : {}) },
      });

      return { grantsRevoked, tokensRevoked };
    },
  };
}

// ---------------------------------------------------------------------------
// Contexts — membership ended
// ---------------------------------------------------------------------------

export function createContextsApi(ctx: ResolvedContext): ContextsApi {
  return {
    /**
     * A grant made as an employee has to die when the employment does.
     *
     * `grantContext.verify()` catches this on the next refresh, but an access
     * token already issued is valid for its full hour and nothing re-checks it.
     * This is the push half of that pair, and it is why the adapter has an
     * outbound direction at all.
     */
    async revoked(userId, contextId) {
      const live = await ctx.models.Grant.find({ userId, contextId, revokedAt: null })
        .limit(MAX_LIST)
        .lean<OAuthGrantDoc[]>();

      const { grantsRevoked } = await revokeGrantsMatching(ctx, { userId, contextId }, 'system');
      // Tokens carry `contextId` denormalized, so this is one indexed write
      // rather than a lookup per grant.
      const tokensRevoked = await revokeTokensMatching(ctx, { userId, contextId });
      await ctx.models.Code.deleteMany({ userId, contextId });

      for (const grant of live) {
        ctx.track({
          type: 'oauth.grant_revoked',
          userId,
          clientId: grant.clientId,
          grantId: String(grant._id),
          contextId,
          scopes: grant.scopes,
        });
        await ctx.audit({
          type: 'oauth.grant_revoked',
          actor: 'system',
          clientId: grant.clientId,
          userId,
          grantId: grant._id,
          meta: { contextId, reason: 'context_membership_ended' },
        });
      }

      return { grantsRevoked, tokensRevoked };
    },
  };
}
