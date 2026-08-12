import { UnredirectableError } from '../errors.js';
import type { CimdHostRule, ResolvedContext } from '../config.js';
import type { ClientBranding, OAuthClientDoc } from '../../../types/index.js';

/**
 * Client ID Metadata Documents — a `client_id` that is an `https://` URL
 * serving the registration it names.
 *
 * **Read this before changing anything below.** Every other file in this
 * package reacts to input; this one goes and gets some. The authorization
 * server issues an outbound HTTP request whose destination comes from an
 * unauthenticated query parameter, which is server-side request forgery by
 * construction. The allowlist in `clientIdMetadata.allowedHosts` contains most
 * of the risk, and the rest of the defenses exist because an allowlist alone
 * has been enough to lose before:
 *
 * - `https:` only, checked before a socket is opened.
 * - Hostname matched by EQUALITY against the allowlist, not by suffix.
 *   `evilclaude.ai` must never match an entry of `claude.ai`.
 * - **Redirects are not followed.** A 3xx is a failure, not a hop — following
 *   one is how an allowlisted host becomes an open proxy to everything else,
 *   including link-local metadata services.
 * - No URL credentials, no fragment, no non-default port unless the entry
 *   names one.
 * - A hard timeout, and a body cap enforced while reading rather than by
 *   trusting `Content-Length`.
 * - **Failures are cached too.** Without negative caching a hostile
 *   `client_id` can be replayed to make this server hammer a third party, and
 *   the authorization endpoint becomes a traffic amplifier.
 *
 * Successful resolutions are persisted in `oauth_clients`, so the cache
 * survives a restart. An in-memory-only cache would mean every process boot
 * re-fetches for every in-flight authorization.
 */

/**
 * How long a failed fetch is remembered. Deliberately much shorter than
 * `cacheTtlMs`: a client fixing a broken document should not wait an hour, but
 * a minute is long enough that a replayed `client_id` cannot be a load
 * generator.
 */
const NEGATIVE_TTL_MS = 60_000;

/** Bound on the negative cache. The key is attacker-chosen, so it cannot grow freely. */
const MAX_REMEMBERED_FAILURES = 1_000;

/**
 * Every refusal is the same class the authorization endpoint already uses for
 * an unknown `client_id`, and for the same reason: we have not validated a
 * `redirect_uri`, so there is nowhere proven safe to report the error to.
 * Rendering it is the only option. See `errors.ts`.
 */
function refuse(description: string): UnredirectableError {
  return new UnredirectableError('invalid_client', description);
}

/** A `client_id` shaped like a metadata document URL. Cheap, and does no I/O. */
export function isMetadataUrl(clientId: string): boolean {
  return /^https:\/\//i.test(clientId);
}

// ---------------------------------------------------------------------------
// Before any network call
// ---------------------------------------------------------------------------

function hostAllowed(rules: CimdHostRule[], url: URL): boolean {
  const hostname = url.hostname.toLowerCase();
  return rules.some((rule) => {
    // `URL.port` is `''` for the scheme default, so this also enforces "no
    // non-default port unless the allowlist entry names one".
    if (url.port !== rule.port) return false;
    if (hostname === rule.host) return true;
    return rule.subdomains && hostname.endsWith(`.${rule.host}`);
  });
}

/**
 * Turn a `client_id` into a URL we are willing to fetch, or throw.
 *
 * Everything here runs before a single byte leaves the process — that ordering
 * is the point, and it is what the "no fetch attempted" tests assert.
 */
export function assertFetchableUrl(ctx: ResolvedContext, clientId: string): URL {
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    throw refuse(`client_id is not a valid URL: '${clientId}'`);
  }
  if (url.protocol !== 'https:') {
    throw refuse(`client_id metadata must be served over https (got '${url.protocol}')`);
  }
  // `https://user:pass@allowed.host@evil.host/` and friends. Credentials in a
  // fetched URL have no legitimate use here and are a parser-differential
  // primitive, so they are refused rather than stripped.
  if (url.username || url.password) {
    throw refuse('client_id must not contain URL credentials');
  }
  // A fragment is never sent on the wire, so a client_id carrying one is a
  // second identifier for the same document — and two identifiers for one
  // registration means two client rows.
  if (url.hash) {
    throw refuse('client_id must not contain a fragment');
  }
  if (!hostAllowed(ctx.cimd.allowedHosts, url)) {
    throw refuse(`client_id host '${url.host}' is not in clientIdMetadata.allowedHosts`);
  }
  return url;
}

// ---------------------------------------------------------------------------
// The fetch
// ---------------------------------------------------------------------------

/** RFC 8259 media types, and the `+json` structured suffix. */
const JSON_CONTENT_TYPE = /^application\/(?:[\w.+-]+\+)?json\s*(?:;|$)/i;

/**
 * Read the body, aborting past the cap.
 *
 * `Content-Length` is a claim by the server we are defending against, so the
 * cap is enforced against bytes actually received. A missing or lying header
 * changes nothing.
 */
async function readCapped(res: Response, maxBytes: number): Promise<string> {
  const body = res.body;
  if (!body) throw refuse('client_id metadata document was empty');

  const reader = body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > maxBytes) {
      // Stop pulling immediately: the point of the cap is not to reject a big
      // document afterwards, it is not to buffer one.
      void reader.cancel();
      throw refuse(`client_id metadata document exceeds ${maxBytes} bytes`);
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks).toString('utf8');
}

interface FetchOutcome {
  /** `null` when the server answered 304 and the cached registration still stands. */
  document: Record<string, unknown> | null;
  etag?: string;
}

async function fetchMetadata(
  ctx: ResolvedContext,
  url: URL,
  etag: string | undefined,
): Promise<FetchOutcome> {
  let res: Response;
  try {
    res = await fetch(url.toString(), {
      method: 'GET',
      // The single most important line in this file. A 3xx is a failure below,
      // not a hop: following redirects would let an allowlisted host forward us
      // to any address it likes, allowlist intact.
      redirect: 'manual',
      headers: {
        accept: 'application/json',
        ...(etag ? { 'if-none-match': etag } : {}),
      },
      signal: AbortSignal.timeout(ctx.cimd.fetchTimeoutMs),
    });
  } catch (err) {
    const name = (err as { name?: string })?.name;
    if (name === 'TimeoutError' || name === 'AbortError') {
      throw refuse(`client_id metadata fetch timed out after ${ctx.cimd.fetchTimeoutMs}ms`);
    }
    throw refuse(`client_id metadata could not be fetched: ${(err as Error)?.message ?? 'network error'}`);
  }

  // Answered by `If-None-Match` — the document has not changed and the row we
  // already hold is still the registration.
  if (res.status === 304) return { document: null };

  if (res.status >= 300 && res.status < 400) {
    throw refuse(
      `client_id metadata returned a ${res.status} redirect, which is not followed — `
      + 'serve the document at the client_id URL itself',
    );
  }
  if (res.status !== 200) {
    throw refuse(`client_id metadata returned HTTP ${res.status}`);
  }

  const contentType = res.headers.get('content-type') ?? '';
  if (!JSON_CONTENT_TYPE.test(contentType)) {
    throw refuse(`client_id metadata must be JSON (got content-type '${contentType || 'none'}')`);
  }

  const text = await readCapped(res, ctx.cimd.maxBytes);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw refuse('client_id metadata document is not valid JSON');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw refuse('client_id metadata document must be a JSON object');
  }

  return {
    document: parsed as Record<string, unknown>,
    ...(res.headers.get('etag') ? { etag: res.headers.get('etag') as string } : {}),
  };
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

export interface CimdRegistration {
  name: string;
  redirectUris: string[];
  allowedScopes: string[];
  branding: ClientBranding;
}

function requireString(doc: Record<string, unknown>, field: string): string {
  const value = doc[field];
  if (typeof value !== 'string' || !value.trim()) {
    throw refuse(`client_id metadata field '${field}' must be a non-empty string`);
  }
  return value.trim();
}

/**
 * A branding URL that reaches the host's consent screen as an attribute.
 *
 * `javascript:` and `data:` are the reason this is a check and not a copy: the
 * host renders `logoUrl` into an `<img src>` and `homepageUrl` into an `href`,
 * and this package is the last place that can refuse the scheme.
 */
function optionalHttpsUri(doc: Record<string, unknown>, field: string): string | undefined {
  const value = doc[field];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string' || !value.trim()) {
    throw refuse(`client_id metadata field '${field}' must be a string`);
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw refuse(`client_id metadata field '${field}' must be an absolute URL: '${value}'`);
  }
  if (url.protocol !== 'https:') {
    throw refuse(`client_id metadata field '${field}' must be https (got '${url.protocol}')`);
  }
  return value;
}

/**
 * `http` on loopback and nowhere else — the same rule `clients.create` applies
 * to a manually registered client, because connector development genuinely runs
 * against `http://localhost` and a package that forbids it gets worked around.
 */
function assertRedirectUris(doc: Record<string, unknown>): string[] {
  const value = doc.redirect_uris;
  if (!Array.isArray(value) || value.length === 0) {
    throw refuse("client_id metadata field 'redirect_uris' must be a non-empty array");
  }
  return value.map((entry) => {
    if (typeof entry !== 'string' || !entry) {
      throw refuse(`client_id metadata 'redirect_uris' entries must be strings (got ${JSON.stringify(entry)})`);
    }
    let url: URL;
    try {
      url = new URL(entry);
    } catch {
      throw refuse(`client_id metadata 'redirect_uris' entry must be an absolute URI: '${entry}'`);
    }
    const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
      throw refuse(
        `client_id metadata 'redirect_uris' entry must be https `
        + `(http is allowed only on localhost/127.0.0.1): '${entry}'`,
      );
    }
    // RFC 6749 §3.1.2 — the authorization response appends its own parameters,
    // and a fragment already present makes what the client receives undefined.
    if (url.hash) {
      throw refuse(`client_id metadata 'redirect_uris' entry must not contain a fragment: '${entry}'`);
    }
    return entry;
  });
}

/**
 * Validate a fetched document against the URL it came from.
 *
 * The `client_id` equality check is the whole binding. Without it any
 * allowlisted host could serve a document claiming to be any other client, and
 * "the client_id is the URL" would stop meaning anything.
 */
export function validateMetadataDocument(
  ctx: ResolvedContext,
  url: URL,
  doc: Record<string, unknown>,
): CimdRegistration {
  const declared = requireString(doc, 'client_id');
  let declaredUrl: URL;
  try {
    declaredUrl = new URL(declared);
  } catch {
    throw refuse(`client_id metadata field 'client_id' is not a URL: '${declared}'`);
  }
  if (declaredUrl.href !== url.href) {
    throw refuse(
      `client_id metadata field 'client_id' is '${declared}', which is not the URL it was `
      + `fetched from ('${url.href}')`,
    );
  }

  const method = doc.token_endpoint_auth_method;
  if (method !== undefined && method !== 'none') {
    throw refuse(
      `client_id metadata field 'token_endpoint_auth_method' must be 'none' `
      + `(got ${JSON.stringify(method)}) — a CIMD client holds no secret`,
    );
  }

  // Required, not optional-with-a-fallback: a client with no name cannot be
  // meaningfully consented to, and defaulting it to the URL puts a hostname in
  // front of a user being asked to trust something.
  const name = requireString(doc, 'client_name');
  const redirectUris = assertRedirectUris(doc);

  // The document narrows; it never widens. A scope the host does not have is
  // dropped rather than refused — a client asking for more than this
  // deployment offers is normal, and the intersection is the honest answer.
  const permitted = new Set(ctx.cimd.allowedScopes.filter((id) => ctx.scopeIndex.has(id)));
  let allowedScopes: string[];
  if (doc.scope === undefined || doc.scope === null) {
    allowedScopes = [...permitted];
  } else {
    if (typeof doc.scope !== 'string') {
      throw refuse("client_id metadata field 'scope' must be a space-delimited string");
    }
    const requested = new Set(doc.scope.split(/\s+/).filter(Boolean));
    allowedScopes = [...permitted].filter((id) => requested.has(id));
  }
  if (allowedScopes.length === 0) {
    throw refuse(
      "client_id metadata field 'scope' has no overlap with what this server offers — "
      + 'there is nothing this client could be granted',
    );
  }

  const branding: ClientBranding = {};
  const logoUrl = optionalHttpsUri(doc, 'logo_uri');
  const homepageUrl = optionalHttpsUri(doc, 'client_uri');
  const tosUrl = optionalHttpsUri(doc, 'tos_uri');
  const privacyUrl = optionalHttpsUri(doc, 'policy_uri');
  if (logoUrl) branding.logoUrl = logoUrl;
  if (homepageUrl) branding.homepageUrl = homepageUrl;
  if (tosUrl) branding.tosUrl = tosUrl;
  if (privacyUrl) branding.privacyUrl = privacyUrl;

  return { name, redirectUris, allowedScopes, branding };
}

// ---------------------------------------------------------------------------
// Caching and persistence
// ---------------------------------------------------------------------------

function rememberFailure(ctx: ResolvedContext, key: string, message: string): void {
  const { failures } = ctx.cimd;
  // Insertion-ordered, so the first key is the oldest. Cheap enough for a cache
  // whose whole job is to be small.
  if (failures.size >= MAX_REMEMBERED_FAILURES) {
    const oldest = failures.keys().next();
    if (!oldest.done) failures.delete(oldest.value);
  }
  failures.set(key, { until: Date.now() + NEGATIVE_TTL_MS, message });
}

function rememberedFailure(ctx: ResolvedContext, key: string): string | null {
  const found = ctx.cimd.failures.get(key);
  if (!found) return null;
  if (found.until <= Date.now()) {
    ctx.cimd.failures.delete(key);
    return null;
  }
  return found.message;
}

function isFresh(ctx: ResolvedContext, client: OAuthClientDoc): boolean {
  const fetchedAt = client.metadataFetchedAt?.getTime();
  if (fetchedAt === undefined) return false;
  return Date.now() - fetchedAt < ctx.cimd.cacheTtlMs;
}

/**
 * Write the registration back.
 *
 * `status` is absent from `$set` on purpose and that absence is load-bearing:
 * an operator who ran `clients.disable()` on a CIMD client must not have it
 * quietly reactivated the next time its document is re-fetched. `$setOnInsert`
 * gives a brand-new row `active`; nothing ever sets it back.
 */
async function persist(
  ctx: ResolvedContext,
  clientId: string,
  url: URL,
  registration: CimdRegistration,
  etag: string | undefined,
): Promise<OAuthClientDoc> {
  const doc = await ctx.models.Client.findOneAndUpdate(
    { clientId },
    {
      $set: {
        name: registration.name,
        redirectUris: registration.redirectUris,
        allowedScopes: registration.allowedScopes,
        // Every declared resource. A CIMD client cannot express an audience
        // preference, and RFC 8707 validation at `/authorize` narrows it anyway.
        allowedResources: ctx.resources.map((r) => r.id),
        branding: registration.branding,
        metadataUrl: url.href,
        metadataFetchedAt: new Date(),
        ...(etag ? { metadataEtag: etag } : {}),
      },
      $setOnInsert: {
        type: 'public',
        registration: 'cimd',
        trusted: false,
        secrets: [],
        status: 'active',
      },
    },
    { upsert: true, returnDocument: 'after', setDefaultsOnInsert: false },
  ).exec();

  return doc as OAuthClientDoc;
}

// ---------------------------------------------------------------------------

/**
 * Resolve a URL-shaped `client_id` into a client registration.
 *
 * Called from `validateAuthorizationRequest` only, and only when CIMD is
 * enabled. Every failure is an `UnredirectableError`, exactly like an unknown
 * `client_id`: at this point in the flow no `redirect_uri` has been validated,
 * so there is no address proven safe to report an error to.
 */
export async function resolveCimdClient(
  ctx: ResolvedContext,
  clientId: string,
): Promise<OAuthClientDoc> {
  const url = assertFetchableUrl(ctx, clientId);

  const existing = await ctx.models.Client.findOne({ clientId }).exec();
  if (existing) {
    // Checked before anything else, and before any fetch: a disabled client is
    // an answer, not a cache miss. This is the one ordering that makes
    // `clients.disable()` stick on a registration that re-derives itself.
    if (existing.status !== 'active') {
      throw refuse(`client '${clientId}' is disabled`);
    }
    // A manually registered client that happens to have a URL id is a
    // deliberate operator override. Use it and never fetch.
    if (existing.registration !== 'cimd') return existing;
    if (isFresh(ctx, existing)) return existing;
  }

  const remembered = rememberedFailure(ctx, url.href);
  if (remembered) throw refuse(remembered);

  try {
    const { document, etag } = await fetchMetadata(ctx, url, existing?.metadataEtag);
    if (!document) {
      // 304. The document is unchanged, so only the freshness stamp moves —
      // without it every request past the TTL would re-ask.
      if (existing) {
        existing.metadataFetchedAt = new Date();
        await existing.save();
        return existing;
      }
      throw refuse('client_id metadata returned 304 with nothing cached to answer from');
    }
    const registration = validateMetadataDocument(ctx, url, document);
    const client = await persist(ctx, clientId, url, registration, etag);
    ctx.logger.debug?.({ clientId }, 'oauth-host: client_id metadata document resolved');
    return client;
  } catch (err) {
    const message = err instanceof UnredirectableError
      ? (err.description ?? 'client_id metadata could not be resolved')
      : 'client_id metadata could not be resolved';
    // Cache the failure. Without this a hostile client_id replayed in a loop
    // turns `/authorize` into an outbound traffic amplifier pointed at whatever
    // allowlisted host is having a bad day.
    rememberFailure(ctx, url.href, message);
    ctx.logger.warn?.({ clientId, err }, 'oauth-host: client_id metadata resolution failed');
    throw err instanceof UnredirectableError ? err : refuse(message);
  }
}
