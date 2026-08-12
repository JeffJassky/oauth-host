import type { Request } from 'express';
import { createModels } from './models.js';
import type {
  ClaimsAdapter,
  ClientIdMetadataConfig,
  CreateOAuthHostConfig,
  GrantContextAdapter,
  Logger,
  OAuthAuditDoc,
  OAuthEvent,
  OAuthModels,
  PackageUser,
  RateLimitConfig,
  LoadUser,
  ResolveUser,
  ResourceSpec,
  ScopeSpec,
  SigningConfig,
  TtlConfig,
  UserAdapter,
} from '../../types/index.js';

/**
 * Config normalization — the single place raw host config becomes the shape
 * every route and service consumes. Nothing downstream re-implements a default.
 *
 * Validation here is deliberately fatal and specific. This package's failure
 * mode is a partner integration that half-works six weeks later, so a bad
 * `issuer` or an unknown scope in a client's `allowedScopes` has to be a boot
 * error with the offending value in the message.
 *
 * If you rename this file, note it is called `config.ts` on purpose and that a
 * bare `config.js`/`config.ts` in a global gitignore silently deletes it from
 * the repo. Run `npm run check-tracked` before the first push — traps #1.
 */

const NOOP_LOGGER: Logger = {
  debug() {},
  info() {},
  warn() {},
  error() {},
};

export const DEFAULT_TTL: Required<TtlConfig> = {
  code: 60,
  accessToken: 3600,
  refreshToken: 60 * 86_400,
  refreshAbsolute: 180 * 86_400,
  authorizationRequest: 600,
};

/** OIDC scopes the package understands without a `claims` adapter. */
export const OIDC_SCOPES = new Set(['openid', 'profile', 'email']);

export interface ResolvedRateLimits {
  token: { max: number; windowMs: number } | false;
  authorize: { max: number; windowMs: number } | false;
  consent: { max: number; windowMs: number } | false;
  hit(key: string, windowMs: number): Promise<{ count: number; resetAt: number }>;
}

/**
 * One parsed `allowedHosts` entry.
 *
 * Kept as structure rather than a string so the match is an equality test, not
 * a suffix test: `evilclaude.ai`.endsWith(`claude.ai`) is true, and that is the
 * bug this shape exists to make unwritable.
 */
export interface CimdHostRule {
  /** Lowercased hostname, no leading dot. */
  host: string;
  /** Matched against `URL.port` — `''` means "the scheme default, and only that". */
  port: string;
  /** Entry was written as `.example.com`, so subdomains are admitted too. */
  subdomains: boolean;
}

export interface ResolvedCimd {
  enabled: boolean;
  allowedHosts: CimdHostRule[];
  cacheTtlMs: number;
  fetchTimeoutMs: number;
  maxBytes: number;
  allowedScopes: string[];
  /**
   * Negative cache: URL → why it failed and until when.
   *
   * State on a config object is unusual, and it lives here for a reason — it
   * has to be per-instance so two hosts in one process cannot poison each
   * other, and a module-level map would do exactly that. Bounded, because the
   * key is a request parameter an attacker chooses.
   */
  failures: Map<string, { until: number; message: string }>;
}

export interface ResolvedContext {
  models: OAuthModels;
  issuer: string;
  /** Mount path of `routes.oauth`, normalized to a leading slash and no trailing one. */
  mountPath: string;
  resources: ResourceSpec[];
  scopes: ScopeSpec[];
  /** `id` → spec. Every scope lookup goes through this, never a linear scan. */
  scopeIndex: Map<string, ScopeSpec>;
  consentUrl: string;
  loginUrl?: string;
  returnParam: string;

  resolveUser: ResolveUser;
  /**
   * Resolve a user the package only has an id for. Always returns something:
   * with no `loadUser` adapter the caller still gets `{ id }`, so `/userinfo`
   * answers a valid (if bare) document rather than 500ing.
   */
  loadUser(userId: PackageUser['id']): Promise<PackageUser>;
  grantContext?: GrantContextAdapter;
  claims?: ClaimsAdapter;

  ttl: Required<TtlConfig>;
  subjectMode: 'public' | 'pairwise';
  pairwiseSalt?: string;
  signing: SigningConfig;
  rateLimits: ResolvedRateLimits;
  tokenCacheTtlMs: number;
  cors: { tokenEndpoint: boolean; origins: string[] };
  clockSkewMs: number;
  cimd: ResolvedCimd;

  logger: Logger;
  track: (event: OAuthEvent) => void;
  /** Append-only. Never throws into a request — an audit failure is logged. */
  audit(entry: Partial<OAuthAuditDoc> & { type: string }): Promise<void>;
}

/**
 * Default user resolution.
 *
 * Reads the conventional spots an upstream auth middleware leaves things:
 * `req.user` (passport) then `req.authUserId`. Hosts using another convention
 * pass their own `resolveUser`.
 *
 * Pure read. Never verify a token in here — it runs on every request through
 * `/authorize` and `/consent`, and a throw becomes a 500 where the host wanted
 * a clean redirect to the login page.
 *
 * The properties read off `req` are written by the HOST's middleware, so they
 * are not on Express's `Request` type. Narrow through a local shape rather than
 * augmenting the global namespace — a library that declares into the host's
 * types leaks its assumptions into the host's own typechecks.
 */
interface AuthedRequestish {
  authUserId?: PackageUser['id'];
  user?: {
    _id?: PackageUser['id'];
    id?: PackageUser['id'];
    email?: string;
    displayName?: string | null;
    avatarUrl?: string | null;
    authTime?: Date;
    isAdmin?: boolean;
  };
}

export function defaultResolveUser(req: Request): PackageUser | null {
  const { authUserId, user } = req as Request & AuthedRequestish;
  const id = user?._id ?? user?.id ?? authUserId;
  if (!id) return null;
  return {
    id,
    email: user?.email,
    displayName: user?.displayName ?? null,
    avatarUrl: user?.avatarUrl ?? null,
    authTime: user?.authTime,
    isAdmin: Boolean(user?.isAdmin),
  };
}

/**
 * The user adapter: the seam between the host's user system and this package.
 *
 *   inbound   resolveUser(req)          "who is making this request?"
 *   outbound  oauth.users.forget(id)    "this user is gone, drop their data"
 *             oauth.users.revokeAll(id) "kill their live access"
 *
 * The package never queries the user collection, never joins against it, and
 * never writes to it.
 *
 * `isAdmin` gates nothing. It cannot: the package cannot know what admin means
 * here, and there is no admin router to guard — the admin surface is a plain
 * module export. See standards/adapters.md.
 *
 * The `typeof` check is not redundant with the types: hosts on plain JS reach
 * this at runtime with no compiler in front of them.
 */
export function createUserAdapter(
  { resolveUser = defaultResolveUser, loadUser }: { resolveUser?: ResolveUser; loadUser?: LoadUser } = {},
): UserAdapter {
  if (typeof resolveUser !== 'function') {
    throw new TypeError('oauth-host: user adapter `resolveUser` must be a function');
  }
  if (loadUser !== undefined && typeof loadUser !== 'function') {
    throw new TypeError('oauth-host: user adapter `loadUser` must be a function');
  }
  return { resolveUser, ...(loadUser ? { loadUser } : {}) };
}

function normalizeScopes(input: CreateOAuthHostConfig['scopes']): ScopeSpec[] {
  if (!Array.isArray(input) || input.length === 0) {
    throw new TypeError('oauth-host: `scopes` must be a non-empty array');
  }
  return input.map((s) => {
    const spec: ScopeSpec = typeof s === 'string' ? { id: s } : { ...s };
    if (!spec.id || typeof spec.id !== 'string') {
      throw new TypeError(`oauth-host: every scope needs a string \`id\` (got ${JSON.stringify(s)})`);
    }
    // RFC 6749 §3.3 — scope tokens are space-delimited, so a space in one makes
    // the whole parameter ambiguous and no error would point back here.
    if (/[\s"\\]/.test(spec.id)) {
      throw new TypeError(`oauth-host: scope id must not contain whitespace or quotes: '${spec.id}'`);
    }
    return {
      ...spec,
      label: spec.label ?? spec.id,
      oidc: spec.oidc ?? OIDC_SCOPES.has(spec.id),
    };
  });
}

function normalizeResources(input: CreateOAuthHostConfig['resources']): ResourceSpec[] {
  if (!Array.isArray(input) || input.length === 0) {
    throw new TypeError(
      'oauth-host: `resources` must list at least one API. MCP clients send `resource` '
      + 'on every request (RFC 8707) and tokens are audience-bound to it.',
    );
  }
  return input.map((r) => {
    const spec: ResourceSpec = typeof r === 'string' ? { id: r } : { ...r };
    let url: URL;
    try {
      url = new URL(spec.id);
    } catch {
      throw new TypeError(`oauth-host: resource id must be an absolute URI: '${spec.id}'`);
    }
    // RFC 8707 §2 — the resource indicator carries no fragment, and comparison
    // is exact. Normalizing here means the comparison downstream can stay a
    // string equality rather than a URL parse on every token request.
    if (url.hash) {
      throw new TypeError(`oauth-host: resource id must not contain a fragment: '${spec.id}'`);
    }
    return { ...spec, label: spec.label ?? spec.id };
  });
}

/**
 * In-memory fixed-window counter.
 *
 * Per-process, so on N instances the effective limit is `max × N`. That is
 * stated rather than hidden, and `rateLimits.store` is how it becomes Redis.
 */
function memoryStore(): RateLimitConfig['store'] & object {
  const buckets = new Map<string, { count: number; resetAt: number }>();
  return {
    async hit(key: string, windowMs: number) {
      const now = Date.now();
      const found = buckets.get(key);
      if (!found || found.resetAt <= now) {
        const fresh = { count: 1, resetAt: now + windowMs };
        buckets.set(key, fresh);
        // Opportunistic sweep: without it the map is an unbounded leak keyed by
        // client id and IP, which is attacker-controlled.
        if (buckets.size > 10_000) {
          for (const [k, v] of buckets) if (v.resetAt <= now) buckets.delete(k);
        }
        return fresh;
      }
      found.count += 1;
      return found;
    },
  };
}

/**
 * Parse one `allowedHosts` entry.
 *
 * The entry is a host, never a URL: accepting `https://claude.ai/` here would
 * invite a path, and a path in an allowlist reads like it constrains something
 * it does not. Reject the shapes that look permissive but are not.
 */
function parseCimdHost(raw: unknown): CimdHostRule {
  if (typeof raw !== 'string' || !raw.trim()) {
    throw new TypeError(
      `oauth-host: clientIdMetadata.allowedHosts entries must be non-empty strings (got ${JSON.stringify(raw)})`,
    );
  }
  const entry = raw.trim().toLowerCase();
  if (/[/\\?#@\s]/.test(entry) || entry.includes('://')) {
    throw new TypeError(
      `oauth-host: clientIdMetadata.allowedHosts takes a host, not a URL: '${raw}'. `
      + "Write 'claude.ai' for that host exactly, or '.claude.ai' to include subdomains.",
    );
  }
  const subdomains = entry.startsWith('.');
  const bare = subdomains ? entry.slice(1) : entry;
  const parts = /^([^:]+)(?::(\d+))?$/.exec(bare);
  if (!parts || !parts[1]) {
    throw new TypeError(`oauth-host: clientIdMetadata.allowedHosts entry is not a hostname: '${raw}'`);
  }
  // A bare `*` reads as "any host", which is precisely the configuration this
  // key exists to prevent. Refuse it by name rather than letting it match
  // nothing and look like a typo.
  if (parts[1].includes('*')) {
    throw new TypeError(
      `oauth-host: clientIdMetadata.allowedHosts does not accept wildcards: '${raw}'. `
      + "Use a leading dot ('.claude.ai') to admit subdomains of one host.",
    );
  }
  return { host: parts[1], port: parts[2] ?? '', subdomains };
}

/**
 * CIMD config, resolved and validated fatally.
 *
 * The one rule worth restating: `allowedHosts` is required when `enabled`. An
 * authorization server that fetches arbitrary URLs on an unauthenticated
 * request parameter is an SSRF proxy, and defaulting this key to "any" would
 * ship that behaviour to whoever flipped `enabled` without reading the page.
 */
function resolveCimd(
  input: ClientIdMetadataConfig | undefined,
  scopeIndex: Map<string, ScopeSpec>,
): ResolvedCimd {
  const off: ResolvedCimd = {
    enabled: false,
    allowedHosts: [],
    cacheTtlMs: 3_600_000,
    fetchTimeoutMs: 5_000,
    maxBytes: 65_536,
    allowedScopes: [],
    failures: new Map(),
  };
  if (!input || !input.enabled) return off;

  if (!Array.isArray(input.allowedHosts) || input.allowedHosts.length === 0) {
    throw new TypeError(
      'oauth-host: `clientIdMetadata.allowedHosts` must list at least one host when '
      + 'clientIdMetadata is enabled. There is no implicit "any host": the server fetches '
      + 'these URLs itself, on an unauthenticated request parameter.',
    );
  }

  const allowedScopes = input.allowedScopes ?? [...scopeIndex.keys()];
  if (!Array.isArray(allowedScopes) || allowedScopes.length === 0) {
    throw new TypeError('oauth-host: `clientIdMetadata.allowedScopes`, when given, must be non-empty');
  }
  for (const id of allowedScopes) {
    if (typeof id !== 'string' || !scopeIndex.has(id)) {
      throw new TypeError(
        `oauth-host: clientIdMetadata.allowedScopes contains '${String(id)}', `
        + 'which is not in the configured scope catalog',
      );
    }
  }

  const positive = (value: unknown, key: string, fallback: number): number => {
    if (value === undefined) return fallback;
    if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
      throw new TypeError(`oauth-host: \`clientIdMetadata.${key}\` must be a positive number`);
    }
    return value;
  };

  return {
    enabled: true,
    allowedHosts: input.allowedHosts.map(parseCimdHost),
    cacheTtlMs: positive(input.cacheTtlMs, 'cacheTtlMs', 3_600_000),
    fetchTimeoutMs: positive(input.fetchTimeoutMs, 'fetchTimeoutMs', 5_000),
    maxBytes: positive(input.maxBytes, 'maxBytes', 65_536),
    allowedScopes: [...allowedScopes],
    failures: new Map(),
  };
}

export function resolveConfig(config: CreateOAuthHostConfig): ResolvedContext {
  if (!config || typeof config !== 'object') {
    throw new TypeError('oauth-host: createOAuthHost(config) requires a config object');
  }

  const {
    connection,
    issuer,
    mountPath = '/oauth',
    consentUrl,
    loginUrl,
    returnParam = 'next',
    userAdapter,
    resolveUser,
    loadUser,
    grantContext,
    claims,
    subjectMode = 'public',
    pairwiseSalt,
    signing = {},
    rateLimits = {},
    tokenCache = {},
    modelNames,
    collectionPrefix,
    audit = {},
    cors = {},
    clockSkewMs = 0,
    clientIdMetadata,
    logger = NOOP_LOGGER,
    track = () => {},
  } = config;

  if (typeof issuer !== 'string' || !/^https?:\/\//.test(issuer)) {
    throw new TypeError(`oauth-host: \`issuer\` must be an absolute http(s) URL (got ${JSON.stringify(issuer)})`);
  }
  // Every metadata URL is built by concatenation. A trailing slash here yields
  // `https://x.com//token`, which some clients treat as a different origin.
  if (issuer.endsWith('/')) {
    throw new TypeError(`oauth-host: \`issuer\` must not end with a slash: '${issuer}'`);
  }
  if (!consentUrl || typeof consentUrl !== 'string') {
    throw new TypeError('oauth-host: `consentUrl` is required — it is where /authorize sends the user');
  }
  if (subjectMode === 'pairwise' && !pairwiseSalt) {
    throw new TypeError(
      'oauth-host: `pairwiseSalt` is required when subjectMode is "pairwise". '
      + 'It is permanent: changing it changes every `sub` a partner has stored.',
    );
  }
  if (userAdapter && (resolveUser || loadUser)) {
    throw new TypeError(
      'oauth-host: pass either `userAdapter` or the `resolveUser`/`loadUser` shorthands, not both',
    );
  }
  if (typeof track !== 'function') {
    throw new TypeError('oauth-host: `track` must be a function');
  }
  if (grantContext && (typeof grantContext.list !== 'function' || typeof grantContext.verify !== 'function')) {
    throw new TypeError('oauth-host: `grantContext` needs both `list()` and `verify()`');
  }

  const scopes = normalizeScopes(config.scopes);
  const resources = normalizeResources(config.resources);

  // A resource may narrow the catalog but cannot invent a scope — otherwise a
  // client could be granted something the consent screen has no label for.
  const scopeIndex = new Map(scopes.map((s) => [s.id, s]));
  for (const r of resources) {
    for (const s of r.scopes ?? []) {
      if (!scopeIndex.has(s)) {
        throw new TypeError(`oauth-host: resource '${r.id}' lists scope '${s}' which is not in the catalog`);
      }
    }
  }

  const models = createModels({
    connection,
    modelNames,
    collectionPrefix,
    auditRetentionDays: audit.retentionDays ?? 400,
  });

  const adapter = userAdapter
    ? createUserAdapter(userAdapter)
    : createUserAdapter({ resolveUser, loadUser });

  if (!adapter.loadUser) {
    // Not fatal — a host that never grants `profile`/`email` has nothing to
    // load. But it IS the reason those claims come back empty, and finding
    // that out from an empty /userinfo response costs an afternoon.
    logger.warn?.(
      'oauth-host: no `loadUser` adapter — `profile`/`email` claims on /userinfo and '
      + 'the id_token will be empty, because those endpoints have no host session to read.',
    );
  }

  const store = rateLimits.store ?? memoryStore();

  // `/oauth`, `oauth/` and `/oauth/` must all produce the same metadata. This
  // is string concatenation downstream, so normalize once here rather than
  // defending against a double slash in nine endpoint URLs.
  const normalizedMount = `/${String(mountPath).replace(/^\/+|\/+$/g, '')}`;

  const ctx: ResolvedContext = {
    models,
    issuer,
    mountPath: normalizedMount === '/' ? '' : normalizedMount,
    resources,
    scopes,
    scopeIndex,
    consentUrl,
    loginUrl,
    returnParam,
    resolveUser: adapter.resolveUser,
    async loadUser(userId) {
      return (await adapter.loadUser?.(userId)) ?? { id: userId };
    },
    grantContext,
    claims,
    ttl: { ...DEFAULT_TTL, ...config.ttl },
    subjectMode,
    pairwiseSalt,
    signing,
    rateLimits: {
      token: rateLimits.token ?? { max: 60, windowMs: 60_000 },
      authorize: rateLimits.authorize ?? { max: 60, windowMs: 60_000 },
      consent: rateLimits.consent ?? { max: 60, windowMs: 60_000 },
      hit: (key, windowMs) => store.hit(key, windowMs),
    },
    tokenCacheTtlMs: tokenCache.ttlMs ?? 0,
    cors: { tokenEndpoint: cors.tokenEndpoint ?? false, origins: cors.origins ?? [] },
    clockSkewMs,
    cimd: resolveCimd(clientIdMetadata, scopeIndex),
    logger,
    track,
    async audit(entry) {
      try {
        await models.Audit.create(entry);
      } catch (err) {
        // The audit log must never be the reason a token request fails. It is
        // evidence, not control flow.
        logger.error?.({ err, entry }, 'oauth-host: audit write failed');
      }
    },
  };

  return ctx;
}
