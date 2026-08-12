/**
 * Compile-only exercise of the public declarations. Never executed — `tsc
 * --noEmit` failing here means the .d.ts files drifted from the source.
 *
 * These declarations are hand-written and the SOURCE IMPORTS THEM, so most
 * drift now fails in `src/` first. This file still earns its place: it is the
 * only thing that checks the surface from OUTSIDE, the way a host consumes it —
 * a type the source never happens to reference can still be wrong here.
 *
 * Hand-written types rot within a day. On featureboard this file immediately
 * caught that `types/` was missing FOUR features added the same afternoon.
 * Every exported symbol must appear below. See standards/traps.md #9.
 */
import type {
  ClaimsAdapter,
  ClientBranding,
  ClientIdMetadataConfig,
  ClientSecretRecord,
  ClientsApi,
  ContextsApi,
  CreateClientSpec,
  CreatedClient,
  CreatedConfidentialClient,
  CreatedPublicClient,
  CreateOAuthHostConfig,
  GrantContext,
  GrantContextAdapter,
  GrantSummary,
  GrantsApi,
  LoadUser,
  Logger,
  ModelNames,
  OAuthAuditDoc,
  OAuthClientDoc,
  OAuthCodeDoc,
  OAuthError,
  OAuthEvent,
  OAuthGrantDoc,
  OAuthHostInstance,
  OAuthHostRouters,
  OAuthKeyDoc,
  OAuthModels,
  OAuthRequestContext,
  OAuthRequestDoc,
  OAuthTokenDoc,
  PackageUser,
  ProtectOptions,
  PublicClient,
  RateLimitConfig,
  RateLimitRule,
  RateLimitStore,
  ResolveUser,
  ResourceSpec,
  ScopeSpec,
  SigningConfig,
  SigningKeySpec,
  TtlConfig,
  UserAdapter,
  UserId,
  UsersApi,
} from './index.js';
// Values, not types: the vendor constants are exported to be pasted into a
// registration, so they have to be importable as such.
import {
  CHATGPT_CONNECTOR_REDIRECT_URI_PATTERN,
  CHATGPT_LEGACY_REDIRECT_URI,
  CIMD_ALLOWED_HOSTS,
  CLAUDE_CODE_REDIRECT_URIS,
  CLAUDE_CONNECTOR_REDIRECT_URI,
} from './index.js';

declare const oauth: OAuthHostInstance;

// The registration a host actually writes. `CLAUDE_CODE_REDIRECT_URIS` and
// `CIMD_ALLOWED_HOSTS` are readonly, so they spread rather than assign — which
// is also how they get combined with the hosted callback in practice.
const vendorClient: CreateClientSpec = {
  name: 'Claude',
  redirectUris: [CLAUDE_CONNECTOR_REDIRECT_URI, ...CLAUDE_CODE_REDIRECT_URIS],
  allowedScopes: ['openid'],
};
const vendorCimd: ClientIdMetadataConfig = {
  enabled: true,
  allowedHosts: [...CIMD_ALLOWED_HOSTS],
};
// A pattern, not a value to register — exercised only so a rename is caught.
void CHATGPT_CONNECTOR_REDIRECT_URI_PATTERN;
void CHATGPT_LEGACY_REDIRECT_URI;
void vendorClient;
void vendorCimd;

// ---------------------------------------------------------------------------
// The degenerate case from plans/build-plan.md §0. If this ever stops
// compiling as written, the config layer grew a required key the paper test
// does not pay for.
// ---------------------------------------------------------------------------
const minimal: CreateOAuthHostConfig = {
  issuer: 'https://api.example.com',
  resources: [{ id: 'https://api.example.com/mcp', label: 'MCP server' }],
  scopes: [
    { id: 'openid', label: 'Sign you in', oidc: true },
    { id: 'contacts.read', label: 'Read your contacts', description: 'Names and emails.' },
    { id: 'contacts.write', label: 'Create and edit contacts', sensitive: true },
  ],
  consentUrl: '/settings/authorize',
};

// Strings are shorthand for `{ id, label: id }` — §0.3.
const shorthandScopes: CreateOAuthHostConfig = {
  ...minimal,
  scopes: ['openid', 'profile', 'email'],
};

// `defaultScopes` is optional and is plain scope ids — deliberately NOT a
// `ScopeSpec[]`, so it cannot be mistaken for a second catalog.
const withDefaultScopes: CreateOAuthHostConfig = {
  ...minimal,
  defaultScopes: ['openid', 'contacts.read'],
};

// ---------------------------------------------------------------------------
// Adapters, both forms and both directions.
// ---------------------------------------------------------------------------
const withFn: CreateOAuthHostConfig = {
  ...minimal,
  resolveUser: () => ({ id: 'abc', email: 'a@b.c', displayName: null }),
};
const withAdapter: CreateOAuthHostConfig = {
  ...minimal,
  userAdapter: { resolveUser: () => null } satisfies UserAdapter,
};
// The second inbound direction. `/userinfo` and the id_token are reached with
// no host session, so `resolveUser` alone cannot serve profile/email claims.
const withLoad: CreateOAuthHostConfig = {
  ...minimal,
  loadUser: async (id: UserId) => ({ id, email: 'a@b.c', displayName: 'A' }),
};
const bothOnAdapter: CreateOAuthHostConfig = {
  ...minimal,
  userAdapter: {
    resolveUser: () => null,
    loadUser: (id) => ({ id }),
  } satisfies UserAdapter,
};
declare const load: LoadUser;
void load;
// Signed-out must be expressible — `/authorize` is a route a signed-out user
// lands on directly.
const anon: CreateOAuthHostConfig = { ...minimal, resolveUser: () => null };
// And async, for a host whose session lookup hits a store.
const asyncUser: CreateOAuthHostConfig = {
  ...minimal,
  resolveUser: async () => null,
};

const contextAdapter: GrantContextAdapter = {
  list: (_user, { client, scopes }) => [
    { id: 'org_1', label: client.name, description: scopes.join(' ') } satisfies GrantContext,
  ],
  verify: async (_user, contextId) => contextId.length > 0,
};

const claims: ClaimsAdapter = (user, { scopes, contextId, client }) => ({
  plan: 'pro',
  seen: [user.id, scopes.length, contextId, client.clientId],
});

const tenanted: CreateOAuthHostConfig = {
  ...minimal,
  grantContext: contextAdapter,
  claims,
  logger: {} satisfies Logger,
  track: (event: OAuthEvent) => void event.type,
};

// ---------------------------------------------------------------------------
// Every remaining config key, so a rename in `src/` cannot pass silently.
// ---------------------------------------------------------------------------
const tuned: CreateOAuthHostConfig = {
  ...minimal,
  mountPath: '/oauth',
  loginUrl: '/login',
  returnParam: 'next',
  ttl: {
    code: 60,
    accessToken: 3600,
    refreshToken: 60 * 86_400,
    refreshAbsolute: 180 * 86_400,
    authorizationRequest: 600,
  } satisfies TtlConfig,
  subjectMode: 'pairwise',
  pairwiseSalt: 'a-permanent-secret',
  signing: {
    autoGenerate: true,
    keys: [{ kid: 'k1', privateKeyPem: '-----BEGIN PRIVATE KEY-----', alg: 'ES256' } satisfies SigningKeySpec],
  } satisfies SigningConfig,
  rateLimits: {
    token: { max: 60, windowMs: 60_000 } satisfies RateLimitRule,
    authorize: false,
    consent: { max: 10, windowMs: 1_000 },
    store: { hit: async () => ({ count: 1, resetAt: Date.now() }) } satisfies RateLimitStore,
  } satisfies RateLimitConfig,
  tokenCache: { ttlMs: 0 },
  modelNames: { client: 'HostOAuthClient', grant: 'HostOAuthGrant' } satisfies ModelNames,
  collectionPrefix: 'oauth_',
  audit: { retentionDays: 400 },
  cors: { tokenEndpoint: false, origins: [] },
  clockSkewMs: 5_000,
  clientIdMetadata: {
    enabled: true,
    allowedHosts: ['claude.ai', '.chatgpt.com'],
    cacheTtlMs: 3_600_000,
    fetchTimeoutMs: 5_000,
    maxBytes: 65_536,
    allowedScopes: ['contacts.read'],
  } satisfies ClientIdMetadataConfig,
};

// `allowedHosts` is required whenever the key is present at all — the type is
// what stops "enabled, with no allowlist" from compiling in the first place.
const cimdMinimal: ClientIdMetadataConfig = { allowedHosts: ['claude.ai'] };

// A resource may narrow the catalog.
const narrowed: ResourceSpec = {
  id: 'https://api.example.com/mcp',
  label: 'MCP',
  scopes: ['contacts.read'],
};
const scopeSpec: ScopeSpec = { id: 'a', label: 'A', description: 'd', sensitive: true, oidc: false };

// ---------------------------------------------------------------------------
// The instance surface — §2's one screen, checked from outside.
// ---------------------------------------------------------------------------
const routers: OAuthHostRouters = oauth.routes;
void routers.discovery;
void routers.oauth;

// Both call shapes the docs show.
void oauth.protect('contacts.read');
void oauth.protect(['a', 'b'], { mode: 'any', resource: 'https://api.example.com/mcp' } satisfies ProtectOptions);
void oauth.protect();

declare const spec: CreateClientSpec;
async function adminSurface(): Promise<void> {
  const clients: ClientsApi = oauth.clients;
  // The default path. The secret is a plain string, returned once — if this
  // ever becomes optional the provisioning script silently prints `undefined`.
  const created: CreatedConfidentialClient = await clients.create({
    name: 'Claude',
    redirectUris: ['https://claude.ai/api/mcp/auth_callback'],
    allowedScopes: ['openid'],
  });
  const secret: string = created.clientSecret;
  void secret;

  // A hand-registered PUBLIC client — `client_id` plus PKCE, no secret at all.
  // The client Codex CLI needs, and the one path CIMD cannot serve because it
  // publishes no metadata document.
  const publicCreated: CreatedPublicClient = await clients.create({
    name: 'Codex CLI',
    redirectUris: ['http://localhost/callback'],
    allowedScopes: ['openid'],
    type: 'public',
  });
  // Reachable, and `undefined` — not a `string` a caller can print by accident.
  const noSecret: undefined = publicCreated.clientSecret;
  void noSecret;

  // A spec whose `type` is not known statically falls to the union overload,
  // and the union is what makes the caller say which kind it asked for before
  // it can reach a secret.
  const either: CreatedClient = await clients.create(spec);
  const maybeSecret: string | undefined = either.clientSecret;
  void maybeSecret;
  if (either.type === 'confidential') {
    const narrowed: string = either.clientSecret;
    void narrowed;
  }

  // Returns the confidential member alone: it throws on a public client, so a
  // caller never has to narrow a value that cannot be the other case.
  const rotated: CreatedConfidentialClient = await clients.rotateSecret(created.clientId, {
    retireAfter: 86_400_000,
    label: 'q3',
  });
  void rotated.clientSecret;
  await clients.update(created.clientId, { name: 'Claude', redirectUris: [] });
  await clients.get(created.clientId);
  await clients.list({ status: 'active', limit: 10, skip: 0 });
  await clients.disable(created.clientId);

  const grants: GrantsApi = oauth.grants;
  const listed = await grants.list({ userId: 'u1', limit: 10 });
  const summary: GrantSummary = listed.items[0]!;
  void summary.client.branding;
  await grants.revoke(summary.id, { by: 'user' });

  const users: UsersApi = oauth.users;
  await users.forget('u1');
  await users.revokeAll('u1', { reason: 'password_change' });

  const contexts: ContextsApi = oauth.contexts;
  await contexts.revoked('u1', 'org_1');

  await oauth.syncIndexes();
  // A boolean, not a promise — a host gates its own mount on it. If this ever
  // becomes awaitable, a host that forgot `syncIndexes()` hangs instead of
  // being told.
  const ready: boolean = oauth.ready;
  void ready;
  const models: OAuthModels = oauth.models;
  void models.Client;
  void models.Grant;
  void models.Code;
  void models.Token;
  void models.Request;
  void models.Key;
  void models.Audit;
}

// ---------------------------------------------------------------------------
// Documents, as a host would type its own queries against them.
// ---------------------------------------------------------------------------
declare const client: OAuthClientDoc;
declare const grant: OAuthGrantDoc;
declare const code: OAuthCodeDoc;
declare const token: OAuthTokenDoc;
declare const request: OAuthRequestDoc;
declare const key: OAuthKeyDoc;
declare const audit: OAuthAuditDoc;
declare const publicClient: PublicClient;
declare const branding: ClientBranding;
declare const secretRecord: ClientSecretRecord;
declare const user: PackageUser;
declare const userId: UserId;
declare const resolve: ResolveUser;
declare const err: OAuthError;

void client.secrets;
void grant.contextId;
void code.codeChallengeMethod;
// The rotation chain has to be reachable from outside, or reuse detection is
// unverifiable by anyone auditing this package.
void token.familyId;
void token.parentId;
void request.requestId;
void key.publicJwk;
void audit.type;
void publicClient.clientId;
// A CIMD row must be distinguishable from a hand-registered one from outside —
// a "connected apps" screen showing both has to be able to say which is which.
void publicClient.registration;
void publicClient.metadataUrl;
void client.registration;
void client.metadataUrl;
void client.metadataFetchedAt;
void client.metadataEtag;
void branding.logoUrl;
void secretRecord.retiresAt;
void user.authTime;
void userId;
void resolve;
void err.code;

// The contract `mcp-server` consumes — plan §6 fixes it here.
declare const reqCtx: OAuthRequestContext;
void reqCtx.userId;
void reqCtx.clientId;
void reqCtx.contextId;
void reqCtx.scopes;
void reqCtx.grantId;
void reqCtx.tokenId;
void reqCtx.audience;

void minimal;
void shorthandScopes;
void withDefaultScopes;
void withFn;
void withAdapter;
void withLoad;
void bothOnAdapter;
void anon;
void asyncUser;
void tenanted;
void tuned;
void narrowed;
void scopeSpec;
void cimdMinimal;
void adminSurface;
