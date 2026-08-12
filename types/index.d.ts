import type { Request, RequestHandler, Router } from 'express';
import type { Connection, Model, Mongoose, Types } from 'mongoose';

/**
 * Published declarations for `@jeffjassky/oauth-host`.
 *
 * Hand-written, not generated — `tsup` runs with `dts: false` and `tsc
 * --noEmit` is what keeps these honest against `src/`. The source imports its
 * public shapes FROM this file, so a field added to a schema or a method added
 * to the instance without a matching declaration here is a compile error rather
 * than a silent divergence. See standards/traps.md #9.
 *
 * Terminology follows the specs, not internal habits: `client` is the
 * third-party app (Claude, ChatGPT), `user` is the resource owner, `host` is
 * the Express app embedding this package, `resource` is an API a token can be
 * audience-bound to.
 */

/** A host user id. The package stores it; it never interprets it. */
export type UserId = Types.ObjectId | string;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * One entry in the host's scope catalog.
 *
 * The consent endpoint's entire job is serving `label`/`description`/`sensitive`
 * to the host's UI, which is why scopes are objects rather than strings. A bare
 * string is accepted as shorthand and inflated to `{ id, label: id }`.
 */
export interface ScopeSpec {
  id: string;
  /** Short imperative phrase shown in the consent list. Defaults to `id`. */
  label?: string;
  /** Optional second line. */
  description?: string;
  /** Render with emphasis — write access, destructive access, billing. */
  sensitive?: boolean;
  /** An OIDC scope (`openid`, `profile`, `email`). Drives claim mapping. */
  oidc?: boolean;
}

/** An API that tokens can be audience-bound to (RFC 8707). */
export interface ResourceSpec {
  /** Absolute URI. MUST match what the client sends as `resource`. */
  id: string;
  label?: string;
  /** Scopes valid at this resource. Omitted means the whole catalog. */
  scopes?: string[];
}

export interface TtlConfig {
  /** Authorization code lifetime. Default 60s; RFC 6749 §4.1.2 caps at 10min. */
  code?: number;
  /** Access token lifetime. Default 3600s. */
  accessToken?: number;
  /** Refresh token sliding lifetime. Default 5_184_000s (60d). */
  refreshToken?: number;
  /** Refresh token absolute ceiling, from first issuance. Default 180d. */
  refreshAbsolute?: number;
  /** How long a pending consent handle lives. Default 600s (10min). */
  authorizationRequest?: number;
}

export interface SigningKeySpec {
  kid: string;
  /** PKCS#8 PEM. ES256 (P-256) only in v1. */
  privateKeyPem: string;
  /** SPKI PEM. Derived from the private key when omitted. */
  publicKeyPem?: string;
  alg?: 'ES256';
  status?: 'active' | 'retiring';
}

export interface SigningConfig {
  keys?: SigningKeySpec[];
  /**
   * Generate a keypair and persist it in `oauth_keys` when none exists.
   * A development convenience: it means the signing key lives in the same
   * database as the tokens it signs. Default false.
   */
  autoGenerate?: boolean;
}

export interface RateLimitRule {
  /** Requests allowed per window. */
  max: number;
  /** Window length in ms. */
  windowMs: number;
}

/**
 * Swap the in-memory counter for something shared.
 *
 * The default is per-process, which on more than one instance means the
 * effective limit is `max × instances`. Documented rather than hidden.
 */
export interface RateLimitStore {
  hit(key: string, windowMs: number): Promise<{ count: number; resetAt: number }>;
}

export interface RateLimitConfig {
  token?: RateLimitRule | false;
  authorize?: RateLimitRule | false;
  consent?: RateLimitRule | false;
  store?: RateLimitStore;
}

/**
 * Client ID Metadata Documents — a client whose `client_id` IS an `https://`
 * URL serving a JSON document that describes it (`client_name`,
 * `redirect_uris`, branding). The server fetches that document and treats it as
 * the registration. No registration endpoint, no registration access tokens, no
 * per-install provisioning; both Claude and ChatGPT prefer it over RFC 7591 DCR.
 *
 * **This makes the authorization server issue an outbound HTTP request driven
 * by an unauthenticated request parameter — server-side request forgery by
 * construction.** `allowedHosts` is the control that contains it, which is why
 * it is required rather than defaulted: an empty or missing list is a boot
 * error, never an implicit "any host". See docs/guide/cimd.md.
 */
export interface ClientIdMetadataConfig {
  /** Default false. Off is the safe default — the SSRF surface does not exist until you turn it on. */
  enabled?: boolean;
  /**
   * Hosts whose metadata documents may be fetched. **Required when `enabled`.**
   *
   * An entry matches the hostname exactly and case-insensitively
   * (`claude.ai` does NOT match `evilclaude.ai`). Write it with a leading dot
   * (`.claude.ai`) to also admit subdomains. A port is matched only when the
   * entry names one (`localhost:8080`); otherwise the URL must use the default.
   */
  allowedHosts: string[];
  /** How long a fetched document is trusted before a re-fetch. Default 3_600_000 (1h). */
  cacheTtlMs?: number;
  /** Hard ceiling on the outbound request. Default 5_000. */
  fetchTimeoutMs?: number;
  /** Response body cap, enforced while reading — `Content-Length` is not trusted. Default 65_536. */
  maxBytes?: number;
  /**
   * Scopes a CIMD client may ever request, whatever its document claims.
   * Defaults to the full catalog. The document's own `scope` narrows further.
   */
  allowedScopes?: string[];
}

export interface ModelNames {
  client?: string;
  grant?: string;
  code?: string;
  token?: string;
  request?: string;
  key?: string;
  audit?: string;
}

export interface Logger {
  debug?(...args: unknown[]): void;
  info?(...args: unknown[]): void;
  warn?(...args: unknown[]): void;
  error?(...args: unknown[]): void;
}

/** The identity the package needs. Never an auth result — the host authed already. */
export interface PackageUser {
  id: UserId;
  email?: string;
  displayName?: string | null;
  avatarUrl?: string | null;
  /**
   * When the host's session was established. Drives `auth_time`, `max_age`
   * and `prompt=login`. Omitted means those are unsupported for this host.
   */
  authTime?: Date;
  /** Drives badges only. Gates nothing — see standards/adapters.md. */
  isAdmin?: boolean;
}

/** Inbound direction of the user adapter. Returns null for a signed-out caller. */
export type ResolveUser = (req: Request) => PackageUser | null | Promise<PackageUser | null>;

/**
 * Second inbound direction: load a user the package only has an id for.
 *
 * `resolveUser` cannot serve `/userinfo` or the `id_token` — both are reached
 * on the client-authenticated and bearer bands, where there is no host session
 * to read and the only identity available is the `userId` on the token. Without
 * this, `profile`/`email` claims come back empty no matter what the host
 * configured.
 *
 * The alternative — snapshotting the profile at consent and carrying it on the
 * grant — was rejected: it makes `/userinfo` serve a name the user changed
 * eight months ago, and this package's stated contract is that tokens carry no
 * claims and `/userinfo` reads live.
 */
export type LoadUser = (userId: UserId) => PackageUser | null | Promise<PackageUser | null>;

export interface UserAdapter {
  resolveUser: ResolveUser;
  loadUser?: LoadUser;
}

/**
 * What a user can grant access *on behalf of* — an org, a workspace, a team.
 *
 * Omit the adapter entirely and the package runs in single-subject mode: no
 * picker in the consent payload, no `contextId` on the grant, no claim in the
 * token, no membership re-check on refresh.
 */
export interface GrantContext {
  id: string;
  label: string;
  description?: string;
}

export interface GrantContextAdapter {
  /** What this user may grant, for this client and scope set. */
  list(
    user: PackageUser,
    ctx: { client: PublicClient; scopes: string[] },
  ): GrantContext[] | Promise<GrantContext[]>;
  /**
   * Still a member? Re-checked on **every refresh**, not only at consent —
   * a grant made as an employee must die when the employment does.
   */
  verify(user: PackageUser, contextId: string): boolean | Promise<boolean>;
}

/**
 * Extra claims for `id_token` and `/userinfo`.
 *
 * Inbound only, deliberately: claims are a read-only projection of host data,
 * and access tokens carry none — `/userinfo` reads live on every call. There is
 * no "a claim changed" event because nothing is cached to invalidate.
 */
export type ClaimsAdapter = (
  user: PackageUser,
  ctx: { scopes: string[]; contextId?: string; client: PublicClient },
) => Record<string, unknown> | Promise<Record<string, unknown>>;

export interface CreateOAuthHostConfig {
  /** Mongoose connection. Defaults to the global mongoose instance. */
  connection?: Mongoose | Connection;

  /**
   * The public origin this server is reached at, no trailing slash. Appears in
   * discovery metadata, in `iss` on every authorization response (RFC 9207),
   * and in `id_token.iss`. A mismatch with the URL the client actually used is
   * a spec violation clients do check.
   */
  issuer: string;

  /**
   * Where the host mounts `routes.oauth`, relative to `issuer`. Defaults to
   * `/oauth`.
   *
   * The package has to be told: discovery metadata publishes absolute
   * `authorization_endpoint` / `token_endpoint` URLs, and a router cannot see
   * the path it was mounted at until a request arrives — by which time the
   * metadata document has already been built. A mismatch here is the failure
   * where discovery looks fine and every client 404s on `/token`.
   */
  mountPath?: string;

  /** APIs tokens can be bound to (RFC 8707). At least one. */
  resources: ResourceSpec[];

  /** The scope catalog. Strings are shorthand for `{ id, label: id }`. */
  scopes: (ScopeSpec | string)[];

  /**
   * What `/authorize` grants when the request omits `scope`. RFC 6749 §3.3
   * makes the parameter optional and leaves the fallback to the server.
   *
   * Deliberately NOT the client's `allowedScopes`. That list is a registration
   * ceiling — everything the client may ever ask for — and making it double as
   * the default hands a broadly registered client the whole catalog the moment
   * it drops one parameter. The two lists answer different questions.
   *
   * Always intersected with the client's `allowedScopes`, so a default can
   * never exceed a registration. Every entry must be in the catalog, and an
   * empty array is a boot error: omit the key instead. Omitted, a `scope`-less
   * `/authorize` is an `invalid_scope` error naming both ways to fix it —
   * an empty grant would be a token that can do nothing.
   */
  defaultScopes?: string[];

  /**
   * Where `/authorize` sends a signed-in user to approve. The package appends
   * `?request_id=…`; the host's page fetches the consent JSON with it.
   */
  consentUrl: string;

  /** Where to send a signed-out user. See standards/adapters.md §Sign-in redirects. */
  loginUrl?: string;
  /** Query param carrying the return URL. Defaults to `next`. */
  returnParam?: string;

  userAdapter?: UserAdapter;
  /** Shorthand for a one-method `userAdapter`. Mutually exclusive with it. */
  resolveUser?: ResolveUser;
  /** Shorthand for `userAdapter.loadUser`. Mutually exclusive with `userAdapter`. */
  loadUser?: LoadUser;
  grantContext?: GrantContextAdapter;
  claims?: ClaimsAdapter;

  ttl?: TtlConfig;

  /**
   * `public` (default) — `sub` is the host's user id.
   * `pairwise` — `sub` is HMAC(userId, clientId, salt), stable per client.
   *
   * Permanent per client once issued: partners store the value. Choose before
   * first issuance. OIDC Core §8.
   */
  subjectMode?: 'public' | 'pairwise';
  /** Required when `subjectMode` is `pairwise`. */
  pairwiseSalt?: string;

  signing?: SigningConfig;
  rateLimits?: RateLimitConfig;

  /**
   * Cache introspected access tokens for this many ms. **Default 0 — off.**
   *
   * Any non-zero value is the window in which a revoked token still works.
   * That is a real tradeoff, not a free performance knob, which is why it is
   * opt-in and named for the thing it costs.
   */
  tokenCache?: { ttlMs?: number };

  /** Override model names when a collision with a host model is plausible — traps #2. */
  modelNames?: ModelNames;
  /** Collection name prefix. Defaults to `oauth_`. */
  collectionPrefix?: string;

  audit?: { retentionDays?: number };

  /**
   * Send CORS headers on `/token` and `/revoke`. **Default off** — v1 has no
   * public clients, so a browser has no business calling either.
   */
  cors?: { tokenEndpoint?: boolean; origins?: string[] };

  /** Tolerance for a client's wrong clock on `id_token` `iat`/`nbf`. Default 0. */
  clockSkewMs?: number;

  /** Client ID Metadata Documents. Off unless `enabled` — see the interface. */
  clientIdMetadata?: ClientIdMetadataConfig;

  logger?: Logger;
  /** Optional peer seam for analytics. No-op by default; never a hard dep. */
  track?: (event: OAuthEvent) => void;
}

export interface OAuthEvent {
  type:
    | 'oauth.authorization_requested'
    | 'oauth.consent_granted'
    | 'oauth.consent_denied'
    | 'oauth.token_issued'
    | 'oauth.token_refreshed'
    | 'oauth.refresh_reuse_detected'
    | 'oauth.client_secret_rotated'
    | 'oauth.grant_revoked';
  userId?: UserId;
  clientId?: string;
  grantId?: string;
  contextId?: string;
  scopes?: string[];
  meta?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Documents
// ---------------------------------------------------------------------------

export interface ClientBranding {
  logoUrl?: string;
  publisher?: string;
  homepageUrl?: string;
  tosUrl?: string;
  privacyUrl?: string;
}

export interface ClientSecretRecord {
  hash: string;
  label?: string;
  createdAt: Date;
  lastUsedAt?: Date;
  /** Set by `rotateSecret`. The secret stops verifying after this instant. */
  retiresAt?: Date;
}

export interface OAuthClientDoc {
  _id: Types.ObjectId;
  clientId: string;
  name: string;
  /**
   * `public` clients hold no secret and authenticate with `client_id` alone —
   * PKCE is the binding that stands in for it. A `confidential` client can
   * never downgrade itself by omitting its secret.
   *
   * Orthogonal to `registration`: a CIMD row is always public, but a public row
   * is not always CIMD. `clients.create({ type: 'public' })` registers one by
   * hand, which is the only path open to a client that wants PKCE-only and
   * publishes no metadata document (Codex CLI).
   */
  type: 'confidential' | 'public';
  /**
   * How this registration came to exist. `cimd` rows are re-derived from the
   * client's metadata document on a cache miss, so anything an operator edits
   * on one is overwritten on the next fetch — with the deliberate exception of
   * `status`, which a re-fetch never resurrects.
   */
  registration: 'manual' | 'cimd';
  /** The document URL a `cimd` registration was fetched from. */
  metadataUrl?: string;
  /** When that document was last fetched. Compared against `clientIdMetadata.cacheTtlMs`. */
  metadataFetchedAt?: Date;
  /** Last `ETag`, replayed as `If-None-Match` so an unchanged document is a 304. */
  metadataEtag?: string;
  /** First-party marker. Reserved — v1 never skips consent. */
  trusted: boolean;
  /** Empty for a public client. There is no secret to store. */
  secrets: ClientSecretRecord[];
  redirectUris: string[];
  allowedScopes: string[];
  allowedResources: string[];
  branding: ClientBranding;
  status: 'active' | 'disabled';
  /** Pairwise `sub` values already handed to this client, by user id. */
  pairwiseSubjects?: Map<string, string>;
  createdAt: Date;
  updatedAt: Date;
}

export interface OAuthGrantDoc {
  _id: Types.ObjectId;
  userId: UserId;
  clientId: string;
  /** Single-subject mode stores `null`, which the unique index treats as a value. */
  contextId: string | null;
  scopes: string[];
  resources: string[];
  /** Bumped when the user approves a superset. Drives `isNew` on re-consent. */
  version: number;
  lastUsedAt?: Date;
  revokedAt?: Date | null;
  revokedBy?: 'user' | 'admin' | 'system' | 'client';
  createdAt: Date;
  updatedAt: Date;
}

export interface OAuthCodeDoc {
  _id: Types.ObjectId;
  codeHash: string;
  clientId: string;
  userId: UserId;
  grantId: Types.ObjectId;
  contextId: string | null;
  scopes: string[];
  resources: string[];
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
  nonce?: string;
  authTime?: Date;
  consumedAt?: Date | null;
  expiresAt: Date;
  createdAt: Date;
}

export interface OAuthTokenDoc {
  _id: Types.ObjectId;
  kind: 'access' | 'refresh';
  tokenHash: string;
  clientId: string;
  userId: UserId;
  grantId: Types.ObjectId;
  contextId: string | null;
  scopes: string[];
  audience: string[];
  /** Shared by every token descended from one authorization code. */
  familyId: string;
  /** The refresh token this one replaced. Null for the first in a family. */
  parentId?: Types.ObjectId | null;
  consumedAt?: Date | null;
  revokedAt?: Date | null;
  /** Absolute ceiling for the family, copied onto each rotation. */
  familyExpiresAt?: Date;
  expiresAt: Date;
  createdAt: Date;
}

export interface OAuthRequestDoc {
  _id: Types.ObjectId;
  requestId: string;
  clientId: string;
  userId: UserId;
  redirectUri: string;
  scopes: string[];
  resources: string[];
  state?: string;
  nonce?: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
  prompt?: string;
  maxAge?: number;
  decision?: 'approved' | 'denied';
  decidedAt?: Date;
  expiresAt: Date;
  createdAt: Date;
}

export interface OAuthKeyDoc {
  _id: Types.ObjectId;
  kid: string;
  alg: 'ES256';
  publicJwk: Record<string, unknown>;
  privateJwk: Record<string, unknown>;
  status: 'active' | 'retiring';
  createdAt: Date;
}

export interface OAuthAuditDoc {
  _id: Types.ObjectId;
  type: string;
  actor?: 'user' | 'client' | 'admin' | 'system';
  clientId?: string;
  userId?: UserId;
  grantId?: Types.ObjectId;
  ip?: string;
  meta?: Record<string, unknown>;
  createdAt: Date;
}

export interface OAuthModels {
  Client: Model<OAuthClientDoc>;
  Grant: Model<OAuthGrantDoc>;
  Code: Model<OAuthCodeDoc>;
  Token: Model<OAuthTokenDoc>;
  Request: Model<OAuthRequestDoc>;
  Key: Model<OAuthKeyDoc>;
  Audit: Model<OAuthAuditDoc>;
}

// ---------------------------------------------------------------------------
// Programmatic admin API
// ---------------------------------------------------------------------------

/** A client as anything outside the package may see it. No secrets, ever. */
export interface PublicClient {
  clientId: string;
  name: string;
  type: 'confidential' | 'public';
  /** `cimd` rows appear in `clients.list()` and are revocable like any other. */
  registration: 'manual' | 'cimd';
  metadataUrl?: string;
  trusted: boolean;
  redirectUris: string[];
  allowedScopes: string[];
  allowedResources: string[];
  branding: ClientBranding;
  status: 'active' | 'disabled';
  createdAt: Date;
}

export interface CreateClientSpec {
  name: string;
  redirectUris: string[];
  allowedScopes: string[];
  /** Defaults to every configured resource. */
  allowedResources?: string[];
  branding?: ClientBranding;
  trusted?: boolean;
  /** Supply a fixed id for a re-provisioned client. Generated when omitted. */
  clientId?: string;
  /**
   * How this client authenticates at `/token`. **Defaults to `confidential`**,
   * so an existing caller is unaffected.
   *
   * `public` generates no secret at all: the registration is `client_id` plus
   * PKCE, `secrets` is empty, and `rotateSecret()` on it throws. Register one
   * for a client that takes a `client_id` and nothing else — Codex CLI's MCP
   * login has `oauth_client_id` and no `oauth_client_secret` field — and cannot
   * use CIMD because it publishes no metadata document.
   */
  type?: 'confidential' | 'public';
}

/** What `clients.create({ type: 'confidential' })` and `rotateSecret()` return. */
export interface CreatedConfidentialClient {
  client: PublicClient;
  clientId: string;
  type: 'confidential';
  /** Returned once. Only its SHA-256 is stored; there is no way to read it back. */
  clientSecret: string;
}

/**
 * What `clients.create({ type: 'public' })` returns.
 *
 * `clientSecret` is declared as `?: undefined` rather than omitted so that
 * `created.clientSecret` still type-checks against the union below — and lands
 * as `string | undefined`, which is what stops a provisioning script printing
 * the word `undefined` into somebody's connector setup screen.
 */
export interface CreatedPublicClient {
  client: PublicClient;
  clientId: string;
  type: 'public';
  clientSecret?: undefined;
}

/**
 * Discriminated on `type`, not a single interface with an optional secret.
 *
 * The alternative — widening `clientSecret` to `string | undefined` on one
 * shape — reads as source-compatible and is not: `const s: string =
 * created.clientSecret` stops compiling either way. The difference is what
 * happens to the code that does not annotate. With an optional field a
 * provisioning script keeps compiling and prints `undefined`; with a union the
 * caller has to say which kind of registration it asked for before it can reach
 * the secret at all.
 */
export type CreatedClient = CreatedConfidentialClient | CreatedPublicClient;

export interface ClientsApi {
  /**
   * The overloads exist so the default path keeps its precise type. A spec with
   * no `type` (or `type: 'confidential'`) returns a `clientSecret: string`
   * exactly as before; only a caller that asked for `public`, or that passes a
   * spec whose `type` is not known statically, has to narrow.
   */
  create(spec: CreateClientSpec & { type: 'public' }): Promise<CreatedPublicClient>;
  create(spec: CreateClientSpec & { type?: 'confidential' }): Promise<CreatedConfidentialClient>;
  create(spec: CreateClientSpec): Promise<CreatedClient>;
  /**
   * Issue a second valid secret and retire the current one after `retireAfter`
   * ms (default 0 — immediate). Two live secrets is what makes a rotation
   * deployable without downtime.
   *
   * Throws on a **public** client. There is no secret to rotate, and returning
   * one would hand the caller a credential the token endpoint refuses — which
   * is also why the return type is the confidential member alone.
   */
  rotateSecret(clientId: string, opts?: { retireAfter?: number; label?: string }): Promise<CreatedConfidentialClient>;
  update(clientId: string, patch: Partial<Omit<CreateClientSpec, 'clientId'>>): Promise<PublicClient>;
  list(query?: { status?: 'active' | 'disabled'; limit?: number; skip?: number }): Promise<{ items: PublicClient[]; limit: number }>;
  get(clientId: string): Promise<PublicClient | null>;
  /** Disables the client and revokes every grant and token it holds. */
  disable(clientId: string): Promise<{ grantsRevoked: number; tokensRevoked: number }>;
}

export interface GrantSummary {
  id: string;
  client: Pick<PublicClient, 'clientId' | 'name' | 'branding'>;
  scopes: ScopeSpec[];
  context?: GrantContext;
  createdAt: Date;
  lastUsedAt?: Date;
}

export interface GrantsApi {
  list(query: { userId?: UserId; clientId?: string; limit?: number; skip?: number }): Promise<{ items: GrantSummary[]; limit: number }>;
  revoke(grantId: string, opts?: { by?: 'user' | 'admin' | 'system' | 'client' }): Promise<{ tokensRevoked: number }>;
}

export interface UsersApi {
  /** Erasure. Deletes grants, tokens, codes, requests and pairwise subjects. */
  forget(userId: UserId): Promise<{ grants: number; tokens: number }>;
  /** Password change, deactivation — kill live access, keep the audit trail. */
  revokeAll(userId: UserId, opts?: { reason?: string }): Promise<{ grantsRevoked: number; tokensRevoked: number }>;
}

export interface ContextsApi {
  /** Membership ended — revoke every grant this user made for this context. */
  revoked(userId: UserId, contextId: string): Promise<{ grantsRevoked: number; tokensRevoked: number }>;
}

// ---------------------------------------------------------------------------
// Resource server
// ---------------------------------------------------------------------------

/** What `protect()` leaves on the request. The contract `mcp-server` consumes. */
export interface OAuthRequestContext {
  userId: UserId;
  clientId: string;
  contextId: string | null;
  scopes: string[];
  grantId: string;
  tokenId: string;
  audience: string[];
}

export interface ProtectOptions {
  /** Which declared resource this middleware guards. Defaults to the first. */
  resource?: string;
  /** Require every listed scope (the default) or any one of them. */
  mode?: 'all' | 'any';
}

// ---------------------------------------------------------------------------
// Instance
// ---------------------------------------------------------------------------

export interface OAuthHostRouters {
  /** Mounted at the origin root — `/.well-known/*` is not relocatable. */
  discovery: Router;
  /** Mounted wherever `issuer`-relative endpoints live, e.g. `/oauth`. */
  oauth: Router;
}

export interface OAuthHostInstance {
  routes: OAuthHostRouters;
  /**
   * Resource-server middleware.
   *
   *   app.use('/mcp', oauth.protect('contacts.read'), mcpRouter)
   *   app.use('/mcp', oauth.protect(['a', 'b'], { mode: 'any' }), mcpRouter)
   */
  protect(scopes?: string | string[], opts?: ProtectOptions): RequestHandler;

  clients: ClientsApi;
  grants: GrantsApi;
  users: UsersApi;
  contexts: ContextsApi;

  /** Build every index. Await at boot, before the first write — traps #3. */
  syncIndexes(): Promise<void>;
  /**
   * True once `syncIndexes()` has resolved.
   *
   * A boolean rather than a promise on purpose: a promise would have to exist
   * from construction, so a host that never calls `syncIndexes()` would await it
   * forever and the mistake would present as a hang with no message. Until this
   * is true, `/authorize`, `POST /consent/:requestId` and `POST /token` answer
   * `server_error` naming `syncIndexes()`; discovery, `/jwks`, `/userinfo` and
   * `protect()` keep serving, because taking a read-only API down would turn a
   * boot-order mistake into an outage.
   */
  readonly ready: boolean;
  /** Escape hatch. Prefer the APIs above; these have no invariants attached. */
  models: OAuthModels;
}

export declare function createOAuthHost(config: CreateOAuthHostConfig): OAuthHostInstance;

export declare function createModels(opts: {
  connection?: Mongoose | Connection;
  modelNames?: ModelNames;
  collectionPrefix?: string;
  auditRetentionDays?: number;
}): OAuthModels;

// ---------------------------------------------------------------------------
// Vendor callback URLs
// ---------------------------------------------------------------------------

/**
 * Callback URLs for the connectors people actually register, shipped as
 * constants because `clients.create()` compares them byte-for-byte and
 * retyping one out of a vendor's documentation is the most typo-prone step in
 * the whole setup.
 *
 * **All of these are vendor product details, not standards.** They can change
 * without notice and without a release of this package; each is stamped in the
 * source with the date it was verified. See docs/guide/mcp.md.
 */

/** claude.ai's hosted connector callback. Verified 2026-08-12. */
export declare const CLAUDE_CONNECTOR_REDIRECT_URI: string;

/**
 * Claude Code's local callbacks. Register both; the PORT varies per session and
 * is allowed to (RFC 8252 §7.3), so register them WITHOUT one.
 * Verified 2026-08-12.
 */
export declare const CLAUDE_CODE_REDIRECT_URIS: readonly string[];

/** ChatGPT's legacy single connector callback. Verified 2026-08-12. */
export declare const CHATGPT_LEGACY_REDIRECT_URI: string;

/**
 * The SHAPE of ChatGPT's current per-connector callback, not a value to
 * register — `{callback_id}` is assigned when the connector is created and the
 * only correct source for the full URL is the connector's own setup screen.
 * Verified 2026-08-12.
 */
export declare const CHATGPT_CONNECTOR_REDIRECT_URI_PATTERN: string;

/**
 * A suggested `clientIdMetadata.allowedHosts` for both vendors. A suggestion,
 * never a default — that key is the control that contains CIMD's SSRF surface.
 * Verified 2026-08-12.
 */
export declare const CIMD_ALLOWED_HOSTS: readonly string[];

export declare function defaultResolveUser(req: Request): PackageUser | null;
export declare function createUserAdapter(opts?: {
  resolveUser?: ResolveUser;
  loadUser?: LoadUser;
}): UserAdapter;

/**
 * A spec-shaped failure.
 *
 * `code` is the RFC token (`invalid_grant`, `invalid_client`, …) and is what
 * reaches the wire as `error`. Never invent one: clients switch on these.
 */
export declare class OAuthError extends Error {
  constructor(
    status: number,
    code: string,
    description?: string,
    opts?: { headers?: Record<string, string> },
  );
  status: number;
  code: string;
  description?: string;
  headers?: Record<string, string>;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      /** Set by `oauth.protect()`. Absent on unprotected routes. */
      oauth?: OAuthRequestContext;
    }
  }
}
