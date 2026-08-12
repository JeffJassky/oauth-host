# Types & payloads

Every exported type from `@jeffjassky/oauth-host`. The declarations are
**hand-written** in `types/index.d.ts` and are the published contract — `tsup`
runs with `dts: false`, and `src/` imports its public shapes *from* that file, so
a field added to a schema without a matching declaration is a compile error
rather than a silent divergence.

```ts
import type {
  CreateOAuthHostConfig,
  OAuthHostInstance,
  PackageUser,
  OAuthRequestContext,
  PublicClient,
  ScopeSpec,
} from '@jeffjassky/oauth-host';
```

## Configuration

### `CreateOAuthHostConfig`

The full table with defaults and reasoning is in
[Configuration](/guide/configuration).

```ts
interface CreateOAuthHostConfig {
  connection?: Mongoose | Connection;
  issuer: string;
  mountPath?: string;                      // '/oauth'
  resources: ResourceSpec[];
  scopes: (ScopeSpec | string)[];
  defaultScopes?: string[];                // fallback when /authorize omits `scope`
  consentUrl: string;
  loginUrl?: string;
  returnParam?: string;                    // 'next'

  userAdapter?: UserAdapter;
  resolveUser?: ResolveUser;               // shorthand; exclusive with userAdapter
  loadUser?: LoadUser;                     // shorthand; exclusive with userAdapter
  grantContext?: GrantContextAdapter;
  claims?: ClaimsAdapter;

  ttl?: TtlConfig;
  subjectMode?: 'public' | 'pairwise';     // 'public'
  pairwiseSalt?: string;                   // required when pairwise
  signing?: SigningConfig;
  rateLimits?: RateLimitConfig;
  tokenCache?: { ttlMs?: number };         // 0

  modelNames?: ModelNames;
  collectionPrefix?: string;               // 'oauth_'
  audit?: { retentionDays?: number };      // 400
  cors?: { tokenEndpoint?: boolean; origins?: string[] };
  clockSkewMs?: number;                    // 0
  clientIdMetadata?: ClientIdMetadataConfig;   // disabled

  logger?: Logger;
  track?: (event: OAuthEvent) => void;
}
```

### `ScopeSpec`

```ts
interface ScopeSpec {
  id: string;
  label?: string;         // defaults to id
  description?: string;   // optional second line on the consent screen
  sensitive?: boolean;    // render with emphasis — write, destructive, billing
  oidc?: boolean;         // defaults true for openid/profile/email
}
```

A bare string is shorthand for `{ id, label: id }`.

### `ResourceSpec`

```ts
interface ResourceSpec {
  id: string;         // absolute URI, no fragment. MUST match what the client sends
  label?: string;
  scopes?: string[];  // valid at this resource; omitted means the whole catalog
}
```

### `TtlConfig`

```ts
interface TtlConfig {
  code?: number;                  // 60 s
  accessToken?: number;           // 3600 s
  refreshToken?: number;          // 5_184_000 s (60 d) — sliding
  refreshAbsolute?: number;       // 15_552_000 s (180 d) — ceiling
  authorizationRequest?: number;  // 600 s
}
```

### `SigningConfig` / `SigningKeySpec`

```ts
interface SigningKeySpec {
  kid: string;
  privateKeyPem: string;          // PKCS#8. ES256 (P-256) only
  publicKeyPem?: string;          // derived when omitted
  alg?: 'ES256';
  status?: 'active' | 'retiring';
}

interface SigningConfig {
  keys?: SigningKeySpec[];
  autoGenerate?: boolean;         // false. Development only
}
```

### `RateLimitConfig` / `RateLimitRule` / `RateLimitStore`

```ts
interface RateLimitRule { max: number; windowMs: number }

interface RateLimitStore {
  hit(key: string, windowMs: number): Promise<{ count: number; resetAt: number }>;
}

interface RateLimitConfig {
  token?: RateLimitRule | false;
  authorize?: RateLimitRule | false;
  consent?: RateLimitRule | false;
  store?: RateLimitStore;
}
```

### `ClientIdMetadataConfig`

Off unless `enabled`. Full page: [Client ID metadata](/guide/cimd).

```ts
interface ClientIdMetadataConfig {
  enabled?: boolean;              // false
  allowedHosts: string[];         // REQUIRED when enabled — empty is a boot error
  cacheTtlMs?: number;            // 3_600_000
  fetchTimeoutMs?: number;        // 5_000
  maxBytes?: number;              // 65_536
  allowedScopes?: string[];       // the full catalog
}
```

### `ModelNames`

```ts
interface ModelNames {
  client?: string; grant?: string; code?: string; token?: string;
  request?: string; key?: string; audit?: string;
}
```

### `Logger`

```ts
interface Logger {
  debug?(...args: unknown[]): void;
  info?(...args: unknown[]): void;
  warn?(...args: unknown[]): void;
  error?(...args: unknown[]): void;
}
```

### `OAuthEvent`

```ts
interface OAuthEvent {
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
```

## Adapters

### `UserId` / `PackageUser`

```ts
type UserId = Types.ObjectId | string;

interface PackageUser {
  id: UserId;
  email?: string;
  displayName?: string | null;
  avatarUrl?: string | null;
  authTime?: Date;      // drives auth_time / max_age / prompt=login
  isAdmin?: boolean;    // badges only. Gates nothing
}
```

`UserId` is stored and never interpreted.

### `ResolveUser` / `LoadUser` / `UserAdapter`

```ts
type ResolveUser = (req: Request) => PackageUser | null | Promise<PackageUser | null>;
type LoadUser = (userId: UserId) => PackageUser | null | Promise<PackageUser | null>;

interface UserAdapter {
  resolveUser: ResolveUser;
  loadUser?: LoadUser;
}
```

`resolveUser` cannot serve `/userinfo` or the `id_token` — see
[Adapters](/guide/adapters).

### `GrantContext` / `GrantContextAdapter`

```ts
interface GrantContext { id: string; label: string; description?: string }

interface GrantContextAdapter {
  list(user: PackageUser, ctx: { client: PublicClient; scopes: string[] })
    : GrantContext[] | Promise<GrantContext[]>;
  verify(user: PackageUser, contextId: string): boolean | Promise<boolean>;
}
```

`verify` is re-checked on **every refresh**, not only at consent.

### `ClaimsAdapter`

```ts
type ClaimsAdapter = (
  user: PackageUser,
  ctx: { scopes: string[]; contextId?: string; client: PublicClient },
) => Record<string, unknown> | Promise<Record<string, unknown>>;
```

Inbound only, deliberately — see
[why `claims` has no outbound direction](/guide/adapters).

## Payloads

### `ConsentPayload`

What `GET /oauth/consent/:requestId` returns. A versioned UI contract: no
internal ids, no secrets, optional keys omitted rather than nulled. Documented in
full on [The consent screen](/guide/consent-screen).

```ts
interface ConsentPayload {
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
  /** Present exactly when `contexts` is. `contexts` carries at most 50. */
  contextsHasMore?: boolean;
  user: { displayName?: string | null; email?: string };
  expiresAt: Date;
}
```

### `OAuthRequestContext`

What `protect()` leaves on the request. The contract a sibling MCP server
consumes; the key set is asserted exactly in the suite.

```ts
interface OAuthRequestContext {
  userId: UserId;
  clientId: string;
  contextId: string | null;
  scopes: string[];
  grantId: string;    // stringified
  tokenId: string;    // stringified
  audience: string[];
}
```

Declared globally on Express's `Request` as `req.oauth?`.

### `ProtectOptions`

```ts
interface ProtectOptions {
  resource?: string;        // defaults to the first configured resource
  mode?: 'all' | 'any';     // 'all'
}
```

### `PublicClient`

A client as anything outside the package may see it. No secrets, ever.

```ts
interface PublicClient {
  clientId: string;
  name: string;
  type: 'confidential' | 'public';           // `public` = a CIMD client, no secret
  registration: 'manual' | 'cimd';
  metadataUrl?: string;                      // `cimd` only
  trusted: boolean;
  redirectUris: string[];
  allowedScopes: string[];
  allowedResources: string[];
  branding: ClientBranding;
  status: 'active' | 'disabled';
  createdAt: Date;
}
```

### `ClientBranding`

```ts
interface ClientBranding {
  logoUrl?: string; publisher?: string; homepageUrl?: string;
  tosUrl?: string; privacyUrl?: string;
}
```

URLs you already host. There is no upload story, deliberately.

### `CreateClientSpec` / `CreatedClient`

```ts
interface CreateClientSpec {
  name: string;
  redirectUris: string[];
  allowedScopes: string[];
  allowedResources?: string[];   // defaults to every configured resource
  branding?: ClientBranding;
  trusted?: boolean;
  clientId?: string;             // generated when omitted
  type?: 'confidential' | 'public';   // default 'confidential'
}

// Discriminated on `type`, not one shape with an optional secret.
interface CreatedConfidentialClient {
  client: PublicClient;
  clientId: string;
  type: 'confidential';
  clientSecret: string;          // returned once. Only its SHA-256 is stored
}

interface CreatedPublicClient {
  client: PublicClient;
  clientId: string;
  type: 'public';
  clientSecret?: undefined;      // there is none, and reading it says so
}

type CreatedClient = CreatedConfidentialClient | CreatedPublicClient;
```

`create()` is overloaded so the default path keeps its precise type: a spec with
no `type` returns `clientSecret: string` exactly as before, and only a caller
that asked for `public` — or that passes a spec whose `type` is not known
statically — has to narrow.

A single shape with `clientSecret?: string` was rejected. It breaks
`const s: string = created.clientSecret` just the same, and it lets the code
that *doesn't* annotate keep compiling and print the word `undefined` into
somebody's connector setup screen. See
[public clients](/guide/cimd#public-clients).

### `GrantSummary`

```ts
interface GrantSummary {
  id: string;
  client: Pick<PublicClient, 'clientId' | 'name' | 'branding'>;
  scopes: ScopeSpec[];
  context?: GrantContext;        // key absent without a grantContext adapter
  createdAt: Date;
  lastUsedAt?: Date;
}
```

## API surfaces

### `OAuthHostInstance` / `OAuthHostRouters`

```ts
interface OAuthHostRouters { discovery: Router; oauth: Router }

interface OAuthHostInstance {
  routes: OAuthHostRouters;
  protect(scopes?: string | string[], opts?: ProtectOptions): RequestHandler;
  clients: ClientsApi;
  grants: GrantsApi;
  users: UsersApi;
  contexts: ContextsApi;
  syncIndexes(): Promise<void>;
  /** True once `syncIndexes()` resolved. The write routes fail closed until it is. */
  readonly ready: boolean;
  models: OAuthModels;
}
```

### `ClientsApi` / `GrantsApi` / `UsersApi` / `ContextsApi`

```ts
interface ClientsApi {
  create(spec: CreateClientSpec & { type: 'public' }): Promise<CreatedPublicClient>;
  create(spec: CreateClientSpec & { type?: 'confidential' }): Promise<CreatedConfidentialClient>;
  create(spec: CreateClientSpec): Promise<CreatedClient>;
  // Throws on a public client, so the caller never narrows a value that cannot
  // be the other case.
  rotateSecret(clientId: string, opts?: { retireAfter?: number; label?: string })
    : Promise<CreatedConfidentialClient>;
  update(clientId: string, patch: Partial<Omit<CreateClientSpec, 'clientId'>>): Promise<PublicClient>;
  list(query?: { status?: 'active' | 'disabled'; limit?: number; skip?: number })
    : Promise<{ items: PublicClient[]; limit: number }>;
  get(clientId: string): Promise<PublicClient | null>;
  disable(clientId: string): Promise<{ grantsRevoked: number; tokensRevoked: number }>;
}

interface GrantsApi {
  list(query: { userId?: UserId; clientId?: string; limit?: number; skip?: number })
    : Promise<{ items: GrantSummary[]; limit: number }>;
  revoke(grantId: string, opts?: { by?: 'user' | 'admin' | 'system' | 'client' })
    : Promise<{ tokensRevoked: number }>;
}

interface UsersApi {
  forget(userId: UserId): Promise<{ grants: number; tokens: number }>;
  revokeAll(userId: UserId, opts?: { reason?: string })
    : Promise<{ grantsRevoked: number; tokensRevoked: number }>;
}

interface ContextsApi {
  revoked(userId: UserId, contextId: string): Promise<{ grantsRevoked: number; tokensRevoked: number }>;
}
```

Reference: [Admin API](/reference/admin-api).

## Documents

Mongoose document shapes. Reference: [Data model](/guide/data-model).

### `OAuthClientDoc`

```ts
interface OAuthClientDoc {
  _id: Types.ObjectId;
  clientId: string;
  name: string;
  type: 'confidential' | 'public';           // `public` — see /guide/cimd
  registration: 'manual' | 'cimd';           // `cimd` rows are re-derived on a cache miss
  metadataUrl?: string;
  metadataFetchedAt?: Date;                  // vs. clientIdMetadata.cacheTtlMs
  metadataEtag?: string;                     // replayed as If-None-Match
  trusted: boolean;                          // reserved — consent is never skipped
  secrets: ClientSecretRecord[];             // empty for a public client
  redirectUris: string[];
  allowedScopes: string[];
  allowedResources: string[];
  branding: ClientBranding;
  status: 'active' | 'disabled';
  pairwiseSubjects?: Map<string, string>;    // by user id
  createdAt: Date;
  updatedAt: Date;
}

interface ClientSecretRecord {
  hash: string;                              // SHA-256. The raw value is never stored
  label?: string;
  createdAt: Date;
  lastUsedAt?: Date;                         // how you know a rotation landed
  retiresAt?: Date;                          // stops verifying at this instant
}
```

### `OAuthGrantDoc`

```ts
interface OAuthGrantDoc {
  _id: Types.ObjectId;
  userId: UserId;
  clientId: string;
  contextId: string | null;                  // null, never absent — the index needs one value
  scopes: string[];
  resources: string[];
  version: number;                           // bumped only when the user widens the grant
  lastUsedAt?: Date;
  revokedAt?: Date | null;
  revokedBy?: 'user' | 'admin' | 'system' | 'client';
  createdAt: Date;
  updatedAt: Date;
}
```

### `OAuthCodeDoc`

```ts
interface OAuthCodeDoc {
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
  consumedAt?: Date | null;                  // set, not deleted — replay detection needs it
  expiresAt: Date;
  createdAt: Date;
}
```

### `OAuthTokenDoc`

```ts
interface OAuthTokenDoc {
  _id: Types.ObjectId;
  kind: 'access' | 'refresh';
  tokenHash: string;
  clientId: string;
  userId: UserId;
  grantId: Types.ObjectId;
  contextId: string | null;
  scopes: string[];
  audience: string[];
  familyId: string;                          // shared by every token from one code
  parentId?: Types.ObjectId | null;          // the refresh token this replaced
  consumedAt?: Date | null;
  revokedAt?: Date | null;
  familyExpiresAt?: Date;                    // absolute ceiling, copied onto each rotation
  expiresAt: Date;                           // sliding window; what the TTL index reaps
  createdAt: Date;
}
```

### `OAuthRequestDoc`

```ts
interface OAuthRequestDoc {
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
```

### `OAuthKeyDoc`

```ts
interface OAuthKeyDoc {
  _id: Types.ObjectId;
  kid: string;
  alg: 'ES256';
  publicJwk: Record<string, unknown>;
  privateJwk: Record<string, unknown>;
  status: 'active' | 'retiring';             // retiring is published but not signed with
  createdAt: Date;
}
```

### `OAuthAuditDoc`

```ts
interface OAuthAuditDoc {
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
```

### `OAuthModels`

```ts
interface OAuthModels {
  Client: Model<OAuthClientDoc>;
  Grant: Model<OAuthGrantDoc>;
  Code: Model<OAuthCodeDoc>;
  Token: Model<OAuthTokenDoc>;
  Request: Model<OAuthRequestDoc>;
  Key: Model<OAuthKeyDoc>;
  Audit: Model<OAuthAuditDoc>;
}
```

## Errors

### `OAuthError`

```ts
declare class OAuthError extends Error {
  constructor(status: number, code: string, description?: string,
              opts?: { headers?: Record<string, string> });
  status: number;
  code: string;                              // the RFC token; reaches the wire as `error`
  description?: string;
  headers?: Record<string, string>;          // e.g. WWW-Authenticate
}
```

`code` is what clients switch on. Never invent one.

`RedirectableAuthError` and `UnredirectableError` extend it and mark which side
of [the redirect boundary](/guide/security) an `/authorize` failure falls on.

## Functions

```ts
declare function createOAuthHost(config: CreateOAuthHostConfig): OAuthHostInstance;

declare function createModels(opts: {
  connection?: Mongoose | Connection;
  modelNames?: ModelNames;
  collectionPrefix?: string;
  auditRetentionDays?: number;
}): OAuthModels;

declare function defaultResolveUser(req: Request): PackageUser | null;
declare function createUserAdapter(opts?: { resolveUser?: ResolveUser }): UserAdapter;
```

`syncModelIndexes(models)` is also exported from the package root.
