import express from 'express';
import type { Express, Request } from 'express';
import mongoose from 'mongoose';
import request from 'supertest';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { resolveConfig, type ResolvedContext } from '../src/server/config.js';
import { syncModelIndexes } from '../src/server/models.js';
import { randomToken, sha256 } from '../src/server/crypto.js';
import { createProtect } from '../src/server/protect.js';
import { createDiscoveryRouter, createOAuthRouter } from '../src/server/routes/index.js';
import { createClientsApi } from '../src/server/services/admin.js';
import type {
  CreateOAuthHostConfig,
  CreatedClient,
  OAuthHostInstance,
  PackageUser,
} from '../types/index.js';

/**
 * The harness. Real HTTP, real Mongo, no mocks — standards/testing.md.
 *
 * It wires the package the way the paper test in the build plan does: the
 * discovery router at the origin root, the protocol router at `/oauth`, and a
 * fake session middleware standing in for the host's own auth, upstream of
 * both. That arrangement is the only one this package supports, so the harness
 * should not be able to express any other.
 *
 * It deliberately does NOT go through `createOAuthHost()`. The factory composes
 * these same pieces; building them here means an HTTP test failure points at a
 * route rather than at the wiring.
 */

let mongod: MongoMemoryServer | undefined;

export async function startDb(): Promise<void> {
  mongod = await MongoMemoryServer.create();
  await mongoose.connect(mongod.getUri(), { dbName: 'oauth-host-test' });
}

export async function stopDb(): Promise<void> {
  await mongoose.disconnect();
  await mongod?.stop();
}

/**
 * Empty every collection between tests.
 *
 * Mongoose's model registry is process-global (traps #2), so every `buildApp`
 * in a run shares one set of models and therefore one set of collections. Drop
 * the documents, not the collections — dropping takes the indexes with them and
 * the next test races the rebuild (traps #3).
 */
export async function clearDb(): Promise<void> {
  const { collections } = mongoose.connection;
  await Promise.all(Object.values(collections).map((c) => c.deleteMany({})));
}

export function newUserId(): mongoose.Types.ObjectId {
  return new mongoose.Types.ObjectId();
}

export const TEST_ISSUER = 'https://auth.test';
export const TEST_RESOURCE = 'https://auth.test/mcp';
export const OTHER_RESOURCE = 'https://auth.test/reports';
export const REDIRECT_URI = 'https://client.test/cb';

/** The mutable "who is signed in" handle `buildApp` hands back. */
export interface Session {
  user: PackageUser | null;
}

export interface BuildAppOptions {
  session?: Session;
  config?: Partial<CreateOAuthHostConfig>;
}

export interface BuiltApp {
  app: Express;
  ctx: ResolvedContext;
  state: Session;
  clients: ReturnType<typeof createClientsApi>;
  protect: OAuthHostInstance['protect'];
}

/** What the fake auth middleware writes onto the request. Mirrors a host. */
type AuthedRequest = Request & { authUser?: PackageUser | null };

export function testUser(overrides: Partial<PackageUser> = {}): PackageUser {
  return {
    id: newUserId(),
    email: 'user@example.com',
    displayName: 'Test User',
    authTime: new Date(),
    ...overrides,
  };
}

export async function buildApp({ session, config = {} }: BuildAppOptions = {}): Promise<BuiltApp> {
  const state: Session = session ?? { user: null };

  const ctx = resolveConfig({
    connection: mongoose,
    issuer: TEST_ISSUER,
    resources: [
      { id: TEST_RESOURCE, label: 'MCP server' },
      { id: OTHER_RESOURCE, label: 'Reporting API' },
    ],
    scopes: [
      { id: 'openid', label: 'Sign you in', oidc: true },
      { id: 'profile', label: 'Your name and avatar', oidc: true },
      { id: 'email', label: 'Your email address', oidc: true },
      { id: 'contacts.read', label: 'Read your contacts' },
      { id: 'contacts.write', label: 'Create and edit contacts', sensitive: true },
    ],
    consentUrl: '/settings/authorize',
    loginUrl: '/login',
    // Dev convenience, and the reason these tests need no key fixtures: the
    // signing key is generated on first use and persisted in `oauth_keys`.
    signing: { autoGenerate: true },
    resolveUser: (req: Request) => (req as AuthedRequest).authUser ?? null,
    ...config,
  });

  // Await index builds rather than race them — traps #3.
  await syncModelIndexes(ctx.models);

  const app = express();
  // The HOST's parsers and auth, upstream of everything. Note there is NO
  // `express.urlencoded` here, on purpose: `test/flow.test.ts` asserts a
  // form-encoded POST to `/token` still works, which is the whole point of the
  // route-level exception in `routes/oauth.ts`.
  app.use(express.json());
  app.use((req, _res, next) => {
    (req as AuthedRequest).authUser = state.user;
    next();
  });

  app.use(createDiscoveryRouter(ctx, '/oauth'));
  app.use('/oauth', createOAuthRouter(ctx));

  return { app, ctx, state, clients: createClientsApi(ctx), protect: createProtect(ctx) };
}

/** Register a client with sensible defaults for the flow helper. */
export async function createTestClient(
  built: BuiltApp,
  overrides: Partial<Parameters<BuiltApp['clients']['create']>[0]> = {},
): Promise<CreatedClient> {
  return built.clients.create({
    name: 'Claude',
    redirectUris: [REDIRECT_URI],
    allowedScopes: ['openid', 'profile', 'email', 'contacts.read', 'contacts.write'],
    allowedResources: [TEST_RESOURCE, OTHER_RESOURCE],
    branding: { publisher: 'Anthropic' },
    ...overrides,
  });
}

export interface Pkce {
  verifier: string;
  challenge: string;
}

/**
 * A PKCE pair. `randomToken(32)` is 43 base64url characters, which satisfies
 * RFC 7636 §4.1's length bound and its `unreserved` character set exactly.
 */
export function pkce(): Pkce {
  const verifier = randomToken(32);
  return { verifier, challenge: sha256(verifier) };
}

export interface FlowOptions {
  scope?: string;
  resource?: string;
  state?: string;
  nonce?: string;
  /** Approve a subset of what was requested. Defaults to everything. */
  approveScopes?: string[];
  /** `client_secret_post` instead of the default `client_secret_basic`. */
  authMethod?: 'basic' | 'post';
}

export interface FlowResult {
  requestId: string;
  consent: Record<string, unknown>;
  redirectTo: string;
  code: string;
  state: string | null;
  iss: string | null;
  tokens: Record<string, unknown>;
  pkce: Pkce;
}

/**
 * Drive a complete authorization: `/authorize` → consent payload → approve →
 * `/token`. Returns everything the steps produced, so a test can assert on the
 * middle of the flow without re-driving it.
 */
export async function authorize(
  built: BuiltApp,
  client: CreatedClient,
  opts: FlowOptions = {},
): Promise<FlowResult> {
  const { app } = built;
  const pair = pkce();
  const scope = opts.scope ?? 'openid profile contacts.read';
  const stateParam = opts.state ?? 'xyz-state';

  const authRes = await request(app).get('/oauth/authorize').query({
    response_type: 'code',
    client_id: client.clientId,
    redirect_uri: REDIRECT_URI,
    scope,
    state: stateParam,
    code_challenge: pair.challenge,
    code_challenge_method: 'S256',
    resource: opts.resource ?? TEST_RESOURCE,
    ...(opts.nonce ? { nonce: opts.nonce } : {}),
  });
  if (authRes.status !== 302) {
    throw new Error(`/authorize did not redirect: ${authRes.status} ${JSON.stringify(authRes.body)}`);
  }
  const requestId = param(authRes.headers.location, 'request_id');
  if (!requestId) throw new Error(`no request_id in ${authRes.headers.location}`);

  const consentRes = await request(app).get(`/oauth/consent/${requestId}`);
  if (consentRes.status !== 200) {
    throw new Error(`consent payload failed: ${consentRes.status} ${JSON.stringify(consentRes.body)}`);
  }

  const decision = await request(app)
    .post(`/oauth/consent/${requestId}`)
    .send({ approve: true, ...(opts.approveScopes ? { scopes: opts.approveScopes } : {}) });
  if (decision.status !== 200) {
    throw new Error(`consent decision failed: ${decision.status} ${JSON.stringify(decision.body)}`);
  }

  const redirectTo = String(decision.body.redirectTo);
  const code = param(redirectTo, 'code');
  if (!code) throw new Error(`no code in ${redirectTo}`);

  const tokens = await exchange(built, client, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: pair.verifier,
  }, opts.authMethod);

  return {
    requestId,
    consent: consentRes.body as Record<string, unknown>,
    redirectTo,
    code,
    state: param(redirectTo, 'state'),
    iss: param(redirectTo, 'iss'),
    tokens: tokens.body as Record<string, unknown>,
    pkce: pair,
  };
}

/** A form-encoded `/token` post with client authentication attached. */
export function exchange(
  built: BuiltApp,
  client: CreatedClient,
  fields: Record<string, string>,
  authMethod: 'basic' | 'post' = 'basic',
): request.Test {
  const req = request(built.app).post('/oauth/token').type('form');
  return authMethod === 'basic'
    ? req.auth(client.clientId, client.clientSecret).send(fields)
    : req.send({ ...fields, client_id: client.clientId, client_secret: client.clientSecret });
}

/** Read a query parameter out of an absolute or root-relative URL. */
export function param(url: string, name: string): string | null {
  return new URL(url, 'https://relative.invalid').searchParams.get(name);
}
