import { randomToken } from '../crypto.js';
import { OAuthError, RedirectableAuthError, UnredirectableError } from '../errors.js';
import { isMetadataUrl, resolveCimdClient } from './cimd.js';
import { parseScope, validateResources, validateScopes } from './scopes.js';
import type { ResolvedContext } from '../config.js';
import type { OAuthClientDoc, OAuthRequestDoc, PackageUser } from '../../../types/index.js';

/**
 * The authorization endpoint's validation, and nothing else.
 *
 * The single most important thing in this file is the ORDER of the checks. It
 * is a security boundary, not a style: until `client_id` resolves to a live
 * registration AND `redirect_uri` matches that registration exactly, there is
 * no address we have proven safe to send a browser to. Reporting an error by
 * redirect before that point is the open-redirect hole. Everything checked
 * after it may be redirected back to the client with `state` and `iss` intact.
 *
 * See plan §9 (traps §19, inverted) and RFC 6749 §4.1.2.1.
 */

export interface ValidatedAuthRequest {
  client: OAuthClientDoc;
  redirectUri: string;
  scopes: string[];
  resources: string[];
  state?: string;
  nonce?: string;
  codeChallenge: string;
  prompt?: string;
  maxAge?: number;
}

/**
 * A single-valued query parameter.
 *
 * Express's query parser yields an array when a parameter repeats. For a
 * security parameter "first one wins" is a parameter-pollution primitive, so a
 * repeat is treated as absent and the required-check below reports it.
 */
function one(query: Record<string, unknown>, name: string): string | undefined {
  const value = query[name];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/** `resource` is the one parameter RFC 8707 lets repeat. */
function many(query: Record<string, unknown>, name: string): string[] {
  const value = query[name];
  if (typeof value === 'string') return value ? [value] : [];
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is string => typeof v === 'string' && v.length > 0);
}

/**
 * `client_id` → registration.
 *
 * Two sources, and which one answers is decided by config, not by the value:
 * with `clientIdMetadata` disabled a URL-shaped `client_id` takes the plain
 * database lookup and fails exactly like any other unknown client — no outbound
 * request, and nothing in the response or the timing that says a different code
 * path exists.
 *
 * An unresolvable CIMD client is an `UnredirectableError` for the same reason
 * an unknown one is: no `redirect_uri` has been validated yet, so there is no
 * address proven safe to redirect an error to.
 */
async function resolveClient(ctx: ResolvedContext, clientId: string): Promise<OAuthClientDoc> {
  if (ctx.cimd.enabled && isMetadataUrl(clientId)) {
    return resolveCimdClient(ctx, clientId);
  }
  const client = await ctx.models.Client.findOne({ clientId }).exec();
  if (!client) {
    throw new UnredirectableError('invalid_client', `unknown client_id '${clientId}'`);
  }
  return client;
}

export async function validateAuthorizationRequest(
  ctx: ResolvedContext,
  query: Record<string, unknown>,
): Promise<ValidatedAuthRequest> {
  // ── Band 1: unredirectable. No trusted destination exists yet. ────────────
  const clientId = one(query, 'client_id');
  if (!clientId) {
    throw new UnredirectableError('invalid_request', '`client_id` is required');
  }

  const client = await resolveClient(ctx, clientId);
  if (client.status !== 'active') {
    throw new UnredirectableError('invalid_client', `client '${clientId}' is disabled`);
  }

  const redirectUri = one(query, 'redirect_uri');
  if (!redirectUri) {
    throw new UnredirectableError('invalid_request', '`redirect_uri` is required');
  }
  // Exact string comparison against the registration — no prefix match, no
  // wildcard, no ignoring the query string. Every relaxation of this rule is a
  // published attack; a client that needs a second callback registers a second
  // URI.
  if (!client.redirectUris.includes(redirectUri)) {
    throw new UnredirectableError(
      'invalid_request',
      `redirect_uri is not registered for client '${clientId}'`,
    );
  }

  // ── Band 2: redirectable. Both identifiers are now proven. ────────────────
  const state = one(query, 'state');
  const fail = (code: string, description: string) =>
    new RedirectableAuthError(code, description, redirectUri, state);

  const responseType = one(query, 'response_type');
  if (responseType !== 'code') {
    throw new RedirectableAuthError(
      'unsupported_response_type',
      'only `response_type=code` is supported',
      redirectUri,
      state,
    );
  }

  // PKCE is mandatory in OAuth 2.1 — not "recommended", and not skippable for
  // confidential clients. A code intercepted in the browser's redirect chain is
  // useless without the verifier.
  const codeChallenge = one(query, 'code_challenge');
  if (!codeChallenge) {
    throw fail('invalid_request', '`code_challenge` is required (PKCE, RFC 7636)');
  }
  // RFC 7636 §4.3 defaults an omitted method to `plain`, which this package
  // does not implement anywhere. Requiring the parameter makes that rejection
  // explicit instead of letting a downgrade arrive as a default.
  if (one(query, 'code_challenge_method') !== 'S256') {
    throw fail('invalid_request', '`code_challenge_method` must be `S256`');
  }

  let scopes: string[];
  let resources: string[];
  try {
    scopes = validateScopes(ctx, parseScope(one(query, 'scope')), client);
    resources = validateResources(ctx, many(query, 'resource'), client);
  } catch (err) {
    // The scope/resource validators are shared with the token endpoint, where
    // there is no redirect to make. Re-shape rather than duplicate them.
    if (err instanceof OAuthError) throw fail(err.code, err.description ?? err.code);
    throw err;
  }

  let maxAge: number | undefined;
  const rawMaxAge = one(query, 'max_age');
  if (rawMaxAge !== undefined) {
    const parsed = Number(rawMaxAge);
    if (!Number.isInteger(parsed) || parsed < 0) {
      throw fail('invalid_request', '`max_age` must be a non-negative integer');
    }
    maxAge = parsed;
  }

  return {
    client,
    redirectUri,
    scopes,
    resources,
    ...(state !== undefined ? { state } : {}),
    ...(one(query, 'nonce') ? { nonce: one(query, 'nonce') } : {}),
    codeChallenge,
    ...(one(query, 'prompt') ? { prompt: one(query, 'prompt') } : {}),
    ...(maxAge !== undefined ? { maxAge } : {}),
  };
}

/**
 * Park the validated request and hand back an opaque handle.
 *
 * The handle is what travels through the host's consent UI, which is why the
 * parameters are snapshotted here rather than round-tripped through the
 * browser: a consent screen that can be re-parameterised by editing its own URL
 * approves whatever the last hop asked for.
 */
export async function createAuthorizationRequest(
  ctx: ResolvedContext,
  validated: ValidatedAuthRequest,
  user: PackageUser,
): Promise<OAuthRequestDoc> {
  const doc = await ctx.models.Request.create({
    requestId: randomToken(),
    clientId: validated.client.clientId,
    userId: user.id,
    redirectUri: validated.redirectUri,
    scopes: validated.scopes,
    resources: validated.resources,
    state: validated.state,
    nonce: validated.nonce,
    codeChallenge: validated.codeChallenge,
    codeChallengeMethod: 'S256',
    prompt: validated.prompt,
    maxAge: validated.maxAge,
    expiresAt: new Date(Date.now() + ctx.ttl.authorizationRequest * 1000),
  });

  ctx.track({
    type: 'oauth.authorization_requested',
    userId: user.id,
    clientId: validated.client.clientId,
    scopes: validated.scopes,
    meta: { resources: validated.resources },
  });

  return doc;
}

/**
 * Merge a query parameter into a configured URL.
 *
 * `consentUrl` and `loginUrl` are usually host-relative (`/settings/authorize`),
 * and both may already carry a query string. Parsing against a placeholder
 * origin gets the merge right — hand-concatenating `?` is how a second `?`
 * ends up in a redirect.
 */
function withParam(configured: string, name: string, value: string): string {
  const absolute = /^https?:\/\//i.test(configured);
  const url = new URL(configured, 'http://oauth-host.invalid');
  url.searchParams.set(name, value);
  return absolute ? url.toString() : `${url.pathname}${url.search}${url.hash}`;
}

/** Where `/authorize` sends a signed-IN user: the host's own consent page. */
export function consentRedirectUrl(ctx: ResolvedContext, requestId: string): string {
  return withParam(ctx.consentUrl, 'request_id', requestId);
}

/**
 * Where `/authorize` sends a signed-OUT user — standards/adapters.md §Sign-in
 * redirects. `/authorize` is one of the few package routes a user can land on
 * cold, so the host's "signed out on arrival" middleware never runs for it.
 *
 * Null when no `loginUrl` is configured: the caller must then answer an error
 * rather than invent a login page that does not exist.
 */
export function loginRedirectUrl(ctx: ResolvedContext, returnTo: string): string | null {
  if (!ctx.loginUrl) return null;
  return withParam(ctx.loginUrl, ctx.returnParam, returnTo);
}
