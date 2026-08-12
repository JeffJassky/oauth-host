import express from 'express';
import type { RequestHandler, Router } from 'express';
import { wrap } from '../errors.js';
import type { ResolvedContext } from '../config.js';
import type { ResourceSpec } from '../../../types/index.js';

/**
 * Discovery metadata — RFC 8414 (authorization server), OpenID Connect
 * Discovery, and RFC 9728 (protected resource).
 *
 * This router is mounted at the ORIGIN ROOT, not under `/oauth`: `/.well-known`
 * paths are defined relative to the issuer's origin and are not relocatable. It
 * is the one router in this package the host cannot choose a mount path for.
 *
 * Everything a client can reach is generated from ONE table below. Adding an
 * endpoint later (`introspection_endpoint`, `registration_endpoint`) is one row
 * in `ENDPOINTS`, not an edit in three documents that drift apart — which is
 * how a server ends up advertising a token endpoint it moved a year ago.
 */

/** `metadata key` → path under the oauth router's mount. */
const ENDPOINTS: ReadonlyArray<readonly [key: string, path: string]> = [
  ['authorization_endpoint', '/authorize'],
  ['token_endpoint', '/token'],
  ['revocation_endpoint', '/revoke'],
  ['userinfo_endpoint', '/userinfo'],
  ['jwks_uri', '/jwks'],
];

const WELL_KNOWN_AS = '/.well-known/oauth-authorization-server';
const WELL_KNOWN_OIDC = '/.well-known/openid-configuration';
const WELL_KNOWN_RESOURCE = '/.well-known/oauth-protected-resource';

/**
 * Where a resource's RFC 9728 metadata lives.
 *
 * RFC 9728 §3.1: insert `/.well-known/oauth-protected-resource` between the
 * host and the path of the resource identifier. `https://api.example.com/mcp`
 * therefore publishes at `…/.well-known/oauth-protected-resource/mcp`, and a
 * resource that is a bare origin publishes at the unsuffixed path.
 *
 * `protect()` puts this exact URL in its `WWW-Authenticate` challenge, so the
 * two must agree — hence one function rather than two format strings.
 */
export function protectedResourceMetadataUrl(issuer: string, resourceId: string): string {
  return `${issuer}${WELL_KNOWN_RESOURCE}${identifierPath(resourceId)}`;
}

/**
 * The path component of an absolute identifier, `''` for a bare origin.
 *
 * Shared by the resource identifier (RFC 9728 §3.1) and the issuer identifier
 * (RFC 8414 §3.1) because both specs mandate the same transformation, and both
 * require the terminating `/` be removed before the segments are joined.
 */
function identifierPath(identifier: string): string {
  const { pathname } = new URL(identifier);
  return pathname === '/' ? '' : pathname.replace(/\/+$/, '');
}

/** Literal path → RegExp, so a path carrying `.` or `(` cannot become a pattern. */
function escapeRe(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Match `/.well-known/<suffix>` and everything under it.
 *
 * A RegExp path, not `/*`: Express 4 and Express 5 disagree about wildcard
 * syntax (v5's path-to-regexp requires a name), and this package claims both in
 * its peer range. A RegExp means the same route works on either.
 */
function wellKnownPattern(wellKnown: string): RegExp {
  return new RegExp(`^${escapeRe(wellKnown)}(?:/.*)?$`);
}

/**
 * One handler for every well-known endpoint that carries an inserted path.
 *
 * RFC 8414 §3.1 (issuer) and RFC 9728 §3.1 (resource) specify the *same*
 * transformation — the well-known segment goes BETWEEN the host and the
 * identifier's path — so they match the same way. Sharing the matcher is what
 * stops the two drifting: the failure this package already had was one endpoint
 * implementing the insertion and the other assuming a fixed path.
 *
 * `bare` answers the unsuffixed path, which is what an identifier with no path
 * component publishes at and what a client that ignores the transformation
 * asks for. Anything else is a 404 in JSON — serving `bare` for an arbitrary
 * suffix would hand a client the metadata of a server it did not ask about.
 */
function wellKnownHandler(
  ctx: ResolvedContext,
  wellKnown: string,
  bare: Record<string, unknown>,
  bySuffix: Map<string, Record<string, unknown>>,
  describeMiss: (suffix: string) => string,
): RequestHandler {
  return wrap(ctx.logger, (req, res) => {
    // Read the suffix off the path rather than a capture group: Express 4 and 5
    // expose RegExp captures differently, and `req.path` is the same string in
    // both.
    const suffix = req.path.slice(wellKnown.length).replace(/^\/+/, '').replace(/\/+$/, '');
    if (!suffix) return res.json(bare);
    const doc = bySuffix.get(suffix);
    if (!doc) {
      return res.status(404).json({ error: 'not_found', error_description: describeMiss(suffix) });
    }
    return res.json(doc);
  });
}

function authorizationServerMetadata(ctx: ResolvedContext, mountPath: string): Record<string, unknown> {
  const base = `${ctx.issuer}${mountPath === '/' ? '' : mountPath}`;
  const endpoints = Object.fromEntries(ENDPOINTS.map(([key, path]) => [key, `${base}${path}`]));

  return {
    issuer: ctx.issuer,
    ...endpoints,
    scopes_supported: ctx.scopes.map((s) => s.id),
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    // S256 only. `plain` is not implemented anywhere in this package, so
    // advertising it would be a lie a client would discover at redemption.
    code_challenge_methods_supported: ['S256'],
    // `none` is advertised only when CIMD is on. Listing it unconditionally
    // would tell every client that secretless authentication is available here,
    // and the only clients that can use it are the ones this server would then
    // refuse to register.
    token_endpoint_auth_methods_supported: [
      'client_secret_basic',
      'client_secret_post',
      ...(ctx.cimd.enabled ? ['none'] : []),
    ],
    // What tells Claude and ChatGPT to skip registration entirely and send
    // their metadata document URL as `client_id`.
    ...(ctx.cimd.enabled ? { client_id_metadata_document_supported: true } : {}),
    subject_types_supported: [ctx.subjectMode],
    id_token_signing_alg_values_supported: ['ES256'],
    // RFC 9207. Advertising it is what lets a client REQUIRE `iss` on the
    // authorization response and so refuse a mix-up attack.
    authorization_response_iss_parameter_supported: true,
  };
}

function protectedResourceMetadata(ctx: ResolvedContext, resource: ResourceSpec): Record<string, unknown> {
  return {
    resource: resource.id,
    authorization_servers: [ctx.issuer],
    scopes_supported: resource.scopes ?? ctx.scopes.map((s) => s.id),
    bearer_methods_supported: ['header'],
  };
}

/**
 * @param mountPath where the host mounts `createOAuthRouter`. The endpoint URLs
 * this document advertises are `issuer + mountPath + path`, and the host — not
 * the package — chooses that mount, so it has to be told. Default `/oauth`.
 */
export function createDiscoveryRouter(ctx: ResolvedContext, mountPath = '/oauth'): Router {
  const router = express.Router();

  const asMetadata = authorizationServerMetadata(ctx, mountPath);

  // RFC 8414 §3.1 — for an issuer WITH a path component the metadata lives at
  // `/.well-known/oauth-authorization-server/{path}`: the well-known segment is
  // inserted between the host and the issuer's path, never appended to it. An
  // issuer of `https://example.com/api` therefore publishes at
  // `…/.well-known/oauth-authorization-server/api`, and a bare-origin issuer at
  // the unsuffixed path. A host that only served the fixed path would be
  // undiscoverable to a spec-following client.
  const issuerSuffix = identifierPath(ctx.issuer).replace(/^\//, '');
  const asBySuffix = new Map(issuerSuffix ? [[issuerSuffix, asMetadata]] : []);
  const notThisIssuer = (suffix: string) =>
    `This authorization server's issuer is '${ctx.issuer}', which does not publish at '${suffix}'`;

  // RFC 8414 and OIDC Discovery are the same document for this server: one
  // grant type, one signing alg, one set of endpoints. Serving one object from
  // every path is what keeps them from diverging.
  const serveAs = wrap(ctx.logger, (_req, res) => res.json(asMetadata));
  router.get(
    wellKnownPattern(WELL_KNOWN_AS),
    wellKnownHandler(ctx, WELL_KNOWN_AS, asMetadata, asBySuffix, notThisIssuer),
  );
  router.get(
    wellKnownPattern(WELL_KNOWN_OIDC),
    wellKnownHandler(ctx, WELL_KNOWN_OIDC, asMetadata, asBySuffix, notThisIssuer),
  );

  // The counterintuitive one. OpenID Connect Discovery 1.0 §4.1 APPENDS
  // `/.well-known/openid-configuration` to the issuer, so an issuer of
  // `https://example.com/api` publishes at `https://example.com/api/.well-known/
  // openid-configuration` — the opposite placement to RFC 8414 §3.1 above, for
  // the byte-identical document. RFC 8414 §5 names the disagreement and says a
  // deployment may have to answer both during the transition, so we answer both
  // rather than pick a winner and be undiscoverable to half the clients.
  //
  // Only registered when the issuer has a path: without one this collapses onto
  // the fixed path the route above already owns.
  if (issuerSuffix) {
    router.get(new RegExp(`^${escapeRe(`/${issuerSuffix}${WELL_KNOWN_OIDC}`)}/?$`), serveAs);
  }

  // Resource metadata keyed by the path suffix a request carries. Built once:
  // the catalog is fixed at boot and these are the hottest unauthenticated
  // reads in the package.
  const bySuffix = new Map(
    ctx.resources.map((r) => [identifierPath(r.id).replace(/^\//, ''), protectedResourceMetadata(ctx, r)]),
  );
  // The bare path serves the first configured resource — the degenerate
  // single-API host never has to know suffixes exist.
  const firstResource = protectedResourceMetadata(ctx, ctx.resources[0]!);
  router.get(
    wellKnownPattern(WELL_KNOWN_RESOURCE),
    wellKnownHandler(
      ctx,
      WELL_KNOWN_RESOURCE,
      firstResource,
      bySuffix,
      (suffix) => `No resource is registered at '${suffix}'`,
    ),
  );

  return router;
}
