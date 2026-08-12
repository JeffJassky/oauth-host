import express from 'express';
import type { Router } from 'express';
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
  return `${issuer}/.well-known/oauth-protected-resource${resourcePathSuffix(resourceId)}`;
}

/** The path component of a resource id, `''` for a bare origin. */
function resourcePathSuffix(resourceId: string): string {
  const { pathname } = new URL(resourceId);
  return pathname === '/' ? '' : pathname.replace(/\/+$/, '');
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
  // Resource metadata keyed by the path suffix a request carries. Built once:
  // the catalog is fixed at boot and these are the hottest unauthenticated
  // reads in the package.
  const bySuffix = new Map(
    ctx.resources.map((r) => [resourcePathSuffix(r.id).replace(/^\//, ''), protectedResourceMetadata(ctx, r)]),
  );
  const firstResource = protectedResourceMetadata(ctx, ctx.resources[0]!);

  // RFC 8414 and OIDC Discovery are the same document for this server: one
  // grant type, one signing alg, one set of endpoints. Serving one object from
  // both paths is what keeps them from diverging.
  const serveAs = wrap(ctx.logger, (_req, res) => res.json(asMetadata));
  router.get('/.well-known/oauth-authorization-server', serveAs);
  router.get('/.well-known/openid-configuration', serveAs);

  // A RegExp path, not `/*`: Express 4 and Express 5 disagree about wildcard
  // syntax (v5's path-to-regexp requires a name), and this package claims both
  // in its peer range. A RegExp means the same route works on either.
  const WELL_KNOWN_RESOURCE = '/.well-known/oauth-protected-resource';
  router.get(
    /^\/\.well-known\/oauth-protected-resource(?:\/.*)?$/,
    wrap(ctx.logger, (req, res) => {
      // Read the suffix off the path rather than a capture group: Express 4 and
      // 5 expose RegExp captures differently, and `req.path` is the same string
      // in both.
      const suffix = req.path.slice(WELL_KNOWN_RESOURCE.length).replace(/^\//, '');
      // The bare path serves the first configured resource — the degenerate
      // single-API host never has to know suffixes exist.
      if (!suffix) return res.json(firstResource);
      const doc = bySuffix.get(suffix.replace(/\/+$/, ''));
      if (!doc) {
        return res.status(404).json({
          error: 'not_found',
          error_description: `No resource is registered at '${suffix}'`,
        });
      }
      return res.json(doc);
    }),
  );

  return router;
}
