import { resolveConfig } from './config.js';
import { syncModelIndexes } from './models.js';
import { createProtect } from './protect.js';
import { createDiscoveryRouter, createOAuthRouter } from './routes/index.js';
import {
  createClientsApi,
  createContextsApi,
  createGrantsApi,
  createUsersApi,
} from './services/admin.js';
import type { CreateOAuthHostConfig, OAuthHostInstance } from '../../types/index.js';

export { defaultResolveUser, createUserAdapter } from './config.js';
export { createModels, syncModelIndexes } from './models.js';
export { OAuthError, RedirectableAuthError, UnredirectableError } from './errors.js';

/**
 * oauth-host — the package factory.
 *
 * Returns routers the host mounts. Never an app, never a server.
 *
 *   const oauth = createOAuthHost({ connection, issuer, resources, scopes, consentUrl })
 *
 *   app.use(oauth.routes.discovery)                     // origin root
 *   app.use('/oauth', express.json(), oauth.routes.oauth)
 *   app.use('/mcp', oauth.protect('contacts.read'), mcpRouter)
 *
 *   await oauth.syncIndexes()                           // before the first write
 *
 * Two routers rather than one because `/.well-known/*` is not relocatable —
 * RFC 8414 and RFC 9728 fix those paths at the origin root, and a client
 * bootstrapping from a URL it was given has no way to be told otherwise.
 *
 * The return type is the hand-written `OAuthHostInstance` from `types/`, not an
 * inferred shape. Annotating it here makes `tsc` fail when the source grows a
 * method the published declarations do not mention — the exact drift
 * `types/test-d.ts` exists to catch. See standards/traps.md #9.
 */
export function createOAuthHost(config: CreateOAuthHostConfig): OAuthHostInstance {
  const ctx = resolveConfig(config);

  return {
    routes: {
      // The discovery document publishes ABSOLUTE endpoint URLs, so it has to be
      // told where the oauth router lives. A router cannot learn its own mount
      // until a request arrives, by which time the metadata is already built.
      discovery: createDiscoveryRouter(ctx, ctx.mountPath),
      oauth: createOAuthRouter(ctx),
    },

    protect: createProtect(ctx),

    clients: createClientsApi(ctx),
    grants: createGrantsApi(ctx),
    users: createUsersApi(ctx),
    contexts: createContextsApi(ctx),

    /**
     * Build every index before the first write.
     *
     * Not optional and not lazy: the unique partial index on grants is what
     * stops one user holding two live grants for the same client, and mongoose
     * builds indexes in the background — a cold database will happily serve
     * the write that violates it first. See standards/traps.md #3.
     */
    syncIndexes: () => syncModelIndexes(ctx.models),

    /** Escape hatch. Prefer the APIs above; these carry no invariants. */
    models: ctx.models,
  };
}
