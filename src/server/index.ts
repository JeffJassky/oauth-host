import { resolveConfig } from './config.js';
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
export {
  CHATGPT_CONNECTOR_REDIRECT_URI_PATTERN,
  CHATGPT_LEGACY_REDIRECT_URI,
  CIMD_ALLOWED_HOSTS,
  CLAUDE_CODE_REDIRECT_URIS,
  CLAUDE_CONNECTOR_REDIRECT_URI,
} from './vendors.js';

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
     *
     * Resolving this is also what flips `ready` and un-gates `/authorize`,
     * `POST /consent/:requestId` and `POST /token`.
     */
    syncIndexes: () => ctx.syncIndexes(),

    /**
     * Has `syncIndexes()` resolved?
     *
     * A boolean, not a promise, and the difference is the failure mode. A
     * promise would have to exist from construction, so a host that never calls
     * `syncIndexes()` would await it forever — a boot-order mistake turning into
     * an unexplained hang with no message. A boolean is plainly `false`, cannot
     * be awaited by accident, and is backed by three routes that say what is
     * wrong by name. Gate a mount on it, or simply
     * `await oauth.syncIndexes()` first, which is the same thing said directly.
     */
    get ready() {
      return ctx.indexes.ready;
    },

    /** Escape hatch. Prefer the APIs above; these carry no invariants. */
    models: ctx.models,
  };
}
