/**
 * The two routers a host mounts. Both are Routers — never an app, never a
 * server (standards/house-style.md).
 *
 * They are separate because their mount points are: discovery MUST sit at the
 * origin root (`/.well-known/*` is not relocatable) while the protocol router
 * lives wherever the host puts it, conventionally `/oauth`. Merging them would
 * force the whole package to the root.
 */
export { createDiscoveryRouter, protectedResourceMetadataUrl } from './discovery.js';
export { createOAuthRouter } from './oauth.js';
