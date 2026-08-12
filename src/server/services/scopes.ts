import { OAuthError, invalidScope } from '../errors.js';
import type { ResolvedContext } from '../config.js';
import type { OAuthClientDoc, ScopeSpec } from '../../../types/index.js';

/**
 * The scope catalog, applied.
 *
 * Two independent gates decide what a client may ask for, and both have to
 * hold: the host's catalog (does this scope exist at all?) and the client's
 * registration (was this client granted the right to ask?). Collapsing them
 * into one list would mean registering a client implicitly extends the catalog.
 *
 * Nothing in here consults the user's existing grants — that is consent's job.
 * These functions run before we know who the user is.
 */

/**
 * RFC 6749 §3.3 — `scope` is a space-delimited list.
 *
 * Deliberately total: an unknown or malformed id survives parsing and is
 * rejected by `validateScopes` with the offending value in the message. Parsing
 * that silently drops junk turns "you asked for a scope that does not exist"
 * into "you were granted less than you asked for", which is the harder bug.
 */
export function parseScope(raw: string | undefined): string[] {
  if (typeof raw !== 'string') return [];
  const seen = new Set<string>();
  for (const id of raw.split(/\s+/)) if (id) seen.add(id);
  return [...seen];
}

/**
 * Intersect the request against both gates.
 *
 * Order preserved from the request so the consent screen lists scopes the way
 * the client wrote them. Throws on the FIRST offender rather than filtering:
 * silently narrowing means the client believes it holds access it does not, and
 * discovers otherwise at the first 403 in production.
 */
export function validateScopes(
  ctx: ResolvedContext,
  requested: string[],
  client: OAuthClientDoc,
): string[] {
  const allowed = new Set(client.allowedScopes);
  for (const id of requested) {
    if (!ctx.scopeIndex.has(id)) {
      throw invalidScope(`unknown scope '${id}'`);
    }
    if (!allowed.has(id)) {
      throw invalidScope(`client '${client.clientId}' is not allowed the scope '${id}'`);
    }
  }
  return [...requested];
}

/**
 * The scope half of the consent payload (plan §8) — a versioned UI contract.
 *
 * Only catalog-visible fields cross this line. `isNew` is the one derived bit:
 * false means the user has already granted it to this client, so the host's UI
 * can dim it and emphasise what re-consent actually adds.
 */
export function describeScopes(
  ctx: ResolvedContext,
  ids: string[],
  opts: { previouslyGranted?: string[] } = {},
): Array<{ id: string; label: string; description?: string; sensitive?: boolean; isNew: boolean }> {
  const granted = new Set(opts.previouslyGranted ?? []);
  return ids.map((id) => {
    // A scope can leave the catalog while a grant referencing it is still live,
    // so fall back to the bare id rather than dropping the row — a consent
    // screen missing a line is worse than one with a thin label.
    const spec: ScopeSpec = ctx.scopeIndex.get(id) ?? { id, label: id };
    return {
      id,
      label: spec.label ?? id,
      ...(spec.description ? { description: spec.description } : {}),
      ...(spec.sensitive ? { sensitive: true } : {}),
      isNew: !granted.has(id),
    };
  });
}

/**
 * RFC 8707 — resource indicators.
 *
 * The same two gates as scopes: the resource must be declared by the host and
 * allowed for this client. Comparison is exact string equality, which is what
 * `resolveConfig` normalizes the catalog for.
 *
 * When the client sends none we default to its first allowed resource rather
 * than issuing an unbound token: an access token with no audience is one a
 * confused deputy can replay at any API the host runs.
 */
export function validateResources(
  ctx: ResolvedContext,
  requested: string[],
  client: OAuthClientDoc,
): string[] {
  const declared = new Set(ctx.resources.map((r) => r.id));
  // A client registered with no explicit list inherits the whole catalog —
  // `clients.create` fills this in, so an empty array here means an old row.
  const allowed = client.allowedResources.length ? new Set(client.allowedResources) : declared;

  if (requested.length === 0) {
    const fallback = client.allowedResources[0] ?? ctx.resources[0]?.id;
    return fallback ? [fallback] : [];
  }

  const seen = new Set<string>();
  for (const id of requested) {
    if (!declared.has(id)) {
      // RFC 8707 §2 names this error; clients switch on it to stop retrying.
      throw new OAuthError(400, 'invalid_target', `unknown resource '${id}'`);
    }
    if (!allowed.has(id)) {
      throw new OAuthError(
        400,
        'invalid_target',
        `client '${client.clientId}' is not allowed the resource '${id}'`,
      );
    }
    seen.add(id);
  }
  return [...seen];
}
