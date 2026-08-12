import { createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { sha256 } from './crypto.js';
import type { ResolvedContext } from './config.js';
import type { OAuthKeyDoc, SigningKeySpec } from '../../types/index.js';

/**
 * Signing keys for the `id_token`, and the JWKS the client validates against.
 *
 * ES256 only. Not a limitation to remove later: one curve means one code path,
 * and P-256 is the intersection of "every OIDC client supports it" and "Node
 * signs it without a dependency". RS256 would add a second branch to every
 * verification story for no client that cannot already do ES256.
 *
 * Two sources, in order:
 *   1. `signing.keys[]` — PEM from the environment. The production answer: the
 *      key is not in the same database as the tokens it signs.
 *   2. `signing.autoGenerate` — generate once, persist as JWK, reuse on the
 *      next boot. A development convenience, and named as one, because it puts
 *      the private key next to the data it authenticates.
 *
 * Neither is not a default. A server that silently invents a fresh key every
 * boot invalidates every `id_token` it ever issued on restart, and the symptom
 * shows up in the client, not here — so `getSigningKey()` throws instead.
 */

export interface SigningKey {
  kid: string;
  alg: 'ES256';
  privateKey: KeyObject;
}

export interface KeyManager {
  /** The active key. Throws a clear error if none is configured and autoGenerate is off. */
  getSigningKey(): Promise<SigningKey>;
  /** RFC 7517 JWK Set — active AND retiring keys, public halves only. */
  jwks(): Promise<{ keys: Record<string, unknown>[] }>;
}

interface ConfiguredKey {
  kid: string;
  status: 'active' | 'retiring';
  privateKey: KeyObject;
  publicJwk: Record<string, unknown>;
}

/**
 * RFC 7638 thumbprint, used as the `kid`.
 *
 * Deterministic in the key material, which is what makes the persist path
 * race-safe: two processes that generate concurrently produce different kids,
 * but a process that re-persists the SAME key collides on the unique index and
 * re-reads instead of writing a duplicate. Member order is lexicographic per
 * the RFC — crv, kty, x, y — and must not be "tidied".
 */
function thumbprint(jwk: Record<string, unknown>): string {
  return sha256(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }));
}

function toJwk(key: KeyObject): Record<string, unknown> {
  return key.export({ format: 'jwk' }) as unknown as Record<string, unknown>;
}

/** The public half. `d` is the private scalar — publishing it publishes the key. */
function publicHalf(jwk: Record<string, unknown>, kid: string): Record<string, unknown> {
  const { d, ...rest } = jwk;
  void d;
  return { ...rest, kid, alg: 'ES256', use: 'sig' };
}

function normalizeConfigured(specs: SigningKeySpec[] | undefined): ConfiguredKey[] {
  if (!specs?.length) return [];
  return specs.map((spec) => {
    if (spec.alg && spec.alg !== 'ES256') {
      throw new TypeError(`oauth-host: signing key '${spec.kid}' has alg '${spec.alg}'; only ES256 is supported`);
    }
    let privateKey: KeyObject;
    try {
      privateKey = createPrivateKey(spec.privateKeyPem);
    } catch (err) {
      throw new TypeError(
        `oauth-host: signing key '${spec.kid}' is not a readable PKCS#8 PEM (${(err as Error).message})`,
      );
    }
    if (privateKey.asymmetricKeyType !== 'ec') {
      throw new TypeError(`oauth-host: signing key '${spec.kid}' must be an EC (P-256) key`);
    }
    const jwk = toJwk(createPublicKey(privateKey));
    if (jwk.crv !== 'P-256') {
      throw new TypeError(`oauth-host: signing key '${spec.kid}' uses curve ${String(jwk.crv)}; ES256 requires P-256`);
    }
    // A host-supplied kid wins even when it differs from the thumbprint: it is
    // already in tokens the clients hold, and changing it orphans them.
    const kid = spec.kid || thumbprint(jwk);
    return { kid, status: spec.status ?? 'active', privateKey, publicJwk: publicHalf(jwk, kid) };
  });
}

const MISSING_KEY = 'oauth-host: no signing key. Set `signing.keys` to a PKCS#8 ES256 PEM, '
  + 'or `signing.autoGenerate: true` to generate and persist one (development only — it '
  + 'stores the private key in the same database as the tokens it signs).';

export function createKeyManager(ctx: ResolvedContext): KeyManager {
  // Eager: a malformed PEM is a boot error with the offending kid in the
  // message, not a 500 on the first client that asks for an id_token.
  const configured = normalizeConfigured(ctx.signing.keys);

  // Importing a JWK is a parse plus a key derivation. The doc is re-read on
  // every call so a rotation lands without a restart; only the KeyObject is
  // cached, keyed by the kid that identifies the material.
  const imported = new Map<string, KeyObject>();
  let generating: Promise<OAuthKeyDoc> | null = null;

  function importPrivate(kid: string, jwk: Record<string, unknown>): KeyObject {
    const cached = imported.get(kid);
    if (cached) return cached;
    const key = createPrivateKey({ key: jwk as never, format: 'jwk' });
    imported.set(kid, key);
    return key;
  }

  async function generateAndPersist(): Promise<OAuthKeyDoc> {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const privateJwk = toJwk(privateKey);
    const kid = thumbprint(privateJwk);
    const doc = {
      kid,
      alg: 'ES256' as const,
      publicJwk: publicHalf(privateJwk, kid),
      privateJwk,
      status: 'active' as const,
    };
    try {
      return await ctx.models.Key.create(doc);
    } catch (err) {
      // Two processes booting a cold database both find no key and both write.
      // A duplicate kid means the other one persisted identical material, so
      // re-read; distinct kids mean two live keys, which is harmless because
      // `jwks()` publishes both and `getSigningKey()` picks deterministically.
      if ((err as { code?: number }).code !== 11000) throw err;
      const existing = await ctx.models.Key.findOne({ kid });
      if (!existing) throw err;
      return existing;
    }
  }

  return {
    async getSigningKey() {
      const active = configured.find((k) => k.status === 'active');
      if (active) return { kid: active.kid, alg: 'ES256', privateKey: active.privateKey };
      if (configured.length) {
        throw new Error('oauth-host: every configured signing key is `retiring`; one must be `active` to sign with');
      }
      if (!ctx.signing.autoGenerate) throw new Error(MISSING_KEY);

      // Oldest first, kid as the tiebreak: every process in the cluster has to
      // land on the same key, or clients see the kid flip per request.
      const doc = await ctx.models.Key.findOne({ status: 'active' }).sort({ createdAt: 1, kid: 1 })
        ?? await (generating ??= generateAndPersist().finally(() => { generating = null; }));
      return { kid: doc.kid, alg: 'ES256', privateKey: importPrivate(doc.kid, doc.privateJwk) };
    },

    async jwks() {
      if (configured.length) {
        // Retiring keys stay published: they still sign nothing, but they must
        // keep validating the tokens they already signed.
        return { keys: configured.map((k) => k.publicJwk) };
      }
      const docs = await ctx.models.Key.find({ status: { $in: ['active', 'retiring'] } })
        .sort({ createdAt: 1, kid: 1 });
      return { keys: docs.map((d) => ({ ...d.publicJwk, kid: d.kid, alg: d.alg, use: 'sig' })) };
    },
  };
}
