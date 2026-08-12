import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual as nodeTimingSafeEqual,
} from 'node:crypto';

/**
 * Every credential this package hands out is generated here, and nothing is
 * ever stored in a form that can be replayed.
 *
 * Codes, tokens and client secrets are 256 bits of CSPRNG output, so a plain
 * SHA-256 is the right digest and bcrypt would be a throughput bug with no
 * security gain — password hashing is slow to defend against low-entropy
 * inputs, and there are none here. Lookup is by hash; comparison of anything
 * secret-derived is constant-time.
 */

/** 32 bytes, base64url, no padding. ~43 chars. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function sha256(value: string): string {
  return createHash('sha256').update(value).digest('base64url');
}

/**
 * Constant-time compare of two strings.
 *
 * Length is compared first and leaks — that is fine here, every input is a
 * fixed-width digest or a fixed-width token. Comparing digests rather than the
 * raw values keeps the buffers equal-length for `timingSafeEqual`, which throws
 * on a length mismatch.
 */
export function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(sha256(a));
  const bufB = Buffer.from(sha256(b));
  if (bufA.length !== bufB.length) return false;
  return nodeTimingSafeEqual(bufA, bufB);
}

/** RFC 7636 §4.6 — S256 only. `plain` is not accepted anywhere in this package. */
export function verifyPkce(verifier: string, challenge: string): boolean {
  // RFC 7636 §4.1 bounds the verifier; an unbounded one is a hashing DoS.
  if (verifier.length < 43 || verifier.length > 128) return false;
  if (!/^[A-Za-z0-9\-._~]+$/.test(verifier)) return false;
  return safeEqual(sha256(verifier), challenge);
}

/**
 * Pairwise `sub` (OIDC Core §8.1).
 *
 * Deterministic so it survives a database restore, and salted so one client
 * cannot correlate its users with another's. The value is permanent for a
 * (user, client) pair — partners store it as their primary key.
 */
export function pairwiseSubject(userId: string, clientId: string, salt: string): string {
  return createHmac('sha256', salt).update(`${clientId}:${userId}`).digest('base64url');
}

/** A client identifier. Opaque, URL-safe, and not guessable from the name. */
export function generateClientId(): string {
  return randomToken(16);
}

/** A client secret. Returned once at creation; only its digest is stored. */
export function generateClientSecret(): string {
  return randomToken(32);
}
