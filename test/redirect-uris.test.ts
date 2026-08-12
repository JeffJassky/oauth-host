import { describe, expect, it } from 'vitest';
import { isLoopbackRedirectUri, redirectUriMatches, redirectUriRegistered } from '../src/server/redirect-uris.js';

/**
 * The loopback-port carve-out, and its blast radius.
 *
 * Every test here is named after a failure. The first group is the reported
 * one: Claude Code registers `http://127.0.0.1/callback` and connects from an
 * ephemeral port, and byte-exact comparison failed every authorization with an
 * unredirectable `invalid_request` that looked like the client's bug.
 *
 * The rest are the reason the carve-out is narrow. A general "ports don't
 * count" comparison is an open redirect, and this is the file that has to fail
 * if anyone widens it.
 */

describe('redirectUriMatches — the loopback port varies (RFC 8252 §7.3)', () => {
  it('matches http://127.0.0.1:54321/callback against a registration with no port', () => {
    expect(redirectUriMatches('http://127.0.0.1/callback', 'http://127.0.0.1:54321/callback')).toBe(true);
  });

  it('matches localhost the same way', () => {
    expect(redirectUriMatches('http://localhost/callback', 'http://localhost:8912/callback')).toBe(true);
  });

  it('matches [::1] the same way', () => {
    expect(redirectUriMatches('http://[::1]/callback', 'http://[::1]:41234/callback')).toBe(true);
  });

  it('matches when the REGISTRATION carries an explicit port too', () => {
    // A registration written as `:3000` is still a loopback registration. The
    // point of the rule is that the port is not part of the identity.
    expect(redirectUriMatches('http://127.0.0.1:3000/cb', 'http://127.0.0.1:54321/cb')).toBe(true);
    expect(redirectUriMatches('http://127.0.0.1:3000/cb', 'http://127.0.0.1/cb')).toBe(true);
  });

  it('does not resolve localhost to 127.0.0.1, or the reverse', () => {
    // Different registrations on purpose — a client that wants both registers
    // both. Treating them as one would be this package deciding what the
    // client's resolver says.
    expect(redirectUriMatches('http://localhost/cb', 'http://127.0.0.1/cb')).toBe(false);
    expect(redirectUriMatches('http://127.0.0.1/cb', 'http://localhost/cb')).toBe(false);
  });
});

describe('redirectUriMatches — everything else stays byte-exact', () => {
  it('does NOT match https://evil.test:8443/cb against https://evil.test/cb', () => {
    // The whole open-redirect hole in one line: a remote host whose port is
    // ignored lets an attacker who controls any port on that host collect codes.
    expect(redirectUriMatches('https://evil.test/cb', 'https://evil.test:8443/cb')).toBe(false);
  });

  it('does not match a differing path or query, loopback included', () => {
    expect(redirectUriMatches('http://127.0.0.1/callback', 'http://127.0.0.1:5/callback/../evil')).toBe(false);
    expect(redirectUriMatches('http://127.0.0.1/callback', 'http://127.0.0.1:5/callback?x=1')).toBe(false);
    expect(redirectUriMatches('http://127.0.0.1/callback?a=1', 'http://127.0.0.1:5/callback')).toBe(false);
    expect(redirectUriMatches('http://127.0.0.1/callback', 'http://127.0.0.1:5/callback/')).toBe(false);
  });

  it('does not match a differing scheme', () => {
    expect(redirectUriMatches('https://127.0.0.1/cb', 'http://127.0.0.1:5/cb')).toBe(false);
  });

  it('does not treat http://localhost.evil.test/cb as loopback', () => {
    // The suffix trap. `'localhost.evil.test'.endsWith('localhost')` is false,
    // but `startsWith` is true, and either sloppy test lets an attacker-owned
    // host inherit the port carve-out.
    expect(isLoopbackRedirectUri('http://localhost.evil.test/cb')).toBe(false);
    expect(redirectUriMatches('http://localhost.evil.test/cb', 'http://localhost.evil.test:8443/cb')).toBe(false);
    expect(redirectUriMatches('http://localhost/cb', 'http://localhost.evil.test/cb')).toBe(false);
  });

  it('does not treat 127.0.0.1.evil.test or evil-127.0.0.1 as loopback', () => {
    expect(isLoopbackRedirectUri('http://127.0.0.1.evil.test/cb')).toBe(false);
    expect(isLoopbackRedirectUri('https://evil-127.0.0.1.test/cb')).toBe(false);
  });

  it('ignores userinfo smuggled into the presented URI', () => {
    expect(redirectUriMatches('http://127.0.0.1/cb', 'http://evil@127.0.0.1:5/cb')).toBe(false);
  });

  it('is still true for two identical remote URIs, which is the common case', () => {
    expect(redirectUriMatches('https://claude.ai/api/mcp/auth_callback', 'https://claude.ai/api/mcp/auth_callback'))
      .toBe(true);
  });

  it('answers false rather than throwing on an unparseable value', () => {
    expect(redirectUriMatches('http://127.0.0.1/cb', 'not a url')).toBe(false);
    expect(redirectUriMatches('/callback', '/callback?x')).toBe(false);
  });
});

describe('redirectUriRegistered — the list form', () => {
  it('accepts an ephemeral port against a registration list carrying both hosts', () => {
    const registered = ['http://localhost/callback', 'http://127.0.0.1/callback'];
    expect(redirectUriRegistered(registered, 'http://127.0.0.1:54321/callback')).toBe(true);
    expect(redirectUriRegistered(registered, 'http://localhost:61000/callback')).toBe(true);
    expect(redirectUriRegistered(registered, 'https://evil.test/callback')).toBe(false);
  });
});
