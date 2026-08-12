/**
 * The one place a `redirect_uri` is compared.
 *
 * Everything here is byte-exact except one carve-out, and the carve-out is
 * mandated: RFC 8252 §7.3 requires an authorization server to allow the PORT of
 * a **loopback** redirect URI to vary, because a native client binds an
 * ephemeral port per session and cannot know it at registration time. Claude
 * Code registers `http://127.0.0.1/callback` and then connects from
 * `http://127.0.0.1:54321/callback`; comparing those as strings fails every
 * authorization with an unredirectable `invalid_request` that looks like the
 * client's bug.
 *
 * Nothing else is relaxed, and the relaxation is confined to this file so that
 * it stays reviewable as a single rule. Scheme, host, path, query, fragment and
 * userinfo all still have to match exactly, and a non-loopback host never
 * matches a different port — a general "ports don't count" comparison is the
 * open-redirect hole the check ORDER in `services/authorize.ts` exists to
 * prevent, and that file's header says so.
 */

/**
 * Hosts that are loopback, exhaustively.
 *
 * A name, not a range: `127.0.0.2` is loopback to the kernel but is not a value
 * any client is documented to use, and admitting a range widens the carve-out
 * for nothing. `[::1]` carries its brackets because that is what
 * `URL.hostname` returns for an IPv6 literal.
 */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/** Is this a loopback redirect URI — the only shape whose port may vary? */
export function isLoopbackRedirectUri(value: string): boolean {
  try {
    return LOOPBACK_HOSTS.has(new URL(value).hostname);
  } catch {
    return false;
  }
}

/**
 * Does a presented `redirect_uri` match a registered one?
 *
 * `registered` is the value on the client registration (or, at the token
 * endpoint, the value bound onto the authorization code); `presented` is what
 * arrived on this request. The order matters only for readability — the
 * relation is symmetric.
 */
export function redirectUriMatches(registered: string, presented: string): boolean {
  // The overwhelmingly common case, and the only one for a hosted client.
  if (registered === presented) return true;

  let a: URL;
  let b: URL;
  try {
    a = new URL(registered);
    b = new URL(presented);
  } catch {
    // An unparseable value cannot be proven safe, so it is not a match. It is
    // also already impossible on the registered side — `clients.create()`
    // parses every entry.
    return false;
  }

  // BOTH sides must be loopback. A registered loopback URI does not admit a
  // remote presented one, and a registered remote URI never admits anything but
  // itself.
  if (!LOOPBACK_HOSTS.has(a.hostname) || !LOOPBACK_HOSTS.has(b.hostname)) return false;

  // `localhost` and `127.0.0.1` are different registrations on purpose: a
  // client that wants both registers both (Claude Code does). Resolving one to
  // the other would mean this package deciding what the client's DNS says.
  return (
    a.protocol === b.protocol
    && a.hostname === b.hostname
    && a.username === b.username
    && a.password === b.password
    && a.pathname === b.pathname
    && a.search === b.search
    && a.hash === b.hash
  );
}

/** The list form — a client's registration is always a list. */
export function redirectUriRegistered(registered: readonly string[], presented: string): boolean {
  return registered.some((entry) => redirectUriMatches(entry, presented));
}
