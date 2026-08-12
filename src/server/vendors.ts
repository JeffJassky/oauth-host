/**
 * Vendor callback URLs, as constants.
 *
 * `clients.create()` compares `redirectUris` byte-for-byte, so registering a
 * connector means transcribing a URL out of somebody else's documentation into
 * a field where a single wrong character is a partner integration that
 * half-works six weeks later with no error pointing back at the typo. That is
 * the most error-prone step in the whole setup and nothing downstream can
 * rescue it — so the values ship here instead of in prose.
 *
 * **Every value below is a vendor product detail, not a standard.** It can
 * change without notice and without a release of this package. Each is stamped
 * with the date it was verified against vendor documentation; if a connector
 * suddenly fails with `redirect_uri is not registered`, check the vendor's
 * current setup screen before assuming a bug here.
 */

/**
 * Claude's hosted connector callback — claude.ai in a browser.
 *
 * Verified against Anthropic's connector documentation 2026-08-12. Vendor
 * product detail; may change without notice.
 */
export const CLAUDE_CONNECTOR_REDIRECT_URI: string = 'https://claude.ai/api/mcp/auth_callback';

/**
 * Claude Code's local callbacks.
 *
 * Both are registered because Claude Code may use either host, and the PORT
 * varies per session — it binds an ephemeral one and connects from, e.g.,
 * `http://127.0.0.1:54321/callback`. That is allowed for loopback URIs by
 * RFC 8252 §7.3 and is handled by `redirectUriMatches` in `redirect-uris.ts`;
 * register these without a port and let the port float.
 *
 * Verified 2026-08-12. Vendor product detail; may change without notice.
 */
export const CLAUDE_CODE_REDIRECT_URIS: readonly string[] = [
  'http://localhost/callback',
  'http://127.0.0.1/callback',
];

/**
 * ChatGPT's legacy single connector callback.
 *
 * Still accepted for existing connectors; new ones get the per-connector URL
 * described by `CHATGPT_CONNECTOR_REDIRECT_URI_PATTERN` instead.
 *
 * Verified 2026-08-12. Vendor product detail; may change without notice.
 */
export const CHATGPT_LEGACY_REDIRECT_URI: string = 'https://chatgpt.com/connector_platform_oauth_redirect';

/**
 * ChatGPT's current callback is **per connector** and therefore NOT a constant.
 *
 * This string is the SHAPE, exported so the documentation and the code agree on
 * it — it is not a value to register. `{callback_id}` is assigned by OpenAI when
 * the connector is created, and the only correct source for the full URL is the
 * connector's own setup screen. Copy it from there; do not construct it.
 *
 * Verified 2026-08-12. Vendor product detail; may change without notice.
 */
export const CHATGPT_CONNECTOR_REDIRECT_URI_PATTERN: string = 'https://chatgpt.com/connector/oauth/{callback_id}';

/**
 * A suggested `clientIdMetadata.allowedHosts` for hosts that enable CIMD for
 * both vendors.
 *
 * A suggestion, deliberately, and not a default: `allowedHosts` is the control
 * that contains the SSRF surface CIMD opens, and a package-supplied default
 * would be this package deciding whose documents your server fetches. Entries
 * match the hostname exactly — write `.claude.ai` yourself if you mean to admit
 * subdomains.
 *
 * Verified 2026-08-12. Vendor product detail; may change without notice.
 */
export const CIMD_ALLOWED_HOSTS: readonly string[] = ['claude.ai', 'chatgpt.com'];
