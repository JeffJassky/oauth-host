# Client ID Metadata Documents

A way for a client to register itself without registering: its `client_id` **is**
an `https://` URL, and that URL serves a JSON document describing the client.
The authorization server fetches the document, validates it, and treats it as
the registration.

No registration endpoint. No registration access tokens. No secret to paste into
a connector setup screen, and no per-install provisioning step. Both Claude and
ChatGPT prefer this over RFC 7591 dynamic client registration.

It is **off by default**, and turning it on has a cost that is spelled out
below — the server starts making outbound HTTP requests to a URL an
unauthenticated request parameter chose.

## Turning it on

```ts
const oauth = createOAuthHost({
  // …the rest of your config…
  clientIdMetadata: {
    enabled: true,
    allowedHosts: ['claude.ai', 'chatgpt.com'],
  },
})
```

`allowedHosts` is **required**. Enabling CIMD with an empty or missing list is a
boot error, not an implicit "any host" — see [the SSRF
section](#what-this-costs-ssrf) for why that is the one default this package
refuses to guess.

With it on, discovery advertises two extra things, which is how Claude and
ChatGPT know to skip registration entirely:

```json
{
  "token_endpoint_auth_methods_supported":
    ["client_secret_basic", "client_secret_post", "none"],
  "client_id_metadata_document_supported": true
}
```

Both appear **only when CIMD is enabled**. Advertising `none` unconditionally
would tell every client that secretless authentication is available, when the
only clients that could use it are ones this server would refuse.

## What the client's document must contain

Fetched from the `client_id` URL, `application/json`:

```json
{
  "client_id": "https://claude.ai/.well-known/oauth-client",
  "client_name": "Claude",
  "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
  "token_endpoint_auth_method": "none",
  "logo_uri": "https://claude.ai/logo.png",
  "client_uri": "https://claude.ai",
  "tos_uri": "https://claude.ai/terms",
  "policy_uri": "https://claude.ai/privacy",
  "scope": "openid profile contacts.read"
}
```

| Field | Rule |
|---|---|
| `client_id` | **Required, and must equal the URL it was fetched from.** This is the entire binding. Without it any allowlisted host could serve a document claiming to be some other client. |
| `client_name` | Required, non-empty. A client with no name cannot be meaningfully consented to, and defaulting it to the hostname puts a URL in front of a user being asked to trust something. |
| `redirect_uris` | Required, non-empty. Every entry absolute and `https`, except `http://localhost` / `http://127.0.0.1` for development. No fragments (RFC 6749 §3.1.2). |
| `token_endpoint_auth_method` | Optional; if present it must be `none`. A CIMD client holds no secret. |
| `scope` | Optional. **Narrows** what the client may request — intersected with `clientIdMetadata.allowedScopes` and your catalog. A scope you do not have is dropped, not refused. |
| `logo_uri` `client_uri` `tos_uri` `policy_uri` | Optional, and each must be `https`. They map onto `branding` and reach your consent screen as attributes — a `javascript:` or `data:` logo URI is refused here because this is the last place that can. |

A document that fails any of these is rejected with an error naming the
offending field, and the authorization does not proceed.

## What you get

A row in `oauth_clients` like any other client, with three differences:

```ts
{
  clientId: 'https://claude.ai/.well-known/oauth-client',
  type: 'public',              // no secret; PKCE is the binding
  registration: 'cimd',        // re-derived from the document
  metadataUrl, metadataFetchedAt, metadataEtag,
  secrets: [],
}
```

It appears in `oauth.clients.list()`, shows on a user's connected-apps screen,
and is revoked by `oauth.clients.disable(clientId)` exactly like a manual one.

Because a `cimd` row is re-derived on every cache miss, **anything you edit on
one through `clients.update()` is overwritten on the next fetch** — with one
deliberate exception, below.

### `disable()` survives a re-fetch

A disabled CIMD client stays disabled. The status check runs *before* the fetch,
so a disabled client is an answer rather than a cache miss, and the write-back
never sets `status` at all — a brand-new row gets `active` on insert and nothing
ever puts it back.

This is the most likely bug in the whole feature (revoke a client, its document
gets re-fetched an hour later, it quietly reactivates) and there is a test named
after exactly that failure.

## Public clients

A public client authenticates at `/token` by presenting `client_id` alone.
There is no secret; **PKCE is what stands in for it**, and PKCE is already
mandatory package-wide (`S256` only, `code_challenge_method` required).

Two symmetric rules, neither optional:

- A **public** client that presents a secret is **refused**, not tolerated.
- A **confidential** client that omits its secret is **refused**.

The second is the one that matters. If omitting a secret were enough to
authenticate, every confidential registration in your database would be
downgradeable to public by anyone who knows a `client_id` — which is a public
value by design. Both violations answer the identical `401 invalid_client`, so
neither is an oracle for which kind of client an id names.

`clients.rotateSecret()` on a public client **throws**. There is no secret to
rotate, and returning one would hand a provisioning script a credential the
token endpoint refuses.

## Caching

| | |
|---|---|
| Success | Persisted in `oauth_clients`, trusted for `cacheTtlMs` (default 1h). Survives a restart, so a process boot does not re-fetch for every in-flight authorization. |
| `ETag` | Stored and replayed as `If-None-Match`. A `304` refreshes the timestamp and reuses the row. |
| Failure | Cached in memory for 60s, per instance, bounded at 1000 entries. |

**Negative caching is a security control, not a performance one.** Without it, a
bad or hostile `client_id` can be replayed in a loop to make your authorization
server hammer a third party — the endpoint becomes a traffic amplifier pointed
at whichever allowlisted host is having a bad day.

## What this costs: SSRF {#what-this-costs-ssrf}

**Enabling CIMD makes your authorization server issue an outbound HTTP request
whose destination comes from an unauthenticated request parameter.** That is
server-side request forgery by construction, and it is the honest description of
the feature rather than a caveat at the bottom of the page.

The allowlist contains most of the risk. Everything else exists because an
allowlist alone has been enough to lose before:

| Control | What it stops |
|---|---|
| `https:` only, checked before any socket | `file:`, `gopher:`, `http:` to an internal address |
| Hostname matched by **equality**, never suffix | `evilclaude.ai` matching an entry of `claude.ai` |
| Subdomains only for a `.example.com` entry | An allowlist that silently covers a host you did not intend |
| No URL credentials | `https://a@allowed.host@evil.host/` parser differentials |
| No non-default port unless the entry names one | Reaching an internal service on the allowlisted host |
| **Redirects not followed** (`redirect: 'manual'`) | An allowlisted host becoming an open proxy to anything, including cloud metadata endpoints. A 3xx is a failure, not a hop. |
| `AbortSignal.timeout(fetchTimeoutMs)` | A slow endpoint holding your request workers |
| Body cap enforced **while reading** | A gigabyte "document"; `Content-Length` is a claim by the party you are defending against |
| JSON content type required | Being fed something that is not a metadata document |
| Negative caching | Replay-driven outbound amplification |

Two things this does **not** do, and you should know it:

- **No IP-level filtering.** An allowlisted host that resolves to a private
  address will be fetched. The allowlist is a statement of trust in specific
  hosts; if that trust is misplaced, this feature does not save you.
- **No DNS-rebinding defense.** Hostname is validated, then `fetch` resolves it
  again. Both are reasons the allowlist should be short and should name vendors
  you would trust with an outbound request anyway.

If any of that is unacceptable in your environment, leave `enabled` off and
register clients manually with
[`oauth.clients.create()`](/reference/admin-api). That path is unchanged and
remains the default.

## Configuration reference

| Key | Default | Notes |
|---|---|---|
| `enabled` | `false` | Off is the safe default; the SSRF surface does not exist until you turn it on. |
| `allowedHosts` | — | **Required when enabled.** `claude.ai` matches that host exactly; `.claude.ai` also admits subdomains; `localhost:8080` names a port. A URL or a `*` wildcard is a boot error. |
| `cacheTtlMs` | `3_600_000` | How long a fetched document is trusted. |
| `fetchTimeoutMs` | `5_000` | Hard ceiling on the outbound request. |
| `maxBytes` | `65_536` | Response body cap, enforced while reading. |
| `allowedScopes` | the full catalog | Scopes a CIMD client may **ever** request, whatever its document says. The document's own `scope` narrows further. |

## Related

- [Configuration](/guide/configuration)
- [Security](/guide/security#the-cimd-fetch)
- [Admin API](/reference/admin-api) — `clients.list()`, `clients.disable()`
- [MCP connectors](/guide/mcp)
