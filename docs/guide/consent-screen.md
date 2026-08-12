# The consent screen

**You write this page.** No markup ships with the package, and that is a
requirement rather than an omission: the consent screen is the one moment in the
flow where a user sees your product, and it has to look like your product.

What the package gives you instead is a JSON description of the pending
authorization at `GET /oauth/consent/:requestId`, and a decision endpoint at
`POST /oauth/consent/:requestId` that answers with the URL to send the browser
to next. Nothing about the OAuth protocol reaches your page — no code, no
`state`, no `redirect_uri`, no client secret.

## Where the page fits

```
client → GET /oauth/authorize
           ├─ signed out → 302 loginUrl?next=…            (your login page)
           └─ signed in  → 302 consentUrl?request_id=…    (your page — here)

your page → GET  /oauth/consent/:requestId  → the payload below
          → POST /oauth/consent/:requestId  → { redirectTo }
          → location.href = redirectTo      → back to the client
```

`consentUrl` is whatever you configured. The package appends `request_id`,
merging it correctly into a URL that already has a query string
(`/settings/authorize?theme=dark` becomes
`/settings/authorize?theme=dark&request_id=abc`).

Both consent endpoints are on the **host-session band**: they authenticate by
calling your `resolveUser(req)`, i.e. the cookie your app already issued. A
signed-out caller gets `401 {"error": "login_required"}`.

## The payload

`GET /oauth/consent/:requestId` → `200`:

```json
{
  "client": {
    "name": "Claude",
    "logoUrl": "https://cdn.example.test/claude.png",
    "publisher": "Anthropic"
  },
  "scopes": [
    { "id": "openid", "label": "Sign you in", "isNew": true },
    {
      "id": "contacts.read",
      "label": "Read your contacts",
      "description": "Names and emails.",
      "isNew": true
    }
  ],
  "user": { "displayName": "Ada Lovelace", "email": "ada@example.test" },
  "expiresAt": "2026-08-12T09:10:00.000Z"
}
```

That is a real response, copied out of `test/consent.test.ts`.

### This payload is a versioned contract

It is tested as strictly as any route, and the test asserts the *absence* of
things as hard as the presence of them:

- **No internal identifiers.** No `_id`, no `grantId`, no `userId`, no client
  `_id`. The serialized payload does not even contain the `requestId` — your
  page already has that, from its own URL.
- **No secrets, ever.** The client's secret digests and its pairwise-subject map
  never cross this line.
- **Absent means absent.** Optional keys are omitted, not set to `null` or `[]`.
  A host with no `grantContext` adapter never sees the word `contexts`, because
  an empty array reads as "there are no organizations to choose from", which is
  a different statement from "this product does not have organizations".

If you find yourself needing an internal id here to render something, that is a
design bug in the package, not a reason to add one.

### Fields

| Field | Type | Notes |
|---|---|---|
| `client.name` | string | Always present. Registered via `clients.create({ name })`. |
| `client.logoUrl` | string? | From `branding`. A URL you host — the package has no upload story, deliberately. |
| `client.publisher` | string? | From `branding`. |
| `client.homepageUrl` | string? | From `branding`. |
| `client.tosUrl` | string? | From `branding`. |
| `client.privacyUrl` | string? | From `branding`. |
| `scopes[].id` | string | What you post back in `scopes`. |
| `scopes[].label` | string | Short imperative phrase. Defaults to the id when the catalog gave none. |
| `scopes[].description` | string? | Optional second line. |
| `scopes[].sensitive` | `true`? | Present only when true. Render with emphasis — write access, destructive access, billing. |
| `scopes[].isNew` | boolean | `false` means the user already granted this scope to this client. |
| `contexts` | array? | **Key absent** unless a `grantContext` adapter is configured. `[{ id, label, description? }]`. **Capped at 50** — see below. |
| `contextsHasMore` | boolean? | Present exactly when `contexts` is. `true` means `grantContext.list()` returned more than the 50 `contexts` carries. |
| `user.displayName` | string \| null | Whose account is about to be connected. Shows the user they are signed in as who they think they are. |
| `user.email` | string? | Omitted when the user adapter gave none. |
| `expiresAt` | ISO date | When the pending request dies. Default 10 minutes (`ttl.authorizationRequest`). |

### `contexts` is capped, and says when it is

**Added to the contract.** `contexts` carries at most **50** entries, and
`contextsHasMore` tells you whether `grantContext.list()` returned more.

Every other list in this package is clamped — the admin API defaults to 50 with
a ceiling of 200 — and this one is on an interactive path with the whole array
embedded in the payload. A host whose `list()` answers "every account in the
system" for an admin was the reported case.

Truncating silently would have been worse than not clamping at all: account #501
would simply be unconnectable, with nothing in the payload saying so. Hence the
flag.

**What to do when `contextsHasMore` is `true`:** do not render the 50 as if they
were the whole list, and do not paginate them — the payload has no cursor and
adding one would put an internal identifier in a contract that deliberately has
none. Offer **search instead of a picker**: a text input backed by your own
endpoint, which already knows how to query the same organizations `list()` reads
from, and which is where the authorization for that query belongs. Post the
chosen `contextId` back exactly as you would from the picker — the decision
endpoint verifies it through `grantContext.verify()` regardless of how your UI
found it, so a context outside the 50 is still perfectly grantable.

When it is `false`, the array is complete and a plain picker is correct.

`isNew` is the one derived bit, and it is computed against **every live grant**
this user holds for this client, unioned — not against one grant. The context is
not chosen until the user picks it, and a scope already granted under any
context is not something to badge as new. Use it to dim what the user has
already approved and emphasise what re-consent actually adds.

### Errors from `GET`

| Status | Body | Means |
|---|---|---|
| 401 | `{"error": "login_required"}` | No user is signed in for this request. |
| 403 | `{"error": "access_denied", "error_description": "this authorization request belongs to another user"}` | The browser is signed in as *somebody*, just not the one who started this flow. Say so; do not restart the flow. |
| 404 | `{"error": "invalid_request", "error_description": "unknown or expired authorization request"}` | Unknown, expired, or already decided. These are deliberately one answer — distinguishing them turns the endpoint into an oracle for whether a handle ever existed. |

## Posting the decision

`POST /oauth/consent/:requestId`, JSON (this band is your own page's `fetch`,
not a spec-mandated form post — the host's `express.json()` parses it):

```json
{ "approve": true, "scopes": ["openid", "contacts.read"], "contextId": "org_1" }
```

| Field | Required | Notes |
|---|---|---|
| `approve` | yes | Must be a boolean. Anything else is `400 invalid_request`. |
| `scopes` | no | What the user actually ticked. Defaults to everything requested. |
| `contextId` | conditional | Required exactly when a `grantContext` adapter is configured; rejected when one is not. |

Response, on both approval and denial:

```json
{ "redirectTo": "https://claude.ai/api/mcp/auth_callback?code=…&state=st-123&iss=https://api.example.test" }
```

Set `location.href` to it. On denial the same field carries
`error=access_denied&error_description=…&state=…&iss=…` instead of a code —
your page does not branch, it just navigates.

### Rules the endpoint enforces

- **You cannot widen the request.** Every id in `scopes` must have been part of
  the original authorization request. Offering more than the client asked for is
  a bug in your UI, and honouring it would let the consent screen widen its own
  request. `400 invalid_request`, naming the scope.
- **You can narrow it.** Approving a subset is supported and is the reason the
  field exists: the grant is created with exactly what you sent.
- **A decision is one-shot.** The handle is claimed atomically, so two
  concurrent approvals cannot mint two codes from one user decision. The second
  gets `400 invalid_request` — "this authorization request has already been
  decided".
- **A *rejected* decision leaves the handle usable.** Validation runs before the
  handle is claimed, so a bad payload is something your page can fix and re-post
  rather than a flow the user has to restart.
- **Re-consent unions, it does not replace.** A client that asks for a narrower
  set on its second connect does not silently lose access it still holds a live
  token for. The grant's `version` moves only when the set actually grew.

### Errors from `POST`

| Status | `error` | Means |
|---|---|---|
| 400 | `invalid_request` | `approve` was not a boolean; a scope was not in the request; the request was already decided; `contextId` was missing (with an adapter) or supplied (without one). |
| 401 | `login_required` | No user is signed in. |
| 403 | `access_denied` | Another user's handle, or `grantContext.verify()` returned false for the chosen `contextId`. |
| 404 | `invalid_request` | Unknown or expired handle. |

## A complete page

From [`examples/express/server.js`](https://github.com/JeffJassky/oauth-host/blob/main/examples/express/server.js).
It is deliberately ugly — the point is how little it has to do:

```js
app.get('/consent', (req, res) => {
  const id = String(req.query.request_id ?? '');
  res.type('html').send(`<!doctype html><meta charset="utf-8">
<h1>Authorize</h1><div id="app">Loading…</div>
<script type="module">
  const id = ${JSON.stringify(id)};
  const r = await fetch('/oauth/consent/' + id).then((x) => x.json());
  document.getElementById('app').innerHTML =
    '<p><b>' + r.client.name + '</b> wants access to your account.</p><ul>'
    + r.scopes.map((s) => '<li>' + s.label + (s.sensitive ? ' (sensitive)' : '') + '</li>').join('')
    + '</ul><button id="y">Allow</button> <button id="n">Deny</button>';
  const decide = async (approve) => {
    const out = await fetch('/oauth/consent/' + id, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ approve, scopes: r.scopes.map((s) => s.id) }),
    }).then((x) => x.json());
    location.href = out.redirectTo;
  };
  document.getElementById('y').onclick = () => decide(true);
  document.getElementById('n').onclick = () => decide(false);
</script>`);
});
```

Server-rendered works identically: fetch the payload server-side with the user's
cookie, render it, and POST from a form handler that redirects to `redirectTo`.
Nothing in the contract assumes a browser fetch.

## Things worth getting right in your version

- **Show `user.displayName` / `user.email`.** Users have more than one account.
  A consent screen that does not say which one is being connected is how someone
  connects their personal account to their employer's assistant.
- **Render `sensitive: true` differently.** It is the only affordance the
  catalog gives you for "this one can write".
- **Do not hide the deny button** or make it a link back. Denial is a real
  outcome the protocol has a code for, and the client is waiting to be told.
- **Handle 403 separately from 404.** "You are signed in as someone else" needs
  an account switcher; "this request expired" needs the user to start again from
  the client.
- **Do not cache the page.** The payload is per-request and short-lived.

## Related

- [Adapters](/guide/adapters) — `grantContext` is what puts `contexts` in the payload
- [`ConsentPayload`](/reference/types#consentpayload) — the type
- [Routers](/reference/routers#get-consent-requestid) — the endpoint reference
