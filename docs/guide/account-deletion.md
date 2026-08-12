# Account deletion

Two calls, and the distinction between them is the entire reason both exist.

```ts
await oauth.users.revokeAll(userId, { reason: 'password_changed' });
await oauth.users.forget(userId);
```

`revokeAll` kills live access and **keeps the record**. `forget` deletes the
record. Wiring the wrong one either destroys an audit trail you are required to
keep, or leaves a deleted user's data behind after you told them it was gone.

## The difference, precisely

| | `revokeAll` | `forget` |
|---|---|---|
| Grant documents | marked `revokedAt`, `revokedBy: 'system'` | **deleted** |
| Tokens | marked `revokedAt` | **deleted** |
| Authorization codes | deleted | deleted |
| Pending consent requests | deleted | deleted |
| Pairwise `sub` values held by clients | untouched | **removed from every client** |
| That user's audit rows | **kept** | **deleted** |
| Audit row written | `oauth.user_access_revoked`, naming the user | `oauth.user_forgotten`, naming **nobody** |
| `track` events | one `oauth.grant_revoked` per live grant | none |
| Returns | `{ grantsRevoked, tokensRevoked }` | `{ grants, tokens }` |
| Effect on live access | instant | instant |
| Idempotent | yes | yes |

Both are idempotent because both will be called twice — by a retry, or by a host
that wires the same hook to a soft delete and a hard delete.

## When to call which

### `users.revokeAll(userId, { reason })`

The user still exists. Their live access should not.

- password changed
- account deactivated or suspended
- suspected compromise
- "sign out everywhere"
- email address changed, if that is an authentication factor for you

The grant documents survive, which means the user's connected-apps list still
renders (as revoked entries), the audit trail still resolves grant ids to
something, and you can answer "what did this account have connected in July".
`reason` lands in the audit row's `meta`.

```ts
app.post('/account/password', async (req, res) => {
  await setPassword(req.user, req.body.password);
  await oauth.users.revokeAll(req.user._id, { reason: 'password_changed' });
  res.json({ ok: true });
});
```

### `users.forget(userId)`

The user is gone and every trace of them has to go with them. A deletion
request, a GDPR erasure, a hard delete.

```ts
app.delete('/account', async (req, res) => {
  const id = req.user._id;
  await oauth.users.forget(id);        // before the user document goes
  await User.deleteOne({ _id: id });
  res.json({ ok: true });
});
```

Call it **before** you delete the user document if you can, but it does not
depend on the user existing — it queries only by id.

Three parts of `forget` are worth calling out because they are the ones a
hand-rolled version misses:

**Pairwise subjects.** If `subjectMode` is `pairwise`, each client holds a
pseudonym for this user in its own document. Leaving those behind means the
erased user is still addressable by the one identifier a partner actually
stored. `forget` `$unset`s them from every client. (User ids containing `.` or
starting with `$` are skipped, because Mongo would interpret those as a path
separator and an operator prefix and unset something else entirely — an
ObjectId, the normal case, is unaffected.)

**The audit rows go too.** That is the point of erasure and the sharpest
difference from `revokeAll`.

**One tombstone stays.** `forget` writes a single `oauth.user_forgotten` row
carrying no `userId`, no client, no scopes — only `{ grants, tokens }` counts.
It exists to prove the erasure ran, which is the only thing an auditor may still
ask after the subject is gone.

## Related calls

Neither of these is an account-lifecycle hook, but they cascade the same way and
are easy to confuse with the two above.

**`oauth.contexts.revoked(userId, contextId)`** — a *membership* ended, not an
account. Revokes only the grants this user made for that context, leaving their
other connections alone. See [Adapters](/guide/adapters#grantcontext-granting-on-behalf-of-an-org).

**`oauth.clients.disable(clientId)`** — a *client* is gone. Revokes every grant
and token it holds, for every user, and deletes its outstanding codes and
pending requests. Disabling without the cascade would leave every issued access
token valid until its own expiry.

## What a user can do themselves

Wire your connected-apps screen to the two `/me/grants` endpoints rather than to
the admin API:

```
GET    /oauth/me/grants        → { limit, items: [...] }
DELETE /oauth/me/grants/:id    → { revoked: true, tokensRevoked: 3 }
```

Both are on the host-session band and both are scoped to the signed-in user, so
one user cannot revoke another's grant by guessing an id — a mismatched id is a
404, not a 403, and there is a test named after that. See
[Routers](/reference/routers#get-me-grants).

## Testing your wiring

The package's own suite proves `forget` and `revokeAll` do what this page says.
What it cannot prove is that *your* deletion path calls them. That test lives in
your repo:

```ts
it('drops oauth grants when an account is deleted', async () => {
  await connectAnApp(user);
  expect(await oauth.models.Grant.countDocuments({ userId: user._id })).toBe(1);

  await request(app).delete('/account').set('Cookie', session(user));

  // Deleted, not revoked — this is the assertion that distinguishes the two.
  expect(await oauth.models.Grant.countDocuments({ userId: user._id })).toBe(0);
  expect(await oauth.models.Token.countDocuments({ userId: user._id })).toBe(0);
});
```

See [Testing](/guide/testing).
