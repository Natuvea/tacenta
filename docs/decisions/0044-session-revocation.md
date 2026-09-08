# 0044 — session revocation

## Decision

Sessions can be revoked before their TTL (decision record 0043), two ways:

- `revoke_session(token)` — invalidate one session (sign-out, or a token the
  user believes is stolen). Returns whether a session was removed.
- `revoke_user_sessions(tenant, username)` — invalidate **every** session for a
  user ("sign out everywhere", and the response to a suspected account
  compromise). Returns how many were removed.

Both remove the session from the store, so `validate_session` then returns
`None` exactly as for an unknown or expired token. A subsequent sign-in issues a
fresh token, unaffected — revocation is not an account lock.

Shape decisions:

- **Delete from the store, no tombstone.** The store keys sessions by token
  hash; removing the entry is the revocation. There is no separate revocation
  list because there is nothing a removed entry needs to be remembered for.
- **`revoke_user_sessions` scans by value.** Sessions are keyed by token hash,
  so "all of a user's sessions" is a `retain` over the map comparing the stored
  `(tenant, username)`. The username is normalised to match how it is stored.
  Fine at the in-memory store's scale; the durable store indexes by user.

## Verification

`tests/session_revocation.rs`: a revoked token stops validating within its TTL
and re-revoking reports nothing removed; `revoke_user_sessions` clears exactly
the target user's tokens (across two devices) and leaves another user's intact,
and reports the count; and a fresh sign-in after revocation issues a live token,
so revocation does not lock the account. Tested mechanism, not a proof; recorded
in `claims.md` under "Tested, not proven".

## Considered

- **Only single-token revocation.** Sufficient for sign-out, but not for the
  compromise case, where the user cannot enumerate every device's token.
  `revoke_user_sessions` is the one that matters for incident response.
- **A revocation list checked at validation** (keep the row, mark it revoked).
  Needed only if something must audit revoked tokens; nothing does, and deletion
  is simpler and leaks no revoked-token metadata.
- **Deferring until the durable store.** Revocation is small and self-contained
  on the in-memory store and pairs naturally with the expiry that just landed;
  waiting would leave "sessions can't be killed" open for no benefit.

## What would reopen this

- **The Postgres store path (done).** `PgAccounts` carries both: `revoke_session`
  is a `DELETE ... WHERE token_hash = …` and `revoke_user_sessions` a
  `DELETE ... WHERE tenant_id = … AND username = …`, dispatched through
  `AccountStore` and exercised against a real Postgres in `tests/pg.rs`.
- **Revocation across replicas.** With a shared session store, a revoke on one
  replica must be seen by the others; the durable store gives that for free, an
  in-memory per-pod store does not.
- **Refresh / sliding sessions** (0043) interact with revocation — a refreshed
  token must be revocable too; the same delete-by-hash applies.
