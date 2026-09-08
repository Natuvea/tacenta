/-!
# Account sessions and provisioning authorization

The account layer issues a session token on sign-in and, at provisioning time,
derives the device's directory handle from the *session*, never from client
input (decision records 0034, 0035). This file models that and proves the
anti-impersonation property: the handle a provisioning binds is a function of the
token's session, so a client can only ever provision under the handle its own
session authorizes — it cannot choose a handle, and a token that was never
issued authorizes nothing.

The tokens' unguessability (they are high-entropy secrets) is a cryptographic
assumption, not modelled here; what is proven is that the *logic* derives the
handle from the validated session and from nothing the client supplies.

- `validate_issued` — a freshly issued token validates to its user.
- `issue_frames` — issuing a token does not change any other token's session.
- `unissued_validates_none` — a token never issued authorizes nothing.
- `provision_handle_from_session` — **anti-impersonation**: the provisioned
  handle is exactly `handleOf` of the session's user, determined by the token,
  not by the client.
- `provision_handle_none` — no valid session, no handle.
-/

namespace Tacenta.Accounts

variable {Token User Handle : Type}

/-- Sessions map an issued token to the user it authorizes. -/
abbrev Sessions (Token User : Type) := Token → Option User

/-- No sessions issued. -/
def noSessions : Sessions Token User := fun _ => none

/-- Issue `tok` for `user`, leaving every other token's session untouched. -/
def issue [DecidableEq Token] (s : Sessions Token User) (tok : Token) (user : User) :
    Sessions Token User :=
  fun t => if t = tok then some user else s t

/-- The user a token authorizes, if any. -/
def validate (s : Sessions Token User) (tok : Token) : Option User := s tok

/-- The handle a provisioning binds: the session's user mapped to its handle.
The client supplies the token, never the handle. -/
def provisionHandle (handleOf : User → Handle) (s : Sessions Token User) (tok : Token) :
    Option Handle :=
  (validate s tok).map handleOf

/-- A freshly issued token validates to its user. -/
theorem validate_issued [DecidableEq Token] (s : Sessions Token User) (tok : Token) (user : User) :
    validate (issue s tok user) tok = some user := by
  simp [validate, issue]

/-- Issuing a token changes no other token's session. -/
theorem issue_frames [DecidableEq Token] (s : Sessions Token User) (tok other : Token) (user : User)
    (h : other ≠ tok) :
    validate (issue s tok user) other = validate s other := by
  simp [validate, issue, h]

/-- A token that was never issued authorizes nothing. -/
theorem unissued_validates_none (tok : Token) :
    validate (noSessions : Sessions Token User) tok = none := rfl

/-- Anti-impersonation: the provisioned handle is exactly the session user's
handle — a function of the (validated) token, never of client input. So a client
presenting a token for `user` provisions under `handleOf user` and no other. -/
theorem provision_handle_from_session (handleOf : User → Handle) (s : Sessions Token User)
    (tok : Token) (user : User) (h : validate s tok = some user) :
    provisionHandle handleOf s tok = some (handleOf user) := by
  simp [provisionHandle, h]

/-- No valid session, no handle. -/
theorem provision_handle_none (handleOf : User → Handle) (s : Sessions Token User) (tok : Token)
    (h : validate s tok = none) :
    provisionHandle handleOf s tok = none := by
  simp [provisionHandle, h]

/-!
## Tenant isolation

Users are unique **per tenant**, not globally: the same username can belong to a
user in two different tenants, and a signup in one tenant never affects another
(decision record 0033). Modelled as a user map keyed by `(tenant, username)`.
-/

/-- The user map, keyed by `(tenant, username)`. -/
abbrev Users (Tenant Username User : Type) := Tenant × Username → Option User

/-- Sign up `user` at `(tenant, username)` — refused (`none`) if that pair is
already taken in this tenant, otherwise the updated map. -/
def signUp {Tenant Username : Type} [DecidableEq Tenant] [DecidableEq Username]
    (u : Users Tenant Username User) (key : Tenant × Username) (user : User) :
    Option (Users Tenant Username User) :=
  match u key with
  | some _ => none
  | none => some fun k => if k = key then some user else u k

/-- A successful signup binds its key to the new user. -/
theorem signUp_binds {Tenant Username : Type} [DecidableEq Tenant] [DecidableEq Username]
    (u : Users Tenant Username User) (key : Tenant × Username) (user : User)
    (u' : Users Tenant Username User) (hfree : u key = none)
    (hs : signUp u key user = some u') :
    u' key = some user := by
  simp only [signUp, hfree] at hs
  injection hs with hs
  subst hs
  simp

/-- A key already taken in this tenant is refused. -/
theorem signUp_rejects_taken {Tenant Username : Type} [DecidableEq Tenant] [DecidableEq Username]
    (u : Users Tenant Username User) (key : Tenant × Username) (user existing : User)
    (h : u key = some existing) :
    signUp u key user = none := by
  simp [signUp, h]

/-- A successful signup leaves every other key untouched — the isolation frame:
a signup at `(t, name)` cannot affect `(t', name')` for any other pair. -/
theorem signUp_frames {Tenant Username : Type} [DecidableEq Tenant] [DecidableEq Username]
    (u : Users Tenant Username User) (key other : Tenant × Username) (user : User)
    (u' : Users Tenant Username User) (hs : signUp u key user = some u') (ho : other ≠ key) :
    u' other = u other := by
  cases hk : u key with
  | some ex => simp [signUp, hk] at hs
  | none =>
    simp only [signUp, hk] at hs
    injection hs with hs
    subst hs
    simp [ho]

/-- Tenant isolation: with the same username taken in tenant `t1`, a signup of
that username in a different tenant `t2` succeeds, leaving `t1`'s user intact and
binding `t2`'s — the two tenants hold the same username independently. -/
theorem tenant_isolation {Tenant Username : Type} [DecidableEq Tenant] [DecidableEq Username]
    (u : Users Tenant Username User) (t1 t2 : Tenant) (name : Username) (a b : User)
    (u' : Users Tenant Username User)
    (h1 : u (t1, name) = some a) (hfree : u (t2, name) = none) (ht : t2 ≠ t1)
    (hs : signUp u (t2, name) b = some u') :
    u' (t1, name) = some a ∧ u' (t2, name) = some b := by
  have hne : (t1, name) ≠ (t2, name) := fun h => ht (congrArg Prod.fst h).symm
  refine ⟨?_, signUp_binds u (t2, name) b u' hfree hs⟩
  rw [signUp_frames u (t2, name) (t1, name) b u' hs hne]
  exact h1

end Tacenta.Accounts
