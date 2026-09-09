/-!
# Directory trust rules

The public-key directory binds each device address to an identity key. The
security-critical rule is **trust on first use**: once a device is bound,
`register` never reassigns it to a *different* identity. Re-registering the same
key refreshes (the prekey bundle, irrelevant to trust); a different key is
rejected; and either way the existing binding is left intact. Rebinding to a new
key is possible only through `rotate` — whose *authorization* (the current key
signing the change) lives in the transport layer, not here; this file models the
store-level rule the transport builds on.

The theorems pin down the trust rule:

- `register_binds_fresh` — a new device is bound (`registered`).
- `register_same_keeps` — re-registering the same key refreshes, binding
  unchanged.
- `register_tofu` — **trust on first use**: whatever a device is bound to,
  `register` leaves it bound to exactly that; a different key cannot displace it.
- `register_frames` — `register` never touches another device's binding.
- `rotate_requires_binding` / `rotate_rebinds` — `rotate` refuses an unbound
  device and otherwise replaces the binding.
-/

namespace Tacenta.Directory

variable {Device Identity : Type} [DecidableEq Device]

/-- The outcome of a registration. -/
inductive Registration
  | registered
  | refreshed
  | rejected
  deriving DecidableEq, Repr

/-- The outcome of a rotation. -/
inductive Rotation
  | rotated
  | unregistered
  deriving DecidableEq, Repr

/-- A directory is the binding map from a device to its bound identity. (The
prekey bundle the Rust also stores plays no part in the trust rule.) -/
abbrev Directory (Device Identity : Type) := Device → Option Identity

/-- The empty directory: nothing bound. -/
def empty : Directory Device Identity := fun _ => none

/-- Bind `dev` to `id`, leaving every other device untouched. -/
def bind (d : Directory Device Identity) (dev : Device) (id : Identity) :
    Directory Device Identity :=
  fun x => if x = dev then some id else d x

/-- Register `id` for `dev`. A new device is bound (`registered`); the same key
refreshes with the binding unchanged; a different key is rejected with the
binding unchanged (trust on first use). -/
def register (d : Directory Device Identity) (dev : Device) (id : Identity)
    [DecidableEq Identity] : Registration × Directory Device Identity :=
  match d dev with
  | none => (Registration.registered, bind d dev id)
  | some existing => if existing = id then (Registration.refreshed, d)
                     else (Registration.rejected, d)

/-- Rotate `dev`'s binding to `newId`. Refused for an unbound device; otherwise
it replaces the binding. -/
def rotate (d : Directory Device Identity) (dev : Device) (newId : Identity) :
    Rotation × Directory Device Identity :=
  match d dev with
  | none => (Rotation.unregistered, d)
  | some _ => (Rotation.rotated, bind d dev newId)

/-- Registering a device with no existing binding binds it. -/
theorem register_binds_fresh [DecidableEq Identity] (d : Directory Device Identity)
    (dev : Device) (id : Identity) (h : d dev = none) :
    register d dev id = (Registration.registered, bind d dev id) := by
  simp [register, h]

/-- Re-registering the currently-bound key refreshes and changes no binding. -/
theorem register_same_keeps [DecidableEq Identity] (d : Directory Device Identity)
    (dev : Device) (id : Identity) (h : d dev = some id) :
    register d dev id = (Registration.refreshed, d) := by
  simp [register, h]

/-- Trust on first use: whatever `dev` is bound to, `register` leaves it bound to
exactly that — a different identity cannot displace an existing binding. -/
theorem register_tofu [DecidableEq Identity] (d : Directory Device Identity)
    (dev : Device) (id key : Identity) (h : d dev = some key) :
    (register d dev id).2 dev = some key := by
  simp only [register, h]
  split <;> exact h

/-- `register` never changes another device's binding. -/
theorem register_frames [DecidableEq Identity] (d : Directory Device Identity)
    (dev other : Device) (id : Identity) (h : other ≠ dev) :
    (register d dev id).2 other = d other := by
  cases hd : d dev with
  | none => simp [register, hd, bind, h]
  | some existing => by_cases hk : existing = id <;> simp [register, hd, hk]

/-- Rotating an unbound device is refused and changes nothing. -/
theorem rotate_requires_binding (d : Directory Device Identity) (dev : Device)
    (newId : Identity) (h : d dev = none) :
    rotate d dev newId = (Rotation.unregistered, d) := by
  simp [rotate, h]

/-- Rotating a bound device replaces its binding with the new key. -/
theorem rotate_rebinds (d : Directory Device Identity) (dev : Device)
    (newId key : Identity) (h : d dev = some key) :
    (rotate d dev newId).2 dev = some newId := by
  simp [rotate, h, bind]

/-!
## The pure trust core — the refinement target

`register` / `rotate` above operate on the whole directory (a `Device → Option
Identity`). The Rust mirrors that with a `HashMap`, which is outside the subset
a Charon/Aeneas refinement can translate. So the Rust factors the *trust
decision* into a pure function of the single device's current binding —
`register_core` / `rotate_core` in `crates/tacenta-directory-core/src/lib.rs` — with
the `HashMap` reduced to trust-irrelevant glue (store the bundle, index the
device). `registerCore` / `rotateCore` below are those exact functions, and are
the crisp target the mechanical refinement
(`verification/Verification/DirectoryRefinement.lean`) translates and inherits
these theorems through. `register_matches_core` closes the loop: the container's
observable behaviour at the device is exactly the pure core applied to its
current binding, so proving the core suffices for the method.
-/

/-- The pure trust-on-first-use decision, a function of one device's current
binding (`registerCore (d dev) id`). Fresh binds; same key refreshes; a
different key is rejected and the existing binding is kept. -/
def registerCore [DecidableEq Identity] (current : Option Identity) (presented : Identity) :
    Registration × Identity :=
  match current with
  | none => (Registration.registered, presented)
  | some existing =>
      if existing = presented then (Registration.refreshed, presented)
      else (Registration.rejected, existing)

/-- The pure rotation decision. Bound rotates to the new key; unbound cannot. -/
def rotateCore (current : Option Identity) (newId : Identity) : Rotation × Option Identity :=
  match current with
  | none => (Rotation.unregistered, none)
  | some _ => (Rotation.rotated, some newId)

/-- Trust on first use, on the pure core: a bound device keeps its binding
whatever it presents — the identity returned for `some key` is exactly `key`. -/
theorem registerCore_tofu [DecidableEq Identity] (key presented : Identity) :
    (registerCore (some key) presented).2 = key := by
  simp only [registerCore]
  split <;> simp_all

/-- A fresh device binds the presented key. -/
theorem registerCore_binds_fresh [DecidableEq Identity] (presented : Identity) :
    registerCore (none : Option Identity) presented = (Registration.registered, presented) := rfl

/-- The pure rotation core refuses an unbound device and rebinds a bound one. -/
theorem rotateCore_requires_binding (newId : Identity) :
    rotateCore (none : Option Identity) newId = (Rotation.unregistered, none) := rfl

theorem rotateCore_rebinds (key newId : Identity) :
    rotateCore (some key) newId = (Rotation.rotated, some newId) := rfl

/-- The container faithfully applies the pure core: `register`'s outcome is the
core's outcome, and the binding it leaves at `dev` is `some` of the core's
resulting identity. So the single-device core carries the method's trust —
proving the core (and translating it) is enough. -/
theorem register_matches_core [DecidableEq Identity] (d : Directory Device Identity)
    (dev : Device) (id : Identity) :
    (register d dev id).1 = (registerCore (d dev) id).1 ∧
      (register d dev id).2 dev = some (registerCore (d dev) id).2 := by
  cases hd : d dev with
  | none => simp [register, registerCore, hd, bind]
  | some k => by_cases hk : k = id <;> simp [register, registerCore, hd, hk]

/-!
## Authorized rotation — key continuity

`rotate` above is the store operation; the transport wraps it in an
authorization check (decision records 0024, 0025): a rebind is accepted only if
the request carries a signature the *currently-bound* key accepts. We model that
check with an abstract predicate `Verify current newId sig` — "under key
`current`, `sig` authorizes rebinding to `newId`". Its **unforgeability is
tacenta-core's** (a signature is producible only by the private key's holder);
that is assumed, not modelled here. What is proven here is that the directory
logic *gates* a rebind on the check: no valid signature, no rebind.

Composed with the assumed unforgeability, this gives key continuity — only the
holder of the currently-bound key can move the binding.
-/

/-- The outcome of an authorized rotation, with an explicit unauthorized case. -/
inductive AuthRotation
  | rotated
  | unregistered
  | unauthorized
  deriving DecidableEq, Repr

/-- Authorized rotation: rebind `dev` to `newId` only when the currently-bound
key accepts the signature. `verify` is the abstract, assumed-unforgeable check. -/
def rotateAuth {Sig : Type} (verify : Identity → Identity → Sig → Bool)
    (d : Directory Device Identity) (dev : Device) (newId : Identity) (sig : Sig) :
    AuthRotation × Directory Device Identity :=
  match d dev with
  | none => (AuthRotation.unregistered, d)
  | some current => match verify current newId sig with
                    | true => (AuthRotation.rotated, bind d dev newId)
                    | false => (AuthRotation.unauthorized, d)

/-- Key continuity: an **unauthorized** rotation cannot move the binding — it
stays at the currently-bound key. A caller without a signature the current key
accepts cannot rebind. -/
theorem rotation_unauthorized_frames {Sig : Type} (verify : Identity → Identity → Sig → Bool)
    (d : Directory Device Identity) (dev : Device) (current newId : Identity) (sig : Sig)
    (hb : d dev = some current) (hv : verify current newId sig = false) :
    (rotateAuth verify d dev newId sig).2 dev = some current := by
  simp [rotateAuth, hb, hv]

/-- An authorized rotation rebinds to the new key. -/
theorem rotation_authorized_rebinds {Sig : Type} (verify : Identity → Identity → Sig → Bool)
    (d : Directory Device Identity) (dev : Device) (current newId : Identity) (sig : Sig)
    (hb : d dev = some current) (hv : verify current newId sig = true) :
    (rotateAuth verify d dev newId sig).2 dev = some newId := by
  simp [rotateAuth, hb, hv, bind]

/-- An authorized rotation of an unbound device is refused and changes nothing —
there is no current key to authorize against. -/
theorem rotation_auth_requires_binding {Sig : Type} (verify : Identity → Identity → Sig → Bool)
    (d : Directory Device Identity) (dev : Device) (newId : Identity) (sig : Sig)
    (h : d dev = none) :
    rotateAuth verify d dev newId sig = (AuthRotation.unregistered, d) := by
  simp [rotateAuth, h]

/-!
## Lost-key recovery — authorized by the recovery key

After device loss the identity key is gone, so a rebind cannot be authorized by
it. Recovery (decision record 0025) rebinds the directory's binding to a new
identity, authorized instead by a **recovery key** provisioned in advance (its
private half kept offline). `recovery dev` is the recovery identity set for a
device, if any. As with rotation, the signature's unforgeability is assumed; the
logic gating the rebind on the recovery key's signature is proven.
-/

/-- Recover `dev` to `newId`, authorized by the device's recovery key. Refused
if no recovery key is set; otherwise rebinds only under a signature the recovery
key accepts. -/
def recoverAuth {Sig : Type} (verify : Identity → Identity → Sig → Bool)
    (recovery : Device → Option Identity) (d : Directory Device Identity) (dev : Device)
    (newId : Identity) (sig : Sig) : AuthRotation × Directory Device Identity :=
  match recovery dev with
  | none => (AuthRotation.unregistered, d)
  | some rkey => match verify rkey newId sig with
                 | true => (AuthRotation.rotated, bind d dev newId)
                 | false => (AuthRotation.unauthorized, d)

/-- A recovery without a signature the recovery key accepts cannot move the
binding — it stays at whatever it was. -/
theorem recovery_unauthorized_frames {Sig : Type} (verify : Identity → Identity → Sig → Bool)
    (recovery : Device → Option Identity) (d : Directory Device Identity) (dev : Device)
    (current newId rkey : Identity) (sig : Sig)
    (hr : recovery dev = some rkey) (hv : verify rkey newId sig = false)
    (hb : d dev = some current) :
    (recoverAuth verify recovery d dev newId sig).2 dev = some current := by
  simp [recoverAuth, hr, hv, hb]

/-- A recovery authorized by the recovery key rebinds to the new key. -/
theorem recovery_authorized_rebinds {Sig : Type} (verify : Identity → Identity → Sig → Bool)
    (recovery : Device → Option Identity) (d : Directory Device Identity) (dev : Device)
    (newId rkey : Identity) (sig : Sig)
    (hr : recovery dev = some rkey) (hv : verify rkey newId sig = true) :
    (recoverAuth verify recovery d dev newId sig).2 dev = some newId := by
  simp [recoverAuth, hr, hv, bind]

/-- Recovery of a device with no recovery key set is refused and changes
nothing — there is nothing to authorize against. -/
theorem recovery_requires_key {Sig : Type} (verify : Identity → Identity → Sig → Bool)
    (recovery : Device → Option Identity) (d : Directory Device Identity) (dev : Device)
    (newId : Identity) (sig : Sig) (hr : recovery dev = none) :
    recoverAuth verify recovery d dev newId sig = (AuthRotation.unregistered, d) := by
  simp [recoverAuth, hr]

end Tacenta.Directory
