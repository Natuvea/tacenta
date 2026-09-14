/-!
# Bounded group-policy model

This executable contract covers the one-authority, one-device-per-identity
development profile. Group, invitation, and commitment values are opaque here:
their byte encodings, cryptographic placement, and production-scale protocol are
specified separately before a codec or crypto implementation is added.
-/

namespace Tacenta.Group

abbrev Identity := Nat
abbrev Device := Nat

/-- An authenticated identity/device binding, not a relay address alone. -/
structure Member where
  identity : Identity
  device : Device
  deriving DecidableEq, Repr

def sameIdentity (a b : Member) : Bool := a.identity == b.identity

/-- u64::MAX is reserved; this is the final usable revision. -/
def lastUsableRevision : Nat := 18_446_744_073_709_551_614
def maxMembers : Nat := 8

inductive InvitationStatus where
  | pending
  | acceptedPendingAdmission
  | admitted (revision : Nat)
  | revoked
  deriving DecidableEq, Repr

structure Invitation where
  id : Nat
  target : Member
  expiresAt : Nat
  status : InvitationStatus
  deriving DecidableEq, Repr

/-- Opaque accepted control history used to distinguish retries from forks. -/
structure Control where
  group : Nat
  revision : Nat
  predecessor : Option Nat
  authority : Member
  commitment : Nat
  deriving DecidableEq, Repr

structure State where
  group : Nat
  authority : Member
  revision : Nat
  closed : Bool
  roster : List Member
  invitations : List Invitation
  history : List Control
  deriving Repr

def genesis (group : Nat) (authority : Member) (commitment : Nat) : State :=
  { group, authority, revision := 0, closed := false, roster := [authority],
    invitations := [], history := [{ group, revision := 0, predecessor := none, authority, commitment }] }

def active (s : State) : Bool := !s.closed && s.revision < lastUsableRevision

def nextRevision? (s : State) : Option Nat :=
  if active s then some (s.revision + 1) else none

/-- Append exactly one authority-channel successor. The commitment is opaque
until the canonical control encoding and authenticated placement are specified. -/
def recordSuccessor (s : State) (next commitment : Nat) : State :=
  let withRevision := { s with revision := next }
  { withRevision with history := s.history ++
    [{ group := s.group, revision := next, predecessor := some s.revision,
       authority := s.authority, commitment }] }

def invitationAt? (id : Nat) : List Invitation -> Option Invitation
  | [] => none
  | x :: xs => if x.id == id then some x else invitationAt? id xs

def replaceInvitation (replacement : Invitation) : List Invitation -> List Invitation
  | [] => []
  | x :: xs => if x.id == replacement.id then replacement :: xs else x :: replaceInvitation replacement xs

def memberPresent (member : Member) (s : State) : Bool := member ∈ s.roster
def identityPresent (member : Member) (s : State) : Bool :=
  s.roster.any (fun existing => sameIdentity existing member)

/-- Only the authority can invite. Expiry is strict: valid exactly while
logical now is less than expiresAt. -/
def invite? (actor : Member) (id now expiresAt commitment : Nat) (target : Member) (s : State) : Option State :=
  match nextRevision? s with
  | none => none
  | some next =>
  if actor != s.authority || now >= expiresAt || memberPresent target s ||
      identityPresent target s || (invitationAt? id s.invitations).isSome ||
      s.roster.length >= maxMembers then none
  else
    let recorded := recordSuccessor s next commitment
    some { recorded with invitations := s.invitations ++
      [{ id, target, expiresAt, status := .pending }] }

/-- Acceptance records pending intent only; it does not grant membership. -/
def accept? (actor : Member) (id now : Nat) (s : State) : Option State :=
  match invitationAt? id s.invitations with
  | none => none
  | some invitation =>
    if !active s || actor != invitation.target || now >= invitation.expiresAt ||
        invitation.status != .pending then none
    else some { s with invitations := (replaceInvitation
      { invitation with status := .acceptedPendingAdmission } s.invitations) }

/-- Admission rechecks expiry and only accepts the exact pending invitation. -/
def admit? (actor : Member) (id now commitment : Nat) (s : State) : Option State :=
  match invitationAt? id s.invitations, nextRevision? s with
  | some invitation, some next =>
    if actor != s.authority || now >= invitation.expiresAt ||
        invitation.status != .acceptedPendingAdmission || memberPresent invitation.target s ||
        identityPresent invitation.target s || s.roster.length >= maxMembers then none
    else
      let updated := { invitation with status := InvitationStatus.admitted next }
      let recorded := recordSuccessor s next commitment
      let withRoster := { recorded with roster := s.roster ++ [invitation.target] }
      some { withRoster with invitations := (replaceInvitation updated s.invitations) }
  | _, _ => none

/-- Revocation wins over a previously accepted pending invitation. -/
def revoke? (actor : Member) (id : Nat) (s : State) : Option State :=
  match invitationAt? id s.invitations with
  | none => none
  | some invitation =>
    if actor != s.authority || !active s ||
        !(invitation.status == .pending || invitation.status == .acceptedPendingAdmission) then none
    else some { s with invitations := (replaceInvitation
      { invitation with status := .revoked } s.invitations) }

/-- Only the authority removes a distinct current member; removal advances once. -/
def remove? (actor target : Member) (s : State) : Option State :=
  match nextRevision? s with
  | none => none
  | some next =>
    if actor != s.authority || target == s.authority || !memberPresent target s then none
    else
      let withRevision := { s with revision := next }
      some { withRevision with roster := s.roster.filter (fun member => member != target) }

/-- Authority leave has no transfer rule in this profile: it closes the group. -/
def close? (actor : Member) (s : State) : Option State :=
  match nextRevision? s with
  | none => none
  | some next =>
    if actor == s.authority then
      let withRevision := { s with revision := next }
      some { withRevision with closed := true }
    else none

def controlAt? (revision : Nat) : List Control -> Option Control
  | [] => none
  | x :: xs => if x.revision == revision then some x else controlAt? revision xs

inductive ControlDisposition where
  | next
  | duplicate
  | conflict
  | staleOrFuture
  deriving DecidableEq, Repr

/-- Same revision is a duplicate only for the identical accepted commitment;
a different commitment is a fork conflict. -/
def controlDisposition (s : State) (candidate : Control) : ControlDisposition :=
  if candidate.group != s.group || candidate.authority != s.authority then .conflict
  else match controlAt? candidate.revision s.history with
    | some known => if known.commitment == candidate.commitment then .duplicate else .conflict
    | none =>
      if candidate.revision == s.revision + 1 && candidate.predecessor == some s.revision then
        .next
      else .staleOrFuture

theorem genesis_has_only_its_authority (group commitment : Nat) (authority : Member) :
    (genesis group authority commitment).roster = [authority] := rfl

theorem different_commitment_is_a_conflict (s : State) (known candidate : Control)
    (hg : candidate.group = s.group) (ha : candidate.authority = s.authority)
    (h : controlAt? candidate.revision s.history = some known)
    (different : known.commitment ≠ candidate.commitment) :
    controlDisposition s candidate = .conflict := by
  unfold controlDisposition
  simp [hg, ha, h, different]

/-! ## Fixed profile traces

These executable traces cover the first r0/r1/r2 path and the rejection that
matters most for the invitation lifecycle: a revocation after acceptance cannot
be turned into an admission by replaying the acceptance.
-/

private def traceAuthority : Member := { identity := 1, device := 1 }
private def traceMember : Member := { identity := 2, device := 1 }
private def traceGenesis : State := genesis 9 traceAuthority 100
private def traceInvited : State :=
  match invite? traceAuthority 7 0 10 101 traceMember traceGenesis with
  | some state => state
  | none => traceGenesis
private def traceAccepted : State :=
  match accept? traceMember 7 1 traceInvited with
  | some state => state
  | none => traceInvited
private def traceAdmitted : State :=
  match admit? traceAuthority 7 2 102 traceAccepted with
  | some state => state
  | none => traceAccepted
private def traceRevoked : State :=
  match revoke? traceAuthority 7 traceAccepted with
  | some state => state
  | none => traceAccepted

example : traceInvited.revision = 1 := rfl
example : traceAdmitted.revision = 2 := rfl
example : traceAdmitted.roster = [traceAuthority, traceMember] := rfl
example : (admit? traceAuthority 7 2 102 traceRevoked).isNone = true := rfl

end Tacenta.Group
