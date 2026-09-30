/-!
# Bounded group-policy model

This executable contract covers the one-authority, one-device-per-identity
development profile. Group, invitation, and commitment values are opaque here:
their byte encodings, cryptographic placement, and production-scale protocol are
specified separately before a codec or crypto implementation is added.

Revision numbering (decision 0137): an invitation does not advance the roster
revision. It records the authority's current revision as its source revision.
Only a roster successor (admission, removal, closure) advances the revision, so
inviting one person at revision 0 and admitting them leaves the group at
revision 1. `contracts/vectors/group-v1.json` is generated from this model and
replayed against the Rust `tacenta-group` types.
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
  /-- The roster revision the authority held when it issued the invitation. -/
  sourceRevision : Nat
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

/-- Only the authority can invite, into an open group with room for one more
member. The target must not share an identity with a current member, so a second
device of a member is refused as well. Expiry is strict: valid exactly while
logical now is less than expiresAt. An invitation is authority-side state and a
bootstrap message, so it records the current revision as its source and does
not advance the roster revision. -/
def invite? (actor : Member) (id now expiresAt : Nat) (target : Member) (s : State) : Option State :=
  if !active s || actor != s.authority || now >= expiresAt ||
      identityPresent target s || (invitationAt? id s.invitations).isSome ||
      s.roster.length >= maxMembers then none
  else
    some { s with invitations := s.invitations ++
      [{ id, target, sourceRevision := s.revision, expiresAt, status := .pending }] }

/-- Acceptance records pending intent only; it does not grant membership. It
must name the invitation's source revision. A repeat of an acceptance that was
already recorded is a no-op while the invitation is unexpired or admitted:
acceptance travels as a retried control message (decision 0137). -/
def accept? (actor : Member) (id now observedRevision : Nat) (s : State) : Option State :=
  match invitationAt? id s.invitations with
  | none => none
  | some invitation =>
    if !active s || actor != invitation.target ||
        observedRevision != invitation.sourceRevision then none
    else match invitation.status with
      | .admitted _ => some s
      | .pending =>
        if now >= invitation.expiresAt then none
        else some { s with invitations := (replaceInvitation
          { invitation with status := .acceptedPendingAdmission } s.invitations) }
      | .acceptedPendingAdmission =>
        if now >= invitation.expiresAt then none else some s
      | .revoked => none

/-- Admission rechecks expiry and only accepts the exact pending invitation. Its
revision is the successor of the current one, which is never at or before the
invitation's source revision (`admission_follows_its_source`). -/
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

/-- An admission is the successor of the current revision, so it lands strictly
after the source revision of any invitation the current revision has reached.
This is the model's form of the code rule that `admit` refuses a revision at or
before the invitation's source revision. -/
theorem admission_follows_its_source (actor : Member) (id now commitment : Nat)
    (s s' : State) (invitation : Invitation)
    (hinv : invitationAt? id s.invitations = some invitation)
    (hsrc : invitation.sourceRevision ≤ s.revision)
    (h : admit? actor id now commitment s = some s') :
    s'.revision = s.revision + 1 ∧ invitation.sourceRevision < s'.revision := by
  unfold admit? at h
  rw [hinv] at h
  by_cases hactive : active s = true
  · have hnext : nextRevision? s = some (s.revision + 1) := by
      simp [nextRevision?, hactive]
    rw [hnext] at h
    simp only at h
    split at h
    · simp at h
    · simp only [Option.some.injEq] at h
      subst h
      refine ⟨?_, ?_⟩ <;> simp [recordSuccessor] <;> omega
  · have hnext : nextRevision? s = none := by
      simp [nextRevision?, hactive]
    rw [hnext] at h
    simp at h

/-- Decision 0137: an invitation changes no roster and no revision. -/
theorem invitation_does_not_advance_the_revision (actor : Member) (id now expiresAt : Nat)
    (target : Member) (s s' : State)
    (h : invite? actor id now expiresAt target s = some s') :
    s'.revision = s.revision ∧ s'.roster = s.roster := by
  unfold invite? at h
  split at h
  · simp at h
  · simp only [Option.some.injEq] at h
    subst h
    exact ⟨rfl, rfl⟩

theorem different_commitment_is_a_conflict (s : State) (known candidate : Control)
    (hg : candidate.group = s.group) (ha : candidate.authority = s.authority)
    (h : controlAt? candidate.revision s.history = some known)
    (different : known.commitment ≠ candidate.commitment) :
    controlDisposition s candidate = .conflict := by
  unfold controlDisposition
  simp [hg, ha, h, different]

/-! ## Rules that hold in every state

The theorems below state the model's guards for every state, not for the fixed
traces alone: who may act, what an operation leaves changed, what a closed group
refuses, how far the revision may run, and how the control history is read.
They are properties of the model's own definitions, so they fail when a guard is
removed or weakened. They say nothing about the Rust types except through the
committed vectors, and decision 0137 lists where the code differs (a repeated
revocation, the removal of a non-member, and `accept`, `revoke` and a second
closure in a closed group are among them). -/

/-- Only the authority invites. -/
theorem only_the_authority_invites (actor : Member) (id now expiresAt : Nat) (target : Member)
    (s s' : State) (h : invite? actor id now expiresAt target s = some s') :
    actor = s.authority := by
  unfold invite? at h
  by_cases hb : actor = s.authority
  · exact hb
  · simp [hb] at h

/-- Only the authority admits. -/
theorem only_the_authority_admits (actor : Member) (id now commitment : Nat)
    (s s' : State) (h : admit? actor id now commitment s = some s') :
    actor = s.authority := by
  unfold admit? at h
  by_cases hb : actor = s.authority
  · exact hb
  · cases hi : invitationAt? id s.invitations <;> cases hn : nextRevision? s <;>
      simp [hi, hn, hb] at h

/-- Only the authority revokes. -/
theorem only_the_authority_revokes (actor : Member) (id : Nat) (s s' : State)
    (h : revoke? actor id s = some s') : actor = s.authority := by
  unfold revoke? at h
  by_cases hb : actor = s.authority
  · exact hb
  · cases hi : invitationAt? id s.invitations <;> simp [hi, hb] at h

/-- Only the authority removes. -/
theorem only_the_authority_removes (actor target : Member) (s s' : State)
    (h : remove? actor target s = some s') : actor = s.authority := by
  unfold remove? at h
  by_cases hb : actor = s.authority
  · exact hb
  · cases hn : nextRevision? s <;> simp [hn, hb] at h

/-- Only the authority closes the group. -/
theorem only_the_authority_closes (actor : Member) (s s' : State)
    (h : close? actor s = some s') : actor = s.authority := by
  unfold close? at h
  cases hn : nextRevision? s <;> simp [hn] at h
  · by_cases hb : actor = s.authority
    · exact hb
    · simp [hb] at h

/-- A removal takes out a current member: removing someone who is not on the
roster is refused. (The Rust roster view accepts such a successor, decision 0137
item 3.) -/
theorem removal_needs_a_current_member (actor target : Member) (s s' : State)
    (h : remove? actor target s = some s') : memberPresent target s = true := by
  unfold remove? at h
  by_cases hb : memberPresent target s = true
  · exact hb
  · cases hn : nextRevision? s <;> simp [hn, hb] at h

/-- Revocation applies to an invitation that is pending or accepted and not yet
admitted: revoking twice is refused. (The Rust book returns the record for a
repeated revocation, decision 0137 item 4.) -/
theorem revocation_needs_a_live_invitation (actor : Member) (id : Nat) (s s' : State)
    (h : revoke? actor id s = some s') :
    ∃ invitation, invitationAt? id s.invitations = some invitation ∧
      (invitation.status = .pending ∨ invitation.status = .acceptedPendingAdmission) := by
  unfold revoke? at h
  cases hi : invitationAt? id s.invitations with
  | none => simp [hi] at h
  | some invitation =>
    refine ⟨invitation, rfl, ?_⟩
    rw [hi] at h
    cases hs : invitation.status <;> simp [hs] at h ⊢

/-- Closing marks the group closed, advances the revision once, and leaves the
roster and the invitations as they were. -/
theorem closure_closes_the_group (actor : Member) (s s' : State)
    (h : close? actor s = some s') :
    s'.closed = true ∧ s'.revision = s.revision + 1 ∧ s'.roster = s.roster ∧
      s'.invitations = s.invitations := by
  unfold close? at h
  cases hn : nextRevision? s with
  | none => simp [hn] at h
  | some next =>
    have hnext : next = s.revision + 1 := by
      unfold nextRevision? at hn
      split at hn
      · simpa using hn.symm
      · simp at hn
    rw [hn] at h
    simp only at h
    split at h
    · simp only [Option.some.injEq] at h
      subst h
      simp [hnext]
    · simp at h

/-- A closed group refuses all six operations, whoever asks. (The Rust invitation
book does not look at the roster, so `create`, `accept` and `revoke` are not
refused there for this reason, and the roster view accepts a second closure;
decision 0137 items 6 and 9.) -/
theorem a_closed_group_refuses_every_operation (s : State) (hclosed : s.closed = true) :
    (∀ actor id now expiresAt target, invite? actor id now expiresAt target s = none) ∧
    (∀ actor id now observed, accept? actor id now observed s = none) ∧
    (∀ actor id now commitment, admit? actor id now commitment s = none) ∧
    (∀ actor id, revoke? actor id s = none) ∧
    (∀ actor target, remove? actor target s = none) ∧
    (∀ actor, close? actor s = none) := by
  have hact : active s = false := by simp [active, hclosed]
  have hnext : nextRevision? s = none := by simp [nextRevision?, hact]
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro actor id now expiresAt target
    simp [invite?, hact]
  · intro actor id now observed
    unfold accept?
    cases hi : invitationAt? id s.invitations <;> simp [hact]
  · intro actor id now commitment
    unfold admit?
    cases hi : invitationAt? id s.invitations <;> simp [hnext]
  · intro actor id
    unfold revoke?
    cases hi : invitationAt? id s.invitations <;> simp [hact]
  · intro actor target
    simp [remove?, hnext]
  · intro actor
    simp [close?, hnext]

/-- A successor revision never passes the last usable one, so no operation of
the model reaches the reserved `u64::MAX`. -/
theorem successor_revisions_stay_usable (s : State) (n : Nat)
    (h : nextRevision? s = some n) : n ≤ lastUsableRevision := by
  unfold nextRevision? active at h
  split at h
  · rename_i ha
    simp only [Option.some.injEq] at h
    subst h
    simp only [Bool.and_eq_true, decide_eq_true_eq] at ha
    omega
  · simp at h

/-- Decision 0137: a repeat of an acceptance that was already recorded changes
nothing, while the invitation is unexpired or once it is admitted. -/
theorem repeat_acceptance_changes_nothing (actor : Member) (id now observed : Nat)
    (s : State) (invitation : Invitation)
    (hinv : invitationAt? id s.invitations = some invitation)
    (hactive : active s = true) (hactor : actor = invitation.target)
    (hobserved : observed = invitation.sourceRevision)
    (hstatus : (∃ revision, invitation.status = .admitted revision) ∨
      (invitation.status = .acceptedPendingAdmission ∧ now < invitation.expiresAt)) :
    accept? actor id now observed s = some s := by
  unfold accept?
  rw [hinv]
  rcases hstatus with ⟨revision, hs⟩ | ⟨hs, hnow⟩
  · simp [hactive, hactor, hobserved, hs]
  · have : ¬ now ≥ invitation.expiresAt := by omega
    simp [hactive, hactor, hobserved, hs, this]

/-- An admission appends exactly one control to the history: the successor of
the current revision, naming that revision as its predecessor and carrying the
commitment it was given. -/
theorem admission_records_its_successor (actor : Member) (id now commitment : Nat)
    (s s' : State) (h : admit? actor id now commitment s = some s') :
    s'.history = s.history ++
      [{ group := s.group, revision := s.revision + 1, predecessor := some s.revision,
         authority := s.authority, commitment }] := by
  unfold admit? at h
  cases hi : invitationAt? id s.invitations with
  | none => simp [hi] at h
  | some invitation =>
    cases hn : nextRevision? s with
    | none => simp [hi, hn] at h
    | some next =>
      have hnext : next = s.revision + 1 := by
        unfold nextRevision? at hn
        split at hn
        · simpa using hn.symm
        · simp at hn
      rw [hi, hn] at h
      simp only at h
      split at h
      · simp at h
      · simp only [Option.some.injEq] at h
        subst h
        simp [recordSuccessor, hnext]

/-- A control from another group or another authority is a conflict, whatever
its revision and commitment. -/
theorem foreign_control_is_a_conflict (s : State) (candidate : Control)
    (h : candidate.group ≠ s.group ∨ candidate.authority ≠ s.authority) :
    controlDisposition s candidate = .conflict := by
  unfold controlDisposition
  rcases h with h | h <;> simp [h]

/-- A control the model calls `next` is the successor of the current revision and
names it as its predecessor. -/
theorem next_control_extends_the_head (s : State) (candidate : Control)
    (h : controlDisposition s candidate = .next) :
    candidate.revision = s.revision + 1 ∧ candidate.predecessor = some s.revision := by
  unfold controlDisposition at h
  split at h
  · simp at h
  · split at h
    · split at h <;> simp at h
    · split at h
      · rename_i hc
        simpa using hc
      · simp at h

/-! ## Fixed profile traces

These executable traces cover the first r0/r1/r2 path and the rejection that
matters most for the invitation lifecycle: a revocation after acceptance cannot
be turned into an admission by replaying the acceptance.
-/

private def traceAuthority : Member := { identity := 1, device := 1 }
private def traceMember : Member := { identity := 2, device := 1 }
private def traceGenesis : State := genesis 9 traceAuthority 100
private def traceInvited : State :=
  match invite? traceAuthority 7 0 10 traceMember traceGenesis with
  | some state => state
  | none => traceGenesis
private def traceAccepted : State :=
  match accept? traceMember 7 1 0 traceInvited with
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

example : traceInvited.revision = 0 := rfl
example : traceAdmitted.revision = 1 := rfl
example : (accept? traceMember 7 1 0 traceAccepted).isSome = true := rfl
example : (accept? traceMember 7 1 5 traceInvited).isNone = true := rfl
example : (accept? traceMember 7 10 0 traceInvited).isNone = true := rfl
example : (invite? traceAuthority 8 0 10 { identity := 2, device := 2 } traceAdmitted).isNone = true := rfl
example : traceAdmitted.roster = [traceAuthority, traceMember] := rfl
example : (admit? traceAuthority 7 2 102 traceRevoked).isNone = true := rfl

/-! ## Further fixed traces

Verdicts of the model that the traces above leave open. Most of them are also
steps of the committed vectors (`contracts/vectors/group-v1.json`), which the
Rust types replay; the examples give the same verdicts inside `lake build`. A
few are model rules that the vectors cannot carry, because the code differs
(decision 0137, items 3 and 4), because the state is out of reach (item 15), or
because the vector JSON does not hold the control history. -/

private def traceOtherDevice : Member := { identity := 2, device := 2 }
private def traceThird : Member := { identity := 3, device := 1 }
private def traceStranger : Member := { identity := 9, device := 1 }

/-- Apply one operation, and stay where we are if the model refuses it. -/
private def stepOrStay (operation : State → Option State) (s : State) : State :=
  (operation s).getD s

/-- `traceMember` admitted at revision 1, `traceThird` at revision 2. -/
private def traceThree : State :=
  stepOrStay (admit? traceAuthority 8 5 103)
    (stepOrStay (accept? traceThird 8 4 1)
      (stepOrStay (invite? traceAuthority 8 3 20 traceThird) traceAdmitted))

example : traceThree.revision = 2 := rfl
example : traceThree.roster = [traceAuthority, traceMember, traceThird] := rfl

-- Only the authority admits, removes and closes; a member and a stranger are
-- refused alike.
example : (admit? traceMember 7 2 102 traceAccepted).isNone = true := rfl
example : (admit? traceStranger 7 2 102 traceAccepted).isNone = true := rfl
example : (remove? traceMember traceThird traceThree).isNone = true := rfl
example : (remove? traceStranger traceThird traceThree).isNone = true := rfl
example : (remove? traceAuthority traceThird traceThree).isSome = true := rfl
example : (close? traceMember traceThree).isNone = true := rfl
example : (close? traceStranger traceThree).isNone = true := rfl

-- Removing someone who is not on the roster, and revoking twice, are refused
-- (decision 0137, items 3 and 4: the code accepts both).
example : (remove? traceAuthority traceStranger traceAdmitted).isNone = true := rfl
example : (revoke? traceAuthority 7 traceAccepted).isSome = true := rfl
example : (revoke? traceAuthority 7 traceRevoked).isNone = true := rfl

-- Two invitations to two devices of one identity can both be accepted while the
-- identity is not on the roster; once one device is admitted the other is
-- refused, and it is admitted after the first device is removed.
private def traceTwoDevices : State :=
  stepOrStay (accept? traceOtherDevice 8 1 0)
    (stepOrStay (accept? traceMember 7 1 0)
      (stepOrStay (invite? traceAuthority 8 0 10 traceOtherDevice) traceInvited))
private def traceFirstDevice : State :=
  stepOrStay (admit? traceAuthority 7 2 102) traceTwoDevices

example : (traceTwoDevices.invitations.map (·.status)) =
    [.acceptedPendingAdmission, .acceptedPendingAdmission] := rfl
example : (admit? traceAuthority 8 2 102 traceTwoDevices).isSome = true := rfl
example : (admit? traceAuthority 8 3 103 traceFirstDevice).isNone = true := rfl
example : (admit? traceAuthority 8 4 103
    (stepOrStay (remove? traceAuthority traceMember) traceFirstDevice)).isSome = true := rfl

-- An invitation is valid exactly while now is less than expiresAt.
example : (invite? traceAuthority 7 10 10 traceMember traceGenesis).isNone = true := rfl
example : (invite? traceAuthority 7 9 10 traceMember traceGenesis).isSome = true := rfl

-- A repeat acceptance after admission changes nothing, even after expiry.
example : (accept? traceMember 7 3 0 traceAdmitted).map (·.revision) = some 1 := rfl
example : (accept? traceMember 7 99 0 traceAdmitted).map (·.roster) =
    some [traceAuthority, traceMember] := rfl

-- Closing: only the authority; the group is then closed and refuses everything.
private def traceClosed : State := stepOrStay (close? traceAuthority) traceThree
private def traceClosedWithAcceptance : State := stepOrStay (close? traceAuthority) traceAccepted

example : traceClosed.closed = true := rfl
example : traceClosed.revision = 3 := rfl
example : traceClosed.roster = traceThree.roster := rfl
example : (invite? traceAuthority 9 6 20 traceStranger traceThree).isSome = true := rfl
example : (invite? traceAuthority 9 6 20 traceStranger traceClosed).isNone = true := rfl
example : (remove? traceAuthority traceThird traceClosed).isNone = true := rfl
example : (close? traceAuthority traceClosed).isNone = true := rfl
example : (admit? traceAuthority 7 2 102 traceClosedWithAcceptance).isNone = true := rfl
example : (accept? traceMember 7 1 0 (stepOrStay (close? traceAuthority) traceInvited)).isNone =
    true := rfl
example : (revoke? traceAuthority 7 traceClosedWithAcceptance).isNone = true := rfl

-- The revision stops one short of the reserved u64::MAX: the last usable
-- revision is reached by a successor from the one before it, and nothing
-- (including an invitation, which does not advance the revision) is accepted
-- there. The two literals below are written out so that they do not move with
-- `lastUsableRevision`. The states are built directly; no trace reaches them.
private def beforeTheLast : Nat := 18_446_744_073_709_551_613
private def theLast : Nat := 18_446_744_073_709_551_614
private def atRevision (s : State) (revision : Nat) : State := { s with revision }

example : lastUsableRevision + 2 = UInt64.size := by decide
example : (admit? traceAuthority 7 2 102 (atRevision traceAccepted beforeTheLast)).map
    (·.revision) = some theLast := rfl
example : (admit? traceAuthority 7 2 102 (atRevision traceAccepted theLast)).isNone = true := rfl
example : (remove? traceAuthority traceMember (atRevision traceAdmitted beforeTheLast)).map
    (·.revision) = some theLast := rfl
example : (remove? traceAuthority traceMember (atRevision traceAdmitted theLast)).isNone = true :=
  rfl
example : (close? traceAuthority (atRevision traceAdmitted beforeTheLast)).map
    (·.revision) = some theLast := rfl
example : (close? traceAuthority (atRevision traceAdmitted theLast)).isNone = true := rfl
example : (invite? traceAuthority 8 0 10 traceThird (atRevision traceAdmitted beforeTheLast)).isSome
    = true := rfl
example : (invite? traceAuthority 8 0 10 traceThird (atRevision traceAdmitted theLast)).isNone
    = true := rfl
example : (accept? traceMember 7 1 0 (atRevision traceInvited theLast)).isNone = true := rfl
example : (revoke? traceAuthority 7 (atRevision traceInvited theLast)).isNone = true := rfl

-- The control history: an admission records its successor, and a candidate is
-- read against it.
private def traceControl (revision : Nat) (predecessor : Option Nat) (commitment : Nat) : Control :=
  { group := 9, revision, predecessor, authority := traceAuthority, commitment }

example : traceAdmitted.history.map (·.predecessor) = [none, some 0] := rfl
example : traceAdmitted.history.map (·.commitment) = [100, 102] := rfl
example : controlDisposition traceAdmitted (traceControl 2 (some 1) 103) = .next := rfl
example : controlDisposition traceAdmitted (traceControl 2 (some 0) 103) = .staleOrFuture := rfl
example : controlDisposition traceAdmitted (traceControl 3 (some 2) 104) = .staleOrFuture := rfl
example : controlDisposition traceAdmitted (traceControl 1 (some 0) 102) = .duplicate := rfl
example : controlDisposition traceAdmitted (traceControl 1 (some 0) 999) = .conflict := rfl
example : controlDisposition traceAdmitted { traceControl 1 (some 0) 102 with group := 10 } =
    .conflict := rfl
example : controlDisposition traceAdmitted
    { traceControl 1 (some 0) 102 with authority := traceMember } = .conflict := rfl

end Tacenta.Group
