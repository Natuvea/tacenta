import Tacenta.Wire

/-!
# Per-device session state

One `Session` per device: an append-only log of envelopes and a cursor
counting how many the device has acknowledged. This is the delivery
model — a message is delivered to a device exactly when the cursor has
passed it.

Acks are cumulative ("everything up to `n`") and strictly monotone: an
ack that does not advance the cursor, or that claims more than the log
holds, is rejected (`none`) and leaves no trace on the state.

The theorems pin down the delivery guarantees positionally:

- `pending_append` — appending never disturbs what is already pending
  (**no loss**: undelivered messages survive every append).
- `ack?_log` / `append_cursor` — appends move only the log, acks move
  only the cursor.
- `ack?_cursor_lt` — the cursor only ever advances (**no rewind**).
- `pending_ack?` — a successful ack removes exactly a prefix of the
  pending list and adds nothing (**no replay, no reorder, no loss**:
  what remains is exactly the undelivered suffix, untouched).
-/

namespace Tacenta.Session

open Tacenta.Wire

/-- Per-device delivery state. The invariant ties the cursor into the
log: a device can never have acknowledged messages that do not exist. -/
structure Session where
  log : List Envelope
  cursor : Nat
  valid : cursor ≤ log.length

/-- The fresh session: empty log, nothing acknowledged. -/
def Session.init : Session :=
  ⟨[], 0, Nat.le_refl 0⟩

/-- Messages appended but not yet acknowledged, oldest first. -/
def pending (s : Session) : List Envelope :=
  s.log.drop s.cursor

/-- Append a message to the log. Total: appending is always allowed. -/
def append (e : Envelope) (s : Session) : Session :=
  ⟨s.log ++ [e], s.cursor, by
    have := s.valid
    simp only [List.length_append, List.length_cons, List.length_nil]
    omega⟩

/-- Acknowledge everything up to `n`. Rejected unless the ack strictly
advances the cursor and stays within the log. -/
def ack? (n : Nat) (s : Session) : Option Session :=
  if h : s.cursor < n ∧ n ≤ s.log.length then
    some ⟨s.log, n, h.2⟩
  else
    none

@[simp] theorem append_log (e : Envelope) (s : Session) :
    (append e s).log = s.log ++ [e] := rfl

@[simp] theorem append_cursor (e : Envelope) (s : Session) :
    (append e s).cursor = s.cursor := rfl

/-- No loss: what was pending stays pending, in order, across appends. -/
theorem pending_append (e : Envelope) (s : Session) :
    pending (append e s) = pending s ++ [e] := by
  simp [pending, append, List.drop_append_of_le_length s.valid]

/-- Acks never touch the log. -/
theorem ack?_log {n : Nat} {s s' : Session}
    (h : ack? n s = some s') : s'.log = s.log := by
  unfold ack? at h
  split at h
  · injection h with h'; subst h'; rfl
  · exact absurd h (by simp)

/-- No rewind: a successful ack strictly advances the cursor. -/
theorem ack?_cursor_lt {n : Nat} {s s' : Session}
    (h : ack? n s = some s') : s.cursor < s'.cursor := by
  unfold ack? at h
  split at h
  case isTrue hc =>
    injection h with h'; subst h'; exact hc.1
  case isFalse =>
    exact absurd h (by simp)

/-- No replay, no reorder, no loss: a successful ack removes exactly a
prefix of the pending list — what remains is the undelivered suffix,
byte-for-byte, and nothing new appears. -/
theorem pending_ack? {n : Nat} {s s' : Session}
    (h : ack? n s = some s') :
    pending s' = (pending s).drop (n - s.cursor) := by
  unfold ack? at h
  split at h
  case isTrue hc =>
    injection h with h'; subst h'
    simp only [pending, List.drop_drop]
    congr 1
    omega
  case isFalse =>
    exact absurd h (by simp)

/-- Rejected acks are total no-ops by construction (`none` carries no
state), so the only reachable states are those the theorems above
describe. Recorded as a sanity lemma: an ack at or below the cursor, or
beyond the log, never succeeds. -/
theorem ack?_rejects {n : Nat} {s : Session}
    (h : n ≤ s.cursor ∨ s.log.length < n) : ack? n s = none := by
  unfold ack?
  split
  case isTrue hc => omega
  case isFalse => rfl

end Tacenta.Session
