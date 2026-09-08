import Tacenta.Wire

/-!
# Multi-device user state

One `User` holds a single append-only envelope log shared by all of the
user's devices, and one acknowledgment cursor per device. Delivery is
per-device (`devicePending`); a message counts as **delivered to the
user** only when every device's cursor has passed it (`delivered`, the
minimum cursor).

Devices are identified by their index into `cursors`. A newly linked
device starts at the log tail — in an end-to-end encrypted system a
device that did not exist when a message was sent has no keys for it,
so history is not deliverable to it (decision record 0005).

The theorems extend the single-device guarantees and add the user-level
ones that only exist with fan-out:

- `cursorOf_ack?_frame` — one device's ack never moves another
  device's cursor.
- `delivered_ack?` — user-level delivery never rewinds under acks.
- `delivered_linkDevice` — linking a device never un-delivers.
-/

namespace Tacenta.User

open Tacenta.Wire

/-- Multi-device delivery state. The invariant ties every cursor into
the shared log. -/
structure User where
  log : List Envelope
  cursors : List Nat
  valid : ∀ i (_ : i < cursors.length), cursors[i] ≤ log.length

/-- A fresh user with no devices and no history. -/
def User.init : User :=
  ⟨[], [], by intro i h; simp at h⟩

private theorem getD_of_lt (l : List Nat) (i fb : Nat) (h : i < l.length) :
    l.getD i fb = l[i] := by
  simp [List.getD, List.getElem?_eq_getElem h]

/-- The cursor of device `d`, or the log tail for an unknown device (an
unknown device has nothing pending). -/
def cursorOf (u : User) (d : Nat) : Nat :=
  u.cursors.getD d u.log.length

/-- Messages not yet acknowledged by device `d`, oldest first. -/
def devicePending (u : User) (d : Nat) : List Envelope :=
  u.log.drop (cursorOf u d)

/-- How many leading messages every device has acknowledged: the
user-level delivery count. With no devices this is the whole log
(vacuously delivered). -/
def delivered (u : User) : Nat :=
  u.cursors.foldr min u.log.length

/-- Append a message to the shared log. Total; touches no cursor. -/
def append (e : Envelope) (u : User) : User :=
  ⟨u.log ++ [e], u.cursors, by
    intro i h
    have := u.valid i h
    simp only [List.length_append, List.length_cons, List.length_nil]
    omega⟩

/-- Link a new device, starting at the log tail (no history backfill). -/
def linkDevice (u : User) : User :=
  ⟨u.log, u.cursors ++ [u.log.length], by
    intro i h
    by_cases hi : i < u.cursors.length
    · rw [List.getElem_append_left hi]
      exact u.valid i hi
    · rw [List.getElem_append_right (Nat.le_of_not_lt hi)]
      simp⟩

/-- Device `d` acknowledges everything up to `n`. Rejected unless the
device exists, the ack strictly advances that device's cursor, and it
stays within the log. -/
def ack? (d n : Nat) (u : User) : Option User :=
  if hd : d < u.cursors.length then
    if hn : u.cursors[d] < n ∧ n ≤ u.log.length then
      some ⟨u.log, u.cursors.set d n, by
        intro i hi
        rw [List.getElem_set]
        split
        · exact hn.2
        · exact u.valid i (by simpa using hi)⟩
    else none
  else none

/-- Characterization of a successful ack: exactly the log unchanged,
exactly one cursor set, and the acceptance conditions. Every ack
theorem below is a corollary. -/
theorem ack?_spec {d n : Nat} {u u' : User} (h : ack? d n u = some u') :
    u'.log = u.log ∧ u'.cursors = u.cursors.set d n ∧
      d < u.cursors.length ∧ cursorOf u d < n ∧ n ≤ u.log.length := by
  unfold ack? at h
  split at h
  case isTrue hd =>
    split at h
    case isTrue hn =>
      injection h with h'
      subst h'
      refine ⟨rfl, rfl, hd, ?_, hn.2⟩
      rw [cursorOf, getD_of_lt u.cursors d _ hd]
      exact hn.1
    case isFalse => exact absurd h (by simp)
  case isFalse => exact absurd h (by simp)

@[simp] theorem append_log (e : Envelope) (u : User) :
    (append e u).log = u.log ++ [e] := rfl

@[simp] theorem append_cursors (e : Envelope) (u : User) :
    (append e u).cursors = u.cursors := rfl

/-- No loss, per device: appends never disturb any device's pending. -/
theorem devicePending_append (e : Envelope) (u : User) (d : Nat)
    (hd : d < u.cursors.length) :
    devicePending (append e u) d = devicePending u d ++ [e] := by
  have hc : cursorOf u d ≤ u.log.length := by
    rw [cursorOf, getD_of_lt u.cursors d _ hd]
    exact u.valid d hd
  have hcursor : cursorOf (append e u) d = cursorOf u d := by
    rw [cursorOf, cursorOf, append_cursors,
      getD_of_lt u.cursors d _ hd, getD_of_lt u.cursors d _ hd]
  simp [devicePending, hcursor, List.drop_append_of_le_length hc]

/-- Acks never touch the log. -/
theorem ack?_log {d n : Nat} {u u' : User}
    (h : ack? d n u = some u') : u'.log = u.log :=
  (ack?_spec h).1

/-- No rewind, per device: a successful ack strictly advances the
acking device's cursor. -/
theorem cursorOf_ack?_lt {d n : Nat} {u u' : User}
    (h : ack? d n u = some u') : cursorOf u d < cursorOf u' d := by
  obtain ⟨hlog, hcur, hd, hlt, _⟩ := ack?_spec h
  have hd' : d < (u.cursors.set d n).length := by simpa using hd
  have hset : cursorOf u' d = n := by
    rw [cursorOf, hcur, hlog, getD_of_lt _ d _ hd', List.getElem_set_self]
  rw [hset]
  exact hlt

/-- Isolation: one device's ack never moves another device's cursor. -/
theorem cursorOf_ack?_frame {d n : Nat} {u u' : User}
    (h : ack? d n u = some u') (i : Nat) (hi : i < u.cursors.length)
    (hne : i ≠ d) : cursorOf u' i = cursorOf u i := by
  obtain ⟨hlog, hcur, _, _, _⟩ := ack?_spec h
  have hi' : i < (u.cursors.set d n).length := by simpa using hi
  rw [cursorOf, cursorOf, hcur, hlog,
    getD_of_lt u.cursors i _ hi, getD_of_lt _ i _ hi',
    List.getElem_set_ne (by omega)]

/-- Raising one element of a list never lowers the fold-min. -/
private theorem foldr_min_set_le {base : Nat} :
    ∀ {l : List Nat} {d n : Nat} (_ : d < l.length),
      l[d] ≤ n → l.foldr min base ≤ (l.set d n).foldr min base := by
  intro l
  induction l with
  | nil => intro d n hd _; simp at hd
  | cons h t ih =>
    intro d n hd hn
    cases d with
    | zero =>
      simp only [List.getElem_cons_zero] at hn
      simp only [List.set_cons_zero, List.foldr_cons]
      simp only [Nat.min_def]
      split <;> split <;> omega
    | succ d =>
      simp only [List.getElem_cons_succ] at hn
      have hd' : d < t.length := by simpa using hd
      have := ih hd' hn
      simp only [List.set_cons_succ, List.foldr_cons]
      simp only [Nat.min_def]
      split <;> split <;> omega

/-- User-level delivery never rewinds: a successful ack can only hold
or advance the delivered count. -/
theorem delivered_ack? {d n : Nat} {u u' : User}
    (h : ack? d n u = some u') : delivered u ≤ delivered u' := by
  obtain ⟨hlog, hcur, hd, hlt, _⟩ := ack?_spec h
  have hle : u.cursors[d] ≤ n := by
    rw [cursorOf, getD_of_lt u.cursors d _ hd] at hlt
    omega
  rw [delivered, delivered, hcur, hlog]
  exact foldr_min_set_le hd hle

/-- Linking a device never un-delivers: the new device starts at the
log tail, so the user-level delivered count is unchanged. -/
theorem delivered_linkDevice (u : User) :
    delivered (linkDevice u) = delivered u := by
  simp [delivered, linkDevice, List.foldr_append]

end Tacenta.User
