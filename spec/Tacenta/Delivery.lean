import Tacenta.User

/-!
# The delivery guarantee, at the whole-system level

The per-operation theorems in `Tacenta.User` are local: each says one
operation behaves. This module composes them into the property a
messaging system actually promises — *a message is delivered to the
user exactly when every device has acknowledged past it* — and proves
that property is stable: once delivered, a message stays delivered
under every later operation.

Because the translated Rust `User::delivered` is proved to refine the
spec's `delivered` (`Verification.user_delivered_refines`), every
theorem here transfers to the shipped implementation: the Rust computes
the same `delivered`, so it satisfies the same delivery guarantee.
-/

namespace Tacenta.User

open Tacenta.Wire

/-! ## Fold-min facts (spec-local, no Mathlib) -/

private theorem getD_of_lt (l : List Nat) (i fb : Nat) (h : i < l.length) :
    l.getD i fb = l[i] := by
  simp [List.getD, List.getElem?_eq_getElem h]

private theorem lt_foldr_min (l : List Nat) (b i : Nat) (hb : i < b)
    (hl : ∀ x ∈ l, i < x) : i < l.foldr min b := by
  induction l with
  | nil => exact hb
  | cons x t ih =>
    have hx : i < x := hl x (List.mem_cons_self ..)
    have ht : i < t.foldr min b := ih (fun y hy => hl y (List.mem_cons_of_mem x hy))
    simp only [List.foldr_cons]; omega

private theorem foldr_min_le_base (l : List Nat) (b : Nat) :
    l.foldr min b ≤ b := by
  induction l with
  | nil => exact Nat.le_refl b
  | cons x t ih => simp only [List.foldr_cons]; omega

private theorem foldr_min_le_getElem (l : List Nat) (b i : Nat)
    (hi : i < l.length) : l.foldr min b ≤ l[i] := by
  induction l generalizing i with
  | nil => simp at hi
  | cons x t ih =>
    simp only [List.foldr_cons]
    cases i with
    | zero => simp only [List.getElem_cons_zero]; omega
    | succ j =>
      simp only [List.getElem_cons_succ]
      have := ih j (by simpa using hi); omega

private theorem foldr_min_mono_base (l : List Nat) {b1 b2 : Nat}
    (h : b1 ≤ b2) : l.foldr min b1 ≤ l.foldr min b2 := by
  induction l with
  | nil => exact h
  | cons x t ih => simp only [List.foldr_cons]; omega

private theorem lt_foldr_min_iff (l : List Nat) (b i : Nat) :
    i < l.foldr min b ↔ (i < b ∧ ∀ j (_ : j < l.length), i < l[j]) := by
  constructor
  · intro h
    refine ⟨Nat.lt_of_lt_of_le h (foldr_min_le_base l b), fun j hj => ?_⟩
    exact Nat.lt_of_lt_of_le h (foldr_min_le_getElem l b j hj)
  · rintro ⟨hb, hj⟩
    refine lt_foldr_min l b i hb (fun x hx => ?_)
    obtain ⟨j, hjlen, rfl⟩ := List.getElem_of_mem hx
    exact hj j hjlen

/-! ## Bounds on `delivered` -/

/-- User-level delivery never runs ahead of the log. -/
theorem delivered_le_log (u : User) : delivered u ≤ u.log.length :=
  foldr_min_le_base _ _

/-- User-level delivery never runs ahead of any single device. -/
theorem delivered_le_cursor (u : User) (d : Nat) (hd : d < u.cursors.length) :
    delivered u ≤ cursorOf u d := by
  rw [cursorOf, getD_of_lt u.cursors d _ hd]
  exact foldr_min_le_getElem _ _ _ hd

/-! ## The delivery predicate -/

/-- The message at log index `i` has been delivered to the user: it is a
real message (`i < log.length`) and every device has acknowledged past
it. Definitionally `i < delivered u`; the characterization below is the
content. -/
def IsDelivered (u : User) (i : Nat) : Prop := i < delivered u

/-- A message is delivered exactly when it exists and every device has
acknowledged past it. This is the delivery guarantee, stated. -/
theorem isDelivered_iff (u : User) (i : Nat) :
    IsDelivered u i ↔
      (i < u.log.length ∧ ∀ d (_ : d < u.cursors.length), i < cursorOf u d) := by
  unfold IsDelivered delivered
  rw [lt_foldr_min_iff]
  constructor
  · rintro ⟨hlog, hj⟩
    exact ⟨hlog, fun d hd => by
      rw [cursorOf, getD_of_lt u.cursors d _ hd]; exact hj d hd⟩
  · rintro ⟨hlog, hd⟩
    refine ⟨hlog, fun j hj => ?_⟩
    have := hd j hj
    rwa [cursorOf, getD_of_lt u.cursors j _ hj] at this

/-! ## Stability — once delivered, always delivered -/

/-- Appending a later message never un-delivers an earlier one. -/
theorem isDelivered_append (e : Envelope) (u : User) (i : Nat)
    (h : IsDelivered u i) : IsDelivered (append e u) i := by
  unfold IsDelivered delivered at h ⊢
  rw [append_cursors]
  refine Nat.lt_of_lt_of_le h (foldr_min_mono_base u.cursors ?_)
  simp only [append_log, List.length_append, List.length_cons, List.length_nil]
  omega

/-- Acknowledgments never un-deliver: a successful ack cannot lower the
delivered count, so anything delivered stays delivered. -/
theorem isDelivered_ack? {d n : Nat} {u u' : User} (hack : ack? d n u = some u')
    (i : Nat) (h : IsDelivered u i) : IsDelivered u' i :=
  Nat.lt_of_lt_of_le h (delivered_ack? hack)

/-- The freshly-appended message lands at index `old log length`, and
it is delivered exactly when every device (that exists after appending)
has acknowledged past it — the acquisition side of the lifecycle,
specialized to a just-sent message. -/
theorem appended_isDelivered_iff (e : Envelope) (u : User) :
    IsDelivered (append e u) u.log.length ↔
      ∀ d (_ : d < u.cursors.length), u.log.length < cursorOf (append e u) d := by
  rw [isDelivered_iff]
  simp only [append_log, append_cursors, List.length_append, List.length_cons,
    List.length_nil]
  constructor
  · rintro ⟨-, hd⟩; exact hd
  · intro hd; exact ⟨by omega, hd⟩

end Tacenta.User
