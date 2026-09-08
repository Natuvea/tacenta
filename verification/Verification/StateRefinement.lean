import Verification.Generated.TacentaState
import Tacenta.Session

/-!
# Refinement: the translated session machine against the spec

The Rust `Session<T>` is generic, so its translation is polymorphic —
which lets us instantiate it directly at the specification's envelope
type. The abstraction function is then just field projection, plus the
invariant (`cursor ≤ log.length`) that the spec carries inside its
structure and the Rust maintains by construction.
-/

open Aeneas Aeneas.Std

set_option linter.unusedSimpArgs false

namespace Verification

/-- The translated generic session, at the spec's envelope type. -/
abbrev RSession := tacenta_state.session.Session Tacenta.Wire.Envelope

/-- The state-machine invariant, as a predicate on the translated
structure (the spec carries it inside `Session.valid`; the Rust
maintains it by construction, which the theorems below prove). -/
def SessionInv (s : RSession) : Prop :=
  s.cursor.val ≤ s.log.val.length

/-- Abstraction: translated session → spec session. -/
def absSession (s : RSession) (h : SessionInv s) : Tacenta.Session.Session :=
  ⟨s.log.val, s.cursor.val, h⟩

private theorem specSession_ext {a b : Tacenta.Session.Session}
    (hl : a.log = b.log) (hc : a.cursor = b.cursor) : a = b := by
  cases a; cases b
  simp_all

/-- `Session::new` never panics, establishes the invariant, and
abstracts to the spec's initial session. -/
theorem session_new_refines :
    ∃ s : RSession,
      tacenta_state.session.Session.new Tacenta.Wire.Envelope =
        Result.ok s ∧
      ∃ h : SessionInv s,
        absSession s h = Tacenta.Session.Session.init := by
  refine ⟨_, rfl, ?_, ?_⟩
  · show (0#usize).val ≤ _
    simp [SessionInv]
  · apply specSession_ext <;> simp [absSession, Tacenta.Session.Session.init]

/-- `Session::append` never panics (while the log is below the address
space), preserves the invariant, and abstracts to the spec's
`append`. -/
theorem session_append_refines (s : RSession) (h : SessionInv s)
    (e : Tacenta.Wire.Envelope) (hroom : s.log.val.length < Usize.max) :
    ∃ s' : RSession,
      tacenta_state.session.Session.append s e = Result.ok s' ∧
      ∃ h' : SessionInv s',
        absSession s' h' = Tacenta.Session.append e (absSession s h) := by
  unfold tacenta_state.session.Session.append
  obtain ⟨v, hv, hvval⟩ := WP.spec_imp_exists (alloc.vec.Vec.push_spec s.log e hroom)
  rw [hv]
  simp only [bind_ok, bind_tc_ok]
  refine ⟨_, rfl, ?_, ?_⟩
  · show s.cursor.val ≤ v.val.length
    rw [hvval]
    simp only [List.length_append, List.length_cons, List.length_nil]
    have := h
    simp [SessionInv] at this
    omega
  · apply specSession_ext <;>
      simp [absSession, Tacenta.Session.append, hvval]

/-- `Session::ack` never panics, preserves the invariant, and agrees
with the spec's `ack?` — accepted exactly when the spec accepts, with
the same resulting state; rejected acks leave the state untouched. -/
theorem session_ack_refines (s : RSession) (h : SessionInv s) (n : Usize) :
    ∃ (b : Bool) (s' : RSession),
      tacenta_state.session.Session.ack s n = Result.ok (b, s') ∧
      ∃ h' : SessionInv s',
        match Tacenta.Session.ack? n.val (absSession s h) with
        | some t => b = true ∧ absSession s' h' = t
        | none => b = false ∧ s' = s := by
  unfold tacenta_state.session.Session.ack
  unfold Tacenta.Session.ack?
  by_cases hc1 : s.cursor.val < n.val
  · by_cases hc2 : n.val ≤ s.log.val.length
    · rw [if_pos (by scalar_tac), if_pos (by scalar_tac)]
      refine ⟨true, _, rfl, ?_, ?_⟩
      · show n.val ≤ s.log.val.length
        exact hc2
      · rw [dif_pos ⟨hc1, hc2⟩]
        exact ⟨rfl, specSession_ext (by simp [absSession]) rfl⟩
    · rw [if_pos (by scalar_tac), if_neg (by scalar_tac)]
      refine ⟨false, s, rfl, h, ?_⟩
      rw [dif_neg (by simp [absSession]; omega)]
      exact ⟨rfl, rfl⟩
  · rw [if_neg (by scalar_tac)]
    refine ⟨false, s, rfl, h, ?_⟩
    rw [dif_neg (by simp [absSession]; omega)]
    exact ⟨rfl, rfl⟩

/-- `Session::pending` never panics on any state satisfying the
invariant, and returns exactly the spec's pending list. -/
theorem session_pending_refines (s : RSession) (h : SessionInv s) :
    ∃ sl : Slice Tacenta.Wire.Envelope,
      tacenta_state.session.Session.pending s = Result.ok sl ∧
      sl.val = Tacenta.Session.pending (absSession s h) := by
  unfold tacenta_state.session.Session.pending
  obtain ⟨sl, hsl, hslval, -⟩ := WP.spec_imp_exists
    (alloc.vec.Vec.index_RangeFrom_spec s.log ⟨s.cursor⟩ (by
      show s.cursor.val ≤ _
      simpa [SessionInv] using h))
  refine ⟨sl, hsl, ?_⟩
  rw [hslval]
  rfl

end Verification
