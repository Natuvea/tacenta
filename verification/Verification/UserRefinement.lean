import Verification.Generated.TacentaState
import Tacenta.User

/-!
# Refinement: the translated multi-device user machine against the spec

Same pattern as the session machine: the generic translation is
instantiated at the specification's envelope type, the abstraction is
field projection (with cursors mapped to naturals), and the invariant
(`every cursor ≤ log length`) is carried as a hypothesis where the spec
carries it inside its structure.
-/

open Aeneas Aeneas.Std

set_option linter.unusedSimpArgs false

namespace Verification

/-- The translated generic user, at the spec's envelope type. -/
abbrev RUser := tacenta_state.user.User Tacenta.Wire.Envelope

/-- The state-machine invariant on the translated structure. -/
def UserInv (u : RUser) : Prop :=
  ∀ i (_ : i < u.cursors.val.length), u.cursors.val[i].val ≤ u.log.val.length

/-- Abstraction: translated user → spec user. -/
def absUser (u : RUser) (h : UserInv u) : Tacenta.User.User :=
  ⟨u.log.val, u.cursors.val.map UScalar.val, by
    intro i hi
    simp only [List.getElem_map]
    exact h i (by simpa using hi)⟩

private theorem specUser_ext {a b : Tacenta.User.User}
    (hl : a.log = b.log) (hc : a.cursors = b.cursors) : a = b := by
  cases a; cases b
  simp_all

private theorem ruser_ext {a b : RUser}
    (hl : a.log.val = b.log.val) (hc : a.cursors.val = b.cursors.val) :
    a = b := by
  cases a; cases b
  congr 1 <;> (apply Subtype.ext; assumption)

private theorem set_opt_none {α : Type} (l : List α) (i : Nat) :
    l.set_opt i none = l := by
  induction l generalizing i with
  | nil => rfl
  | cons a l ih =>
    cases i with
    | zero => simp [List.set_opt]
    | succ n => simp [List.set_opt, ih]

private theorem set_opt_some {α : Type} (l : List α) (i : Nat) (x : α) :
    l.set_opt i (some x) = l.set i x := by
  induction l generalizing i with
  | nil => rfl
  | cons a l ih =>
    cases i with
    | zero => simp [List.set_opt]
    | succ n => simp [List.set_opt, ih]

private theorem vec_index_usize_spec {α : Type} (v : alloc.vec.Vec α)
    (i : Usize) (h : i.val < v.val.length) :
    ∃ x, alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice α) v i =
      Result.ok x ∧ x = v.val[i.val] := by
  simp only [alloc.vec.Vec.index, core.slice.index.SliceIndexUsizeSlice,
    core.slice.index.Usize.index]
  obtain ⟨x, hx, hxval⟩ := WP.spec_imp_exists
    (Slice.index_usize_spec ↑v i (by scalar_tac))
  exact ⟨x, hx, by rw [hxval]⟩

/-- `User::new` refines the spec's initial user. -/
theorem user_new_refines :
    ∃ u : RUser,
      tacenta_state.user.User.new Tacenta.Wire.Envelope = Result.ok u ∧
      ∃ h : UserInv u, absUser u h = Tacenta.User.User.init := by
  refine ⟨_, rfl, ?_, ?_⟩
  · intro i hi
    simp at hi
  · apply specUser_ext <;> simp [absUser, Tacenta.User.User.init]

/-- `User::append` refines the spec's `append`. -/
theorem user_append_refines (u : RUser) (h : UserInv u)
    (e : Tacenta.Wire.Envelope) (hroom : u.log.val.length < Usize.max) :
    ∃ u' : RUser,
      tacenta_state.user.User.append u e = Result.ok u' ∧
      ∃ h' : UserInv u',
        absUser u' h' = Tacenta.User.append e (absUser u h) := by
  unfold tacenta_state.user.User.append
  obtain ⟨v, hv, hvval⟩ := WP.spec_imp_exists
    (alloc.vec.Vec.push_spec u.log e hroom)
  rw [hv]
  simp only [bind_ok, bind_tc_ok]
  refine ⟨_, rfl, ?_, ?_⟩
  · intro i hi
    show (u.cursors.val[i]).val ≤ v.val.length
    have := h i hi
    rw [hvval]
    simp only [List.length_append, List.length_cons, List.length_nil]
    omega
  · apply specUser_ext <;> simp [absUser, Tacenta.User.append, hvval]

/-- `User::link_device` refines the spec's `linkDevice`, and the
returned id is the new device's index. -/
theorem user_link_refines (u : RUser) (h : UserInv u)
    (hroom : u.cursors.val.length < Usize.max) :
    ∃ (d : Usize) (u' : RUser),
      tacenta_state.user.User.link_device u = Result.ok (d, u') ∧
      d.val = u.cursors.val.length ∧
      ∃ h' : UserInv u',
        absUser u' h' = Tacenta.User.linkDevice (absUser u h) := by
  unfold tacenta_state.user.User.link_device
  try dsimp only
  obtain ⟨v, hv, hvval⟩ := WP.spec_imp_exists
    (alloc.vec.Vec.push_spec u.cursors (alloc.vec.Vec.len u.log) hroom)
  rw [hv]
  simp only [bind_ok, bind_tc_ok]
  have hlen : (alloc.vec.Vec.len v).val = u.cursors.val.length + 1 := by
    rw [alloc.vec.Vec.len_val]
    simp [alloc.vec.Vec.length, hvval]
  obtain ⟨d, hd, hdval⟩ := WP.spec_imp_exists
    (Usize.sub_spec (x := alloc.vec.Vec.len v) (y := 1#usize)
      (by scalar_tac))
  rw [hd]
  simp only [bind_ok, bind_tc_ok]
  refine ⟨d, _, rfl, by scalar_tac, ?_, ?_⟩
  · intro i hi
    show (v.val[i]).val ≤ u.log.val.length
    simp only [hvval] at hi ⊢
    simp only [List.length_append, List.length_cons, List.length_nil] at hi
    by_cases hilt : i < u.cursors.val.length
    · rw [List.getElem_append_left hilt]
      exact h i hilt
    · rw [List.getElem_append_right (by omega)]
      have hz : i - u.cursors.val.length = 0 := by omega
      simp [hz, alloc.vec.Vec.len_val, alloc.vec.Vec.length]
  · apply specUser_ext
    · simp [absUser, Tacenta.User.linkDevice]
    · simp [absUser, Tacenta.User.linkDevice, hvval,
        alloc.vec.Vec.len_val, alloc.vec.Vec.length]

/-- `User::device_pending` never panics on invariant-satisfying states
and returns exactly the spec's per-device pending list — including for
unknown devices. -/
theorem user_device_pending_refines (u : RUser) (h : UserInv u)
    (d : Usize) :
    ∃ sl : Slice Tacenta.Wire.Envelope,
      tacenta_state.user.User.device_pending u d = Result.ok sl ∧
      sl.val = Tacenta.User.devicePending (absUser u h) d.val := by
  unfold tacenta_state.user.User.device_pending
  try dsimp only
  by_cases hd : d.val < u.cursors.val.length
  · rw [if_pos (by scalar_tac)]
    obtain ⟨c, hc, hcval⟩ := vec_index_usize_spec u.cursors d (by scalar_tac)
    rw [hc]
    simp only [bind_ok, bind_tc_ok]
    obtain ⟨sl, hsl, hslval, -⟩ := WP.spec_imp_exists
      (alloc.vec.Vec.index_RangeFrom_spec u.log ⟨c⟩ (by
        show c.val ≤ _
        rw [hcval]
        exact h d.val hd))
    refine ⟨sl, hsl, ?_⟩
    rw [hslval, hcval]
    simp [Tacenta.User.devicePending, Tacenta.User.cursorOf, absUser,
      List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hd,
      List.getElem?_map]
  · rw [if_neg (by scalar_tac)]
    simp only [bind_ok, bind_tc_ok]
    obtain ⟨sl, hsl, hslval, -⟩ := WP.spec_imp_exists
      (alloc.vec.Vec.index_RangeFrom_spec u.log ⟨alloc.vec.Vec.len u.log⟩
        (by show (alloc.vec.Vec.len u.log).val ≤ _; scalar_tac))
    refine ⟨sl, hsl, ?_⟩
    rw [hslval]
    have hnone : (u.cursors.val.map UScalar.val)[d.val]? = none :=
      List.getElem?_eq_none (by simp; omega)
    simp [Tacenta.User.devicePending, Tacenta.User.cursorOf, absUser,
      List.getD_eq_getElem?_getD, hnone, alloc.vec.Vec.len_val,
      alloc.vec.Vec.length]

private theorem foldr_min_le_base (l : List Nat) (b : Nat) :
    l.foldr min b ≤ b := by
  induction l with
  | nil => exact Nat.le_refl b
  | cons x l ih =>
    simp only [List.foldr_cons]
    omega

private theorem foldr_min_base (a b : Nat) (l : List Nat) :
    l.foldr min (min a b) = min a (l.foldr min b) := by
  induction l with
  | nil => rfl
  | cons x l ih =>
    simp only [List.foldr_cons, ih]
    omega

/-- The delivered loop: folds min over the remaining cursors. -/
private theorem delivered_loop_spec (v : alloc.vec.Vec Std.Usize)
    (m i : Std.Usize) (hi : i.val ≤ v.val.length) :
    tacenta_state.user.User.delivered_loop v m i ⦃ r =>
      r.val = ((v.val.drop i.val).map UScalar.val).foldr min m.val ⦄ := by
  obtain ⟨lv, hlv⟩ := v
  simp only at hi ⊢
  unfold tacenta_state.user.User.delivered_loop
  apply Std.loop.spec_decr_nat
    (measure := fun p => lv.length - p.2.val)
    (inv := fun p => p.2.val ≤ lv.length ∧
      ((lv.drop p.2.val).map UScalar.val).foldr min p.1.val =
        ((lv.drop i.val).map UScalar.val).foldr min m.val)
  · rintro ⟨m1, i1⟩ ⟨hle, heq⟩
    simp only at hle heq
    unfold tacenta_state.user.User.delivered_loop.body
    try dsimp only
    by_cases hlt : i1.val < lv.length
    · rw [if_pos (by scalar_tac)]
      obtain ⟨c, hc, hcval⟩ := vec_index_usize_spec ⟨lv, hlv⟩ i1
        (by simpa using hlt)
      rw [hc, bind_tc_ok]
      beta_reduce
      simp only at hcval
      have hdrop : lv.drop i1.val = lv[i1.val] :: lv.drop (i1.val + 1) :=
        List.drop_eq_getElem_cons hlt
      obtain ⟨i2, hi2, hi2val⟩ := WP.spec_imp_exists
        (Usize.add_spec (x := i1) (y := 1#usize) (by scalar_tac))
      by_cases hcm : c.val < m1.val
      · rw [if_pos (by scalar_tac), bind_tc_ok]
        beta_reduce
        rw [hi2, bind_tc_ok]
        beta_reduce
        simp only [WP.spec_ok]
        refine ⟨⟨by scalar_tac, ?_⟩, by scalar_tac⟩
        have h1v : (1#usize).val = 1 := by scalar_tac
        have hcval' : c.val = (lv[i1.val]).val := by rw [hcval]
        rw [← heq, hdrop, hi2val]
        simp only [List.map_cons, List.foldr_cons, hcval, h1v]
        have hmin : min (lv[i1.val]).val m1.val = (lv[i1.val]).val :=
          Nat.min_eq_left (by omega)
        have hthis := foldr_min_base (lv[i1.val]).val m1.val
          ((lv.drop (i1.val + 1)).map UScalar.val)
        rw [hmin] at hthis
        omega
      · rw [if_neg (by scalar_tac), bind_tc_ok]
        beta_reduce
        rw [hi2, bind_tc_ok]
        beta_reduce
        simp only [WP.spec_ok]
        refine ⟨⟨by scalar_tac, ?_⟩, by scalar_tac⟩
        have h1v : (1#usize).val = 1 := by scalar_tac
        have hcval' : c.val = (lv[i1.val]).val := by rw [hcval]
        rw [← heq, hdrop, hi2val]
        simp only [List.map_cons, List.foldr_cons, hcval, h1v]
        have hble := foldr_min_le_base
          ((lv.drop (i1.val + 1)).map UScalar.val) m1.val
        omega
    · rw [if_neg (by scalar_tac)]
      simp only [WP.spec_ok]
      rw [← heq, List.drop_eq_nil_of_le (by omega)]
      rfl
  · exact ⟨hi, rfl⟩

/-- `User::delivered` never panics and returns exactly the spec's
user-level delivered count. -/
theorem user_delivered_refines (u : RUser) (h : UserInv u) :
    ∃ r : Usize,
      tacenta_state.user.User.delivered u = Result.ok r ∧
      r.val = Tacenta.User.delivered (absUser u h) := by
  unfold tacenta_state.user.User.delivered
  try dsimp only
  obtain ⟨r, hr, hrval⟩ := WP.spec_imp_exists
    (delivered_loop_spec u.cursors (alloc.vec.Vec.len u.log) 0#usize
      (by scalar_tac))
  refine ⟨r, hr, ?_⟩
  rw [hrval]
  simp [Tacenta.User.delivered, absUser, alloc.vec.Vec.len_val,
    alloc.vec.Vec.length]

private theorem getD_of_lt' {α : Type} (l : List α) (i : Nat) (fb : α)
    (h : i < l.length) : l.getD i fb = l[i] := by
  simp [List.getD, List.getElem?_eq_getElem h]

/-- `User::ack` refines the spec's `ack?` — accepted exactly when the
spec accepts, same resulting state; rejections (including unknown
devices) leave the state untouched. -/
theorem user_ack_refines (u : RUser) (h : UserInv u) (d n : Usize) :
    ∃ (b : Bool) (u' : RUser),
      tacenta_state.user.User.ack u d n = Result.ok (b, u') ∧
      ∃ h' : UserInv u',
        match Tacenta.User.ack? d.val n.val (absUser u h) with
        | some t => b = true ∧ absUser u' h' = t
        | none => b = false ∧ u' = u := by
  unfold tacenta_state.user.User.ack
  unfold Tacenta.User.ack?
  by_cases hd : d.val < u.cursors.val.length
  · rw [if_pos (by scalar_tac)]
    simp only [alloc.vec.Vec.index_slice_index]
    obtain ⟨c, hc, hcval⟩ := WP.spec_imp_exists
      (alloc.vec.Vec.index_usize_spec u.cursors d (by scalar_tac))
    rw [hc]
    simp only [bind_ok, bind_tc_ok]
    have hdc : d.val < (absUser u h).cursors.length := by
      simpa [absUser] using hd
    rw [dif_pos hdc]
    have hcursd : (absUser u h).cursors[d.val]'hdc = c.val := by
      simp only [absUser, List.getElem_map]; rw [hcval]
    by_cases hc1 : c.val < n.val
    · by_cases hc2 : n.val ≤ u.log.val.length
      · rw [if_pos (by scalar_tac), if_pos (by scalar_tac)]
        simp only [alloc.vec.Vec.index_mut_slice_index]
        obtain ⟨p, hp, hpval⟩ := WP.spec_imp_exists
          (alloc.vec.Vec.index_mut_usize_spec u.cursors d (by scalar_tac))
        rw [hp]
        simp only [bind_ok, bind_tc_ok]
        rw [dif_pos (show (absUser u h).cursors[d.val]'hdc < n.val ∧
            n.val ≤ (absUser u h).log.length from
          ⟨by rw [hcursd]; exact hc1, by simpa [absUser] using hc2⟩)]
        refine ⟨true, _, rfl, ?_, rfl, specUser_ext rfl ?_⟩
        · intro i hi
          simp only [hpval.2, alloc.vec.Vec.set] at hi ⊢
          rw [List.length_set] at hi
          by_cases hid : i = d.val
          · subst hid; rw [List.getElem_set_self]; exact hc2
          · rw [List.getElem_set_ne (by omega)]; exact h i hi
        · simp only [absUser, hpval.2, alloc.vec.Vec.set, List.map_set]
      · rw [if_pos (by scalar_tac), if_neg (by scalar_tac)]
        rw [dif_neg ?nc]
        case nc =>
          rw [hcursd]; rintro ⟨-, hn⟩; exact hc2 (by simpa [absUser] using hn)
        exact ⟨false, _, rfl, h, rfl, rfl⟩
    · rw [if_neg (by scalar_tac)]
      rw [dif_neg ?nc]
      case nc => rw [hcursd]; rintro ⟨hlt, -⟩; exact hc1 hlt
      exact ⟨false, _, rfl, h, rfl, rfl⟩
  · rw [if_neg (by scalar_tac),
      dif_neg (by simpa [absUser] using hd)]
    exact ⟨false, _, rfl, h, rfl, rfl⟩

end Verification
