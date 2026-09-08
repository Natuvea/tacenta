import Verification.Generated.TacentaDirectoryCore
import Verification.Refinement
import Tacenta.Directory

/-!
# Refinement: the translated directory trust core against the spec

`spec/Tacenta/Directory.lean` proves trust on first use of a model
(`registerCore` / `rotateCore` over an abstract `Identity`). This file connects
the **actual Rust** trust core — `tacenta-directory-core`, translated to Lean by
Charon/Aeneas under `Generated/TacentaDirectoryCore.lean` — to that spec, under
the byte abstraction `absBytes` (translated `U8` list → spec `UInt8` list, reused
from `Verification.Refinement`). Each theorem states panic-freedom (the
translated function returns `ok`) and agreement with the spec model. The
security corollaries (`register_core_tofu_translated`,
`rotate_core_requires_binding_translated`) then hold of the shipped Rust, not
just of a hand-written model of it.

`Directory::register` / `rotate` (the `HashMap` wrappers) are outside the
translatable subset by construction; `spec/Tacenta/Directory.lean`'s
`register_matches_core` proves they apply this core faithfully, so the core
carries their trust.
-/

open Aeneas Aeneas.Std Aeneas.Std.WP

namespace Verification

/-- Abstraction: translated registration outcome → spec outcome. -/
def absReg : tacenta_directory_core.Registration → Tacenta.Directory.Registration
  | .Registered => .registered
  | .Refreshed => .refreshed
  | .Rejected => .rejected

/-- Abstraction: translated rotation outcome → spec outcome. -/
def absRot : tacenta_directory_core.Rotation → Tacenta.Directory.Rotation
  | .Rotated => .rotated
  | .Unregistered => .unregistered

/-- `absByte` is injective (it is `UInt8.ofNat` of a byte < 256). -/
private theorem absByte_inj {a b : Std.U8} (h : absByte a = absByte b) : a = b := by
  have ha : a.val < 256 := a.hBounds
  have hb : b.val < 256 := b.hBounds
  have : a.val = b.val := by
    simpa [absByte, UInt8.ext_iff, UInt8.toNat_ofNat, Nat.mod_eq_of_lt ha,
      Nat.mod_eq_of_lt hb] using h
  exact Std.U8.bv_eq_imp_eq a b (BitVec.toNat_injective this)

/-- `absBytes` is injective, so byte-list equality transfers across the
abstraction in both directions. -/
theorem absBytes_inj {l1 l2 : List Std.U8} : absBytes l1 = absBytes l2 ↔ l1 = l2 := by
  constructor
  · intro h
    exact List.map_injective_iff.mpr (fun _ _ => absByte_inj) h
  · intro h; rw [h]

/-- `allM` over a decidable elementwise equality decides list equality. Mirrors
the Aeneas library's private slice helper, for the `.eq` form the Vec instance
uses. -/
private theorem allM_eq_spec {α} (p : α → α → Result Bool)
    (hp : ∀ x y, p x y ⦃ b => b ↔ x = y ⦄) :
    ∀ (l1 l2 : List α), l1.length = l2.length →
      (List.allM (fun (xy : α × α) => p xy.1 xy.2) (List.zip l1 l2)) ⦃ b => b ↔ l1 = l2 ⦄ := by
  intro l1
  induction l1 with
  | nil =>
    intro l2 hlen
    have : l2 = [] := by cases l2 <;> simp_all
    subst this
    simp only [List.zip_nil_left, List.allM, pure, WP.spec_ok]
  | cons x xs ih =>
    intro l2 hlen
    cases l2 with
    | nil => simp at hlen
    | cons y ys =>
      simp only [List.length_cons, Nat.add_right_cancel_iff] at hlen
      simp only [List.zip_cons_cons, List.allM]
      apply spec_bind (hp x y)
      intro r hr
      cases r with
      | true =>
        have hxy : x = y := hr.mp rfl
        subst hxy
        apply spec_mono (ih ys hlen)
        intro b hb
        simp only [List.cons.injEq, true_and] at *
        exact hb
      | false =>
        simp only [pure, WP.spec_ok]
        have hne : x ≠ y := by intro h; have := hr.mpr h; simp at this
        simp [hne]

/-- The translated `Vec<u8>` `PartialEq::eq` decides byte-list equality. -/
theorem vec_eq_u8 (v0 v1 : alloc.vec.Vec Std.U8) :
    alloc.vec.partial_eq.PartialEqVec.eq core.cmp.PartialEqU8 v0 v1 ⦃ b => b ↔ v0.val = v1.val ⦄ := by
  unfold alloc.vec.partial_eq.PartialEqVec.eq
  by_cases hlen : v0.length = v1.length
  · simp only [hlen, ↓reduceIte]
    have hp : ∀ x y : Std.U8, core.cmp.PartialEqU8.eq x y ⦃ b => b ↔ x = y ⦄ := by
      intro x y
      simp only [core.cmp.impls.PartialEqU8.eq, liftFun2, WP.spec_ok]
      exact decide_eq_true_iff
    exact allM_eq_spec _ hp v0.val v1.val hlen
  · simp only [hlen, ↓reduceIte, WP.spec_ok]
    have hne : v0.val ≠ v1.val := fun h => hlen (congrArg List.length h)
    simp [hne]

/-- The translated Rust `register_core` never panics and agrees with the spec's
`registerCore` under the byte abstraction. -/
theorem register_core_refines (current : Option (alloc.vec.Vec Std.U8))
    (presented : alloc.vec.Vec Std.U8) :
    tacenta_directory_core.register_core current presented ⦃ r =>
      (absReg r.1, absBytes r.2.val) =
        Tacenta.Directory.registerCore (current.map (fun v => absBytes v.val)) (absBytes presented.val) ⦄ := by
  rcases current with _ | existing
  · unfold tacenta_directory_core.register_core
    simp only [WP.spec_ok, Option.map_none, Tacenta.Directory.registerCore, absReg]
  · unfold tacenta_directory_core.register_core
    simp only [Option.map_some]
    apply spec_bind (vec_eq_u8 existing presented)
    intro b hb
    cases b with
    | true =>
      have heq : existing.val = presented.val := hb.mp rfl
      simp only [↓reduceIte, WP.spec_ok, absReg, Tacenta.Directory.registerCore,
        if_pos (absBytes_inj.mpr heq)]
    | false =>
      have hne : existing.val ≠ presented.val := fun h => absurd (hb.mpr h) (by decide)
      rw [if_neg (show ¬(false = true) by decide)]
      simp only [WP.spec_ok, absReg, Tacenta.Directory.registerCore,
        if_neg (fun h => hne (absBytes_inj.mp h))]

/-- The translated Rust `rotate_core` never panics and agrees with the spec's
`rotateCore` under the byte abstraction. -/
theorem rotate_core_refines (current : Option (alloc.vec.Vec Std.U8))
    (newId : alloc.vec.Vec Std.U8) :
    tacenta_directory_core.rotate_core current newId ⦃ r =>
      (absRot r.1, (r.2).map (fun v => absBytes v.val)) =
        Tacenta.Directory.rotateCore (current.map (fun v => absBytes v.val)) (absBytes newId.val) ⦄ := by
  rcases current with _ | existing
  · unfold tacenta_directory_core.rotate_core
    simp only [WP.spec_ok, Option.map_none, Tacenta.Directory.rotateCore, absRot]
  · unfold tacenta_directory_core.rotate_core
    simp only [WP.spec_ok, Option.map_some, Tacenta.Directory.rotateCore, absRot]

/-! ## Security corollaries — on the shipped Rust trust core -/

/-- Trust on first use, inherited by the translated Rust: for a bound device
(`some existing`), `register_core` returns `ok` and the identity it leaves bound
is exactly the existing one — a different key cannot displace it. -/
theorem register_core_tofu_translated (existing presented : alloc.vec.Vec Std.U8) :
    tacenta_directory_core.register_core (some existing) presented ⦃ r =>
      absBytes r.2.val = absBytes existing.val ⦄ := by
  apply spec_mono (register_core_refines (some existing) presented)
  intro r hr
  have h2 := congrArg Prod.snd hr
  simp only [Option.map_some] at h2
  rw [Tacenta.Directory.registerCore_tofu] at h2
  exact h2

/-- The translated Rust `rotate_core` refuses an unbound device: it returns `ok`
with the `Unregistered` outcome and no binding. -/
theorem rotate_core_requires_binding_translated (newId : alloc.vec.Vec Std.U8) :
    tacenta_directory_core.rotate_core none newId ⦃ r =>
      absRot r.1 = Tacenta.Directory.Rotation.unregistered ∧ r.2 = none ⦄ := by
  simp only [tacenta_directory_core.rotate_core, WP.spec_ok, absRot, and_self]

end Verification
