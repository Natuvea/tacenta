import Verification.Refinement
import Verification.StateRefinement
import Verification.UserRefinement
import Verification.StreamRefinement
import Verification.DirectoryRefinement

/-!
# Axiom audit for the refinement theorems -- machine-enforced

This file pins the refinement theorems' axiom baseline the same way
`../spec/Tacenta/Assurance.lean` does for the spec-level theorems. `#guard_msgs`
pins the exact axiom set each headline refinement theorem depends on, so a
`sorry` (which would add `sorryAx`) or any unexpected axiom fails this file and
the verification build, rather than widening the trusted base unnoticed.

The baseline is Lean's three standard classical axioms -- `propext`,
`Classical.choice`, `Quot.sound` -- and several theorems use a strict subset.
The three wire-decode theorems additionally carry two `bv_decide` byte-order
axioms (`fromBE2`/`fromBE4`), which is the compiled-evaluator dependency the TCB
names; both are standard and neither is a soundness risk. `sorryAx` is the one
this exists to catch. `whitespace := lax` lets the expected set be written on one
line while Lean's pretty-printer wraps the actual; it ignores whitespace only,
never an added or removed axiom.
-/

-- Wire codec: the round trip, the kind byte, and the decoder.

/-- info: 'Verification.encode_decode_roundtrip' depends on axioms: [propext, Classical.choice, Quot.sound, Verification.fromBE2_toNat._native.bv_decide.ax_1_9✝, Verification.fromBE4_toNat._native.bv_decide.ax_1_9✝] -/
#guard_msgs (whitespace := lax) in #print axioms Verification.encode_decode_roundtrip

/-- info: 'Verification.decode.spec' depends on axioms: [propext, Classical.choice, Quot.sound, Verification.fromBE2_toNat._native.bv_decide.ax_1_9✝, Verification.fromBE4_toNat._native.bv_decide.ax_1_9✝] -/
#guard_msgs (whitespace := lax) in #print axioms Verification.decode.spec

/-- info: 'Verification.to_byte_refines' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Verification.to_byte_refines

/-- info: 'Verification.from_byte_refines' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Verification.from_byte_refines

-- Delivery: the single-device Session machine.

/-- info: 'Verification.session_new_refines' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Verification.session_new_refines

/-- info: 'Verification.session_append_refines' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Verification.session_append_refines

/-- info: 'Verification.session_ack_refines' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Verification.session_ack_refines

/-- info: 'Verification.session_pending_refines' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Verification.session_pending_refines

-- Delivery: the multi-device User machine.

/-- info: 'Verification.user_new_refines' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms Verification.user_new_refines

/-- info: 'Verification.user_append_refines' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Verification.user_append_refines

/-- info: 'Verification.user_link_refines' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Verification.user_link_refines

/-- info: 'Verification.user_device_pending_refines' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Verification.user_device_pending_refines

/-- info: 'Verification.user_delivered_refines' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Verification.user_delivered_refines

/-- info: 'Verification.user_ack_refines' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Verification.user_ack_refines

-- Directory trust core: register / rotate refinement and the trust corollaries.

/-- info: 'Verification.register_core_refines' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Verification.register_core_refines

/-- info: 'Verification.rotate_core_refines' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms Verification.rotate_core_refines

/-- info: 'Verification.register_core_tofu_translated' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Verification.register_core_tofu_translated

/-- info: 'Verification.rotate_core_requires_binding_translated' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms Verification.rotate_core_requires_binding_translated

-- Streamed delivery decode.

/-- info: 'Verification.decode_one.spec' depends on axioms: [propext, Classical.choice, Quot.sound, Verification.fromBE2_toNat._native.bv_decide.ax_1_9✝, Verification.fromBE4_toNat._native.bv_decide.ax_1_9✝] -/
#guard_msgs (whitespace := lax) in #print axioms Verification.decode_one.spec
