import Tacenta.Directory
import Tacenta.Accounts
import Tacenta.RelayAuth
import Tacenta.Ratchet
import Tacenta.Stream

/-!
# Axiom audit — machine-enforced

The verification TCB (`docs/verification-tcb.md`) claims the trust proofs use no
`sorry` and no axioms beyond Lean's standard, uncontroversial ones. This file
**enforces** that claim rather than asserting it: `#guard_msgs` pins the exact
axiom set each trust theorem depends on, so if a `sorry` ever slipped in (which
would add `sorryAx`) or a proof pulled in an unexpected axiom, this file — and
the CI `spec` build — would fail.

The state-machine theorems below depend on at most `propext` (propositional
extensionality, a standard Lean axiom). The **wire** theorems additionally
depend on `Quot.sound`, which arrives through the standard `List` and `Nat`
libraries rather than from anything this repository writes. Both are among
Lean's four standard axioms; neither is a soundness risk.

The one that matters is the fourth. **`sorryAx` is what this file exists to
catch**, because a `sorry` makes a theorem prove nothing while still reading as
proved; pinning the axiom set turns that into a build failure.
-/

-- Directory: trust on first use, framing, and rotation.

/-- info: 'Tacenta.Directory.register_binds_fresh' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Directory.register_binds_fresh

/-- info: 'Tacenta.Directory.register_same_keeps' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Directory.register_same_keeps

/-- info: 'Tacenta.Directory.register_tofu' does not depend on any axioms -/
#guard_msgs in #print axioms Tacenta.Directory.register_tofu

/-- info: 'Tacenta.Directory.register_frames' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Directory.register_frames

/-- info: 'Tacenta.Directory.rotate_requires_binding' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Directory.rotate_requires_binding

/-- info: 'Tacenta.Directory.rotate_rebinds' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Directory.rotate_rebinds

/-- info: 'Tacenta.Directory.rotation_unauthorized_frames' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Directory.rotation_unauthorized_frames

/-- info: 'Tacenta.Directory.rotation_authorized_rebinds' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Directory.rotation_authorized_rebinds

/-- info: 'Tacenta.Directory.rotation_auth_requires_binding' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Directory.rotation_auth_requires_binding

/-- info: 'Tacenta.Directory.recovery_unauthorized_frames' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Directory.recovery_unauthorized_frames

/-- info: 'Tacenta.Directory.recovery_authorized_rebinds' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Directory.recovery_authorized_rebinds

/-- info: 'Tacenta.Directory.recovery_requires_key' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Directory.recovery_requires_key

-- Directory: the pure trust core (the Charon/Aeneas refinement target) and
-- the theorem that the container faithfully applies it.

/-- info: 'Tacenta.Directory.registerCore_tofu' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Directory.registerCore_tofu

/-- info: 'Tacenta.Directory.registerCore_binds_fresh' does not depend on any axioms -/
#guard_msgs in #print axioms Tacenta.Directory.registerCore_binds_fresh

/-- info: 'Tacenta.Directory.rotateCore_requires_binding' does not depend on any axioms -/
#guard_msgs in #print axioms Tacenta.Directory.rotateCore_requires_binding

/-- info: 'Tacenta.Directory.rotateCore_rebinds' does not depend on any axioms -/
#guard_msgs in #print axioms Tacenta.Directory.rotateCore_rebinds

/-- info: 'Tacenta.Directory.register_matches_core' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Directory.register_matches_core

-- Accounts: session validation and provisioning anti-impersonation.

/-- info: 'Tacenta.Accounts.validate_issued' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Accounts.validate_issued

/-- info: 'Tacenta.Accounts.issue_frames' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Accounts.issue_frames

/-- info: 'Tacenta.Accounts.unissued_validates_none' does not depend on any axioms -/
#guard_msgs in #print axioms Tacenta.Accounts.unissued_validates_none

/-- info: 'Tacenta.Accounts.provision_handle_from_session' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Accounts.provision_handle_from_session

/-- info: 'Tacenta.Accounts.provision_handle_none' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Accounts.provision_handle_none

/-- info: 'Tacenta.Accounts.signUp_binds' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Accounts.signUp_binds

/-- info: 'Tacenta.Accounts.signUp_rejects_taken' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Accounts.signUp_rejects_taken

/-- info: 'Tacenta.Accounts.signUp_frames' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Accounts.signUp_frames

/-- info: 'Tacenta.Accounts.tenant_isolation' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Accounts.tenant_isolation

-- RelayAuth: per-device authorization.

/-- info: 'Tacenta.RelayAuth.poll_own' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.RelayAuth.poll_own

/-- info: 'Tacenta.RelayAuth.poll_only_own' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.RelayAuth.poll_only_own

/-- info: 'Tacenta.RelayAuth.ack_own_advances' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.RelayAuth.ack_own_advances

/-- info: 'Tacenta.RelayAuth.ack_only_own' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.RelayAuth.ack_only_own

/-- info: 'Tacenta.RelayAuth.ack_frames_others' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.RelayAuth.ack_frames_others

-- Protocol layer: PQXDH agreement and the ratchet ping-pong (spec-only;
-- tacenta-core is the implementation).

/-- info: 'Tacenta.Handshake.pqxdh_agree' does not depend on any axioms -/
#guard_msgs in #print axioms Tacenta.Handshake.pqxdh_agree

/-- info: 'Tacenta.Ratchet.ratchet_sync' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Ratchet.ratchet_sync

/-- info: 'Tacenta.Ratchet.init_facing' does not depend on any axioms -/
#guard_msgs in #print axioms Tacenta.Ratchet.init_facing

/-- info: 'Tacenta.Ratchet.step_idx' does not depend on any axioms -/
#guard_msgs in #print axioms Tacenta.Ratchet.step_idx


-- Wire format: the round trips, and the canonicity direction that makes an
-- authenticator over exact bytes mean anything (decision 0061's
-- contract item 6). These use `Quot.sound` as well as `propext`; see the
-- header for why that is not a finding.

/-- info: 'Tacenta.Wire.decode_encode' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Tacenta.Wire.decode_encode

/-- info: 'Tacenta.Wire.encode_decode' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Tacenta.Wire.encode_decode

/-- info: 'Tacenta.Wire.encode_reassembles' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Tacenta.Wire.encode_reassembles

/-- info: 'Tacenta.Wire.decodeStream_encodeStream' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Tacenta.Wire.decodeStream_encodeStream

/-- info: 'Tacenta.Wire.encodeStream_decodeStream' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Tacenta.Wire.encodeStream_decodeStream

/-- info: 'Tacenta.Wire.decodeOne_canonical' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Tacenta.Wire.decodeOne_canonical

/-- info: 'Tacenta.Wire.decodeOne_reassembles' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Tacenta.Wire.decodeOne_reassembles

/-- info: 'Tacenta.Wire.Kind.toByte_ofByte?' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Wire.Kind.toByte_ofByte?
