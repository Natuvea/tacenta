import Tacenta.Directory
import Tacenta.Accounts
import Tacenta.RelayAuth
import Tacenta.Ratchet
import Tacenta.Stream
import Tacenta.Group

/-!
# Axiom audit of the listed theorems

The verification TCB (`docs/verification-tcb.md`) claims the trust proofs use no
`sorry` and no axioms beyond Lean's standard, uncontroversial ones. This file
checks that claim **for the theorems it lists**: `#guard_msgs` pins the exact
axiom set each listed theorem depends on, so if a `sorry` slipped into one of
them (which would add `sorryAx`), or a proof pulled in an unexpected axiom, this
file, and with it the CI `spec` build, would fail.

What that covers, and what it does not. It covers the listed theorems only: 61
`#print axioms` lines, where `spec/Tacenta` declares 104 `theorem`s, and nothing
checks that a new theorem is added to the list. It sees axioms and not
statements: a theorem weakened to `True`, or to a conjunction with `True`, with
the same axiom set passes. A new theorem that is not listed and is built on an
added axiom builds green, and so does `native_decide` in an `example`. A `sorry`
in an unlisted theorem is not caught here either; CI catches it by searching the
build log for `declaration uses`.

The state-machine theorems below depend on at most `propext` (propositional
extensionality, a standard Lean axiom). The **wire** theorems, and six of the
eighteen bounded group-policy theorems, additionally depend on `Quot.sound`, which
arrives through the standard `List` and `Nat` libraries rather than from
anything this repository writes. Both are among Lean's three standard axioms
(`propext`, `Classical.choice` and `Quot.sound`); neither is a soundness risk.

What this file exists to catch is not among them. **`sorryAx` is what a `sorry`
adds**, and a `sorry` makes a theorem prove nothing while still reading as
proved; pinning the axiom set turns that into a build failure for a listed
theorem.
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

-- Bounded group policy (decision 0137): the eighteen theorems of `Group.lean`,
-- four of them from the first cut and fourteen stating its guards for every
-- state. The model, the trace vectors it generates and these theorems have had
-- no human review; this pins only the axioms they rest on.

/-- info: 'Tacenta.Group.genesis_has_only_its_authority' does not depend on any axioms -/
#guard_msgs in #print axioms Tacenta.Group.genesis_has_only_its_authority

/-- info: 'Tacenta.Group.admission_follows_its_source' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Tacenta.Group.admission_follows_its_source

/-- info: 'Tacenta.Group.invitation_does_not_advance_the_revision' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Group.invitation_does_not_advance_the_revision

/-- info: 'Tacenta.Group.different_commitment_is_a_conflict' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Tacenta.Group.different_commitment_is_a_conflict

/-- info: 'Tacenta.Group.only_the_authority_invites' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Group.only_the_authority_invites

/-- info: 'Tacenta.Group.only_the_authority_admits' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Group.only_the_authority_admits

/-- info: 'Tacenta.Group.only_the_authority_revokes' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Group.only_the_authority_revokes

/-- info: 'Tacenta.Group.only_the_authority_removes' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Group.only_the_authority_removes

/-- info: 'Tacenta.Group.only_the_authority_closes' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Group.only_the_authority_closes

/-- info: 'Tacenta.Group.removal_needs_a_current_member' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Group.removal_needs_a_current_member

/-- info: 'Tacenta.Group.revocation_needs_a_live_invitation' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Group.revocation_needs_a_live_invitation

/-- info: 'Tacenta.Group.closure_closes_the_group' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Group.closure_closes_the_group

/-- info: 'Tacenta.Group.a_closed_group_refuses_every_operation' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Group.a_closed_group_refuses_every_operation

/-- info: 'Tacenta.Group.successor_revisions_stay_usable' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Tacenta.Group.successor_revisions_stay_usable

/-- info: 'Tacenta.Group.repeat_acceptance_changes_nothing' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Tacenta.Group.repeat_acceptance_changes_nothing

/-- info: 'Tacenta.Group.admission_records_its_successor' depends on axioms: [propext] -/
#guard_msgs in #print axioms Tacenta.Group.admission_records_its_successor

/-- info: 'Tacenta.Group.foreign_control_is_a_conflict' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Tacenta.Group.foreign_control_is_a_conflict

/-- info: 'Tacenta.Group.next_control_extends_the_head' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Tacenta.Group.next_control_extends_the_head
