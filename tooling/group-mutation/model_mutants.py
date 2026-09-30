"""Single-change mutants of the Lean group model, for tooling/group-mutation/mutate_model.py.

Each mutant replaces one piece of text in `spec/Tacenta/Group.lean` and is meant
to change what the model does. `desc` says what the change is. The set is a
sample chosen by a reviewer who read the model, not a complete enumeration of
its guards, so a run that kills all of it would show that these changes are
noticed and would not show that every change is. One entry is marked
`equivalent`: the change cannot be observed while the inputs stay in the range
the model is used in, and a survivor of that kind is expected.

The ids are this file's own (`LM`, for Lean model). They are not the `M###` ids
that some test comments cite, whose lists are not kept in this repository.
"""

FILE = "spec/Tacenta/Group.lean"
MODEL_MUTATIONS = []


def add(mid, old, new, desc, **kw):
    MODEL_MUTATIONS.append(dict(id=mid, file=FILE, old=old, new=new, desc=desc, **kw))


add("LM01", "if !active s || actor != s.authority || now >= expiresAt ||", "if !active s || actor != s.authority || now > expiresAt ||", "invite?: the expiry boundary is `>` instead of `>=` (decision 0137, item 19)")
add("LM02", "        observedRevision != invitation.sourceRevision then none", "        false then none", "accept?: the observed revision is not checked")
add("LM03", "      | .pending =>\n        if now >= invitation.expiresAt then none", "      | .pending =>\n        if now > invitation.expiresAt then none", "accept?: the expiry boundary of a pending invitation is `>`")
add("LM04", "      | .acceptedPendingAdmission =>\n        if now >= invitation.expiresAt then none else some s", "      | .acceptedPendingAdmission =>\n        some s", "accept?: a repeated acceptance ignores expiry")
add("LM05", "    if actor != s.authority || now >= invitation.expiresAt ||\n        invitation.status", "    if actor != s.authority ||\n        invitation.status", "admit?: expiry is not checked")
add("LM06", "invitation.status != .acceptedPendingAdmission || memberPresent", "false || memberPresent", "admit?: a pending or revoked invitation can be admitted")
add("LM07", "        identityPresent invitation.target s || s.roster.length >= maxMembers then none\n    else\n      let updated", "        s.roster.length >= maxMembers then none\n    else\n      let updated", "admit?: the second-device test (`identityPresent`) is dropped; the exact-member test stays")
add("LM08", "identityPresent invitation.target s || s.roster.length >= maxMembers then none\n    else\n      let updated", "identityPresent invitation.target s then none\n    else\n      let updated", "admit?: the eight-member cap is dropped")
add("LM09", "      identityPresent target s || (invitationAt? id s.invitations).isSome ||", "      (invitationAt? id s.invitations).isSome ||", "invite?: the second-device test is dropped")
add("LM10", "(invitationAt? id s.invitations).isSome ||\n      s.roster.length >= maxMembers then none", "(invitationAt? id s.invitations).isSome then none", "invite?: the eight-member cap is dropped")
add("LM11", "identityPresent target s || (invitationAt? id s.invitations).isSome ||", "identityPresent target s ||", "invite?: a duplicate invitation id is accepted")
add("LM12", "if !active s || actor != s.authority || now >= expiresAt ||", "if !active s || now >= expiresAt ||", "invite?: any actor may invite")
add("LM13", "    if actor != s.authority || !active s ||\n        !(invitation.status == .pending || invitation.status == .acceptedPendingAdmission) then none", "    if actor != s.authority || !active s ||\n        !(invitation.status == .pending || invitation.status == .acceptedPendingAdmission || invitation.status == .revoked) then none", "revoke?: a repeat revoke is accepted (decision 0137, item 4)")
add("LM14", "if actor != s.authority || target == s.authority || !memberPresent target s then none", "if actor != s.authority || !memberPresent target s then none", "remove?: the authority can be removed")
add("LM15", "if actor != s.authority || target == s.authority || !memberPresent target s then none", "if actor != s.authority || target == s.authority then none", "remove?: a non-member can be removed (decision 0137, item 3)")
add("LM16", "if actor != s.authority || target == s.authority || !memberPresent target s then none", "if target == s.authority || !memberPresent target s then none", "remove?: any actor may remove")
add("LM17", "      some { withRevision with closed := true }", "      some { withRevision with closed := false }", "close?: the group is not closed")
add("LM18", "    if actor != s.authority || now >= invitation.expiresAt ||", "    if now >= invitation.expiresAt ||", "admit?: any actor may admit")
add("LM19", "def maxMembers : Nat := 8", "def maxMembers : Nat := 9", "maxMembers is nine")
add("LM20", "def lastUsableRevision : Nat := 18_446_744_073_709_551_614", "def lastUsableRevision : Nat := 18_446_744_073_709_551_613", "lastUsableRevision is one lower")
add("LM21", "def active (s : State) : Bool := !s.closed && s.revision < lastUsableRevision", "def active (s : State) : Bool := !s.closed", "active: the last-usable-revision bound is dropped")
add("LM22", "def active (s : State) : Bool := !s.closed && s.revision < lastUsableRevision", "def active (s : State) : Bool := s.revision < lastUsableRevision", "active: a closed group stays active")
add("LM23", "[{ id, target, sourceRevision := s.revision, expiresAt, status := .pending }]", "[{ id, target, sourceRevision := s.revision + 1, expiresAt, status := .pending }]", "invite?: the recorded source revision is one higher")
add("LM24", "predecessor := some s.revision,\n       authority := s.authority, commitment }] }", "predecessor := none,\n       authority := s.authority, commitment }] }", "recordSuccessor: the predecessor is not recorded")
add("LM25", "      if candidate.revision == s.revision + 1 && candidate.predecessor == some s.revision then", "      if candidate.revision == s.revision + 2 && candidate.predecessor == some s.revision then", "controlDisposition: `next` needs revision + 2")
add("LM26", "    | some known => if known.commitment == candidate.commitment then .duplicate else .conflict", "    | some known => if known.commitment == candidate.commitment then .conflict else .duplicate", "controlDisposition: duplicate and conflict are swapped")
add("LM27", "  if candidate.group != s.group || candidate.authority != s.authority then .conflict", "  if candidate.authority != s.authority then .conflict", "controlDisposition: the group is not compared")
add("LM28", "  | x :: xs => if x.id == replacement.id then replacement :: xs else x :: replaceInvitation replacement xs", "  | x :: xs => if x.id == replacement.id then replacement :: replaceInvitation replacement xs else x :: replaceInvitation replacement xs", "replaceInvitation: the replaced entry is kept as well (visible only with duplicate ids, which invite? refuses)", equivalent=True)
add("LM29", "  { group, authority, revision := 0, closed := false, roster := [authority],", "  { group, authority, revision := 0, closed := false, roster := [authority, authority],", "genesis: the authority is listed twice")
add("LM30", "def sameIdentity (a b : Member) : Bool := a.identity == b.identity", "def sameIdentity (a b : Member) : Bool := a == b", "sameIdentity compares the whole member, so a second device is allowed")
add("LM31", "    else match invitation.status with\n      | .admitted _ => some s", "    else match invitation.status with\n      | .admitted _ => none", "accept?: a repeated acceptance of an admitted invitation is refused (the behaviour before decision 0137)")
add("LM32", "      let withRoster := { recorded with roster := s.roster ++ [invitation.target] }", "      let withRoster := { recorded with roster := invitation.target :: s.roster }", "admit?: the new member is put first instead of last")
