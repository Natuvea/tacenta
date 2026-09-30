"""Single-change mutants of the Lean group model spec/Tacenta/Group.lean, for
tooling/group-model-mutation/mutate.py.

GM01 to GM32 are one fixed set of thirty-two single changes, each a guard, a
constant, an order or a disposition of the model. GX01 to GX17 are seventeen
more, written to test whether the checks that kill GM01 to GM32 also kill their
neighbours. A mutant with an `equivalent` reason is one no state the model
can reach tells apart from the original; mutate.py reports it as EQUIVALENT
when it survives and does not count it as a failure.
"""

MUTATIONS = []


def add(mid, old, new, desc, **kw):
    MUTATIONS.append(dict(id=mid, old=old, new=new, desc=desc, **kw))


add("GM01", "if !active s || actor != s.authority || now >= expiresAt ||", "if !active s || actor != s.authority || now > expiresAt ||", "invite? expiry boundary >= to > (0137 item 19)")
add("GM02", "        observedRevision != invitation.sourceRevision then none", "        false then none", "accept? no longer checks the observed revision")
add("GM03", "      | .pending =>\n        if now >= invitation.expiresAt then none", "      | .pending =>\n        if now > invitation.expiresAt then none", "accept? pending expiry boundary >= to >")
add("GM04", "      | .acceptedPendingAdmission =>\n        if now >= invitation.expiresAt then none else some s", "      | .acceptedPendingAdmission =>\n        some s", "accept? repeat acceptance ignores expiry")
add("GM05", "    if actor != s.authority || now >= invitation.expiresAt ||\n        invitation.status", "    if actor != s.authority ||\n        invitation.status", "admit? no expiry check")
add("GM06", "invitation.status != .acceptedPendingAdmission || memberPresent", "false || memberPresent", "admit? admits a merely pending or revoked invitation")
add("GM07", "        identityPresent invitation.target s || s.roster.length >= maxMembers then none\n    else\n      let updated", "        s.roster.length >= maxMembers then none\n    else\n      let updated", "admit? drops the one-device-per-identity check (memberPresent stays)")
add("GM08", "identityPresent invitation.target s || s.roster.length >= maxMembers then none\n    else\n      let updated", "identityPresent invitation.target s then none\n    else\n      let updated", "admit? drops the member cap")
add("GM09", "      identityPresent target s || (invitationAt? id s.invitations).isSome ||", "      (invitationAt? id s.invitations).isSome ||", "invite? drops the identity-present (second device) refusal")
add("GM10", "(invitationAt? id s.invitations).isSome ||\n      s.roster.length >= maxMembers then none", "(invitationAt? id s.invitations).isSome then none", "invite? drops the member cap")
add("GM11", "identityPresent target s || (invitationAt? id s.invitations).isSome ||", "identityPresent target s ||", "invite? accepts a duplicate invitation id (append shadows)")
add("GM12", "if !active s || actor != s.authority || now >= expiresAt ||", "if !active s || now >= expiresAt ||", "invite? any actor may invite")
add("GM13", "    if actor != s.authority || !active s ||\n        !(invitation.status == .pending || invitation.status == .acceptedPendingAdmission) then none", "    if actor != s.authority || !active s ||\n        !(invitation.status == .pending || invitation.status == .acceptedPendingAdmission || invitation.status == .revoked) then none", "revoke? repeat revoke accepted (0137 item 4, model moved to code)")
add("GM14", "if actor != s.authority || target == s.authority || !memberPresent target s then none", "if actor != s.authority || !memberPresent target s then none", "remove? authority can be removed")
add("GM15", "if actor != s.authority || target == s.authority || !memberPresent target s then none", "if actor != s.authority || target == s.authority then none", "remove? non-member removal accepted (0137 item 3, model moved to code)")
add("GM16", "if actor != s.authority || target == s.authority || !memberPresent target s then none", "if target == s.authority || !memberPresent target s then none", "remove? any actor may remove")
add("GM17", "      some { withRevision with closed := true }", "      some { withRevision with closed := false }", "close? does not close")
add("GM18", "    if actor != s.authority || now >= invitation.expiresAt ||", "    if now >= invitation.expiresAt ||", "admit? any actor may admit")
add("GM19", "def maxMembers : Nat := 8", "def maxMembers : Nat := 9", "maxMembers 8 -> 9")
add("GM20", "def lastUsableRevision : Nat := 18_446_744_073_709_551_614", "def lastUsableRevision : Nat := 18_446_744_073_709_551_613", "lastUsableRevision off by one")
add("GM21", "def active (s : State) : Bool := !s.closed && s.revision < lastUsableRevision", "def active (s : State) : Bool := !s.closed", "active drops the last-usable-revision bound")
add("GM22", "def active (s : State) : Bool := !s.closed && s.revision < lastUsableRevision", "def active (s : State) : Bool := s.revision < lastUsableRevision", "active ignores closed (closed group stays active)")
add("GM23", "[{ id, target, sourceRevision := s.revision, expiresAt, status := .pending }]", "[{ id, target, sourceRevision := s.revision + 1, expiresAt, status := .pending }]", "invite? records source revision + 1")
add("GM24", "predecessor := some s.revision,\n       authority := s.authority, commitment }] }", "predecessor := none,\n       authority := s.authority, commitment }] }", "recordSuccessor drops the predecessor")
add("GM25", "      if candidate.revision == s.revision + 1 && candidate.predecessor == some s.revision then", "      if candidate.revision == s.revision + 2 && candidate.predecessor == some s.revision then", "controlDisposition .next requires revision + 2")
add("GM26", "    | some known => if known.commitment == candidate.commitment then .duplicate else .conflict", "    | some known => if known.commitment == candidate.commitment then .conflict else .duplicate", "controlDisposition duplicate/conflict swapped")
add("GM27", "  if candidate.group != s.group || candidate.authority != s.authority then .conflict", "  if candidate.authority != s.authority then .conflict", "controlDisposition ignores the group")
add("GM28", "  | x :: xs => if x.id == replacement.id then replacement :: xs else x :: replaceInvitation replacement xs", "  | x :: xs => if x.id == replacement.id then replacement :: replaceInvitation replacement xs else x :: replaceInvitation replacement xs", "replaceInvitation duplicates the replaced entry (only visible with duplicate ids)",
    equivalent="differs from the original only on a list holding two invitations with one id; invite? refuses an id it already holds and every other operation keeps the ids, so no reachable state has such a list")
add("GM29", "  { group, authority, revision := 0, closed := false, roster := [authority],", "  { group, authority, revision := 0, closed := false, roster := [authority, authority],", "genesis lists the authority twice (breaks genesis_has_only_its_authority)")
add("GM30", "def sameIdentity (a b : Member) : Bool := a.identity == b.identity", "def sameIdentity (a b : Member) : Bool := a == b", "sameIdentity compares the whole member (second device allowed)")
add("GM31", "    else match invitation.status with\n      | .admitted _ => some s", "    else match invitation.status with\n      | .admitted _ => none", "accept? repeat of an admitted acceptance refused (pre-0137 behaviour)")
add("GM32", "      let withRoster := { recorded with roster := s.roster ++ [invitation.target] }", "      let withRoster := { recorded with roster := invitation.target :: s.roster }", "admit? prepends instead of appends (order only)")

add("GX01", "if !active s || actor != invitation.target ||\n        observedRevision", "if !active s ||\n        observedRevision", "accept? any actor may accept")
add("GX02", "    if actor != s.authority || !active s ||\n        !(invitation.status == .pending", "    if !active s ||\n        !(invitation.status == .pending", "revoke? any actor may revoke")
add("GX03", "    if actor == s.authority then\n      let withRevision := { s with revision := next }\n      some { withRevision with closed := true }", "    if true then\n      let withRevision := { s with revision := next }\n      some { withRevision with closed := true }", "close? any actor may close")
add("GX04", "roster := s.roster.filter (fun member => member != target) }", "roster := s.roster }", "remove? removes nobody")
add("GX05", "(invitationAt? id s.invitations).isSome ||\n      s.roster.length >= maxMembers then none", "(invitationAt? id s.invitations).isSome ||\n      s.roster.length > maxMembers then none", "invite? cap off by one")
add("GX06", "identityPresent invitation.target s || s.roster.length >= maxMembers then none", "identityPresent invitation.target s || s.roster.length > maxMembers then none", "admit? cap off by one")
add("GX07", "if active s then some (s.revision + 1) else none", "if active s then some (s.revision + 2) else none", "nextRevision? skips a revision")
add("GX08", "      let recorded := recordSuccessor s next commitment\n", "      let recorded := { s with revision := next }\n", "admit? records no control")
add("GX09", "      { invitation with status := .revoked } s.invitations) }", "      invitation s.invitations) }", "revoke? changes nothing")
add("GX10", "          { invitation with status := .acceptedPendingAdmission } s.invitations) }", "          invitation s.invitations) }", "accept? changes nothing")
add("GX11", "if candidate.revision == s.revision + 1 && candidate.predecessor == some s.revision then", "if candidate.revision == s.revision + 1 then", "controlDisposition next ignores the predecessor")
add("GX12", "  if candidate.group != s.group || candidate.authority != s.authority then .conflict", "  if candidate.group != s.group then .conflict", "controlDisposition ignores the authority")
add("GX13", "def active (s : State) : Bool := !s.closed && s.revision < lastUsableRevision", "def active (s : State) : Bool := !s.closed && s.revision <= lastUsableRevision", "active bound off by one")
add("GX14", "def maxMembers : Nat := 8", "def maxMembers : Nat := 7", "maxMembers 8 -> 7")
add("GX15", "def memberPresent (member : Member) (s : State) : Bool := member ∈ s.roster", "def memberPresent (member : Member) (s : State) : Bool := false", "memberPresent always false")
add("GX16", "        invitation.status != .acceptedPendingAdmission || memberPresent invitation.target s ||", "        invitation.status != .acceptedPendingAdmission ||", "admit? drops the exact-member-present check",
    equivalent="a member on the roster has its identity on the roster, and admit? refuses on identityPresent, so the dropped test never decides")
add("GX17", "      let withRoster := { recorded with roster := s.roster ++ [invitation.target] }", "      let withRoster := recorded", "admit? adds nobody to the roster")
