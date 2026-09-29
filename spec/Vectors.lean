import Tacenta.Wire
import Tacenta.Stream
import Tacenta.Session
import Tacenta.User
import Tacenta.Group

/-!
Conformance-vector extraction. `lake exe vectors <envelope|session|user|stream|group>`
prints the named vector set as JSON on stdout; CI regenerates all five
and diffs against the committed files under
`contracts/vectors/`, so the committed vectors can never drift from the
specification. The Rust test suites consume the committed files.
-/

open Tacenta.Wire Tacenta.Session

def hexDigit (n : Nat) : Char :=
  if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)

def hexByte (b : UInt8) : String :=
  String.ofList [hexDigit (b.toNat / 16), hexDigit (b.toNat % 16)]

def hexBytes (bs : List UInt8) : String :=
  String.join (bs.map hexByte)

def Tacenta.Wire.Kind.name : Kind → String
  | .dm => "dm"
  | .group => "group"
  | .receipt => "receipt"

def envelopeJson (e : Envelope) : String :=
  "{\"kind\": \"" ++ e.kind.name ++ "\", \"payload\": \"" ++ hexBytes e.payload ++ "\"}"

/-! ## Envelope wire vectors -/

/-- The published sample set: every kind, plus edge-shaped payloads. -/
def envelopeSamples : List Envelope :=
  [ ⟨.dm, []⟩,
    ⟨.dm, [0x00]⟩,
    ⟨.dm, [0xff]⟩,
    ⟨.group, [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]⟩,
    ⟨.receipt, (List.range 300).map (fun i => UInt8.ofNat (i % 256))⟩ ]

def envelopeVectorJson (e : Envelope) : String :=
  let encoded := (encode e).getD []
  "    {\"kind\": \"" ++ e.kind.name ++ "\", \"payload\": \""
    ++ hexBytes e.payload ++ "\", \"encoded\": \"" ++ hexBytes encoded ++ "\"}"

def printEnvelopeVectors : IO Unit := do
  IO.println "{"
  IO.println "  \"format\": \"envelope-v1\","
  IO.println ("  \"wire_version\": " ++ toString Tacenta.wireVersion ++ ",")
  IO.println "  \"vectors\": ["
  IO.println (String.intercalate ",\n" (envelopeSamples.map envelopeVectorJson))
  IO.println "  ]"
  IO.println "}"

/-! ## Session trace vectors -/

inductive Op where
  | append (e : Envelope)
  | ack (n : Nat)

/-- Run one op. Rejected acks leave the state untouched, exactly as in
the model (`ack?` returns `none`); the boolean records acceptance. -/
def stepOp (s : Session) : Op → Session × Bool
  | .append e => (Tacenta.Session.append e s, true)
  | .ack n =>
    match ack? n s with
    | some s' => (s', true)
    | none => (s, false)

def opJson (s : Session) (op : Op) : String :=
  match op with
  | .append e => "      {\"op\": \"append\", \"kind\": \"" ++ e.kind.name
      ++ "\", \"payload\": \"" ++ hexBytes e.payload ++ "\"}"
  | .ack n =>
    let accepted := (ack? n s).isSome
    "      {\"op\": \"ack\", \"n\": " ++ toString n
      ++ ", \"accepted\": " ++ (if accepted then "true" else "false") ++ "}"

/-- Fold a trace, emitting per-op JSON (with acceptance computed in the
pre-state) and the final session. -/
def runTrace (ops : List Op) : List String × Session :=
  ops.foldl
    (fun (acc : List String × Session) op =>
      let (lines, s) := acc
      (lines ++ [opJson s op], (stepOp s op).1))
    ([], Session.init)

def traceSamples : List (List Op) :=
  [ -- Deliver-in-order: two appends, ack the first, append another.
    [.append ⟨.dm, []⟩, .append ⟨.group, [0x00, 0x01]⟩, .ack 1,
     .append ⟨.receipt, [0xff]⟩],
    -- Fully drained log.
    [.append ⟨.dm, [0xaa]⟩, .ack 1, .append ⟨.dm, [0xbb]⟩, .ack 2],
    -- Rejected acks: not advancing (0), beyond the log (2), then valid.
    [.append ⟨.dm, [0xaa]⟩, .ack 0, .ack 2, .ack 1],
    -- The empty trace.
    [] ]

def traceJson (ops : List Op) : String :=
  let (opLines, final) := runTrace ops
  let opsBlock := if opLines.isEmpty then "" else
    "\n" ++ String.intercalate ",\n" opLines ++ "\n    "
  let pendingBlock := String.intercalate ", " ((pending final).map envelopeJson)
  "    {\"ops\": [" ++ opsBlock ++ "], \"final\": {\"cursor\": "
    ++ toString final.cursor ++ ", \"pending\": [" ++ pendingBlock ++ "]}}"

def printSessionVectors : IO Unit := do
  IO.println "{"
  IO.println "  \"format\": \"session-v1\","
  IO.println "  \"traces\": ["
  IO.println (String.intercalate ",\n" (traceSamples.map traceJson))
  IO.println "  ]"
  IO.println "}"

/-! ## User (multi-device) trace vectors -/

inductive UOp where
  | link
  | append (e : Envelope)
  | ack (d n : Nat)

/-- Run one user op. Rejected acks leave the state untouched, exactly
as in the model; the boolean records acceptance. -/
def stepUOp (u : Tacenta.User.User) : UOp → Tacenta.User.User × Bool
  | .link => (Tacenta.User.linkDevice u, true)
  | .append e => (Tacenta.User.append e u, true)
  | .ack d n =>
    match Tacenta.User.ack? d n u with
    | some u' => (u', true)
    | none => (u, false)

def uopJson (u : Tacenta.User.User) : UOp → String
  | .link => "      {\"op\": \"link\"}"
  | .append e => "      {\"op\": \"append\", \"kind\": \"" ++ e.kind.name
      ++ "\", \"payload\": \"" ++ hexBytes e.payload ++ "\"}"
  | .ack d n =>
    let accepted := (Tacenta.User.ack? d n u).isSome
    "      {\"op\": \"ack\", \"device\": " ++ toString d ++ ", \"n\": " ++ toString n
      ++ ", \"accepted\": " ++ (if accepted then "true" else "false") ++ "}"

def runUTrace (ops : List UOp) : List String × Tacenta.User.User :=
  ops.foldl
    (fun (acc : List String × Tacenta.User.User) op =>
      let (lines, u) := acc
      (lines ++ [uopJson u op], (stepUOp u op).1))
    ([], Tacenta.User.User.init)

def uTraceSamples : List (List UOp) :=
  [ -- Two devices: the second links mid-stream and starts at the tail.
    [.link, .append ⟨.dm, [0xaa]⟩, .append ⟨.group, [0xbb]⟩, .ack 0 1,
     .link, .append ⟨.receipt, [0xcc]⟩, .ack 1 3],
    -- No devices: everything is vacuously delivered.
    [.append ⟨.dm, [0xaa]⟩],
    -- Rejections: unknown device, rewind, beyond the log, then valid.
    [.link, .append ⟨.dm, [0xaa]⟩, .ack 1 1, .ack 0 0, .ack 0 2, .ack 0 1],
    -- The empty trace.
    [] ]

def uTraceJson (ops : List UOp) : String :=
  let (opLines, final) := runUTrace ops
  let opsBlock := if opLines.isEmpty then "" else
    "\n" ++ String.intercalate ",\n" opLines ++ "\n    "
  let cursorsBlock := String.intercalate ", " (final.cursors.map toString)
  let pendingBlock := String.intercalate ", "
    ((List.range final.cursors.length).map (fun d =>
      "[" ++ String.intercalate ", "
        ((Tacenta.User.devicePending final d).map envelopeJson) ++ "]"))
  "    {\"ops\": [" ++ opsBlock ++ "], \"final\": {\"cursors\": ["
    ++ cursorsBlock ++ "], \"delivered\": " ++ toString (Tacenta.User.delivered final)
    ++ ", \"pending_per_device\": [" ++ pendingBlock ++ "]}}"

def printUserVectors : IO Unit := do
  IO.println "{"
  IO.println "  \"format\": \"user-v1\","
  IO.println "  \"traces\": ["
  IO.println (String.intercalate ",\n" (uTraceSamples.map uTraceJson))
  IO.println "  ]"
  IO.println "}"

/-! ## Stream vectors -/

def streamSamples : List (List Envelope) :=
  [ [],
    [⟨.dm, [0xaa]⟩],
    [⟨.dm, []⟩, ⟨.group, [0x01, 0x02]⟩, ⟨.receipt, [0xff]⟩],
    [⟨.receipt, (List.range 300).map (fun i => UInt8.ofNat (i % 256))⟩,
     ⟨.dm, [0x00]⟩] ]

def streamVectorJson (es : List Envelope) : String :=
  let encoded := (encodeStream es).getD []
  "    {\"envelopes\": [" ++ String.intercalate ", " (es.map envelopeJson)
    ++ "], \"encoded\": \"" ++ hexBytes encoded ++ "\"}"

def printStreamVectors : IO Unit := do
  IO.println "{"
  IO.println "  \"format\": \"stream-v1\","
  IO.println "  \"streams\": ["
  IO.println (String.intercalate ",\n" (streamSamples.map streamVectorJson))
  IO.println "  ]"
  IO.println "}"

/-! ## Group policy trace vectors

Each step names the model operation, whether the model accepted it, and the
state the model holds afterwards (a refused step leaves the state unchanged).
The Rust `tacenta-group` types replay every step; see decision 0137. The model
has no exact-retry rule for a duplicate invitation ID (it refuses any
duplicate), so the traces only repeat an ID with a different target, which both
sides refuse. Revocation carries no logical time in the model, and removal of a
non-member has no Rust counterpart in the invitation book, so neither appears.
-/

namespace GroupVectors

open Tacenta.Group

inductive Step where
  | invite (actor : Member) (id now expiresAt : Nat) (target : Member)
  | accept (actor : Member) (id now observedRevision : Nat)
  | admit (actor : Member) (id now : Nat)
  | revoke (actor : Member) (id : Nat)
  | remove (actor target : Member)

def Step.run (s : State) : Step → Option State
  | .invite a i n e t => invite? a i n e t s
  | .accept a i n o => accept? a i n o s
  | .admit a i n => admit? a i n (100 + s.revision + 1) s
  | .revoke a i => revoke? a i s
  | .remove a t => remove? a t s

def memberJson (m : Member) : String :=
  "{\"identity\": " ++ toString m.identity ++ ", \"device\": " ++ toString m.device ++ "}"

def statusJson : InvitationStatus → String
  | .pending => "{\"state\": \"pending\"}"
  | .acceptedPendingAdmission => "{\"state\": \"accepted_pending_admission\"}"
  | .admitted r => "{\"state\": \"admitted\", \"revision\": " ++ toString r ++ "}"
  | .revoked => "{\"state\": \"revoked\"}"

def invitationJson (i : Invitation) : String :=
  "{\"id\": " ++ toString i.id ++ ", \"target\": " ++ memberJson i.target
    ++ ", \"source_revision\": " ++ toString i.sourceRevision
    ++ ", \"status\": " ++ statusJson i.status ++ "}"

def stateJson (s : State) : String :=
  "{\"revision\": " ++ toString s.revision
    ++ ", \"roster\": [" ++ String.intercalate ", " (s.roster.map memberJson)
    ++ "], \"invitations\": [" ++ String.intercalate ", " (s.invitations.map invitationJson) ++ "]}"

def stepHead : Step → String
  | .invite a i n e t => "\"op\": \"invite\", \"actor\": " ++ memberJson a ++ ", \"id\": "
      ++ toString i ++ ", \"now\": " ++ toString n ++ ", \"expires_at\": " ++ toString e
      ++ ", \"target\": " ++ memberJson t
  | .accept a i n o => "\"op\": \"accept\", \"actor\": " ++ memberJson a ++ ", \"id\": "
      ++ toString i ++ ", \"now\": " ++ toString n ++ ", \"observed_revision\": " ++ toString o
  | .admit a i n => "\"op\": \"admit\", \"actor\": " ++ memberJson a ++ ", \"id\": "
      ++ toString i ++ ", \"now\": " ++ toString n
  | .revoke a i => "\"op\": \"revoke\", \"actor\": " ++ memberJson a ++ ", \"id\": " ++ toString i
  | .remove a t => "\"op\": \"remove\", \"actor\": " ++ memberJson a
      ++ ", \"target\": " ++ memberJson t

def stepJson (step : Step) (accepted : Bool) (after : State) : String :=
  "      {" ++ stepHead step ++ ", \"accepted\": " ++ (if accepted then "true" else "false")
    ++ ", \"state\": " ++ stateJson after ++ "}"

def runTrace (start : State) (steps : List Step) : List String :=
  (steps.foldl
    (fun (acc : List String × State) step =>
      let (lines, s) := acc
      match step.run s with
      | some s' => (lines ++ [stepJson step true s'], s')
      | none => (lines ++ [stepJson step false s], s))
    ([], start)).1

def authority : Member := { identity := 1, device := 1 }
def person (n : Nat) : Member := { identity := n, device := 1 }
def start : State := genesis 9 authority 100

/-- Invite, accept (twice), admit; then a second invitation issued at revision 1. -/
def numberingTrace : List Step :=
  [ .invite authority 7 0 10 (person 2),
    .accept (person 2) 7 1 0,
    .accept (person 2) 7 2 0,
    .admit authority 7 3,
    .invite authority 8 4 20 (person 3),
    .accept (person 3) 8 5 1,
    .admit authority 8 6 ]

/-- Refusals: wrong actor, wrong target, stale source, expiry, revocation wins,
an admitted invitation cannot be revoked, an existing member and a second device
cannot be invited. -/
def refusalTrace : List Step :=
  [ .invite (person 2) 1 0 10 (person 3),
    .invite authority 7 0 10 (person 2),
    .invite authority 7 0 10 (person 3),
    .accept (person 3) 7 1 0,
    .accept (person 2) 7 1 4,
    .accept (person 2) 7 10 0,
    .admit authority 7 2,
    .accept (person 2) 7 3 0,
    .revoke (person 2) 7,
    .revoke authority 7,
    .admit authority 7 4,
    .accept (person 2) 7 5 0,
    .invite authority 8 6 20 (person 4),
    .accept (person 4) 8 7 0,
    .admit authority 8 8,
    .revoke authority 8,
    .invite authority 9 9 20 (person 4),
    .invite authority 10 9 20 { identity := 4, device := 2 } ]

/-- An invitation that expires between acceptance and admission cannot be admitted. -/
def expiryTrace : List Step :=
  [ .invite authority 5 0 3 (person 2),
    .accept (person 2) 5 2 0,
    .admit authority 5 3,
    .accept (person 2) 5 3 0 ]

/-- Eight members is the cap: the ninth invitation is refused, and so is the
admission of a ninth member whose invitation was issued while there was room. -/
def capTrace : List Step :=
  ((List.range 6).flatMap (fun k =>
    let n := k + 2
    [ .invite authority n 0 100 (person n),
      .accept (person n) n 1 k,
      .admit authority n 2 ])) ++
  [ .invite authority 20 3 100 (person 8),
    .invite authority 21 3 100 (person 9),
    .accept (person 8) 20 4 6,
    .accept (person 9) 21 4 6,
    .admit authority 20 5,
    .admit authority 21 5,
    .invite authority 22 6 100 (person 10) ]

/-- Removal is one revision; the authority cannot be removed; a removed member
can be invited again. -/
def removalTrace : List Step :=
  [ .invite authority 7 0 10 (person 2),
    .accept (person 2) 7 1 0,
    .admit authority 7 2,
    .remove (person 2) authority,
    .remove authority authority,
    .remove authority (person 2),
    .invite authority 8 3 20 (person 2),
    .accept (person 2) 8 4 2,
    .admit authority 8 5 ]

def traces : List (String × List Step) :=
  [ ("admission-numbering", numberingTrace), ("refusals", refusalTrace),
    ("expiry", expiryTrace), ("member-cap", capTrace), ("removal", removalTrace) ]

def traceJson (entry : String × List Step) : String :=
  "    {\"name\": \"" ++ entry.1 ++ "\", \"authority\": " ++ memberJson authority
    ++ ", \"steps\": [\n" ++ String.intercalate ",\n" (runTrace start entry.2) ++ "\n    ]}"

def printGroupVectors : IO Unit := do
  IO.println "{"
  IO.println "  \"format\": \"group-v1\","
  IO.println ("  \"max_members\": " ++ toString maxMembers ++ ",")
  IO.println "  \"traces\": ["
  IO.println (String.intercalate ",\n" (traces.map traceJson))
  IO.println "  ]"
  IO.println "}"

end GroupVectors

def main (args : List String) : IO UInt32 := do
  match args with
  | ["envelope"] => printEnvelopeVectors; return 0
  | ["session"] => printSessionVectors; return 0
  | ["user"] => printUserVectors; return 0
  | ["stream"] => printStreamVectors; return 0
  | ["group"] => GroupVectors.printGroupVectors; return 0
  | _ =>
    IO.eprintln "usage: vectors (envelope|session|user|stream|group)"
    return 1
