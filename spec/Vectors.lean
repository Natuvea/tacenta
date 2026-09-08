import Tacenta.Wire
import Tacenta.Stream
import Tacenta.Session
import Tacenta.User

/-!
Conformance-vector extraction. `lake exe vectors <envelope|session|user|stream>`
prints the named vector set as JSON on stdout; CI regenerates all four
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

def main (args : List String) : IO UInt32 := do
  match args with
  | ["envelope"] => printEnvelopeVectors; return 0
  | ["session"] => printSessionVectors; return 0
  | ["user"] => printUserVectors; return 0
  | ["stream"] => printStreamVectors; return 0
  | _ =>
    IO.eprintln "usage: vectors (envelope|session|user|stream)"
    return 1
