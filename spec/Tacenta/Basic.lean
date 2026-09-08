/-!
# Tacenta protocol specification — root module

The Lean model is the source of truth for the wire protocol and the core
state machines. The Rust implementation in `crates/` is checked against
vectors extracted from this specification, and the verified zone
(`tacenta-wire`) is translated to Lean via Aeneas and proved against it.

Discipline: no `sorry` anywhere in this tree — `lake build` in CI is the
gate. Claims about what is and is not proven live in the claims page, not
here.
-/

namespace Tacenta

/-- Wire-format version tag carried by every envelope.

Must match `WIRE_VERSION` in `crates/tacenta-wire/src/lib.rs`; the
conformance suite checks the two never drift. -/
def wireVersion : Nat := 1

theorem wireVersion_pos : 0 < wireVersion := by decide

end Tacenta
