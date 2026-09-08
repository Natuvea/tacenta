import Tacenta.Wire

/-!
# Envelope stream framing

A transport carries many envelopes over one byte buffer. Because each
envelope is self-describing (its header carries the payload length),
a stream is just the concatenation of encoded envelopes — no separators
needed. `decodeOne` parses the first envelope and returns the
remaining bytes; `decodeStream` iterates it to the end.

The headline theorem is `decodeStream_encodeStream`: any sequence of
envelopes, encoded and concatenated, decodes back to exactly that
sequence.
-/

set_option linter.unusedVariables false

namespace Tacenta.Wire

/-- Parse one envelope from the front of a buffer, returning it together
with the unconsumed remainder. Rejects (returns `none`) on a short
buffer, wrong version, unknown kind, or a length field larger than the
bytes that follow. -/
def decodeOne : List UInt8 → Option (Envelope × List UInt8)
  | v0 :: v1 :: k :: l0 :: l1 :: l2 :: l3 :: rest =>
    if decodeU16 v0 v1 = wireVersion then
      match Kind.ofByte? k with
      | some kind =>
        let len := decodeU32 l0 l1 l2 l3
        if len ≤ rest.length then
          some (⟨kind, rest.take len⟩, rest.drop len)
        else
          none
      | none => none
    else
      none
  | _ => none

/-- `decodeOne` always makes progress: the remainder is strictly shorter
than the input. This is what makes `decodeStream` terminate. -/
theorem decodeOne_consumes {bytes : List UInt8} {e : Envelope}
    {rest : List UInt8} (h : decodeOne bytes = some (e, rest)) :
    rest.length < bytes.length := by
  unfold decodeOne at h
  split at h
  · rename_i v0 v1 k l0 l1 l2 l3 tail
    simp only at h
    split at h
    · split at h
      · rename_i kind _
        split at h
        · injection h with h
          rw [Prod.mk.injEq] at h
          obtain ⟨-, h2⟩ := h
          subst h2
          simp only [List.length_drop, List.length_cons]
          omega
        · exact absurd h (by simp)
      · exact absurd h (by simp)
    · exact absurd h (by simp)
  · exact absurd h (by simp)

/-- Decode a whole stream: repeatedly parse one envelope until the
buffer is empty. `none` if any parse fails or the bytes do not divide
cleanly into envelopes. -/
def decodeStream (bytes : List UInt8) : Option (List Envelope) :=
  if bytes.isEmpty then
    some []
  else
    match h : decodeOne bytes with
    | none => none
    | some (e, rest) => (decodeStream rest).map (e :: ·)
  termination_by bytes.length
  decreasing_by exact decodeOne_consumes h

/-- Encode a stream: concatenate the encodings, `none` if any envelope
is too large to encode. -/
def encodeStream : List Envelope → Option (List UInt8)
  | [] => some []
  | e :: es =>
    match encode e with
    | none => none
    | some b =>
      match encodeStream es with
      | none => none
      | some rest => some (b ++ rest)

/-- Unfolding equation for the recursive step, worked around the
dependent `match` that the termination proof requires. -/
theorem decodeStream_cons {bytes : List UInt8} {e : Envelope}
    {rest : List UInt8} (hne : bytes.isEmpty = false)
    (h : decodeOne bytes = some (e, rest)) :
    decodeStream bytes = (decodeStream rest).map (e :: ·) := by
  rw [decodeStream]
  simp only [hne, Bool.false_eq_true, if_false]
  split
  · rename_i hnone; rw [h] at hnone; exact absurd hnone (by simp)
  · rename_i e' rest' heq
    rw [h] at heq
    injection heq with heq
    rw [Prod.mk.injEq] at heq
    obtain ⟨he, hr⟩ := heq
    subst he; subst hr; rfl

/-- One envelope, encoded and followed by any suffix, parses back to
that envelope with the suffix intact. The streaming analogue of
`decode_encode`. -/
theorem decodeOne_encode {e : Envelope} {b rest : List UInt8}
    (h : encode e = some b) : decodeOne (b ++ rest) = some (e, rest) := by
  unfold encode at h
  split at h
  · rename_i hlen
    injection h with h
    subst h
    have hle : e.payload.length ≤ (e.payload ++ rest).length := by
      simp only [List.length_append]; omega
    have htake : (e.payload ++ rest).take e.payload.length = e.payload := by
      rw [List.take_append_of_le_length (Nat.le_refl _), List.take_length]
    have hdrop : (e.payload ++ rest).drop e.payload.length = rest := by
      rw [List.drop_append_of_le_length (Nat.le_refl _), List.drop_length,
        List.nil_append]
    simp only [encodeU16, encodeU32, List.cons_append, List.nil_append,
      decodeOne, decodeU16_encodeU16 wireVersion (by decide),
      Kind.ofByte?_toByte, decodeU32_encodeU32 e.payload.length hlen,
      if_pos hle, htake, hdrop, if_true]
  · exact absurd h (by simp)

/-- The stream round trip: any sequence of envelopes, encoded and
concatenated, decodes back to exactly that sequence. -/
theorem decodeStream_encodeStream {es : List Envelope} {bs : List UInt8}
    (h : encodeStream es = some bs) : decodeStream bs = some es := by
  induction es generalizing bs with
  | nil =>
    simp only [encodeStream] at h
    injection h with h
    subst h
    rw [decodeStream]
    simp
  | cons e es ih =>
    simp only [encodeStream] at h
    split at h
    · exact absurd h (by simp)
    · rename_i b hb
      split at h
      · exact absurd h (by simp)
      · rename_i rest hrest
        injection h with h
        subst h
        have hbpos : 0 < b.length := by
          unfold encode at hb
          split at hb
          · injection hb with hb; subst hb
            simp only [encodeU16, encodeU32, List.length_append,
              List.length_cons, List.length_nil]
            omega
          · exact absurd hb (by simp)
        have hbne : (b ++ rest).isEmpty = false := by
          cases hbc : b with
          | nil => rw [hbc] at hbpos; simp at hbpos
          | cons x xs => simp
        rw [decodeStream_cons hbne (decodeOne_encode hb), ih hrest]
        rfl

/-! ## Canonicity of the stream

The mirror of `decodeStream_encodeStream`, and the direction with the
content: every byte string the decoder accepts is one the encoder
writes. `Wire.encode_decode` says it for a single envelope; these lift
it to the stream, which is the level a frame is actually authenticated
at.

Same discipline as there: the reassembly is a standalone lemma over
abstract header bytes, so the main proof carries no case analysis into
its closing step. -/

/-- Re-encoding the envelope `decodeOne` read, followed by the
remainder it returned, reproduces the bytes it consumed.

`decodeOne` splits the tail at the declared length rather than taking
all of it, so this carries a `take`/`drop` pair where the envelope
version carries neither. That is the whole difference between the two. -/
theorem decodeOne_reassembles {v0 v1 k l0 l1 l2 l3 : UInt8} {kind : Kind}
    {tail : List UInt8}
    (hver : decodeU16 v0 v1 = wireVersion)
    (hkind : kind.toByte = k)
    (hle : decodeU32 l0 l1 l2 l3 ≤ tail.length) :
    (encodeU16 wireVersion ++ [kind.toByte]
        ++ encodeU32 (tail.take (decodeU32 l0 l1 l2 l3)).length
        ++ tail.take (decodeU32 l0 l1 l2 l3))
      ++ tail.drop (decodeU32 l0 l1 l2 l3)
      = v0 :: v1 :: k :: l0 :: l1 :: l2 :: l3 :: tail := by
  have hlen : (tail.take (decodeU32 l0 l1 l2 l3)).length = decodeU32 l0 l1 l2 l3 := by
    rw [List.length_take]; omega
  rw [hlen, ← hver, encodeU16_decodeU16, hkind, encodeU32_decodeU32,
    List.append_assoc, List.take_append_drop]
  rfl

/-- Canonicity for one envelope: whatever `decodeOne` accepted is
`encode`'s output for the envelope it returned, followed by the
remainder it handed back. -/
theorem decodeOne_canonical {bs : List UInt8} {e : Envelope} {rest : List UInt8}
    (h : decodeOne bs = some (e, rest)) :
    ∃ b, encode e = some b ∧ bs = b ++ rest := by
  match bs with
  | [] => simp [decodeOne] at h
  | [_] => simp [decodeOne] at h
  | [_, _] => simp [decodeOne] at h
  | [_, _, _] => simp [decodeOne] at h
  | [_, _, _, _] => simp [decodeOne] at h
  | [_, _, _, _, _] => simp [decodeOne] at h
  | [_, _, _, _, _, _] => simp [decodeOne] at h
  | v0 :: v1 :: k :: l0 :: l1 :: l2 :: l3 :: tail =>
    simp only [decodeOne] at h
    split at h
    case isFalse => exact absurd h (by simp)
    case isTrue hver =>
      split at h
      case h_2 => exact absurd h (by simp)
      case h_1 kind hkind =>
        split at h
        case isFalse => exact absurd h (by simp)
        case isTrue hle =>
          injection h with h
          rw [Prod.mk.injEq] at h
          obtain ⟨he, hr⟩ := h
          subst he; subst hr
          -- The payload is as long as a four-byte length field said, so
          -- `encode` cannot refuse it.
          have hfit : (tail.take (decodeU32 l0 l1 l2 l3)).length < 2 ^ 32 := by
            rw [List.length_take]
            have := decodeU32_lt l0 l1 l2 l3
            omega
          refine ⟨encodeU16 wireVersion ++ [kind.toByte]
              ++ encodeU32 (tail.take (decodeU32 l0 l1 l2 l3)).length
              ++ tail.take (decodeU32 l0 l1 l2 l3), ?_, ?_⟩
          · simp only [encode, if_pos hfit]
          · exact (decodeOne_reassembles hver (Kind.toByte_ofByte? hkind) hle).symm

/-- The induction carries an explicit bound rather than recursing on
`decodeStream`'s own measure. Well-founded recursion in tactic mode
generates its decrease goal in a context that cannot see the hypothesis
`split` bound inside the branch, so the fact that makes it terminate --
`decodeOne_consumes` -- is unavailable exactly where it is needed. A
fuel parameter turns the same argument into structural induction on
`Nat`, where the bound travels as an ordinary hypothesis. -/
theorem encodeStream_decodeStream_bounded : ∀ (n : Nat) (bs : List UInt8)
    (es : List Envelope), bs.length ≤ n → decodeStream bs = some es →
    encodeStream es = some bs := by
  intro n
  induction n with
  | zero =>
    intro bs es hbound h
    have : bs = [] := List.length_eq_zero_iff.mp (Nat.le_zero.mp hbound)
    subst this
    rw [decodeStream] at h
    simp only [List.isEmpty_nil, if_true] at h
    injection h with h
    subst h
    rfl
  | succ n ih =>
    intro bs es hbound h
    rw [decodeStream] at h
    split at h
    case isTrue hempty =>
      injection h with h
      subst h
      have : bs = [] := List.isEmpty_iff.mp hempty
      subst this
      rfl
    case isFalse =>
      split at h
      case h_1 => exact absurd h (by simp)
      case h_2 e rest hone =>
        -- `decodeStream rest` succeeded, or the `map` could not have.
        match hrest : decodeStream rest with
        | none => rw [hrest] at h; exact absurd h (by simp)
        | some es' =>
          rw [hrest] at h
          simp only [Option.map_some] at h
          injection h with h
          subst h
          obtain ⟨b, hb, hsplit⟩ := decodeOne_canonical hone
          have hshorter : rest.length ≤ n := by
            have := decodeOne_consumes hone
            omega
          rw [encodeStream, hb, ih rest es' hshorter hrest, hsplit]

/-- Stream canonicity: every byte string `decodeStream` accepts is what
`encodeStream` writes for the envelopes it returned.

With `decodeStream_encodeStream` this makes the accepted set and the
written set one set, which is the property an authenticator over exact
bytes needs. The fuel above is discharged with the input's own length. -/
theorem encodeStream_decodeStream {bs : List UInt8} {es : List Envelope}
    (h : decodeStream bs = some es) : encodeStream es = some bs :=
  encodeStream_decodeStream_bounded bs.length bs es (Nat.le_refl _) h

end Tacenta.Wire
