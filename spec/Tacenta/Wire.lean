import Tacenta.Basic

/-!
# Envelope wire format

The v1 envelope layout, big-endian throughout:

```
offset  size  field
0       2     wire version (u16)
2       1     kind (u8)
3       4     payload length (u32)
7       n     payload bytes
```

`decode` accepts exactly the strings `encode` produces: wrong version,
unknown kind, or a length field that disagrees with the actual payload
size are all rejected, and no trailing bytes are tolerated. The
round-trip theorem `decode_encode` is the contract the Rust
implementation is held to via the extracted conformance vectors.
-/

namespace Tacenta.Wire

/-- Big-endian 2-byte encoding of a natural number below `2 ^ 16`. -/
def encodeU16 (n : Nat) : List UInt8 :=
  [UInt8.ofNat (n / 256), UInt8.ofNat (n % 256)]

/-- Big-endian read of two bytes. -/
def decodeU16 (b0 b1 : UInt8) : Nat :=
  b0.toNat * 256 + b1.toNat

theorem decodeU16_encodeU16 (n : Nat) (h : n < 2 ^ 16) :
    decodeU16 (UInt8.ofNat (n / 256)) (UInt8.ofNat (n % 256)) = n := by
  simp [decodeU16]
  omega

/-- Big-endian 4-byte encoding of a natural number below `2 ^ 32`. -/
def encodeU32 (n : Nat) : List UInt8 :=
  [UInt8.ofNat (n / 2 ^ 24), UInt8.ofNat (n / 2 ^ 16 % 256),
   UInt8.ofNat (n / 2 ^ 8 % 256), UInt8.ofNat (n % 256)]

/-- Big-endian read of four bytes. -/
def decodeU32 (b0 b1 b2 b3 : UInt8) : Nat :=
  b0.toNat * 2 ^ 24 + b1.toNat * 2 ^ 16 + b2.toNat * 2 ^ 8 + b3.toNat

theorem decodeU32_encodeU32 (n : Nat) (h : n < 2 ^ 32) :
    decodeU32 (UInt8.ofNat (n / 2 ^ 24)) (UInt8.ofNat (n / 2 ^ 16 % 256))
      (UInt8.ofNat (n / 2 ^ 8 % 256)) (UInt8.ofNat (n % 256)) = n := by
  simp [decodeU32]
  omega

/-! ## The other direction: canonicity of the byte-level readers

The three theorems above say the readers recover what the writers put
down. That constrains the *writer*, and says nothing about which byte
strings the reader accepts. These say the accepted set is exactly the
written one: re-encoding what a reader returned reproduces the very
bytes it read, so no value has two spellings.

That is what `encodeStream_decodeStream` is built from, and it is the
property an authenticator over exact bytes needs. Without it a peer
could re-spell a frame, keep its meaning, and change its bytes. -/

/-- Re-encoding a two-byte read reproduces those two bytes. -/
theorem encodeU16_decodeU16 (b0 b1 : UInt8) :
    encodeU16 (decodeU16 b0 b1) = [b0, b1] := by
  have h0 : b0.toNat < 256 := b0.toNat_lt_size
  have h1 : b1.toNat < 256 := b1.toNat_lt_size
  simp only [encodeU16, decodeU16, List.cons.injEq, and_true]
  constructor
  · have : (b0.toNat * 256 + b1.toNat) / 256 = b0.toNat := by omega
    rw [this, UInt8.ofNat_toNat]
  · have : (b0.toNat * 256 + b1.toNat) % 256 = b1.toNat := by omega
    rw [this, UInt8.ofNat_toNat]

/-- Re-encoding a four-byte read reproduces those four bytes. -/
theorem encodeU32_decodeU32 (b0 b1 b2 b3 : UInt8) :
    encodeU32 (decodeU32 b0 b1 b2 b3) = [b0, b1, b2, b3] := by
  have h0 : b0.toNat < 256 := b0.toNat_lt_size
  have h1 : b1.toNat < 256 := b1.toNat_lt_size
  have h2 : b2.toNat < 256 := b2.toNat_lt_size
  have h3 : b3.toNat < 256 := b3.toNat_lt_size
  simp only [encodeU32, decodeU32, List.cons.injEq, and_true]
  refine ⟨?_, ?_, ?_, ?_⟩
  · have : (b0.toNat * 2 ^ 24 + b1.toNat * 2 ^ 16 + b2.toNat * 2 ^ 8
        + b3.toNat) / 2 ^ 24 = b0.toNat := by omega
    rw [this, UInt8.ofNat_toNat]
  · have : (b0.toNat * 2 ^ 24 + b1.toNat * 2 ^ 16 + b2.toNat * 2 ^ 8
        + b3.toNat) / 2 ^ 16 % 256 = b1.toNat := by omega
    rw [this, UInt8.ofNat_toNat]
  · have : (b0.toNat * 2 ^ 24 + b1.toNat * 2 ^ 16 + b2.toNat * 2 ^ 8
        + b3.toNat) / 2 ^ 8 % 256 = b2.toNat := by omega
    rw [this, UInt8.ofNat_toNat]
  · have : (b0.toNat * 2 ^ 24 + b1.toNat * 2 ^ 16 + b2.toNat * 2 ^ 8
        + b3.toNat) % 256 = b3.toNat := by omega
    rw [this, UInt8.ofNat_toNat]

/-- Any four bytes read as a u32 are below `2 ^ 32`, so `encode` never
refuses a length a decoder produced. -/
theorem decodeU32_lt (b0 b1 b2 b3 : UInt8) :
    decodeU32 b0 b1 b2 b3 < 2 ^ 32 := by
  have h0 : b0.toNat < 256 := b0.toNat_lt_size
  have h1 : b1.toNat < 256 := b1.toNat_lt_size
  have h2 : b2.toNat < 256 := b2.toNat_lt_size
  have h3 : b3.toNat < 256 := b3.toNat_lt_size
  simp only [decodeU32]
  omega

/-- Envelope kinds carried on the wire. -/
inductive Kind where
  | dm
  | group
  | receipt
deriving Repr, DecidableEq

def Kind.toByte : Kind → UInt8
  | .dm => 1
  | .group => 2
  | .receipt => 3

def Kind.ofByte? (b : UInt8) : Option Kind :=
  if b = 1 then some .dm
  else if b = 2 then some .group
  else if b = 3 then some .receipt
  else none

theorem Kind.ofByte?_toByte (k : Kind) : Kind.ofByte? k.toByte = some k := by
  cases k <;> rfl

/-- The reader's inverse: a byte it accepted is the byte that kind
writes. Three accepted values, each with one spelling. -/
theorem Kind.toByte_ofByte? {b : UInt8} {k : Kind}
    (h : Kind.ofByte? b = some k) : k.toByte = b := by
  unfold Kind.ofByte? at h
  split at h
  · rename_i hb; injection h with h; subst h; simp [Kind.toByte, hb]
  · split at h
    · rename_i hb; injection h with h; subst h; simp [Kind.toByte, hb]
    · split at h
      · rename_i hb; injection h with h; subst h; simp [Kind.toByte, hb]
      · exact absurd h (by simp)

/-- A v1 envelope. The payload-length bound is enforced by `encode`. -/
structure Envelope where
  kind : Kind
  payload : List UInt8
deriving Repr, DecidableEq

/-- Encode an envelope. `none` iff the payload cannot fit a u32 length. -/
def encode (e : Envelope) : Option (List UInt8) :=
  if e.payload.length < 2 ^ 32 then
    some (encodeU16 wireVersion ++ [e.kind.toByte]
      ++ encodeU32 e.payload.length ++ e.payload)
  else
    none

/-- Decode an envelope, rejecting anything `encode` would not produce. -/
def decode : List UInt8 → Option Envelope
  | v0 :: v1 :: k :: l0 :: l1 :: l2 :: l3 :: rest =>
    if decodeU16 v0 v1 = wireVersion then
      match Kind.ofByte? k with
      | some kind =>
        if rest.length = decodeU32 l0 l1 l2 l3 then
          some ⟨kind, rest⟩
        else
          none
      | none => none
    else
      none
  | _ => none

/-- Round trip: everything `encode` produces, `decode` returns intact. -/
theorem decode_encode {e : Envelope} {bs : List UInt8}
    (henc : encode e = some bs) : decode bs = some e := by
  unfold encode at henc
  split at henc
  case isTrue h =>
    injection henc with hbs
    subst hbs
    simp [encodeU16, encodeU32, decode, Kind.ofByte?_toByte,
      decodeU16_encodeU16 wireVersion (by decide),
      decodeU32_encodeU32 e.payload.length h]
  case isFalse =>
    exact absurd henc (by simp)

/-! ## Canonicity of the envelope

`decode_encode` above constrains the encoder. This constrains the
*decoder*: every byte string `decode` accepts is exactly what `encode`
writes for the value it returned. Together they make the accepted set
and the written set the same set, which is what an authenticator over
exact bytes needs -- otherwise a peer could re-spell a frame, keep its
meaning, and change its bytes.

The reassembly is its own lemma rather than a block inside the main
proof, and that is not a matter of taste. Inline, the closing step
unfolds `encode` and rebuilds the byte string in a context carrying the
whole case analysis, and the resulting term is large enough to trip the
kernel's recursion limit. Stated over
abstract header bytes it has no case analysis to carry, and the main
proof closes by applying it. -/

/-- Re-encoding what `decode` read reproduces the bytes it read from.

Every hypothesis here is one of `decode`'s own acceptance conditions:
the version matched, the kind byte was one of the three, and the
remainder was exactly as long as the length field said. -/
theorem encode_reassembles {v0 v1 k l0 l1 l2 l3 : UInt8} {kind : Kind}
    {rest : List UInt8}
    (hver : decodeU16 v0 v1 = wireVersion)
    (hkind : kind.toByte = k)
    (hlen : rest.length = decodeU32 l0 l1 l2 l3) :
    encodeU16 wireVersion ++ [kind.toByte] ++ encodeU32 rest.length ++ rest
      = v0 :: v1 :: k :: l0 :: l1 :: l2 :: l3 :: rest := by
  rw [← hver, encodeU16_decodeU16, hkind, hlen, encodeU32_decodeU32]
  rfl

/-- Canonicity: a byte string `decode` accepts is the one `encode`
writes for the envelope it returned. -/
theorem encode_decode {bs : List UInt8} {e : Envelope}
    (h : decode bs = some e) : encode e = some bs := by
  match bs with
  | [] => simp [decode] at h
  | [_] => simp [decode] at h
  | [_, _] => simp [decode] at h
  | [_, _, _] => simp [decode] at h
  | [_, _, _, _] => simp [decode] at h
  | [_, _, _, _, _] => simp [decode] at h
  | [_, _, _, _, _, _] => simp [decode] at h
  | v0 :: v1 :: k :: l0 :: l1 :: l2 :: l3 :: rest =>
    simp only [decode] at h
    split at h
    case isFalse => exact absurd h (by simp)
    case isTrue hver =>
      split at h
      case h_2 => exact absurd h (by simp)
      case h_1 kind hkind =>
        split at h
        case isFalse => exact absurd h (by simp)
        case isTrue hlen =>
          injection h with he
          subst he
          -- `encode` refuses only an over-long payload, and this one is
          -- as long as a four-byte length field said, so it fits.
          have hfit : rest.length < 2 ^ 32 := by
            rw [hlen]; exact decodeU32_lt l0 l1 l2 l3
          simp only [encode, if_pos hfit, Option.some.injEq]
          exact encode_reassembles hver (Kind.toByte_ofByte? hkind) hlen

end Tacenta.Wire
