import Verification.Generated.TacentaWire
import Tacenta.Wire

/-!
# Refinement: the translated Rust against the spec

Theorems connecting the Aeneas translation of `tacenta-wire` (the
actual Rust, under `Generated/`) to the specification model
(`Tacenta.Wire`). Each theorem states both panic-freedom (the
translated function returns `ok`) and agreement with the model under
the abstraction functions below.
-/

open Aeneas Aeneas.Std

-- The u16/u32 bridge proofs and the encode proof deliberately share
-- simp sets; some arguments are unused at individual sites.
set_option linter.unusedSimpArgs false

namespace Verification

/-- Abstraction: translated kind → spec kind. -/
def absKind : tacenta_wire.Kind → Tacenta.Wire.Kind
  | .Dm => .dm
  | .Group => .group
  | .Receipt => .receipt

/-- Abstraction: machine byte → spec byte. -/
def absByte (b : Std.U8) : UInt8 := UInt8.ofNat b.val

/-- Abstraction: machine byte list → spec byte list. -/
def absBytes (l : List Std.U8) : List UInt8 := l.map absByte

/-- `Kind.to_byte` never panics and agrees with the spec's `toByte`. -/
theorem to_byte_refines (k : tacenta_wire.Kind) :
    ∃ b, tacenta_wire.Kind.to_byte k = Result.ok b ∧
      absByte b = (absKind k).toByte := by
  cases k <;> exact ⟨_, rfl, by decide⟩

private theorem u8_eq_of_val_eq {a b : Std.U8} (h : a.val = b.val) :
    a = b :=
  Std.U8.bv_eq_imp_eq a b (BitVec.toNat_injective h)

/-- `Kind.from_byte` never panics and agrees with the spec's
`ofByte?`. -/
theorem from_byte_refines (b : Std.U8) :
    ∃ o, tacenta_wire.Kind.from_byte b = Result.ok o ∧
      o.map absKind = Tacenta.Wire.Kind.ofByte? (absByte b) := by
  unfold tacenta_wire.Kind.from_byte
  split
  · exact ⟨_, rfl, by decide⟩
  · exact ⟨_, rfl, by decide⟩
  · exact ⟨_, rfl, by decide⟩
  · rename_i h1 h2 h3
    refine ⟨none, rfl, ?_⟩
    have hb : b.val < 256 := b.hBounds
    have hv1 : b.val ≠ 1 := fun h => h1 (u8_eq_of_val_eq (by rw [h]; decide))
    have hv2 : b.val ≠ 2 := fun h => h2 (u8_eq_of_val_eq (by rw [h]; decide))
    have hv3 : b.val ≠ 3 := fun h => h3 (u8_eq_of_val_eq (by rw [h]; decide))
    simp [Tacenta.Wire.Kind.ofByte?, absByte, UInt8.ext_iff, UInt8.toNat_ofNat,
      hv1, hv2, hv3]

/-! ## Step lemmas (WP style, for `encode.spec` / `decode.spec`) -/

/-- Abstraction: translated envelope → spec envelope. -/
def absEnvelope (e : tacenta_wire.Envelope) : Tacenta.Wire.Envelope :=
  ⟨absKind e.kind, absBytes e.payload.val⟩

@[step]
theorem to_byte.step_spec (k : tacenta_wire.Kind) :
    tacenta_wire.Kind.to_byte k ⦃ b => absByte b = (absKind k).toByte ⦄ := by
  obtain ⟨b, heq, habs⟩ := to_byte_refines k
  simp only [heq, WP.spec_ok]
  exact habs

/-- `extend_from_slice` for byte vectors: appends, when the result
fits. (Upstream has the definition but no spec lemma yet.) -/
@[step]
theorem extend_from_slice_u8.step_spec (v : alloc.vec.Vec Std.U8)
    (s : Slice Std.U8) (h : v.val.length + s.val.length ≤ Usize.max) :
    alloc.vec.Vec.extend_from_slice core.clone.CloneU8 v s ⦃ v1 =>
      v1.val = v.val ++ s.val ⦄ := by
  unfold alloc.vec.Vec.extend_from_slice
  have hclone : ∀ x ∈ s.val,
      liftFun1 core.clone.impls.CloneU8.clone x = Result.ok x :=
    fun x _ => rfl
  obtain ⟨s', heq, hpost⟩ := WP.spec_imp_exists (Slice.clone_spec hclone)
  split
  · subst hpost
    split
    · rename_i s'' h'
      rw [heq] at h'
      injection h' with h''
      subst h''
      simp [WP.spec_ok]
    · rename_i e h'
      rw [heq] at h'
      simp at h'
    · rename_i h'
      rw [heq] at h'
      simp at h'
  · exfalso
    scalar_tac

/-! ## Byte-level bridges: `BitVec.toBEBytes` vs the spec's div/mod -/

private theorem absByte_mk (bv : BitVec 8) :
    absByte (UScalar.mk bv) = UInt8.ofNat bv.toNat := rfl

private theorem u8_toNat_ofNat (n : Nat) : (UInt8.ofNat n).toNat = n % 256 := by
  simp [UInt8.toNat, UInt8.ofNat]

private theorem absBytes_u16_be (x : Std.U16) :
    absBytes (x.bv.toBEBytes.map (@UScalar.mk .U8)) =
      Tacenta.Wire.encodeU16 x.val := by
  have hb : x.val < 2 ^ 16 := x.hBounds
  have hval : x.bv.toNat = x.val := rfl
  rw [BitVec.toBEBytes]
  rw [BitVec.toLEBytes.eq_def]; norm_num
  rw [BitVec.toLEBytes.eq_def]; norm_num
  rw [BitVec.toLEBytes.eq_def]; norm_num
  simp only [List.reverse_cons, List.reverse_nil, List.nil_append,
    List.cons_append, List.map_cons, List.map_nil, absBytes, absByte_mk,
    Tacenta.Wire.encodeU16, List.cons.injEq, and_true,
    BitVec.toNat_setWidth, BitVec.toNat_ushiftRight, hval,
    UInt8.ext_iff, u8_toNat_ofNat, UScalar.bv_toNat,
    Nat.shiftRight_eq_div_pow]
  omega

private theorem absBytes_u32_be (x : Std.U32) :
    absBytes (x.bv.toBEBytes.map (@UScalar.mk .U8)) =
      Tacenta.Wire.encodeU32 x.val := by
  have hb : x.val < 2 ^ 32 := x.hBounds
  have hval : x.bv.toNat = x.val := rfl
  rw [BitVec.toBEBytes]
  rw [BitVec.toLEBytes.eq_def]; norm_num
  rw [BitVec.toLEBytes.eq_def]; norm_num
  rw [BitVec.toLEBytes.eq_def]; norm_num
  rw [BitVec.toLEBytes.eq_def]; norm_num
  rw [BitVec.toLEBytes.eq_def]; norm_num
  simp only [List.reverse_cons, List.reverse_nil, List.nil_append,
    List.cons_append, List.map_cons, List.map_nil, absBytes, absByte_mk,
    Tacenta.Wire.encodeU32, List.cons.injEq, and_true,
    BitVec.toNat_setWidth, BitVec.toNat_ushiftRight, hval,
    UInt8.ext_iff, u8_toNat_ofNat, UScalar.bv_toNat,
    Nat.shiftRight_eq_div_pow]
  omega

/-! ## Value lemmas so `scalar_tac` sees through the translated ops -/

@[simp, scalar_tac_simps]
theorem with_capacity_val (n : Usize) :
    (alloc.vec.Vec.with_capacity Std.U8 n).val = [] := rfl

@[simp, scalar_tac_simps]
theorem to_slice_val {n : Usize} (a : Array Std.U8 n) :
    (Array.to_slice a).val = a.val := rfl

@[simp, scalar_tac_simps]
theorem to_be_bytes16_val (x : Std.U16) :
    (core.num.U16.to_be_bytes x).val =
      x.bv.toBEBytes.map (@UScalar.mk .U8) := rfl

@[simp, scalar_tac_simps]
theorem to_be_bytes32_val (x : Std.U32) :
    (core.num.U32.to_be_bytes x).val =
      x.bv.toBEBytes.map (@UScalar.mk .U8) := rfl

@[simp, scalar_tac_simps]
theorem deref_val (v : alloc.vec.Vec Std.U8) :
    (alloc.vec.Vec.deref v).val = v.val := rfl

theorem absBytes_append (a b : List Std.U8) :
    absBytes (a ++ b) = absBytes a ++ absBytes b := List.map_append ..

theorem absBytes_nil : absBytes [] = [] := rfl

private theorem absBytes_singleton (x : Std.U8) :
    absBytes [x] = [absByte x] := rfl

theorem absBytes_length (l : List Std.U8) :
    (absBytes l).length = l.length := List.length_map ..

/-! ## The main refinement: `encode` -/

/-- The translated Rust `encode` never panics and agrees with the
spec's `encode` under abstraction.

The hypothesis excludes only payloads within 7 bytes of the address
space (`Usize.max`), which no real `Vec` can reach; it exists because
the model must account for 32-bit platforms. -/
theorem encode.spec (e : tacenta_wire.Envelope)
    (h : e.payload.val.length + 7 ≤ Usize.max) :
    tacenta_wire.encode e ⦃ r =>
      Option.map (fun v => absBytes v.val) r =
        Tacenta.Wire.encode (absEnvelope e) ⦄ := by
  have hlen : (alloc.vec.Vec.len e.payload).val = e.payload.val.length :=
    alloc.vec.Vec.len_val e.payload
  unfold tacenta_wire.encode
  step as ⟨ r, hr1, hr2 ⟩
  by_cases hle : (alloc.vec.Vec.len e.payload).val ≤ U32.max
  · obtain ⟨len, hlen_eq, hlen_val⟩ := hr1 hle
    subst hlen_eq
    simp only [Std.lift, bind_ok]
    step as ⟨ out1, hout1 ⟩
    have hlout1 : out1.val.length = 2 := by simp [hout1]
    step as ⟨ i3, hi3 ⟩
    step as ⟨ out2, hout2 ⟩
    have hlout2 : out2.val.length = 3 := by simp [hout2, hlout1]
    step as ⟨ out3, hout3 ⟩
    have hlout3 : out3.val.length = 7 := by simp [hout3, hlout2]
    step as ⟨ out4, hout4 ⟩
    have hwv : tacenta_wire.WIRE_VERSION.val = Tacenta.wireVersion := by
      unfold tacenta_wire.WIRE_VERSION
      decide
    simp only [WP.spec_ok, Option.map_some]
    rw [Tacenta.Wire.encode]
    rw [if_pos (by simp [absEnvelope, absBytes_length]; scalar_tac)]
    simp only [hout4, hout3, hout2, hout1, absBytes_append, absBytes_nil,
      absBytes_singleton, List.nil_append, with_capacity_val, to_slice_val,
      to_be_bytes16_val, to_be_bytes32_val, deref_val, absBytes_u16_be,
      absBytes_u32_be, hi3, hwv, hlen_val, hlen, absEnvelope,
      absBytes_length, List.append_assoc, Option.some.injEq]
  · have herr := hr2 (by scalar_tac)
    subst herr
    simp only [WP.spec_ok, Option.map_none]
    rw [Tacenta.Wire.encode]
    rw [if_neg (by simp [absEnvelope, absBytes]; scalar_tac)]

/-! ## Bridges for `decode` -/

private theorem u16_eq_of_val_eq {a b : Std.U16} (h : a.val = b.val) :
    a = b :=
  Std.U16.bv_eq_imp_eq a b (BitVec.toNat_injective h)

private theorem fromBE2_toNat (b0 b1 : BitVec 8) :
    (BitVec.fromBEBytes [b0, b1]).toNat = b0.toNat * 256 + b1.toNat := by
  have h0 := b0.isLt
  have h1 := b1.isLt
  simp only [BitVec.fromBEBytes, BitVec.toNat_cast]
  show (BitVec.fromLEBytes [b1, b0]).toNat = _
  have key : BitVec.fromLEBytes [b1, b0] =
      (b0.setWidth 16 <<< 8) + b1.setWidth 16 := by
    simp only [BitVec.fromLEBytes, List.length_cons, List.length_nil]
    bv_decide
  rw [key]
  simp only [BitVec.toNat_add, BitVec.toNat_shiftLeft, BitVec.toNat_setWidth,
    Nat.shiftLeft_eq, List.length_cons, List.length_nil]
  norm_num [BitVec.toNat_setWidth]
  omega

private theorem fromBE4_toNat (b0 b1 b2 b3 : BitVec 8) :
    (BitVec.fromBEBytes [b0, b1, b2, b3]).toNat =
      b0.toNat * 2 ^ 24 + b1.toNat * 2 ^ 16 + b2.toNat * 2 ^ 8 + b3.toNat := by
  have h0 := b0.isLt
  have h1 := b1.isLt
  have h2 := b2.isLt
  have h3 := b3.isLt
  simp only [BitVec.fromBEBytes, BitVec.toNat_cast]
  show (BitVec.fromLEBytes [b3, b2, b1, b0]).toNat = _
  have key : BitVec.fromLEBytes [b3, b2, b1, b0] =
      (b0.setWidth 32 <<< 24) + (b1.setWidth 32 <<< 16) +
        (b2.setWidth 32 <<< 8) + b3.setWidth 32 := by
    simp only [BitVec.fromLEBytes, List.length_cons, List.length_nil]
    bv_decide
  rw [key]
  simp only [BitVec.toNat_add, BitVec.toNat_shiftLeft, BitVec.toNat_setWidth,
    Nat.shiftLeft_eq, List.length_cons, List.length_nil]
  norm_num [BitVec.toNat_setWidth]
  omega

theorem from_be16_val {b0 b1 : Std.U8}
    (a : Std.Array Std.U8 (2#usize)) (h : a.val = [b0, b1]) :
    (core.num.U16.from_be_bytes a).val = b0.val * 256 + b1.val := by
  obtain ⟨aval, hlen⟩ := a
  simp only at h
  subst h
  rw [show (core.num.U16.from_be_bytes ⟨[b0, b1], hlen⟩).val =
    ((BitVec.fromBEBytes ([b0, b1].map Std.U8.bv)).cast (by simp)).toNat
    from rfl]
  simp only [List.map_cons, List.map_nil, BitVec.toNat_cast, fromBE2_toNat,
    UScalar.bv_toNat]

theorem from_be32_val {b0 b1 b2 b3 : Std.U8}
    (a : Std.Array Std.U8 (4#usize)) (h : a.val = [b0, b1, b2, b3]) :
    (core.num.U32.from_be_bytes a).val =
      b0.val * 2 ^ 24 + b1.val * 2 ^ 16 + b2.val * 2 ^ 8 + b3.val := by
  obtain ⟨aval, hlen⟩ := a
  simp only at h
  subst h
  rw [show (core.num.U32.from_be_bytes ⟨[b0, b1, b2, b3], hlen⟩).val =
    ((BitVec.fromBEBytes ([b0, b1, b2, b3].map Std.U8.bv)).cast
      (by simp)).toNat from rfl]
  simp only [List.map_cons, List.map_nil, BitVec.toNat_cast, fromBE4_toNat,
    UScalar.bv_toNat]

theorem decodeU16_abs (b0 b1 : Std.U8) :
    Tacenta.Wire.decodeU16 (absByte b0) (absByte b1) =
      b0.val * 256 + b1.val := by
  have := b0.hBounds
  have := b1.hBounds
  simp [Tacenta.Wire.decodeU16, absByte, u8_toNat_ofNat]

theorem decodeU32_abs (b0 b1 b2 b3 : Std.U8) :
    Tacenta.Wire.decodeU32 (absByte b0) (absByte b1) (absByte b2)
      (absByte b3) =
      b0.val * 2 ^ 24 + b1.val * 2 ^ 16 + b2.val * 2 ^ 8 + b3.val := by
  have := b0.hBounds
  have := b1.hBounds
  have := b2.hBounds
  have := b3.hBounds
  simp [Tacenta.Wire.decodeU32, absByte, u8_toNat_ofNat]

/-- Everything shorter than a full header decodes to nothing. -/
private theorem spec_decode_short {l : List UInt8} (h : l.length < 7) :
    Tacenta.Wire.decode l = none := by
  unfold Tacenta.Wire.decode
  split
  · exfalso
    simp_all
    omega
  · rfl

theorem cast_usize_val (x : Std.U32) :
    (UScalar.cast .Usize x).val = x.val := by
  obtain ⟨y, hy, hyval⟩ := WP.spec_imp_exists
    (UScalar.cast_inBounds_spec .Usize x (by scalar_tac))
  simp only [Std.lift, Result.ok.injEq] at hy
  rw [hy]
  exact hyval

theorem exists_seven_prefix {l : List Std.U8} (h : 7 ≤ l.length) :
    ∃ b0 b1 b2 b3 b4 b5 b6 rest,
      l = b0 :: b1 :: b2 :: b3 :: b4 :: b5 :: b6 :: rest := by
  match l, h with
  | b0 :: b1 :: b2 :: b3 :: b4 :: b5 :: b6 :: rest, _ =>
    exact ⟨_, _, _, _, _, _, _, _, rfl⟩
  | [], h | [_], h | [_, _], h | [_, _, _], h | [_, _, _, _], h
  | [_, _, _, _, _], h | [_, _, _, _, _, _], h => simp at h

theorem wire_version_val : tacenta_wire.WIRE_VERSION.val = 1 := by
  unfold tacenta_wire.WIRE_VERSION
  decide

private theorem uscalar_eq_iff_val_eq {ty : UScalarTy} (x y : UScalar ty) :
    x = y ↔ x.val = y.val := by
  constructor
  · intro h; rw [h]
  · intro h
    have hbv := BitVec.toNat_injective h
    cases x; cases y
    simpa using hbv

theorem bne_val {ty : UScalarTy} (x y : UScalar ty) :
    (x != y) = decide (x.val ≠ y.val) := by
  by_cases h : x = y
  · subst h; simp
  · have hv : x.val ≠ y.val := fun hv => h ((uscalar_eq_iff_val_eq x y).mpr hv)
    simp [bne_iff_ne, h, hv]

/-- The translated Rust `decode` never panics and agrees with the
spec's `decode` under abstraction. -/
theorem get_range_some {T : Type} (s : Slice T)
    (r : core.ops.range.Range Usize)
    (h : r.start ≤ r.«end» ∧ ↑r.«end» ≤ s.length) :
    ∃ sub : Slice T,
      core.slice.Slice.get (core.slice.index.SliceIndexRangeUsizeSlice T) s r
        = Result.ok (some sub) ∧
      sub.val = s.val.slice r.start.val r.«end».val := by
  refine ⟨⟨s.val.slice r.start.val r.«end».val, by
    have := s.property
    have := List.slice_length_le r.start.val r.«end».val s.val
    scalar_tac⟩, ?_, rfl⟩
  simp [core.slice.Slice.get, core.slice.index.SliceIndexRangeUsizeSlice,
    core.slice.index.SliceIndexRangeUsizeSlice.get, h]

theorem get_rangeFrom_some {T : Type} (s : Slice T)
    (r : core.ops.range.RangeFrom Usize) (h : ↑r.start ≤ s.length) :
    ∃ sub : Slice T,
      core.slice.Slice.get (core.slice.index.SliceIndexRangeFromUsizeSlice T)
        s r = Result.ok (some sub) ∧
      sub.val = s.val.drop r.start.val := by
  refine ⟨s.drop r.start, ?_, by simp⟩
  simp [core.slice.Slice.get, core.slice.index.SliceIndexRangeFromUsizeSlice,
    core.slice.index.SliceIndexRangeFromUsizeSlice.get, h]

theorem get_range_none {T : Type} (s : Slice T)
    (r : core.ops.range.Range Usize)
    (h : ¬(r.start ≤ r.«end» ∧ ↑r.«end» ≤ s.length)) :
    core.slice.Slice.get (core.slice.index.SliceIndexRangeUsizeSlice T) s r =
      Result.ok none := by
  simp [core.slice.Slice.get, core.slice.index.SliceIndexRangeUsizeSlice,
    core.slice.index.SliceIndexRangeUsizeSlice.get, h]
  intro h1
  by_contra hc
  push_neg at hc
  exact h ⟨by scalar_tac, by scalar_tac⟩

theorem get_usize_eq {T : Type} (s : Slice T) (i : Usize) :
    core.slice.Slice.get (core.slice.index.SliceIndexUsizeSlice T) s i =
      Result.ok s.val[i.val]? := by
  simp [core.slice.Slice.get, core.slice.index.SliceIndexUsizeSlice]

theorem get_usize_some {T : Type} (s : Slice T) (i : Usize) (x : T)
    (h : s.val[i.val]? = some x) :
    core.slice.Slice.get (core.slice.index.SliceIndexUsizeSlice T) s i =
      Result.ok (some x) := by
  simp [core.slice.Slice.get, core.slice.index.SliceIndexUsizeSlice, h]

theorem try_from_ok {T : Type} (N : Usize)
    (ci : core.marker.Copy T) (s : Slice T) (h : s.length = ↑N) :
    ∃ a : Std.Array T N,
      core.array.TryFromArrayCopySlice.try_from N ci s =
        Result.ok (core.result.Result.Ok a) ∧ a.val = s.val := by
  refine ⟨⟨s.val, by scalar_tac⟩, ?_, rfl⟩
  simp [core.array.TryFromArrayCopySlice.try_from, h]

theorem decode.spec (bytes : Slice Std.U8) :
    tacenta_wire.decode bytes ⦃ o =>
      Option.map absEnvelope o = Tacenta.Wire.decode (absBytes bytes.val) ⦄ := by
  by_cases hlong : 7 ≤ bytes.val.length
  · obtain ⟨b0, b1, b2, b3, b4, b5, b6, rest, hbytes⟩ :=
      exists_seven_prefix hlong
    have hlen7 : bytes.val.length = 7 + rest.length := by
      rw [hbytes]; simp; omega
    have h0v : (0#usize).val = 0 := by scalar_tac
    have h2v : (2#usize).val = 2 := by scalar_tac
    have h3v : (3#usize).val = 3 := by scalar_tac
    have hHLv : tacenta_wire.HEADER_LEN.val = 7 := by
      unfold tacenta_wire.HEADER_LEN; scalar_tac
    have hslice2 : List.slice (0#usize).val (2#usize).val bytes.val
        = [b0, b1] := by
      rw [hbytes, h0v, h2v]; rfl
    have hslice4 : List.slice (3#usize).val tacenta_wire.HEADER_LEN.val
        bytes.val = [b3, b4, b5, b6] := by
      rw [hbytes, h3v, hHLv]; rfl
    have hget2 : bytes.val[(2#usize).val]? = some b2 := by
      rw [hbytes, h2v]; rfl
    have hdrop7 : bytes.val.drop tacenta_wire.HEADER_LEN.val = rest := by
      rw [hbytes, hHLv]; rfl
    have hspec : Tacenta.Wire.decode (absBytes bytes.val) =
        (if Tacenta.Wire.decodeU16 (absByte b0) (absByte b1) =
            Tacenta.wireVersion then
          match Tacenta.Wire.Kind.ofByte? (absByte b2) with
          | some kind =>
            if (absBytes rest).length = Tacenta.Wire.decodeU32 (absByte b3)
                (absByte b4) (absByte b5) (absByte b6) then
              some ⟨kind, absBytes rest⟩
            else none
          | none => none
        else none) := by
      rw [hbytes]
      simp only [absBytes, List.map_cons]
      rfl
    unfold tacenta_wire.decode
    obtain ⟨s2, hs2eq, hs2val⟩ := get_range_some bytes
      ⟨0#usize, 2#usize⟩ (by scalar_tac)
    rw [hs2eq]
    simp only [bind_ok, bind_tc_ok]
    obtain ⟨a2, ha2eq, ha2val⟩ := try_from_ok 2#usize
      core.marker.CopyU8 s2 (by scalar_tac)
    rw [ha2eq]
    simp only [Std.lift, bind_ok, bind_tc_ok]
    have hfv16 : (core.num.U16.from_be_bytes a2).val =
        b0.val * 256 + b1.val :=
      from_be16_val a2 (by rw [ha2val, hs2val, hslice2])
    rw [bne_val, wire_version_val]
    by_cases hv : b0.val * 256 + b1.val = 1
    · rw [if_neg (by simp [hfv16, hv])]
      rw [get_usize_some bytes _ b2 hget2]
      simp only [bind_ok, bind_tc_ok]
      obtain ⟨o2, ho2, ho2abs⟩ := from_byte_refines b2
      rw [ho2]
      simp only [bind_ok, bind_tc_ok]
      cases o2 with
      | none =>
        simp only [WP.spec_ok, Option.map_none]
        rw [hspec, if_pos (by rw [decodeU16_abs]; exact hv),
          show Tacenta.Wire.Kind.ofByte? (absByte b2) = none from
            by simpa using ho2abs.symm]
      | some k =>
        obtain ⟨s4, hs4eq, hs4val⟩ := get_range_some bytes
          ⟨3#usize, tacenta_wire.HEADER_LEN⟩ (by scalar_tac)
        rw [hs4eq]
        simp only [bind_ok, bind_tc_ok]
        obtain ⟨a4, ha4eq, ha4val⟩ := try_from_ok 4#usize
          core.marker.CopyU8 s4 (by scalar_tac)
        rw [ha4eq]
        simp only [Std.lift, bind_ok, bind_tc_ok]
        obtain ⟨sp, hspeq, hspval⟩ := get_rangeFrom_some bytes
          ⟨tacenta_wire.HEADER_LEN⟩ (by scalar_tac)
        rw [hspeq]
        simp only [Std.lift, bind_ok, bind_tc_ok]
        have hfv32 : (core.num.U32.from_be_bytes a4).val =
            b3.val * 2 ^ 24 + b4.val * 2 ^ 16 + b5.val * 2 ^ 8 + b6.val :=
          from_be32_val a4 (by rw [ha4val, hs4val, hslice4])
        have hspv : sp.val = rest := by rw [hspval, hdrop7]
        have hlenv : (Slice.len sp).val = rest.length := by
          rw [Slice.len_val]
          simp [Slice.length, hspv]
        rw [bne_val]
        by_cases hplen : rest.length =
            b3.val * 2 ^ 24 + b4.val * 2 ^ 16 + b5.val * 2 ^ 8 + b6.val
        · rw [if_neg (by simp [hlenv, hfv32, cast_usize_val, hplen])]
          obtain ⟨v, hveq, hvpost⟩ := WP.spec_imp_exists
            (alloc.slice.Slice.to_vec_spec core.clone.CloneU8 sp
              (fun x _ => rfl))
          rw [hveq]
          simp only [bind_ok, bind_tc_ok, WP.spec_ok, Option.map_some]
          rw [hspec, if_pos (by rw [decodeU16_abs]; exact hv),
            show Tacenta.Wire.Kind.ofByte? (absByte b2) = some (absKind k)
              from by simpa using ho2abs.symm]
          have hvval : v.val = rest := by
            rw [← hvpost]; exact hspv
          simp [absEnvelope, hvval, absBytes_length, decodeU32_abs, hplen]
        · rw [if_pos (by simp [hlenv, hfv32, cast_usize_val]; omega)]
          simp only [WP.spec_ok, Option.map_none]
          rw [hspec, if_pos (by rw [decodeU16_abs]; exact hv),
            show Tacenta.Wire.Kind.ofByte? (absByte b2) = some (absKind k)
              from by simpa using ho2abs.symm]
          simp [absBytes_length, decodeU32_abs, hplen]
          omega
    · rw [if_pos (by simp [hfv16, hv])]
      simp only [WP.spec_ok, Option.map_none]
      rw [hspec, if_neg (by rw [decodeU16_abs]; exact hv)]
  · have hshort : (absBytes bytes.val).length < 7 := by
      rw [absBytes_length]; omega
    have h2v : (2#usize).val = 2 := by scalar_tac
    have hHLv : tacenta_wire.HEADER_LEN.val = 7 := by
      unfold tacenta_wire.HEADER_LEN; scalar_tac
    unfold tacenta_wire.decode
    by_cases h2 : 2 ≤ bytes.val.length
    case neg =>
      rw [get_range_none bytes _ (by rintro ⟨-, hc⟩; scalar_tac)]
      simp only [bind_ok, bind_tc_ok, WP.spec_ok, Option.map_none]
      rw [spec_decode_short hshort]
    case pos =>
      obtain ⟨s2, hs2eq, hs2val⟩ := get_range_some bytes
        ⟨0#usize, 2#usize⟩ (by scalar_tac)
      rw [hs2eq]
      simp only [bind_ok, bind_tc_ok]
      obtain ⟨a2, ha2eq, ha2val⟩ := try_from_ok 2#usize
        core.marker.CopyU8 s2 (by scalar_tac)
      rw [ha2eq]
      simp only [Std.lift, bind_ok, bind_tc_ok]
      rw [bne_val, wire_version_val]
      by_cases hv : (core.num.U16.from_be_bytes a2).val = 1
      case neg =>
        rw [if_pos (by simp [hv])]
        simp only [WP.spec_ok, Option.map_none]
        rw [spec_decode_short hshort]
      case pos =>
        rw [if_neg (by simp [hv])]
        rw [get_usize_eq]
        by_cases hg : 2 < bytes.val.length
        case neg =>
          rw [show bytes.val[(2#usize).val]? = none from by
            rw [h2v]; exact List.getElem?_eq_none (by omega)]
          simp only [bind_ok, bind_tc_ok, WP.spec_ok, Option.map_none]
          rw [spec_decode_short hshort]
        case pos =>
          rw [show bytes.val[(2#usize).val]? = some (bytes.val[2]'hg) from by
            rw [h2v]; exact List.getElem?_eq_getElem hg]
          simp only [bind_ok, bind_tc_ok]
          obtain ⟨o2, ho2, ho2abs⟩ := from_byte_refines (bytes.val[2]'hg)
          rw [ho2]
          simp only [bind_ok, bind_tc_ok]
          cases o2 with
          | none =>
            simp only [WP.spec_ok, Option.map_none]
            rw [spec_decode_short hshort]
          | some k =>
            rw [get_range_none bytes _ (by rintro ⟨-, hc⟩; scalar_tac)]
            simp only [bind_ok, bind_tc_ok, WP.spec_ok, Option.map_none]
            rw [spec_decode_short hshort]

/-- The composed round trip, through the translated Rust on both
sides: whatever the Rust `encode` emits, the Rust `decode` returns an
envelope that abstracts to the original. Rests on `encode.spec`,
`decode.spec`, and the specification's own `decode_encode`. -/
theorem encode_decode_roundtrip (e : tacenta_wire.Envelope)
    (h : e.payload.val.length + 7 ≤ Usize.max)
    (v : alloc.vec.Vec Std.U8)
    (henc : tacenta_wire.encode e = Result.ok (some v)) :
    ∃ e', tacenta_wire.decode (alloc.vec.Vec.deref v) =
        Result.ok (some e') ∧
      absEnvelope e' = absEnvelope e := by
  obtain ⟨r, hr, hpost⟩ := WP.spec_imp_exists (encode.spec e h)
  rw [henc] at hr
  injection hr with hr
  subst hr
  simp only [Option.map_some] at hpost
  obtain ⟨o, ho, hopost⟩ := WP.spec_imp_exists
    (decode.spec (alloc.vec.Vec.deref v))
  rw [deref_val] at hopost
  rw [Tacenta.Wire.decode_encode hpost.symm] at hopost
  cases o with
  | none => simp at hopost
  | some e' => exact ⟨e', ho, by simpa using hopost⟩

end Verification
