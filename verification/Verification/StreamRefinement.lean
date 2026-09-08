import Verification.Generated.TacentaWire
import Verification.Refinement
import Tacenta.Stream

/-!
# Refinement: the translated stream framing against the spec

`decode_one` refines `Tacenta.Wire.decodeOne`, and both stream loops
refine their spec counterparts, so the whole wire codec — single envelope
and stream, both directions — is machine-checked:

- `decode_stream` refines `decodeStream`: any byte buffer decodes to
  exactly the envelope sequence the spec says, or is rejected, no panic.
- `encode_stream` refines `encodeStream` (given the total encoded length
  fits `Usize`): the concatenated encodings are exactly what the spec
  produces.

Both loops use `loop.spec_decr_nat` (the same shape as
`user_delivered_refines`) — the byte count is the measure for decode
(each step consumes ≥ 1 byte via `decodeOne_consumes`), the envelope
index for encode. Each carries a capacity bound in its invariant: for
decode a simple length bound for `push`; for encode a running
`totalEncodedLen` bound for `extend_from_slice`. The single-envelope
proofs reuse the codec-refinement helpers from `Verification.Refinement`.
-/

open Aeneas Aeneas.Std

set_option linter.unusedSimpArgs false

namespace Verification

/-- RangeTo slice-get, in the existential shape the proofs consume. -/
private theorem get_rangeTo_some {T : Type} (s : Slice T)
    (r : core.ops.range.RangeTo Usize) (h : ↑r.«end» ≤ s.length) :
    ∃ sub : Slice T,
      core.slice.Slice.get (core.slice.index.SliceIndexRangeToUsizeSlice T) s r
        = Result.ok (some sub) ∧
      sub.val = s.val.slice 0 r.«end».val := by
  refine ⟨⟨s.val.slice 0 r.«end».val, by
    have := s.property
    have := List.slice_length_le 0 r.«end».val s.val
    scalar_tac⟩, ?_, rfl⟩
  simp [core.slice.Slice.get, core.slice.index.SliceIndexRangeToUsizeSlice,
    core.slice.index.SliceIndexRangeToUsizeSlice.get, h]

private theorem get_rangeTo_none {T : Type} (s : Slice T)
    (r : core.ops.range.RangeTo Usize) (h : ¬ ↑r.«end» ≤ s.length) :
    core.slice.Slice.get (core.slice.index.SliceIndexRangeToUsizeSlice T) s r
      = Result.ok none ∧ True := by
  refine ⟨?_, trivial⟩
  simp [core.slice.Slice.get, core.slice.index.SliceIndexRangeToUsizeSlice,
    core.slice.index.SliceIndexRangeToUsizeSlice.get, h]

/-- Everything shorter than a full header parses to nothing. -/
private theorem decodeOne_short {l : List UInt8} (h : l.length < 7) :
    Tacenta.Wire.decodeOne l = none := by
  unfold Tacenta.Wire.decodeOne
  split
  · rename_i v0 v1 k l0 l1 l2 l3 tail
    simp only [List.length_cons] at h
    omega
  · rfl

/-- `slice 0 n = take n`, and `take`/`drop` of the header tail line up
with the spec's `rest.take len` / `rest.drop len`. -/
private theorem slice_zero {α : Type} (l : List α) (n : Nat) :
    l.slice 0 n = l.take n := by
  simp [List.slice]

/-- The translated `decode_one` never panics and agrees with the spec's
`decodeOne` under abstraction (envelope abstracted, remainder bytes
abstracted). -/
theorem decode_one.spec (bytes : Slice Std.U8) :
    tacenta_wire.decode_one bytes ⦃ o =>
      Option.map (fun p => (absEnvelope p.1, absBytes p.2.val)) o
        = Tacenta.Wire.decodeOne (absBytes bytes.val) ⦄ := by
  by_cases hlong : 7 ≤ bytes.val.length
  · obtain ⟨b0, b1, b2, b3, b4, b5, b6, rest, hbytes⟩ :=
      exists_seven_prefix hlong
    have h0v : (0#usize).val = 0 := by scalar_tac
    have h2v : (2#usize).val = 2 := by scalar_tac
    have h3v : (3#usize).val = 3 := by scalar_tac
    have hHLv : tacenta_wire.HEADER_LEN.val = 7 := by
      unfold tacenta_wire.HEADER_LEN; scalar_tac
    have hslice2 : List.slice (0#usize).val (2#usize).val bytes.val = [b0, b1] := by
      rw [hbytes, h0v, h2v]; rfl
    have hslice4 : List.slice (3#usize).val tacenta_wire.HEADER_LEN.val
        bytes.val = [b3, b4, b5, b6] := by
      rw [hbytes, h3v, hHLv]; rfl
    have hget2 : bytes.val[(2#usize).val]? = some b2 := by
      rw [hbytes, h2v]; rfl
    have hdrop7 : bytes.val.drop tacenta_wire.HEADER_LEN.val = rest := by
      rw [hbytes, hHLv]; rfl
    -- spec decodeOne, expanded on the 7-prefix.
    have hspec : Tacenta.Wire.decodeOne (absBytes bytes.val) =
        (if Tacenta.Wire.decodeU16 (absByte b0) (absByte b1) = Tacenta.wireVersion then
          match Tacenta.Wire.Kind.ofByte? (absByte b2) with
          | some kind =>
            let len := Tacenta.Wire.decodeU32 (absByte b3) (absByte b4)
              (absByte b5) (absByte b6)
            if len ≤ (absBytes rest).length then
              some (⟨kind, (absBytes rest).take len⟩, (absBytes rest).drop len)
            else none
          | none => none
        else none) := by
      rw [hbytes]; simp only [absBytes, List.map_cons]; rfl
    unfold tacenta_wire.decode_one
    obtain ⟨s2, hs2eq, hs2val⟩ := get_range_some bytes ⟨0#usize, 2#usize⟩ (by scalar_tac)
    rw [hs2eq]; simp only [bind_ok, bind_tc_ok]
    obtain ⟨a2, ha2eq, ha2val⟩ := try_from_ok 2#usize core.marker.CopyU8 s2 (by scalar_tac)
    rw [ha2eq]; simp only [Std.lift, bind_ok, bind_tc_ok]
    have hfv16 : (core.num.U16.from_be_bytes a2).val = b0.val * 256 + b1.val :=
      from_be16_val a2 (by rw [ha2val, hs2val, hslice2])
    rw [bne_val, wire_version_val]
    by_cases hv : b0.val * 256 + b1.val = 1
    · rw [if_neg (by simp [hfv16, hv]), get_usize_some bytes _ b2 hget2]
      simp only [bind_ok, bind_tc_ok]
      obtain ⟨o2, ho2, ho2abs⟩ := from_byte_refines b2
      rw [ho2]; simp only [bind_ok, bind_tc_ok]
      cases o2 with
      | none =>
        simp only [WP.spec_ok, Option.map_none]
        rw [hspec, if_pos (by rw [decodeU16_abs]; exact hv),
          show Tacenta.Wire.Kind.ofByte? (absByte b2) = none from by simpa using ho2abs.symm]
      | some k =>
        obtain ⟨s4, hs4eq, hs4val⟩ := get_range_some bytes
          ⟨3#usize, tacenta_wire.HEADER_LEN⟩ (by scalar_tac)
        rw [hs4eq]; simp only [bind_ok, bind_tc_ok]
        obtain ⟨a4, ha4eq, ha4val⟩ := try_from_ok 4#usize core.marker.CopyU8 s4 (by scalar_tac)
        rw [ha4eq]; simp only [Std.lift, bind_ok, bind_tc_ok]
        have hfv32 : (core.num.U32.from_be_bytes a4).val =
            b3.val * 2 ^ 24 + b4.val * 2 ^ 16 + b5.val * 2 ^ 8 + b6.val :=
          from_be32_val a4 (by rw [ha4val, hs4val, hslice4])
        -- after_header = bytes[7..] = rest.
        obtain ⟨sah, hsaheq, hsahval⟩ := get_rangeFrom_some bytes
          ⟨tacenta_wire.HEADER_LEN⟩ (by scalar_tac)
        rw [hsaheq]; simp only [bind_ok, bind_tc_ok]
        have hsahv : sah.val = rest := by rw [hsahval, hdrop7]
        -- the len cast.
        have hlencast : (UScalar.cast .Usize (core.num.U32.from_be_bytes a4)).val =
            b3.val * 2 ^ 24 + b4.val * 2 ^ 16 + b5.val * 2 ^ 8 + b6.val := by
          rw [cast_usize_val, hfv32]
        set len := UScalar.cast .Usize (core.num.U32.from_be_bytes a4) with hlendef
        have hsahlen : sah.length = rest.length := by
          show sah.val.length = _; rw [hsahv]
        have hlenabs : (absBytes rest).length = rest.length := absBytes_length rest
        have hspeclen : Tacenta.Wire.decodeU32 (absByte b3) (absByte b4)
            (absByte b5) (absByte b6) = len.val := by
          rw [decodeU32_abs, ← hlencast]
        by_cases hle : len.val ≤ rest.length
        · obtain ⟨sp, hspeq, hspval⟩ := get_rangeTo_some sah ⟨len⟩ (by
            show len.val ≤ sah.length; rw [hsahlen]; exact hle)
          rw [hspeq]; simp only [bind_ok, bind_tc_ok]
          obtain ⟨sr, hsreq, hsrval⟩ := get_rangeFrom_some sah ⟨len⟩ (by
            show len.val ≤ sah.length; rw [hsahlen]; exact hle)
          rw [hsreq]; simp only [bind_ok, bind_tc_ok]
          obtain ⟨v, hveq, hvpost⟩ := WP.spec_imp_exists
            (alloc.slice.Slice.to_vec_spec core.clone.CloneU8 sp (fun x _ => rfl))
          rw [hveq]; simp only [bind_ok, bind_tc_ok, WP.spec_ok, Option.map_some]
          have hvval : v.val = rest.take len.val := by
            rw [(congrArg Subtype.val hvpost).symm, hspval]
            show sah.val.slice 0 len.val = rest.take len.val
            rw [hsahv]; exact slice_zero rest len.val
          have hsrv : sr.val = rest.drop len.val := by rw [hsrval, hsahv]
          rw [hspec, if_pos (by rw [decodeU16_abs]; exact hv),
            show Tacenta.Wire.Kind.ofByte? (absByte b2) = some (absKind k)
              from by simpa using ho2abs.symm]
          simp only [hspeclen, hlenabs]
          rw [if_pos hle]
          simp only [absEnvelope, hvval, hsrv, absBytes, List.map_take,
            List.map_drop, Prod.mk.injEq, Tacenta.Wire.Envelope.mk.injEq,
            and_self]
        · obtain ⟨hpeq, -⟩ := get_rangeTo_none sah ⟨len⟩ (by
            show ¬ len.val ≤ sah.length; rw [hsahlen]; exact hle)
          rw [hpeq]; simp only [bind_ok, bind_tc_ok, WP.spec_ok, Option.map_none]
          rw [hspec, if_pos (by rw [decodeU16_abs]; exact hv),
            show Tacenta.Wire.Kind.ofByte? (absByte b2) = some (absKind k)
              from by simpa using ho2abs.symm]
          simp only [hspeclen, hlenabs]
          rw [if_neg hle]
    · rw [if_pos (by simp [hfv16, hv])]
      simp only [WP.spec_ok, Option.map_none]
      rw [hspec, if_neg (by rw [decodeU16_abs]; exact hv)]
  · have hshort : (absBytes bytes.val).length < 7 := by
      rw [absBytes_length]; omega
    have h2v : (2#usize).val = 2 := by scalar_tac
    have hHLv : tacenta_wire.HEADER_LEN.val = 7 := by
      unfold tacenta_wire.HEADER_LEN; scalar_tac
    unfold tacenta_wire.decode_one
    by_cases h2 : 2 ≤ bytes.val.length
    case neg =>
      rw [get_range_none bytes _ (by rintro ⟨-, hc⟩; scalar_tac)]
      simp only [bind_ok, bind_tc_ok, WP.spec_ok, Option.map_none]
      rw [decodeOne_short hshort]
    case pos =>
      obtain ⟨s2, hs2eq, hs2val⟩ := get_range_some bytes ⟨0#usize, 2#usize⟩ (by scalar_tac)
      rw [hs2eq]; simp only [bind_ok, bind_tc_ok]
      obtain ⟨a2, ha2eq, ha2val⟩ := try_from_ok 2#usize core.marker.CopyU8 s2 (by scalar_tac)
      rw [ha2eq]; simp only [Std.lift, bind_ok, bind_tc_ok]
      rw [bne_val, wire_version_val]
      by_cases hv : (core.num.U16.from_be_bytes a2).val = 1
      case neg =>
        rw [if_pos (by simp [hv])]
        simp only [WP.spec_ok, Option.map_none]
        rw [decodeOne_short hshort]
      case pos =>
        rw [if_neg (by simp [hv]), get_usize_eq]
        by_cases hg : 2 < bytes.val.length
        case neg =>
          rw [show bytes.val[(2#usize).val]? = none from by
            rw [h2v]; exact List.getElem?_eq_none (by omega)]
          simp only [bind_ok, bind_tc_ok, WP.spec_ok, Option.map_none]
          rw [decodeOne_short hshort]
        case pos =>
          rw [show bytes.val[(2#usize).val]? = some (bytes.val[2]'hg) from by
            rw [h2v]; exact List.getElem?_eq_getElem hg]
          simp only [bind_ok, bind_tc_ok]
          obtain ⟨o2, ho2, ho2abs⟩ := from_byte_refines (bytes.val[2]'hg)
          rw [ho2]; simp only [bind_ok, bind_tc_ok]
          cases o2 with
          | none =>
            simp only [WP.spec_ok, Option.map_none]
            rw [decodeOne_short hshort]
          | some k =>
            rw [get_range_none bytes _ (by
              rintro ⟨-, hc⟩; rw [hHLv] at hc; exact absurd hc hlong)]
            simp only [bind_ok, bind_tc_ok, WP.spec_ok, Option.map_none]
            rw [decodeOne_short hshort]

/-- The decode loop refines `decodeStream`: starting from accumulator
`out`, decoding `buf` yields the already-accumulated envelopes followed by
the stream decode of `buf`. The measure is the byte count (each step
consumes ≥ 1 byte via `decodeOne_consumes`); the length bound in the
invariant discharges `push`'s capacity side condition. -/
private theorem decode_stream_loop_spec
    (out : alloc.vec.Vec tacenta_wire.Envelope) (buf : Slice Std.U8)
    (hcap : out.val.length + buf.val.length ≤ Usize.max) :
    tacenta_wire.decode_stream_loop out buf ⦃ r =>
      Option.map (fun v => v.val.map absEnvelope) r
        = (Tacenta.Wire.decodeStream (absBytes buf.val)).map
            (fun es => out.val.map absEnvelope ++ es) ⦄ := by
  unfold tacenta_wire.decode_stream_loop
  apply Std.loop.spec_decr_nat
    (measure := fun p => p.2.val.length)
    (inv := fun p =>
      (Tacenta.Wire.decodeStream (absBytes p.2.val)).map
          (fun es => p.1.val.map absEnvelope ++ es)
        = (Tacenta.Wire.decodeStream (absBytes buf.val)).map
            (fun es => out.val.map absEnvelope ++ es)
      ∧ p.1.val.length + p.2.val.length ≤ Usize.max)
  · rintro ⟨o, b⟩ ⟨hinv, hbnd⟩
    simp only at hinv hbnd ⊢
    unfold tacenta_wire.decode_stream_loop.body
    obtain ⟨bemp, hbemp, hbval⟩ := WP.spec_imp_exists (core.slice.Slice.is_empty_spec b)
    rw [hbemp]
    simp only [bind_ok, bind_tc_ok]
    by_cases hbe : b.val.length = 0
    · have htrue : bemp = true :=
        (iff_of_eq hbval).mpr (by simpa [Slice.length] using hbe)
      rw [htrue]
      simp only [if_true, WP.spec_ok]
      have hbnil : absBytes b.val = [] := by
        rw [List.length_eq_zero_iff.mp hbe]; rfl
      rw [← hinv, hbnil]
      simp [Tacenta.Wire.decodeStream]
    · have hfalse : bemp = false := by
        have hne : ¬ (bemp = true) :=
          fun h => hbe (by simpa [Slice.length] using (iff_of_eq hbval).mp h)
        simpa using hne
      rw [hfalse]
      simp only [Bool.false_eq_true, if_false]
      obtain ⟨dres, hdres, hdpost⟩ := WP.spec_imp_exists (decode_one.spec b)
      rw [hdres]
      simp only [bind_ok, bind_tc_ok]
      have hbne : (absBytes b.val).isEmpty = false := by
        cases hb : b.val with
        | nil => rw [hb] at hbe; simp at hbe
        | cons x xs => simp [absBytes]
      cases dres with
      | none =>
        simp only [WP.spec_ok]
        have hnone : Tacenta.Wire.decodeOne (absBytes b.val) = none := by
          simpa using hdpost.symm
        have hds : Tacenta.Wire.decodeStream (absBytes b.val) = none := by
          rw [Tacenta.Wire.decodeStream]
          simp only [hbne, Bool.false_eq_true, if_false]
          rw [hnone]
        rw [← hinv, hds]
        simp
      | some p =>
        obtain ⟨e, rest⟩ := p
        show (do
          let out1 ← alloc.vec.Vec.push o e
          Result.ok (ControlFlow.cont (out1, rest))) ⦃ _ ⦄
        obtain ⟨o1, ho1, ho1val⟩ := WP.spec_imp_exists
          (alloc.vec.Vec.push_spec o e (by scalar_tac))
        rw [ho1]
        simp only [bind_ok, bind_tc_ok, WP.spec_ok]
        have hdo : Tacenta.Wire.decodeOne (absBytes b.val)
            = some (absEnvelope e, absBytes rest.val) := by
          simpa using hdpost.symm
        have hconsume : rest.val.length < b.val.length := by
          have hc := Tacenta.Wire.decodeOne_consumes hdo
          rw [absBytes_length, absBytes_length] at hc
          exact hc
        refine ⟨⟨?_, ?_⟩, ?_⟩
        · have hcons := Tacenta.Wire.decodeStream_cons hbne hdo
          rw [ho1val, ← hinv, hcons]
          simp only [List.map_append, List.map_cons, List.map_nil,
            Option.map_map, Function.comp]
          congr 1
          funext es
          simp [List.append_assoc]
        · rw [ho1val]; simp only [List.length_append, List.length_cons,
            List.length_nil]; scalar_tac
        · exact hconsume
  · exact ⟨rfl, hcap⟩

/-- The translated `decode_stream` never panics and agrees with the
spec's `decodeStream` under abstraction. -/
theorem decode_stream.spec (bytes : Slice Std.U8) :
    tacenta_wire.decode_stream bytes ⦃ r =>
      Option.map (fun v => v.val.map absEnvelope) r
        = Tacenta.Wire.decodeStream (absBytes bytes.val) ⦄ := by
  unfold tacenta_wire.decode_stream
  have hcap : (alloc.vec.Vec.new tacenta_wire.Envelope).val.length
      + bytes.val.length ≤ Usize.max := by
    have := bytes.property
    simp only [alloc.vec.Vec.new, List.length_nil, Nat.zero_add]
    scalar_tac
  have h := decode_stream_loop_spec (alloc.vec.Vec.new tacenta_wire.Envelope) bytes hcap
  simp only [alloc.vec.Vec.new, List.map_nil, List.nil_append] at h
  simpa using h

/-- Total encoded length of a Rust envelope list: seven header bytes plus
the payload, per envelope. Bounds the bytes the encode loop appends. -/
private def totalEncodedLen (es : List tacenta_wire.Envelope) : Nat :=
  (es.map (fun e => e.payload.val.length + 7)).sum

private theorem totalEncodedLen_drop (es : List tacenta_wire.Envelope)
    (i : Nat) (h : i < es.length) :
    totalEncodedLen (es.drop i)
      = (es[i].payload.val.length + 7) + totalEncodedLen (es.drop (i + 1)) := by
  unfold totalEncodedLen
  rw [List.drop_eq_getElem_cons h, List.map_cons, List.sum_cons]

/-- Spec-level: encoding a cons whose head encodes prepends the head's
bytes to the stream encode of the tail. -/
private theorem encodeStream_cons {e : Tacenta.Wire.Envelope} {b : List UInt8}
    {es : List Tacenta.Wire.Envelope} (h : Tacenta.Wire.encode e = some b) :
    Tacenta.Wire.encodeStream (e :: es)
      = (Tacenta.Wire.encodeStream es).map (fun rest => b ++ rest) := by
  simp only [Tacenta.Wire.encodeStream, h]
  cases Tacenta.Wire.encodeStream es <;> simp

/-- The encode loop refines `encodeStream`: starting from accumulator
`out` at index `i`, encoding the remaining envelopes appends their
concatenated encodings to `out`. The measure is the number of remaining
envelopes; the total-length hypothesis discharges `extend`'s capacity. -/
private theorem encode_stream_loop_spec
    (envelopes : Slice tacenta_wire.Envelope) (out : alloc.vec.Vec Std.U8)
    (i : Usize) (hi : i.val ≤ envelopes.val.length)
    (hcap : out.val.length + totalEncodedLen (envelopes.val.drop i.val) ≤ Usize.max) :
    tacenta_wire.encode_stream_loop envelopes out i ⦃ r =>
      Option.map (fun v => absBytes v.val) r
        = (Tacenta.Wire.encodeStream ((envelopes.val.drop i.val).map absEnvelope)).map
            (fun bs => absBytes out.val ++ bs) ⦄ := by
  unfold tacenta_wire.encode_stream_loop
  apply Std.loop.spec_decr_nat
    (measure := fun p => envelopes.val.length - p.2.val)
    (inv := fun p =>
      p.2.val ≤ envelopes.val.length
      ∧ p.1.val.length + totalEncodedLen (envelopes.val.drop p.2.val) ≤ Usize.max
      ∧ (Tacenta.Wire.encodeStream ((envelopes.val.drop p.2.val).map absEnvelope)).map
          (fun bs => absBytes p.1.val ++ bs)
        = (Tacenta.Wire.encodeStream ((envelopes.val.drop i.val).map absEnvelope)).map
            (fun bs => absBytes out.val ++ bs))
  · rintro ⟨o, j⟩ ⟨hjle, hjcap, hinv⟩
    simp only at hjle hjcap hinv ⊢
    unfold tacenta_wire.encode_stream_loop.body
    by_cases hjlt : j.val < envelopes.val.length
    · rw [if_pos (by have := Slice.len_val envelopes; scalar_tac)]
      obtain ⟨e, he, heval⟩ := WP.spec_imp_exists
        (Slice.index_usize_spec envelopes j (by scalar_tac))
      rw [he]
      simp only [bind_ok, bind_tc_ok]
      have hstep : totalEncodedLen (envelopes.val.drop j.val)
          = (e.payload.val.length + 7)
            + totalEncodedLen (envelopes.val.drop (j.val + 1)) := by
        rw [totalEncodedLen_drop envelopes.val j.val hjlt, ← heval]
      have hencap : e.payload.val.length + 7 ≤ Usize.max := by omega
      obtain ⟨r, hr, hrpost⟩ := WP.spec_imp_exists (encode.spec e hencap)
      rw [hr]
      simp only [bind_ok, bind_tc_ok]
      have hdrop : (envelopes.val.drop j.val).map absEnvelope
          = absEnvelope e :: (envelopes.val.drop (j.val + 1)).map absEnvelope := by
        rw [List.drop_eq_getElem_cons hjlt, List.map_cons, heval]
      cases r with
      | none =>
        show (Result.ok (ControlFlow.done (none : Option (alloc.vec.Vec Std.U8)))) ⦃ _ ⦄
        simp only [WP.spec_ok]
        have hnone : Tacenta.Wire.encode (absEnvelope e) = none := by
          simpa using hrpost.symm
        rw [← hinv, hdrop, Tacenta.Wire.encodeStream, hnone]
        simp
      | some b =>
        have hb : Tacenta.Wire.encode (absEnvelope e) = some (absBytes b.val) := by
          simpa using hrpost.symm
        have hlt32 : (absEnvelope e).payload.length < 2 ^ 32 := by
          by_contra hc
          rw [Tacenta.Wire.encode, if_neg hc] at hb
          exact absurd hb (by simp)
        have hbeq : absBytes b.val
            = Tacenta.Wire.encodeU16 Tacenta.wireVersion ++ [(absEnvelope e).kind.toByte]
              ++ Tacenta.Wire.encodeU32 (absEnvelope e).payload.length
              ++ (absEnvelope e).payload := by
          have hh := hb
          rw [Tacenta.Wire.encode, if_pos hlt32] at hh
          injection hh with hh
          exact hh.symm
        have hblen : b.val.length = e.payload.val.length + 7 := by
          have hl := congrArg List.length hbeq
          simp only [absBytes_length, List.length_append, List.length_cons,
            List.length_nil, Tacenta.Wire.encodeU16, Tacenta.Wire.encodeU32,
            absEnvelope] at hl
          omega
        have hcapb : o.val.length + b.val.length ≤ Usize.max := by
          rw [hblen]; omega
        show (do
          let out1 ← alloc.vec.Vec.extend_from_slice core.clone.CloneU8 o
            (alloc.vec.Vec.deref b)
          let i2 ← j + 1#usize
          Result.ok (ControlFlow.cont (out1, i2))) ⦃ _ ⦄
        obtain ⟨s, hs, hsval⟩ := WP.spec_imp_exists
          (extend_from_slice_u8.step_spec o (alloc.vec.Vec.deref b) (by
            rw [deref_val]; exact hcapb))
        rw [hs]
        simp only [bind_ok, bind_tc_ok]
        obtain ⟨j2, hj2, hj2val⟩ := WP.spec_imp_exists
          (Usize.add_spec (x := j) (y := 1#usize) (by scalar_tac))
        have hj2v : j2.val = j.val + 1 := by scalar_tac
        rw [hj2]
        simp only [bind_ok, bind_tc_ok, WP.spec_ok]
        refine ⟨⟨by scalar_tac, ?_, ?_⟩, by scalar_tac⟩
        · rw [hsval, deref_val, List.length_append, hj2v, hblen, Nat.add_assoc,
            ← hstep]
          exact hjcap
        · rw [hsval, deref_val, hj2v, ← hinv, hdrop, encodeStream_cons hb]
          simp only [Option.map_map, Function.comp_def, absBytes_append,
            List.append_assoc]
    · rw [if_neg (by have := Slice.len_val envelopes; scalar_tac)]
      simp only [WP.spec_ok]
      have hdnil : envelopes.val.drop j.val = [] :=
        List.drop_eq_nil_of_le (by omega)
      rw [← hinv, hdnil]
      simp [Tacenta.Wire.encodeStream]
  · exact ⟨hi, hcap, rfl⟩

/-- The translated `encode_stream` never panics (given the total encoded
length fits) and agrees with the spec's `encodeStream` under abstraction. -/
theorem encode_stream.spec (envelopes : Slice tacenta_wire.Envelope)
    (hcap : totalEncodedLen envelopes.val ≤ Usize.max) :
    tacenta_wire.encode_stream envelopes ⦃ r =>
      Option.map (fun v => absBytes v.val) r
        = Tacenta.Wire.encodeStream (envelopes.val.map absEnvelope) ⦄ := by
  unfold tacenta_wire.encode_stream
  have hcap0 : (alloc.vec.Vec.new Std.U8).val.length
      + totalEncodedLen (envelopes.val.drop 0) ≤ Usize.max := by
    simpa using hcap
  have h := encode_stream_loop_spec envelopes (alloc.vec.Vec.new Std.U8) 0#usize
    (by scalar_tac) hcap0
  simp only [alloc.vec.Vec.new, List.drop_zero, absBytes_nil, List.nil_append] at h
  simpa using h

end Verification
