import Tacenta.Handshake

/-!
# Double Ratchet state machine

The ratchet layer above the PQXDH handshake, modelled from the
published specification (Signal's Double Ratchet document), over the
same abstract-primitive style as `Tacenta.Handshake`: the root KDF,
chain KDF, and Diffie-Hellman function are type parameters, and DH
commutativity enters as a hypothesis. Functional correctness of the
state machine only — no cryptographic security claims (see
`docs/claims.md` for the spec-only boundary).

Two layers, each with its guarantee:

**Symmetric-key chains** (`Chain`, `step`): a chain key stepped once
per message, yielding a message key per position.

- `step_key_at` / `step_chain_at` — the key at position `i` is a pure
  function of the initial chain key and `i` (`keyAt`), and stepping
  from position `i` lands at position `i + 1`: derivation is
  deterministic and positional.
- `step_idx` — the position strictly advances on every step, so a
  position is consumed exactly once: the state machine can never
  derive the same message position twice (**no key reuse, by
  position**).
- `keys_agree` — two chains started from equal chain keys derive equal
  keys at every position: the sender/receiver agreement, in-order.

**The DH ratchet** (`Peer`, `ratchetSend` / `ratchetRecv`): each side
holds a root key, a ratchet keypair, the peer's current ratchet public
key, and its two chains. Starting a new sending chain generates a
fresh ratchet key and advances the root; the receiver, on seeing the
new public key, advances symmetrically.

- `ratchet_sync` — if the two peers face each other (equal root keys,
  and A holds the public half of B's current ratchet key), then after
  A ratchets to send and B ratchets on receipt: the new sending and
  receiving chains are equal, and the peers face each other again with
  roles swapped — the induction step of the ping-pong, so agreement is
  preserved across every round trip.
- `init_facing` — a session initialised from the PQXDH handshake
  (session secret as the initial root key, the responder's signed
  prekey as its initial ratchet key) starts facing: the handshake
  composes with the ratchet.

In-order delivery is assumed throughout — which the relay provides and
`Tacenta.Session.pending_ack?` proves (no reorder). Skipped-message
keys (out-of-order receipt) are deliberately not modelled yet; that is
future work, noted in `docs/claims.md`.
-/

namespace Tacenta.Ratchet

variable {RK CK MK S Pub Priv : Type}

/-- A symmetric-key chain: the current chain key and the position of
the next message. -/
structure Chain (CK : Type) where
  ck : CK
  idx : Nat

variable (kdfCk : CK → CK × MK)

/-- The chain key after `n` steps from `ck` — derivation is iteration,
nothing else. -/
def chainAt (ck : CK) : Nat → CK
  | 0 => ck
  | n + 1 => (kdfCk (chainAt ck n)).1

/-- The message key at position `n` of the chain starting at `ck`. -/
def keyAt (ck : CK) (n : Nat) : MK :=
  (kdfCk (chainAt kdfCk ck n)).2

/-- Step the chain once: derive this position's message key, advance
the chain key and the position. -/
def step (c : Chain CK) : MK × Chain CK :=
  ((kdfCk c.ck).2, ⟨(kdfCk c.ck).1, c.idx + 1⟩)

@[simp] theorem chainAt_zero (ck : CK) : chainAt kdfCk ck 0 = ck := rfl

@[simp] theorem chainAt_succ (ck : CK) (n : Nat) :
    chainAt kdfCk ck (n + 1) = (kdfCk (chainAt kdfCk ck n)).1 := rfl

/-- The position strictly advances on every step: a position is
consumed exactly once, so the machine can never derive the same
message position twice. -/
theorem step_idx (c : Chain CK) : (step kdfCk c).2.idx = c.idx + 1 := rfl

/-- Stepping a chain that sits at position `n` of the run from `ck₀`
derives exactly the position-`n` key: derivation is deterministic and
positional. -/
theorem step_key_at (ck₀ : CK) (n : Nat) :
    (step kdfCk ⟨chainAt kdfCk ck₀ n, n⟩).1 = keyAt kdfCk ck₀ n := rfl

/-- ... and lands exactly at position `n + 1` of the same run: the
chain never leaves the run determined by its initial key. -/
theorem step_chain_at (ck₀ : CK) (n : Nat) :
    (step kdfCk ⟨chainAt kdfCk ck₀ n, n⟩).2
      = ⟨chainAt kdfCk ck₀ (n + 1), n + 1⟩ := rfl

/-- Sender/receiver agreement, in-order: chains started from equal
chain keys derive equal message keys at every position. -/
theorem keys_agree {ckA ckB : CK} (h : ckA = ckB) (n : Nat) :
    keyAt kdfCk ckA n = keyAt kdfCk ckB n := by rw [h]

/-- One side of a ratcheting session. -/
structure Peer (RK CK Pub Priv : Type) where
  root : RK
  ourPriv : Priv
  theirPub : Pub
  send : Chain CK
  recv : Chain CK

variable (kdfRk : RK → S → RK × CK) (dh : Priv → Pub → S) (pub : Priv → Pub)

/-- Start a new sending chain with the fresh ratchet key `x`: advance
the root with `DH(x, their current key)`; the receiving chain is
untouched. -/
def ratchetSend (p : Peer RK CK Pub Priv) (x : Priv) : Peer RK CK Pub Priv :=
  { root := (kdfRk p.root (dh x p.theirPub)).1
    ourPriv := x
    theirPub := p.theirPub
    send := ⟨(kdfRk p.root (dh x p.theirPub)).2, 0⟩
    recv := p.recv }

/-- On receiving a message under the new ratchet public key `X`:
advance the root with `DH(our current key, X)` and start the matching
receiving chain; the sending chain is untouched. -/
def ratchetRecv (p : Peer RK CK Pub Priv) (X : Pub) : Peer RK CK Pub Priv :=
  { root := (kdfRk p.root (dh p.ourPriv X)).1
    ourPriv := p.ourPriv
    theirPub := X
    send := p.send
    recv := ⟨(kdfRk p.root (dh p.ourPriv X)).2, 0⟩ }

/-- `A` faces `B` when their root keys agree and `A` holds the public
half of `B`'s current ratchet key — the configuration from which `A`
can ratchet toward `B`. -/
def Facing (A B : Peer RK CK Pub Priv) : Prop :=
  A.root = B.root ∧ A.theirPub = pub B.ourPriv

/-- The ping-pong induction step. If `A` faces `B`, then after `A`
ratchets to send with a fresh key `x` and `B` ratchets on receipt of
`pub x`: `A`'s new sending chain equals `B`'s new receiving chain
(so, with `keys_agree`, every message key of the round agrees), and
`B` faces `A` — the configuration for the reply. Agreement is
therefore preserved across every round trip. -/
theorem ratchet_sync
    (comm : ∀ (a b : Priv), dh a (pub b) = dh b (pub a))
    {A B : Peer RK CK Pub Priv} (x : Priv)
    (h : Facing pub A B) :
    (ratchetSend kdfRk dh A x).send.ck
        = (ratchetRecv kdfRk dh B (pub x)).recv.ck
      ∧ Facing pub (ratchetRecv kdfRk dh B (pub x))
          (ratchetSend kdfRk dh A x) := by
  obtain ⟨hroot, hpub⟩ := h
  have hdh : dh x A.theirPub = dh B.ourPriv (pub x) := by
    rw [hpub, comm]
  refine ⟨?_, ?_, ?_⟩
  · simp only [ratchetSend, ratchetRecv, hroot, hdh]
  · simp only [ratchetSend, ratchetRecv, hroot, hdh]
  · rfl

open Tacenta.Handshake in
/-- The handshake composes with the ratchet: a session initialised
from PQXDH — the session secret as the initial root key on both sides,
the responder's signed prekey as its initial ratchet key, the
initiator holding its public half — starts facing, given the
hypotheses of `pqxdh_agree`. From here `ratchet_sync` carries
agreement through every subsequent round trip. -/
theorem init_facing
    {KemPriv KemPub KemCt R : Type}
    (encap : KemPub → R → KemCt × S) (decap : KemPriv → KemCt → S)
    (kemPub : KemPriv → KemPub)
    (comb : S → S → S → Option S → S → RK)
    (comm : ∀ (a b : Priv), dh a (pub b) = dh b (pub a))
    (kemCorrect : ∀ (sk : KemPriv) (rand : R),
      decap sk (encap (kemPub sk) rand).1 = (encap (kemPub sk) rand).2)
    (i : Initiator Priv) (r : Responder Priv KemPriv) (rand : R)
    (initSend initRecv : Chain CK) (a₀ : Priv) :
    Facing pub
      { root := (initiate dh encap comb i (r.bundle pub kemPub) rand).1
        ourPriv := a₀
        theirPub := pub r.signedPre
        send := initSend
        recv := initRecv }
      { root := respond dh decap comb r (pub i.identity) (pub i.ephemeral)
          (initiate dh encap comb i (r.bundle pub kemPub) rand).2
        ourPriv := r.signedPre
        theirPub := pub i.ephemeral
        send := initRecv
        recv := initSend } := by
  exact ⟨pqxdh_agree dh pub encap decap kemPub comb comm kemCorrect i r rand, rfl⟩

end Tacenta.Ratchet
