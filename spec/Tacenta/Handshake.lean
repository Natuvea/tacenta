/-!
# PQXDH key agreement

The post-quantum extended Diffie-Hellman handshake, modelled from the
published specification (Signal's PQXDH document), over *abstract*
primitives: a Diffie-Hellman function, a KEM, and a combining KDF are
type parameters, and the properties the proofs need — DH commutativity
and KEM correctness — enter as hypotheses on the theorems, never as
axioms. No cryptography is implemented here and no cryptographic
*security* is claimed; these are functional-correctness theorems about
the handshake's composition (see `docs/claims.md`; the spec-only
boundary is stated there).

The responder publishes a bundle (identity key, signed prekey, optional
one-time prekey, KEM prekey). The initiator computes three (or four)
DH secrets and a KEM encapsulation against the bundle, and combines
them; the responder recomputes the same secrets from the private
halves and the ciphertext. The theorems pin the handshake's one job:

- `pqxdh_agree` — the initiator and the responder derive the *same*
  session secret, whether or not a one-time prekey is present, given
  DH commutativity and KEM correctness.
- `bundle_public` — the published bundle is a function of public
  halves only: it carries no private key, by construction.
-/

namespace Tacenta.Handshake

variable {Priv Pub S KemPriv KemPub KemCt R SK : Type}

/-- The responder's published prekey bundle: all public halves. The
one-time prekey is optional — a directory may have run out. -/
structure Bundle (Pub KemPub : Type) where
  identity : Pub
  signedPre : Pub
  oneTime : Option Pub
  pqPre : KemPub

/-- The responder's private state behind a bundle. -/
structure Responder (Priv KemPriv : Type) where
  identity : Priv
  signedPre : Priv
  oneTime : Option Priv
  pq : KemPriv

/-- The initiator's private state: a long-term identity and a fresh
ephemeral. -/
structure Initiator (Priv : Type) where
  identity : Priv
  ephemeral : Priv

variable (dh : Priv → Pub → S) (pub : Priv → Pub)
variable (encap : KemPub → R → KemCt × S) (decap : KemPriv → KemCt → S)
variable (kemPub : KemPriv → KemPub)
variable (comb : S → S → S → Option S → S → SK)

/-- The bundle a responder publishes: exactly the public halves of its
private state. -/
def Responder.bundle (r : Responder Priv KemPriv) : Bundle Pub KemPub :=
  ⟨pub r.identity, pub r.signedPre, r.oneTime.map pub, kemPub r.pq⟩

/-- The initiator's side: DH against the bundle's public keys, an
encapsulation against the KEM prekey, and the combine. Returns the
session secret and the ciphertext to send. -/
def initiate (i : Initiator Priv) (b : Bundle Pub KemPub) (rand : R) :
    SK × KemCt :=
  (comb (dh i.identity b.signedPre)
        (dh i.ephemeral b.identity)
        (dh i.ephemeral b.signedPre)
        (b.oneTime.map (dh i.ephemeral))
        (encap b.pqPre rand).2,
   (encap b.pqPre rand).1)

/-- The responder's side: the same secrets from the private halves and
the received ciphertext. -/
def respond (r : Responder Priv KemPriv) (ikA ekA : Pub) (ct : KemCt) : SK :=
  comb (dh r.signedPre ikA)
       (dh r.identity ekA)
       (dh r.signedPre ekA)
       (r.oneTime.map (fun o => dh o ekA))
       (decap r.pq ct)

/-- The bundle carries public halves only, by construction: its fields
are images of `pub`/`kemPub`, so no private key can appear in it. -/
theorem bundle_public (r : Responder Priv KemPriv) :
    (r.bundle (Pub := Pub) (KemPub := KemPub) pub kemPub).identity
        = pub r.identity
      ∧ (r.bundle pub kemPub).signedPre = pub r.signedPre
      ∧ (r.bundle pub kemPub).oneTime = r.oneTime.map pub
      ∧ (r.bundle pub kemPub).pqPre = kemPub r.pq :=
  ⟨rfl, rfl, rfl, rfl⟩

/-- The handshake's one job: both parties derive the same session
secret — with or without a one-time prekey — given DH commutativity
(`dh a (pub b) = dh b (pub a)`) and KEM correctness (decapsulating an
encapsulation returns its shared secret). -/
theorem pqxdh_agree
    (comm : ∀ (a b : Priv), dh a (pub b) = dh b (pub a))
    (kemCorrect : ∀ (sk : KemPriv) (rand : R),
      decap sk (encap (kemPub sk) rand).1 = (encap (kemPub sk) rand).2)
    (i : Initiator Priv) (r : Responder Priv KemPriv) (rand : R) :
    (initiate dh encap comb i (r.bundle pub kemPub) rand).1
      = respond dh decap comb r (pub i.identity) (pub i.ephemeral)
          (initiate dh encap comb i (r.bundle pub kemPub) rand).2 := by
  simp only [initiate, respond, Responder.bundle]
  have hopt : (r.oneTime.map pub).map (dh i.ephemeral)
      = r.oneTime.map (fun o => dh o (pub i.ephemeral)) := by
    cases r.oneTime with
    | none => rfl
    | some o => exact congrArg some (comm i.ephemeral o)
  rw [comm i.identity r.signedPre, comm i.ephemeral r.identity,
      comm i.ephemeral r.signedPre, hopt, kemCorrect]

end Tacenta.Handshake
