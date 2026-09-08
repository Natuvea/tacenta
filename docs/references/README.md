# Protocol specification references

The Signal protocol specifications, as published at signal.org and retrieved
on 2026-07-24. These published documents are what
`spec/Tacenta/Handshake.lean` and `spec/Tacenta/Ratchet.lean` were written
from. The table pins the exact revision the Lean model targets by its SHA-256:
fetch the linked PDF and compare its digest. The documents are not
redistributed here; this file carries only the links and digests, since the
documents are Signal's to distribute.

| Document | Revision (as published) | SHA-256 |
| --- | --- | --- |
| [pqxdh.pdf](https://signal.org/docs/specifications/pqxdh/pqxdh.pdf) | Revision 3, 2023-05-24, Last Updated 2024-01-23 | `9fd0e02a5e13075b64adc7aa6dc9baade4f65af70b5571a332991756d98fe896` |
| [doubleratchet.pdf](https://signal.org/docs/specifications/doubleratchet/doubleratchet.pdf) | Revision 4, 2025-11-04 | `1d9b4dc3c6440b0777d747ff42707fccba3a45d209a2bdc33d1ea816aa05990c` |
| [mlkembraid.pdf](https://signal.org/docs/specifications/mlkembraid/mlkembraid.pdf) | Revision 1, 2025-02-21, Last updated 2025-09-26 | `c38a3ab844c7c583e7be15ff714b07792220cb662b5d1e9590e46aa5909a3ee6` |
| [x3dh.pdf](https://signal.org/docs/specifications/x3dh/x3dh.pdf) | Revision 1, 2016-11-04 | `4f699ce92b5afdc1fb7d2f670f18f48372895c30a84cd34e9aec3589dc851a49` |
| [xeddsa.pdf](https://signal.org/docs/specifications/xeddsa/xeddsa.pdf) | Revision 1, 2016-10-20 | `a65684d87d747934e5b05698ed20bec72cd3c30e3f7ff2f6376555d65a5104b7` |
| [sesame.pdf](https://signal.org/docs/specifications/sesame/sesame.pdf) | Revision 2, 2017-04-14 | `e7eca9fdc7bf79a769bea626fd39bf21fbaee5a9ac6bae9350e63768d9502593` |

Source pattern: `https://signal.org/docs/specifications/<name>/<name>.pdf`.

**ML-KEM Braid** is the Sparse Continuous Key Agreement protocol the Double
Ratchet's Section 5 defers to: Section 5 specifies the Sparse Post-Quantum
Ratchet generically over an SCKA and names this document as the recommended
instantiation, so the two are only implementable together.

Roles: **PQXDH** is what `Tacenta.Handshake` models (X3DH is its
predecessor, kept for context); **Double Ratchet** is what
`Tacenta.Ratchet` models; **XEdDSA** is the signature scheme behind the
signed prekey (abstracted in our model, implemented by tacenta-core);
**Sesame** is multi-device session management, relevant to the
device/session model but not yet modelled.

Contributors extending the protocol spec work from these documents and the
standards they cite (tacenta-core's ADR-0003).
