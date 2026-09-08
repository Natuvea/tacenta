# Decision records

One file per non-obvious call — anything a future reader might naively
flip. The bar is one screenful, four sections:

- **Decision** — what was chosen, in one or two sentences.
- **Considered** — the alternatives that were actually on the table.
- **Why** — the reasoning that settled it.
- **What would reopen this** — the observable conditions under which the
  decision should be revisited.

## The five questions

Any record that touches tacenta-core answers these, in the record, before the
**Why**. They come from the mission at the top of that repository's README.

1. **Does this keep the trusted core small?**
2. **Is the behaviour owned by a written specification?**
3. **Can the security claim be reproduced?**
4. **Does it preserve wire compatibility with a named profile?**
5. **Is this protocol functionality, or product coupling trying to enter the
   core?**

A clean answer is not a yes. "No, and here is the boundary that contains it" is
a clean answer; "not applicable" usually is not, and is worth a second look
before it is written.

The fifth question is the one most easily answered wrongly, because product
coupling never arrives announcing itself. It arrives as a convenience: a field
the client happens to need, a type re-exported to save a conversion. The
provider seam is a trait, and the compiler is what forces every call through
it: **a seam that nothing is forced through is a seam that things go around**,
and no amount of counting references finds that.

Numbered in order of arrival (`0003-…`, `0004-…`). Add records as
decisions surface; never backfill speculatively. The numbering has gaps.
