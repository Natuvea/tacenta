# Contributing

Thank you for your interest. A few things keep contributions clean to accept.

## Developer Certificate of Origin

Every commit must be signed off under the Developer Certificate of Origin (DCO)
version 1.1 (https://developercertificate.org). Signing off certifies that you
wrote the change or otherwise have the right to submit it under the project's
licence. Add a line to each commit message:

    Signed-off-by: Your Name <you@example.com>

`git commit -s` adds it for you.

CI checks this. The `sign-off` job fails a pull request when any commit it adds
lacks a `Signed-off-by:` line, in the last paragraph of the message, that names
the commit's author exactly (`Name <email>` as `git log` shows the author). A
pull request that fails it is not merged. A merge commit is a commit and needs
the line too, so bring a branch up to date by rebasing it rather than merging
the base in. To fix commits already made:

    git rebase --signoff origin/main

A squash merge writes a new commit, and GitHub writes its message when the pull
request is merged, after that check has run. That message must end with the
author's `Signed-off-by:` line as well: keep the lines GitHub copies from the
commits, or add one when the message is replaced or edited. The `checks` job
runs the same check on every push to `main` and fails if a commit the push
introduced is missing it.

## Licence of contributions

This project is licensed under the Apache License, Version 2.0 (see `LICENSE`).
By contributing, you agree that your contributions are licensed under the same
terms. The Apache-2.0 licence includes an express patent grant (section 3).

## Provenance

Work from the published specifications and the standards they cite; do not
use third-party protocol implementations as a reference (tacenta-core's
ADR-0003). See `docs/clean-room-provenance.md`.
