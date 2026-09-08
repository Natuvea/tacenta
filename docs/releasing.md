# Releasing

A release is a tag, and the tag is checked against the tree (decision 0090). The order is: version and changelog
in the tree first, merged to `main` and green; the tag second.

1. **Bump the version** everywhere it is declared, to the version the tag
   will carry:
   - `Cargo.toml`, under `[workspace.package]` (every crate takes it);
   - `sdk/typescript/package.json` and `package-lock.json` (both `version`
     fields at the top of the lockfile);
   - `bindings/android/lib/build.gradle.kts` (`version = "..."`).
   The Swift package takes the git tag; it has no version of its own.
2. **Write the changelog section**: `## vX.Y.Z (YYYY-MM-DD)` at the top of
   `CHANGELOG.md`, dated the day the tag is pushed, one bullet per change a
   user of a head or the CLI would notice.
3. **Check**: `bash tooling/check-versions.sh --tag vX.Y.Z` passes on the
   tree. The pre-push hook and the hygiene job run the same script without
   `--tag`, so a tree whose packages disagree cannot be pushed or merged.
4. **Merge to `main` and wait for CI** to be green on the merge commit. If the
   release rides a **stack of pull requests** (each based on the one below),
   retarget every upper PR to `main` first, then merge bottom-up; after each
   merge, rebase the next branch onto the new `main`
   (`git rebase --onto main <old-base-tip> <branch>`) so its diff is only its
   own change. Merging a base while another PR still points at its branch
   closes that PR when the branch is deleted, and its content then conflicts.
5. **Tag that commit** and push the tag. Start from a **clean tree** — a
   `git checkout main` that aborts on an uncommitted file (a rebuilt
   `Cargo.lock`, say) leaves you on the wrong branch, and the tag follows it
   off `main`:

   ```bash
   git reset --hard && git checkout main && git pull
   git tag -a vX.Y.Z -m "vX.Y.Z: one line"
   git push origin vX.Y.Z
   git merge-base --is-ancestor vX.Y.Z origin/main && echo "on main"
   ```

   The last line must print `on main`; if it does not, the tag is on the wrong
   commit (see the immutability note below).

   the deploy, CLI-publish, and conformance workflows all fire on
   the tag. The first two run `check-versions.sh --tag` before anything
   ships, so a tag that got ahead of the tree fails there rather than
   publishing packages that call themselves something else. The
   conformance run waits for the other two, then drives every head
   against the deployed server and places its transcript at
   `tacenta.com/dl/conformance/vX.Y.Z.md`.
6. **Verify what is live** — a green workflow is not proof. The generated
   references (DocC, Dokka, rustdoc, TypeDoc) are **best-effort**
   (`continue-on-error` in the publish workflow): they must never gate a release,
   and a step that "succeeds" under that flag may have failed and published
   nothing. Check the artifact, not the run: the transcript's verdict, the
   manifest's `release` field at `tacenta.com/dl/sdk/surface.json`, the CLI's
   `SHA256SUMS`, and each reference URL returning 200. Then merge any site
   change that was waiting on the tag.

The tag cannot be moved or re-tagged; a mistake is a new version.

The SDK packages (the xcframework zip and the `.aar`) are built on every
push and kept as CI artifacts, not published; `docs/artifacts.md` has what
they are, how they are checked and signed, and what their publication
needs.
