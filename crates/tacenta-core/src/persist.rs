//! Writing bytes to a file so that a crash cannot lose or tear them.
//!
//! **Why this is a public utility and not a private detail of one type.**
//! Decision 0077 makes the exported blob the persistence contract:
//! `Client::export_state` hands the caller bytes and the caller decides where
//! they live. That leaves every caller to rediscover the crash-safe write, and
//! most will reach for `fs::write`, which can tear and is not durable when it
//! returns.
//!
//! The sequence lives here, over a path and a slice, rather than inside
//! `DurableOpenParty` (a type the SDK's own client cannot construct), because
//! the write is orthogonal to whatever produced the bytes and every caller
//! has to be able to reach it.
//!
//! **Decision 0078 attaches the rollback anchor here**, for the same reason:
//! so that an anchor can sit on every caller's path rather than inside one
//! provider.
//!
//! **These are 0078's anchor B, reachable on the sealed path.** `seal`/`unseal`
//! below authenticate a generation into the bytes;
//! `tacenta_client::Client::export_state_sealed` calls `seal`, and
//! `connect_with_state_sealed` / `sign_in_with_state_sealed` call `unseal`,
//! refusing a state whose authenticator does not verify. `freshness` is a
//! statement of decisions 3/3a as a function; the running freshness check is
//! the directory's `witness_core`, which the sealed restore reaches through
//! `Client::checkpoint`.
//!
//! **The key is the seam.** 0078 puts the wrapping key in platform secure
//! storage; the client takes it through a `SecureStore` trait, so
//! `seal`/`unseal` authenticate under whatever the platform binding supplies.
//! The iOS Keychain / Android Keystore implementations of that trait are still
//! to be written — until they are, the FFI ships the unsealed path — but the
//! *authenticator* is wired and tested (under a mock key).
//!
//! **Anchor A alone is detection, not the full closure — and B is why.** The
//! directory witnesses a monotone generation (`tacenta-directory`,
//! `Directory::witness`) and the client presents it (`Client::checkpoint`), so
//! a restore of an *unmodified* older state — a legitimate backup, or a naive
//! whole-file replay — is caught and answered by discarding sessions (decision
//! 3). But on the **unsealed** path the generation the client presents is
//! *these very bytes* as plaintext: an attacker who can rewrite the file
//! (the rollback threat) sets the generation high and A reports Fresh. The
//! **sealed** path closes that — the generation is authenticated, so the
//! forgery breaks the seal and the restore is refused — and a `SecureStore`
//! rollback counter additionally catches an older *saved* state. Together they
//! narrow the rollback gap sharply, but do not fully close it: the per-send
//! window remains (`docs/decisions/0078`).

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Write `bytes` to `path` so that a crash leaves `path` holding either its
/// previous complete contents or these new complete contents, never a mix, and,
/// on platforms that support directory synchronization, so that a successful
/// return means the new contents survive a power loss.
///
/// **Those are two separate guarantees and it is worth keeping them apart.**
///
/// *Atomicity*: a temp file in the same directory, written and `fsync`ed, then
/// renamed over the target. `rename` is atomic on a filesystem, so the target
/// is never observed half-written. This is what the fault-injection tests
/// exercise, by simulating a crash between the write and the rename.
///
/// *Durability after return*: where the platform permits it, the containing
/// directory is then `fsync`ed too. A rename is a directory modification and
/// is not on disk until the directory is flushed. Without that step this
/// function could return, the caller could treat the mutation as committed --
/// advance a ratchet, drop a one-time prekey -- and a power loss could still
/// leave the directory entry pointing at the old file. Atomicity would have
/// held; durability would not. Windows does not expose a supported directory
/// sync through Rust's standard library, so this helper preserves atomic
/// replacement there but cannot make that durability claim.
///
/// **The temp file is owner-only and is never reused.** The bytes written here
/// are state and key material, so on Unix the temp file is created with mode
/// `0600` in the `open` call itself, whatever the process umask, and the rename
/// carries that mode to `path`: a file this function writes is `0600` even if
/// it replaced one that was not. The temp file gets a fresh random name and is
/// created with `create_new`, which fails rather than truncate a file that is
/// already there or follow a symbolic link found at that name; on such a
/// collision the next name is tried, and after a few collisions the call fails
/// with `AlreadyExists`. A file or link left at a name this function does not
/// pick is never opened. A crash between creating the temp file and the rename
/// leaves that file behind (owner-only, and safe to delete); the next write
/// does not reuse it. On other platforms the file's access control is whatever
/// the containing directory gives a new file, as before.
///
/// The tests below are split the same way: the fault-injection test covers
/// the first guarantee, and a separate test covers the mechanism of the
/// second.
pub fn write_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_via_temp(path, bytes, temp_path_beside)
}

/// How many times to try again when a temp name is taken (or a lock file
/// vanishes) before reporting it. A random 64-bit name is taken only if
/// something put a file at exactly that name.
const ATTEMPTS: u32 = 8;

/// The write sequence of [`write_atomically`], with the choice of temp name
/// passed in so that a test can make the first names collide.
fn write_via_temp(
    path: &Path,
    bytes: &[u8],
    mut name_temp: impl FnMut(&Path) -> PathBuf,
) -> io::Result<()> {
    let (tmp_path, mut f) = create_temp(path, &mut name_temp)?;
    let staged = f.write_all(bytes).and_then(|()| f.sync_all());
    // Closed before the rename: Windows will not rename an open file.
    drop(f);
    if let Err(e) = staged.and_then(|()| fs::rename(&tmp_path, path)) {
        // The temp file is ours (created just now, exclusively), so removing
        // it cannot touch anything else. Best effort: the error to report is
        // the write's, not the cleanup's.
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    fsync_parent_dir(path)?;
    Ok(())
}

/// Create a fresh temp file for `path`, trying a new name after each collision.
fn create_temp(
    path: &Path,
    name_temp: &mut impl FnMut(&Path) -> PathBuf,
) -> io::Result<(PathBuf, fs::File)> {
    let mut attempt = 1;
    loop {
        let tmp_path = name_temp(path);
        match create_new_private(&tmp_path) {
            Ok(f) => return Ok((tmp_path, f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && attempt < ATTEMPTS => {
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

/// A new name beside `path`: `<path>.<16 hex digits>.tmp`.
fn temp_path_beside(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{:016x}.tmp", rand::random::<u64>()));
    PathBuf::from(tmp)
}

/// Create `path` as a new, empty, write-only handle that only its owner can
/// open (mode `0600` on Unix), failing with `AlreadyExists` if anything -- a
/// file, a directory, or a symbolic link, dangling or not -- is already there.
///
/// The mode is passed to the `open` call, so there is no moment at which the
/// file exists with the umask's mode. On other platforms this is the platform's
/// default access for a new file.
fn create_new_private(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Create `dir`, and any parents that are missing, so that only their owner can
/// open them (mode `0700` on Unix, whatever the umask).
///
/// **A directory that already exists is left as it is**: its mode is its
/// owner's choice and this does not change it, so a directory made by an
/// earlier version keeps whatever mode it has. On other platforms this is
/// `create_dir_all`, and access is whatever the parent gives a new directory.
pub fn create_dir_all_private(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Open the advisory-lock file at `path` for writing, creating it owner-only
/// (mode `0600` on Unix, whatever the umask) if it is not there.
///
/// A lock file is opened again by every caller that takes the lock, so unlike a
/// temp file it has to accept a file that is already there. It accepts only a
/// regular file: a symbolic link, dangling or not, is refused, and so is
/// anything that is swapped in while the file is being opened. Nothing is
/// created through a link, and nothing is written to what a link points at.
/// A lock file left by an earlier version with a wider mode is made owner-only
/// here, and it is an error if that cannot be done. On other platforms the
/// access to a new file is the platform's default.
pub fn open_lock_file(path: &Path) -> io::Result<fs::File> {
    // The file may be removed between "it exists" and opening it; a few rounds
    // ride that out without ever creating through a link.
    for _ in 0..ATTEMPTS {
        match create_new_private(path) {
            Ok(file) => return Ok(file),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        // Without `create`, so a link to a file that is not there is an error
        // and not a new file at the link's target.
        let file = match fs::OpenOptions::new().write(true).open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        require_regular_file_at(&file, path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if file.metadata()?.permissions().mode() & 0o077 != 0 {
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
            }
        }
        return Ok(file);
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "the lock file kept appearing and disappearing",
    ))
}

/// Fail unless `path` is, right now, the regular file `file` is open on: not a
/// link (which `open` follows), and not something swapped in after the check.
fn require_regular_file_at(file: &fs::File, path: &Path) -> io::Result<()> {
    let refuse = || {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not the regular file it was opened as",
        ))
    };
    let on_disk = fs::symlink_metadata(path)?;
    if !on_disk.file_type().is_file() {
        return refuse();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let open = file.metadata()?;
        if (open.dev(), open.ino()) != (on_disk.dev(), on_disk.ino()) {
            return refuse();
        }
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}

/// Flush the directory entry a rename created.
///
/// Named rather than inlined so a test can reach it. **What a test can and
/// cannot show is worth stating**: that this succeeds on a real directory and
/// reports failure rather than swallowing it is testable in process; that the
/// entry survives a power loss is not, because nothing in userspace can cut the
/// power. The fsync is the mechanism, and the mechanism is what is covered.
fn fsync_parent_dir(path: &Path) -> io::Result<()> {
    let Some(dir) = path.parent() else {
        // No parent means the rename could not have succeeded, so this is
        // unreachable in practice.
        return Ok(());
    };
    // An empty parent is `.`, which `File::open` handles; a directory opened
    // read-only can still be synced on Unix.
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    #[cfg(windows)]
    {
        // `File::sync_all` on a directory is unsupported on Windows and turns
        // an already-completed atomic rename into a false write failure. Keep
        // the missing-parent failure contract, but do not claim a directory
        // flush that this platform cannot perform through std.
        if !dir.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "parent directory missing",
            ));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        fs::File::open(dir)?.sync_all()
    }
}

/// The name older versions used for the temp file. Nothing may treat a file or
/// link found there as its own.
#[cfg(test)]
fn old_temp_name(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        // Random rather than a timestamp: the clock ticks in microseconds on
        // some systems, and two tests that start in the same tick would share
        // a directory and remove each other's files.
        p.push(format!(
            "tacenta-persist-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn it_creates_and_then_fully_replaces() {
        let dir = tempdir();
        let path = dir.join("f.bin");
        write_atomically(&path, b"one").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"one");
        write_atomically(&path, b"two-and-longer").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two-and-longer");
        fs::remove_dir_all(&dir).ok();
    }

    /// A crash between the temp write and the rename must not disturb the
    /// target. This is the *atomicity* half.
    #[test]
    fn a_stray_temp_file_does_not_disturb_the_target() {
        let dir = tempdir();
        let path = dir.join("f.bin");
        write_atomically(&path, b"committed").unwrap();

        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        fs::write(PathBuf::from(tmp), b"never renamed").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"committed");
        write_atomically(&path, b"next").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"next");
        fs::remove_dir_all(&dir).ok();
    }

    /// The *durability* half, as far as a process can check it: the parent sync
    /// runs, and it reports failure rather than swallowing it. It does not
    /// prove the entry survives a power loss, and no in-process test can.
    #[test]
    fn the_parent_directory_sync_runs_and_reports_failure() {
        let dir = tempdir();
        let path = dir.join("f.bin");
        write_atomically(&path, b"one").unwrap();
        fsync_parent_dir(&path).unwrap();

        let gone = dir.join("no-such-dir").join("f.bin");
        assert!(
            fsync_parent_dir(&gone).is_err(),
            "a missing parent must be reported, not ignored"
        );
        fs::remove_dir_all(&dir).ok();
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    /// A file already sitting at the old temp name is not reused: the write
    /// neither truncates it nor renames it onto the target.
    #[test]
    fn a_file_at_the_old_temp_name_is_left_alone() {
        let dir = tempdir();
        let path = dir.join("f.bin");
        let existing = old_temp_name(&path);
        fs::write(&existing, b"existing").unwrap();

        write_atomically(&path, b"written").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"written");
        assert_eq!(
            fs::read(&existing).unwrap(),
            b"existing",
            "the file at the old temp name was reused"
        );
        fs::remove_dir_all(&dir).ok();
    }

    /// Two calls do not pick the same temp name, and the name stays beside the
    /// target so the rename cannot cross a filesystem.
    #[test]
    fn temp_names_are_unique_and_beside_the_target() {
        let path = Path::new("/some/dir/f.bin");
        let (a, b) = (temp_path_beside(path), temp_path_beside(path));
        assert_ne!(a, b);
        for name in [a, b] {
            assert_eq!(name.parent(), path.parent());
            let name = name.file_name().unwrap().to_str().unwrap().to_owned();
            assert!(
                name.starts_with("f.bin.") && name.ends_with(".tmp"),
                "{name}"
            );
        }
    }

    /// Creation refuses a file that is already there and leaves it as it was.
    #[test]
    fn creating_a_temp_file_refuses_an_existing_file() {
        let dir = tempdir();
        let existing = dir.join("existing");
        fs::write(&existing, b"existing").unwrap();

        let err = create_new_private(&existing).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&existing).unwrap(), b"existing");
        fs::remove_dir_all(&dir).ok();
    }

    /// The temp name collides with an existing file: that name is skipped, the
    /// existing file is untouched, and the write completes under the next name.
    #[test]
    fn a_collision_moves_on_to_the_next_name() {
        let dir = tempdir();
        let path = dir.join("f.bin");
        let existing = dir.join("existing");
        fs::write(&existing, b"existing").unwrap();

        let mut names = vec![existing.clone(), dir.join("second")].into_iter();
        write_via_temp(&path, b"written", |_| names.next().unwrap()).unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"written");
        assert_eq!(fs::read(&existing).unwrap(), b"existing");
        assert_eq!(
            entries(&dir),
            ["existing", "f.bin"],
            "no temp file left over"
        );
        fs::remove_dir_all(&dir).ok();
    }

    /// Names that keep colliding end in an error after a bounded number of
    /// tries, with the existing file and the target both as they were.
    #[test]
    fn repeated_collisions_fail_and_change_nothing() {
        let dir = tempdir();
        let path = dir.join("f.bin");
        let existing = dir.join("existing");
        fs::write(&path, b"committed").unwrap();
        fs::write(&existing, b"existing").unwrap();

        let mut tries = 0;
        let err = write_via_temp(&path, b"written", |_| {
            tries += 1;
            // A loop that never gives up is a failure, not a hung test run.
            assert!(tries <= 4 * ATTEMPTS, "kept trying a name that is taken");
            existing.clone()
        })
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(tries, ATTEMPTS);
        assert_eq!(fs::read(&path).unwrap(), b"committed");
        assert_eq!(fs::read(&existing).unwrap(), b"existing");
        fs::remove_dir_all(&dir).ok();
    }

    /// A write that cannot complete does not leave its temp file behind. The
    /// rename is made to fail by putting a non-empty directory at the target.
    #[test]
    fn a_failed_write_removes_its_temp_file() {
        let dir = tempdir();
        let path = dir.join("f.bin");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("inside"), b"x").unwrap();

        assert!(write_atomically(&path, b"written").is_err());

        assert_eq!(entries(&dir), ["f.bin"], "a temp file was left behind");
        fs::remove_dir_all(&dir).ok();
    }
}

/// Running a test body in a child process under a relaxed umask, for the tests
/// of what the files and directories in this module look like to another user
/// of the machine.
///
/// **Why a child process.** The mode a new file gets is the requested mode with
/// the process umask's bits cleared, and the umask is process-wide: changing it
/// in a test would race every other test in the binary that creates a file, and
/// a test run under `umask 077` would pass with or without the fix. So the
/// parent test starts this same test binary under `sh -c 'umask 000; ...'`,
/// where a plain `File::create` yields `0666` and a plain `create_dir` `0777`,
/// runs one `#[ignore]`d test in it, and reads back what that test made.
#[cfg(all(test, unix))]
pub(crate) mod umask_child {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    const CHILD_DIR: &str = "TACENTA_TEST_CHILD_DIR";

    /// The directory the parent gave the child. Called by the `#[ignore]`d test.
    pub(crate) fn dir() -> PathBuf {
        PathBuf::from(std::env::var_os(CHILD_DIR).expect("run by its parent test"))
    }

    /// Run the ignored test `name` of the module `module` (`module_path!()` at
    /// the caller) under `umask 000`, with [`dir`] set to `dir`. Panics with the
    /// child's output if it fails.
    pub(crate) fn run(module: &str, name: &str, dir: &Path) {
        let test = format!("{}::{name}", module.split_once("::").unwrap().1);
        let out = Command::new("sh")
            .arg("-c")
            .arg(r#"umask 000; exec "$0" --exact "$1" --ignored"#)
            .arg(std::env::current_exe().unwrap())
            .arg(&test)
            .env(CHILD_DIR, dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "child {test} failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[cfg(all(test, unix))]
mod owner_only {
    use super::umask_child;
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    fn tempdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "tacenta-persist-mode-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Runs only under [`files_are_owner_only_whatever_the_umask`], which
    /// starts it under `umask 000`.
    #[test]
    #[ignore = "started by files_are_owner_only_whatever_the_umask under umask 000"]
    fn writer_child() {
        let dir = umask_child::dir();
        // What a plain create yields under this umask, so the parent can check
        // the relaxed umask took effect and its `0600` is not vacuous.
        fs::File::create(dir.join("probe")).unwrap();
        write_atomically(&dir.join("fresh.bin"), b"fresh").unwrap();
        // A file that already exists with a wide mode, then replaced.
        fs::write(dir.join("replaced.bin"), b"old").unwrap();
        write_atomically(&dir.join("replaced.bin"), b"new").unwrap();
    }

    #[test]
    fn files_are_owner_only_whatever_the_umask() {
        let dir = tempdir();
        umask_child::run(module_path!(), "writer_child", &dir);

        assert_eq!(mode(&dir.join("probe")), 0o666, "the umask was not relaxed");
        assert_eq!(mode(&dir.join("fresh.bin")), 0o600);
        assert_eq!(mode(&dir.join("replaced.bin")), 0o600);
        assert_eq!(fs::read(dir.join("fresh.bin")).unwrap(), b"fresh");
        assert_eq!(fs::read(dir.join("replaced.bin")).unwrap(), b"new");
        let mut left: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, ["fresh.bin", "probe", "replaced.bin"]);
        fs::remove_dir_all(&dir).ok();
    }

    /// Runs only under
    /// [`directories_and_lock_files_are_owner_only_whatever_the_umask`].
    #[test]
    #[ignore = "started by directories_and_lock_files_are_owner_only_whatever_the_umask"]
    fn directories_and_lock_child() {
        let dir = umask_child::dir();
        fs::File::create(dir.join("probe")).unwrap();
        create_dir_all_private(&dir.join("made").join("nested")).unwrap();
        drop(open_lock_file(&dir.join("fresh.lock")).unwrap());
        // A lock file an earlier version created with a wide mode.
        fs::write(dir.join("old.lock"), b"").unwrap();
        drop(open_lock_file(&dir.join("old.lock")).unwrap());
    }

    #[test]
    fn directories_and_lock_files_are_owner_only_whatever_the_umask() {
        let dir = tempdir();
        umask_child::run(module_path!(), "directories_and_lock_child", &dir);

        assert_eq!(mode(&dir.join("probe")), 0o666, "the umask was not relaxed");
        // Every directory the call had to create, not only the last.
        assert_eq!(mode(&dir.join("made")), 0o700);
        assert_eq!(mode(&dir.join("made").join("nested")), 0o700);
        assert_eq!(mode(&dir.join("fresh.lock")), 0o600);
        assert_eq!(mode(&dir.join("old.lock")), 0o600);
        fs::remove_dir_all(&dir).ok();
    }

    /// A directory that exists keeps its mode, and one made inside it is
    /// still owner-only.
    #[test]
    fn an_existing_directory_keeps_its_mode() {
        let dir = tempdir();
        set_mode(&dir, 0o755);

        create_dir_all_private(&dir).unwrap();
        assert_eq!(mode(&dir), 0o755, "an existing directory was changed");
        create_dir_all_private(&dir.join("inside")).unwrap();
        assert_eq!(mode(&dir), 0o755);
        assert_eq!(mode(&dir.join("inside")), 0o700);

        // Something that is not a directory is still an error.
        fs::write(dir.join("file"), b"x").unwrap();
        assert!(create_dir_all_private(&dir.join("file")).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    /// A link at the old temp name is not followed: the file it points at is
    /// not written to, and the link itself is not renamed onto the target.
    #[test]
    fn a_symlink_at_the_old_temp_name_is_not_followed() {
        let dir = tempdir();
        let path = dir.join("f.bin");
        let victim = dir.join("victim");
        fs::write(&victim, b"victim").unwrap();
        let link = old_temp_name(&path);
        symlink(&victim, &link).unwrap();

        write_atomically(&path, b"written").unwrap();

        assert_eq!(fs::read(&victim).unwrap(), b"victim");
        assert_eq!(fs::read(&path).unwrap(), b"written");
        assert!(
            !fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the link was renamed onto the target"
        );
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fs::remove_dir_all(&dir).ok();
    }

    /// A dangling link at the old temp name does not make the write create the
    /// file the link points at.
    #[test]
    fn a_dangling_symlink_at_the_old_temp_name_creates_nothing() {
        let dir = tempdir();
        let path = dir.join("f.bin");
        let elsewhere = dir.join("elsewhere");
        symlink(&elsewhere, old_temp_name(&path)).unwrap();

        write_atomically(&path, b"written").unwrap();

        assert!(!elsewhere.exists(), "the write went through the link");
        assert_eq!(fs::read(&path).unwrap(), b"written");
        fs::remove_dir_all(&dir).ok();
    }

    /// A link at the very name the write chose is skipped, not followed: the
    /// write moves on to the next name, and what the link points at is as it was
    /// (a file that exists, and one that does not).
    #[test]
    fn a_symlink_at_the_chosen_staging_name_is_skipped() {
        let dir = tempdir();
        let path = dir.join("f.bin");
        let victim = dir.join("victim");
        fs::write(&victim, b"victim").unwrap();
        let live = dir.join("live.tmp");
        let dangling = dir.join("dangling.tmp");
        symlink(&victim, &live).unwrap();
        symlink(dir.join("nowhere"), &dangling).unwrap();

        let mut names = vec![live.clone(), dangling.clone(), dir.join("third.tmp")].into_iter();
        write_via_temp(&path, b"written", |_| names.next().unwrap()).unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"written");
        assert_eq!(fs::read(&victim).unwrap(), b"victim");
        assert!(
            !dir.join("nowhere").exists(),
            "the write went through a link"
        );
        assert!(
            fs::symlink_metadata(&live)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            fs::symlink_metadata(&dangling)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fs::remove_dir_all(&dir).ok();
    }

    /// Creation refuses a link, dangling or not, and leaves what it points at
    /// as it was.
    #[test]
    fn creating_a_temp_file_refuses_a_symlink() {
        let dir = tempdir();
        let victim = dir.join("victim");
        fs::write(&victim, b"victim").unwrap();
        let live = dir.join("live");
        let dangling = dir.join("dangling");
        symlink(&victim, &live).unwrap();
        symlink(dir.join("nowhere"), &dangling).unwrap();

        for link in [&live, &dangling] {
            let err = create_new_private(link).unwrap_err();
            assert_eq!(
                err.kind(),
                io::ErrorKind::AlreadyExists,
                "{}",
                link.display()
            );
        }

        assert_eq!(fs::read(&victim).unwrap(), b"victim");
        assert!(!dir.join("nowhere").exists());
        fs::remove_dir_all(&dir).ok();
    }

    /// A lock file is opened again and again: the second open is the same file,
    /// not a new one, and it is left as it was.
    #[test]
    fn a_lock_file_is_reused() {
        let dir = tempdir();
        let path = dir.join("f.lock");

        let first = open_lock_file(&path).unwrap();
        let inode = first.metadata().unwrap().ino();
        drop(first);
        fs::write(&path, b"contents").unwrap();
        let second = open_lock_file(&path).unwrap();

        assert_eq!(second.metadata().unwrap().ino(), inode);
        assert_eq!(fs::read(&path).unwrap(), b"contents", "it was emptied");
        fs::remove_dir_all(&dir).ok();
    }

    /// A link at the lock path is refused, whether it points at a file or at
    /// nothing: no file is created through it and none is written to.
    #[test]
    fn a_symlink_at_the_lock_path_is_refused() {
        let dir = tempdir();
        let victim = dir.join("victim");
        fs::write(&victim, b"victim").unwrap();
        set_mode(&victim, 0o644);
        let live = dir.join("live.lock");
        let dangling = dir.join("dangling.lock");
        symlink(&victim, &live).unwrap();
        symlink(dir.join("nowhere"), &dangling).unwrap();

        for link in [&live, &dangling] {
            assert!(open_lock_file(link).is_err(), "{}", link.display());
        }

        assert_eq!(fs::read(&victim).unwrap(), b"victim");
        assert_eq!(mode(&victim), 0o644, "what the link points at was changed");
        assert!(
            !dir.join("nowhere").exists(),
            "a file was created via the link"
        );
        fs::remove_dir_all(&dir).ok();
    }

    /// Anything else at the lock path that is not a regular file is refused.
    #[test]
    fn a_directory_at_the_lock_path_is_refused() {
        let dir = tempdir();
        let path = dir.join("f.lock");
        fs::create_dir(&path).unwrap();

        assert!(open_lock_file(&path).is_err());
        fs::remove_dir_all(&dir).ok();
    }
}

// ---------------------------------------------------------------- the anchor
//
// Decision 0078's local half. The server-side generation witness is not here:
// it travels on the authenticated directory path, so it belongs to that
// frame's authentication rather than to a new field here.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// This envelope's own format version, separate from any version inside the
/// bytes it wraps.
const SEAL_VERSION: u8 = 0x01;
const GENERATION_LEN: usize = 8;
const TAG_LEN: usize = 32;
const SEAL_OVERHEAD: usize = 1 + GENERATION_LEN + TAG_LEN;

/// The label this envelope's authenticator is derived under.
///
/// Follows the scheme tacenta-core's `tacenta-core/LABELS.md` sets for new labels: a
/// `tacenta:` prefix, `:` as the only separator, a version segment, and a
/// terminator byte that cannot occur in the prefix, which makes prefix-freedom
/// structural rather than something to check.
const SEAL_LABEL: &[u8] = b"tacenta:persisted-state:v1\xff";

/// Why a sealed blob was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SealError {
    /// Not this envelope format, or a version this build does not know.
    UnknownVersion,
    /// Too short to contain a version, a generation and a tag.
    TooShort,
    /// The authenticator does not match. **The bytes were altered, or the key
    /// is wrong, and this cannot tell you which** -- deliberately, because
    /// saying which is a decryption oracle in miniature.
    BadAuthenticator,
}

/// What came out of a blob that authenticated.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Unsealed {
    /// The generation the writer stamped. Authenticated, so an attacker cannot
    /// lower it without breaking the tag.
    pub generation: u64,
    pub payload: Vec<u8>,
}

/// Wrap `payload` with a generation counter and an authenticator.
///
/// **The generation is the point.** A MAC alone gives integrity and not
/// freshness: an attacker who can write the file can write an earlier, validly
/// authenticated file, and every byte checks out. Binding a counter into the
/// authenticated bytes is what lets a reader notice that the state it is
/// holding is older than one it has seen before.
///
/// `key` belongs in platform secure storage -- Keychain, Android Keystore, or
/// equivalent -- and **not beside the blob**. An attacker who can rewrite the
/// file and the key has defeated this; the whole construction rests on those
/// two living in different places.
///
/// The payload is authenticated, not encrypted. At-rest confidentiality is a
/// separate boundary, stated in tacenta-core's
/// `tacenta-spec/protocol/key-deletion.md` as the
/// caller's job, and widening it here would be a decision rather than an
/// implementation detail.
pub fn seal(key: &[u8; 32], generation: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SEAL_OVERHEAD + payload.len());
    out.push(SEAL_VERSION);
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(payload);
    let tag = tag_over(key, &out);
    out.extend_from_slice(&tag);
    out
}

/// Verify and open a blob produced by [`seal`].
pub fn unseal(key: &[u8; 32], sealed: &[u8]) -> Result<Unsealed, SealError> {
    if sealed.len() < SEAL_OVERHEAD {
        return Err(SealError::TooShort);
    }
    if sealed[0] != SEAL_VERSION {
        return Err(SealError::UnknownVersion);
    }
    let (body, tag) = sealed.split_at(sealed.len() - TAG_LEN);

    // Constant-time, through the Mac machinery rather than a byte comparison.
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(SEAL_LABEL);
    m.update(body);
    m.verify_slice(tag)
        .map_err(|_| SealError::BadAuthenticator)?;

    let mut gen_bytes = [0u8; GENERATION_LEN];
    gen_bytes.copy_from_slice(&body[1..1 + GENERATION_LEN]);
    Ok(Unsealed {
        generation: u64::from_be_bytes(gen_bytes),
        payload: body[1 + GENERATION_LEN..].to_vec(),
    })
}

fn tag_over(key: &[u8; 32], body: &[u8]) -> [u8; TAG_LEN] {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(SEAL_LABEL);
    m.update(body);
    let out = m.finalize().into_bytes();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&out);
    tag
}

/// What a reader should do with state whose generation it has just learned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Freshness {
    /// At or ahead of anything seen before. Resume normally.
    Current,
    /// Older than a generation already seen. **Decision 0078: load it, keep the
    /// identity, and discard every session rather than resuming a ratchet.**
    ///
    /// Rollback and a legitimate backup restore are indistinguishable from
    /// outside -- the same bytes, the same action -- so refusing would break
    /// restore and resuming would be the vulnerability. Discarding sessions is
    /// neither: a fresh session is an ordinary event, so the user gets working
    /// software and an attacker gets a client that has forgotten the chain keys
    /// they wanted replayed.
    RolledBack,
}

/// Compare a generation against the highest previously seen.
///
/// `highest_seen` is whatever the caller has recorded, and under 0078 the
/// authoritative copy of it lives in the directory. **Before the directory has
/// been reached, a caller has no `highest_seen` and should resume** (decision
/// 3a): assuming stale until the witness confirms would discard every session
/// on every offline start, which is a protection users switch off.
pub fn freshness(highest_seen: u64, offered: u64) -> Freshness {
    if offered < highest_seen {
        Freshness::RolledBack
    } else {
        Freshness::Current
    }
}

#[cfg(test)]
mod seal_tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    #[test]
    fn a_sealed_blob_opens_to_what_went_in() {
        let sealed = seal(&KEY, 42, b"state bytes");
        let out = unseal(&KEY, &sealed).expect("our own seal must open");
        assert_eq!(out.generation, 42);
        assert_eq!(out.payload, b"state bytes");
    }

    /// **The point of the whole construction.** An attacker who rewrites the
    /// file wants to present an older generation with a payload that still
    /// authenticates. The counter is inside the authenticated bytes, so
    /// lowering it breaks the tag.
    #[test]
    fn the_generation_cannot_be_lowered_without_breaking_the_tag() {
        let sealed = seal(&KEY, 9, b"state bytes");
        let mut rolled = sealed.clone();
        rolled[1..9].copy_from_slice(&1u64.to_be_bytes());
        assert_ne!(rolled, sealed);
        assert_eq!(unseal(&KEY, &rolled), Err(SealError::BadAuthenticator));
    }

    #[test]
    fn every_single_byte_change_is_refused() {
        let sealed = seal(&KEY, 3, b"a payload worth protecting");
        for i in 0..sealed.len() {
            let mut dirty = sealed.clone();
            dirty[i] ^= 0xFF;
            assert!(
                unseal(&KEY, &dirty).is_err(),
                "byte {i} was altered and the blob still opened"
            );
        }
    }

    #[test]
    fn a_different_key_does_not_open_it() {
        let sealed = seal(&KEY, 1, b"x");
        assert_eq!(
            unseal(&[8u8; 32], &sealed),
            Err(SealError::BadAuthenticator)
        );
    }

    #[test]
    fn short_and_foreign_blobs_are_refused_before_the_mac() {
        assert_eq!(unseal(&KEY, b"too short"), Err(SealError::TooShort));
        let mut wrong_version = seal(&KEY, 1, b"x");
        wrong_version[0] = 0xFE;
        assert_eq!(unseal(&KEY, &wrong_version), Err(SealError::UnknownVersion));
    }

    /// Decision 0078's policy, as a function. An equal generation is current,
    /// not rolled back: a client that writes and reads without advancing has
    /// not gone backwards.
    #[test]
    fn freshness_follows_the_policy() {
        assert_eq!(freshness(5, 6), Freshness::Current);
        assert_eq!(freshness(5, 5), Freshness::Current);
        assert_eq!(freshness(5, 4), Freshness::RolledBack);
        // Decision 3a: with nothing seen yet, everything is current.
        assert_eq!(freshness(0, 0), Freshness::Current);
    }
}
