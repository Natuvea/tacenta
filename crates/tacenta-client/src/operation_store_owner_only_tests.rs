//! What the native operation store's files look like to another user of the
//! machine, and what it does when something else is already at a name it uses.
//!
//! The snapshot holds the client's key material, so the file, its lock file and
//! the temporary file a write stages in are all owner-only, and none of them is
//! reached through a link that is already there.
//!
//! **Why the mode test starts a child process.** The mode a new file gets is the
//! requested mode with the process umask's bits cleared, and the umask is
//! process-wide. The parent test starts this same test binary under
//! `sh -c 'umask 000; ...'`, where a plain create yields `0666`, and reads back
//! what the child wrote; a run under the developer's own `022` or `077` would
//! pass or fail with the shell. The shell's probe file shows the relaxed umask
//! took effect.

use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::process::Command;

const CHILD_DIR: &str = "TACENTA_OPERATION_STORE_TEST_DIR";

fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tacenta-operation-store-mode-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn marked(generation: u64, mark: u8) -> OperationSnapshot {
    let mut snapshot = OperationSnapshot::empty(generation);
    snapshot.provider_state = vec![mark];
    snapshot
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// Runs only under [`the_stores_files_are_owner_only_whatever_the_umask`],
/// which starts it under `umask 000`.
#[test]
#[ignore = "started by the_stores_files_are_owner_only_whatever_the_umask under umask 000"]
fn store_child() {
    let dir = PathBuf::from(std::env::var_os(CHILD_DIR).expect("run by the parent test"));
    // What a plain create yields under this umask, so the parent can check the
    // relaxed umask took effect and its `0600` is not vacuous.
    std::fs::File::create(dir.join("probe")).unwrap();
    let mut store = FileOperationStore::new(dir.join("ops.bin"));
    // A first commit creates the files; a second replaces the snapshot.
    assert_eq!(store.commit(&marked(1, 1)), CommitOutcome::Committed);
    assert_eq!(store.commit(&marked(2, 2)), CommitOutcome::Committed);
}

#[test]
fn the_stores_files_are_owner_only_whatever_the_umask() {
    let dir = scratch_dir("umask");
    let child = format!(
        "{}::store_child",
        module_path!().split_once("::").unwrap().1
    );
    let out = Command::new("sh")
        .arg("-c")
        .arg(r#"umask 000; exec "$0" --exact "$1" --ignored"#)
        .arg(std::env::current_exe().unwrap())
        .arg(&child)
        .env(CHILD_DIR, &dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "child failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert_eq!(mode(&dir.join("probe")), 0o666, "the umask was not relaxed");
    assert_eq!(mode(&dir.join("ops.bin")), 0o600);
    assert_eq!(mode(&dir.join("ops.bin.lock")), 0o600);
    assert_eq!(names(&dir), ["ops.bin", "ops.bin.lock", "probe"]);
    let mut store = FileOperationStore::new(dir.join("ops.bin"));
    assert_eq!(store.recover().unwrap().unwrap().generation, 2);
    std::fs::remove_dir_all(&dir).ok();
}

/// A link at the name older versions staged a write in is not followed: the file
/// it points at is not written to, no file is created where a dangling one
/// points, and the commit is unaffected.
#[test]
fn a_link_at_the_old_staging_name_is_not_followed() {
    let dir = scratch_dir("staging");
    let victim = dir.join("victim");
    std::fs::write(&victim, b"victim").unwrap();
    let elsewhere = dir.join("elsewhere");

    for (name, target) in [("live", &victim), ("dangling", &elsewhere)] {
        let path = dir.join(format!("{name}.bin"));
        symlink(target, dir.join(format!("{name}.bin.tmp"))).unwrap();

        let mut store = FileOperationStore::new(&path);
        assert_eq!(store.commit(&marked(1, 7)), CommitOutcome::Committed);

        assert_eq!(store.recover().unwrap().unwrap().provider_state, [7]);
        assert!(
            !std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the link was renamed onto the store's file"
        );
    }

    assert_eq!(std::fs::read(&victim).unwrap(), b"victim");
    assert!(!elsewhere.exists(), "a file was created through the link");
    std::fs::remove_dir_all(&dir).ok();
}

/// A link at the lock name is refused, so the commit fails: nothing is written
/// to the file the link points at, no file is created where a dangling one
/// points, and the store's own file is not written either.
#[test]
fn a_link_at_the_lock_name_refuses_the_commit() {
    let dir = scratch_dir("lock");
    let victim = dir.join("victim");
    std::fs::write(&victim, b"victim").unwrap();
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
    let elsewhere = dir.join("elsewhere");

    for (name, target) in [("live", &victim), ("dangling", &elsewhere)] {
        let path = dir.join(format!("{name}.bin"));
        symlink(target, dir.join(format!("{name}.bin.lock"))).unwrap();

        let mut store = FileOperationStore::new(&path);
        assert_eq!(store.commit(&marked(1, 7)), CommitOutcome::Failed);
        assert_eq!(
            store.commit_after(None, &marked(1, 7)),
            CommitOutcome::Failed
        );

        assert!(!path.exists(), "the store wrote without holding its lock");
    }

    assert_eq!(std::fs::read(&victim).unwrap(), b"victim");
    assert_eq!(mode(&victim), 0o644, "what the link points at was changed");
    assert!(!elsewhere.exists(), "a file was created through the link");
    std::fs::remove_dir_all(&dir).ok();
}
