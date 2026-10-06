//! Windows-only: a directory made by `create_admin_only_dir` (or locked by
//! `set_admin_only` through its handle) passes `check_admin_only`, and stops
//! passing once `BUILTIN\Users` is granted write access to it; a junction or a
//! hard link opened without following is reported as such.
//!
//! Naming Administrators as owner needs an elevated token (CI runners are
//! elevated). Without one the tests print why and return, rather than fail on
//! a developer's unelevated shell.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;

use ferro_winauth::file_acl::{
    check_admin_only, check_object, AclViolation, ObjectKind, ObjectViolation,
    FILE_READ_ATTRIBUTES, READ_CONTROL, SID_BUILTIN_ADMINISTRATORS, SID_BUILTIN_USERS, WRITE_DAC,
    WRITE_OWNER,
};

/// `ERROR_INVALID_OWNER`: the token cannot name Administrators as owner.
const ERROR_INVALID_OWNER: i32 = 1307;

/// A fresh, not-yet-existing path under the temp directory.
fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!(
        "ferro-winauth-acl-{tag}-{}-{nanos}",
        std::process::id()
    ))
}

/// Run a System32 tool, asserting it succeeds.
fn run(tool: &str, args: &[&std::ffi::OsStr]) {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    let status = Command::new(Path::new(&root).join("System32").join(tool))
        .args(args)
        .status()
        .expect("run tool");
    assert!(status.success(), "{tool} {args:?} failed: {status}");
}

/// `icacls <path> <args…>`.
fn icacls(path: &Path, args: &[&str]) {
    let mut all = vec![path.as_os_str()];
    all.extend(args.iter().map(std::ffi::OsStr::new));
    run("icacls.exe", &all);
}

/// `mklink <flag> <link> <target>` (junctions and hard links need no
/// privilege).
fn mklink(flag: &str, link: &Path, target: &Path) {
    run(
        "cmd.exe",
        &[
            "/c".as_ref(),
            "mklink".as_ref(),
            flag.as_ref(),
            link.as_os_str(),
            target.as_os_str(),
        ],
    );
}

/// Create an administrator-only directory, or `None` when not elevated.
fn admin_only_dir(tag: &str) -> Option<PathBuf> {
    let dir = scratch(tag);
    match ferro_winauth::create_admin_only_dir(&dir) {
        Ok(()) => Some(dir),
        Err(e) if e.raw_os_error() == Some(ERROR_INVALID_OWNER) => {
            eprintln!("skipping: not elevated, cannot create an Administrators-owned directory");
            None
        }
        Err(e) => panic!("create_admin_only_dir: {e}"),
    }
}

#[test]
fn hardened_directory_passes_until_users_may_write() {
    let Some(dir) = admin_only_dir("dir") else {
        return;
    };
    let facts = ferro_winauth::read_security(&dir).expect("read security");
    assert_eq!(facts.owner.as_deref(), Some(SID_BUILTIN_ADMINISTRATORS));
    assert_eq!(check_admin_only(&facts), Ok(()));

    // A file created inside inherits SYSTEM + Administrators only; once it is
    // handed to Administrators through its handle it passes too.
    let path = dir.join("mia.toml");
    std::fs::write(&path, b"log = 'info'\n").expect("write file");
    let file =
        ferro_winauth::open_no_follow(&path, WRITE_OWNER | READ_CONTROL | FILE_READ_ATTRIBUTES)
            .expect("open file");
    assert_eq!(
        check_object(ObjectKind::File, ferro_winauth::object_info(&file).unwrap()),
        Ok(())
    );
    ferro_winauth::set_administrators_owner(&file).expect("take ownership");
    assert_eq!(
        check_admin_only(&ferro_winauth::security_of(&file).unwrap()),
        Ok(())
    );
    drop(file);

    icacls(&dir, &["/grant", "*S-1-5-32-545:(OI)(CI)(W)"]);
    let facts = ferro_winauth::read_security(&dir).expect("read security");
    assert!(
        matches!(
            check_admin_only(&facts),
            Err(AclViolation::WritableBy { ref sid, .. }) if sid == SID_BUILTIN_USERS
        ),
        "{facts:?}"
    );
    // The new ACE is inherited by the file as well.
    let file_facts = ferro_winauth::read_security(&path).expect("read file security");
    assert!(check_admin_only(&file_facts).is_err(), "{file_facts:?}");

    std::fs::remove_dir_all(&dir).expect("clean up");
}

#[test]
fn set_admin_only_locks_an_open_directory() {
    let Some(probe) = admin_only_dir("probe") else {
        return;
    };
    std::fs::remove_dir(&probe).expect("clean up probe");

    let dir = scratch("lock");
    std::fs::create_dir(&dir).expect("create dir");
    icacls(&dir, &["/grant", "*S-1-5-32-545:(OI)(CI)(M)"]);
    std::fs::write(dir.join("child"), b"x").unwrap();
    assert!(check_admin_only(&ferro_winauth::read_security(&dir).unwrap()).is_err());

    let handle = ferro_winauth::open_no_follow(
        &dir,
        WRITE_DAC | WRITE_OWNER | READ_CONTROL | FILE_READ_ATTRIBUTES,
    )
    .expect("open dir");
    // Without propagation only the directory changes.
    ferro_winauth::set_admin_only(&handle, false).expect("lock");
    let after = ferro_winauth::security_of(&handle).expect("read security");
    assert_eq!(after.owner.as_deref(), Some(SID_BUILTIN_ADMINISTRATORS));
    assert_eq!(check_admin_only(&after), Ok(()), "{after:?}");
    // With it, the child's inherited Users ACE goes too.
    ferro_winauth::set_admin_only(&handle, true).expect("propagate");
    let child = ferro_winauth::read_security(&dir.join("child")).unwrap();
    assert!(
        child
            .dacl
            .as_deref()
            .unwrap()
            .iter()
            .all(|ace| ace.sid.as_deref() != Some(SID_BUILTIN_USERS)),
        "{child:?}"
    );
    drop(handle);

    std::fs::remove_dir_all(&dir).expect("clean up");
}

#[test]
fn junctions_and_hard_links_open_as_themselves() {
    let base = scratch("links");
    std::fs::create_dir(&base).unwrap();
    let target = base.join("target");
    std::fs::create_dir(&target).unwrap();
    let junction = base.join("junction");
    mklink("/J", &junction, &target);
    let file = ferro_winauth::open_no_follow(&junction, READ_CONTROL | FILE_READ_ATTRIBUTES)
        .expect("open junction");
    assert_eq!(
        check_object(
            ObjectKind::Directory,
            ferro_winauth::object_info(&file).unwrap()
        ),
        Err(ObjectViolation::ReparsePoint)
    );
    drop(file);

    let original = base.join("original");
    std::fs::write(&original, b"x").unwrap();
    let link = base.join("link");
    mklink("/H", &link, &original);
    let file = ferro_winauth::open_no_follow(&link, READ_CONTROL | FILE_READ_ATTRIBUTES).unwrap();
    assert_eq!(
        check_object(ObjectKind::File, ferro_winauth::object_info(&file).unwrap()),
        Err(ObjectViolation::HardLinked { links: 2 })
    );
    drop(file);

    std::fs::remove_dir(&junction).unwrap(); // removes the junction, not its target
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn missing_object_is_not_found() {
    let err = ferro_winauth::read_security(&scratch("absent")).expect_err("absent");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}
