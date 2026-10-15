//! `ferro_appid::identify` on hand-built ELF, PE and Mach-O fixtures, an app
//! bundle and a dpkg database on disk, plus truncated and mutated inputs:
//! malformed metadata must yield an error-free identification with no
//! version, never a panic.

mod common;

use std::io::Cursor;
use std::time::Duration;

use ferro_appid::{
    display_version, identify, BinaryFormat, IdentifyError, IdentifyOptions, Limits, Platform,
    RiskFlags, SignerKind, SignerSummary, VersionSource,
};
use sha2::{Digest, Sha384};

struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ferro-appid-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn opts(platform: Platform) -> IdentifyOptions {
    IdentifyOptions {
        platform,
        dpkg_root: "/nonexistent/dpkg".into(),
        ..IdentifyOptions::default()
    }
}

fn run(bytes: &[u8], path: &str, o: &IdentifyOptions) -> ferro_appid::Identification {
    identify(&mut Cursor::new(bytes.to_vec()), path, None, o).unwrap()
}

const NOTE: &str = r#"{"type":"deb","name":"tool","version":"4.2.0-1","os":"debian"}"#;

#[test]
fn hash_and_size_come_from_the_same_bytes() {
    let bin = common::elf64_with_package_note(NOTE);
    let id = run(&bin, "/usr/bin/tool", &opts(Platform::Linux));
    assert_eq!(id.size, bin.len() as u64);
    assert_eq!(id.sha384.as_slice(), Sha384::digest(&bin).as_slice());
    assert_eq!(id.sha384_hex().len(), 96);
    assert_eq!(id.format, BinaryFormat::Elf);
}

#[test]
fn elf_package_notes_are_read_from_sections_and_program_headers() {
    for bin in [
        common::elf64_with_package_note(NOTE),
        common::elf32be_with_program_note(NOTE),
    ] {
        let id = run(&bin, "/usr/bin/tool", &opts(Platform::Linux));
        assert_eq!(id.version.declared_version.as_deref(), Some("4.2.0-1"));
        assert_eq!(id.version.source, VersionSource::ElfNotePackage);
        assert_eq!(id.version.package_name.as_deref(), Some("tool"));
        assert_eq!(id.metadata_error, None);
        assert_eq!(id.flags, RiskFlags(0), "ELF is never flagged unsigned");
    }
    let no_version = run(
        &common::elf64_with_package_note(r#"{"type":"rpm","name":"x"}"#),
        "/usr/bin/x",
        &opts(Platform::Linux),
    );
    assert_eq!(no_version.version.declared_version, None);
    assert_eq!(no_version.version.source, VersionSource::None);
    assert_eq!(display_version(None, 3), "r3");
}

#[test]
fn pe_version_resources_are_read() {
    let vs = common::version_info(&[
        ("CompanyName", "ACME\u{202e}"),
        ("ProductName", "Tool"),
        ("FileVersion", "2.5.1.7"),
        ("ProductVersion", " 2.5.1 "),
    ]);
    let bin = common::pe(Some(&vs), true);
    let id = run(
        &bin,
        r"C:\Program Files\Tool\tool.exe",
        &opts(Platform::Windows),
    );
    assert_eq!(id.format, BinaryFormat::Pe);
    assert_eq!(id.version.declared_version.as_deref(), Some("2.5.1"));
    assert_eq!(id.version.source, VersionSource::PeString);
    assert_eq!(id.version.product_name.as_deref(), Some("Tool"));
    assert_eq!(id.version.company_name.as_deref(), Some("ACME"));
    assert!(id.embedded_signature);
    assert!(id.flags.contains(RiskFlags::UNSIGNED), "no verifier result");

    let valid = SignerSummary {
        kind: SignerKind::Authenticode,
        id: "aa".repeat(32),
        subject: Some("ACME".into()),
        valid: true,
    };
    let id = identify(
        &mut Cursor::new(bin.clone()),
        r"C:\Program Files\Tool\tool.exe",
        Some(&valid),
        &opts(Platform::Windows),
    )
    .unwrap();
    assert!(!id.flags.contains(RiskFlags::UNSIGNED));

    // Only the fixed version: version source 1.
    let id = run(
        &common::pe(Some(&common::version_info(&[])), false),
        r"C:\x\y.exe",
        &opts(Platform::Windows),
    );
    assert_eq!(id.version.declared_version.as_deref(), Some("2.5.1.0"));
    assert_eq!(id.version.source, VersionSource::PeFixed);
    assert!(!id.embedded_signature);

    // ProductVersion missing: FileVersion is used.
    let id = run(
        &common::pe(
            Some(&common::version_info(&[("FileVersion", "9.8")])),
            false,
        ),
        r"C:\x\y.exe",
        &opts(Platform::Windows),
    );
    assert_eq!(id.version.declared_version.as_deref(), Some("9.8"));

    // No resource at all.
    let id = run(
        &common::pe(None, false),
        r"C:\x\y.exe",
        &opts(Platform::Windows),
    );
    assert_eq!(id.version.source, VersionSource::None);
}

#[test]
fn macho_signatures_are_detected_in_every_slice() {
    let signed = run(
        &common::macho64(true),
        "/usr/local/bin/t",
        &opts(Platform::MacOs),
    );
    assert_eq!(signed.format, BinaryFormat::MachO);
    assert!(signed.embedded_signature);
    assert!(
        signed.flags.contains(RiskFlags::UNSIGNED),
        "valid only per verifier"
    );
    assert!(
        !run(
            &common::macho64(false),
            "/usr/local/bin/t",
            &opts(Platform::MacOs)
        )
        .embedded_signature
    );
    let both = common::fat(&[common::macho64(true), common::macho64(true)]);
    assert!(run(&both, "/usr/local/bin/t", &opts(Platform::MacOs)).embedded_signature);
    let mixed = common::fat(&[common::macho64(true), common::macho64(false)]);
    let id = run(&mixed, "/usr/local/bin/t", &opts(Platform::MacOs));
    assert_eq!(id.format, BinaryFormat::MachO);
    assert!(!id.embedded_signature);
}

#[cfg(unix)]
#[test]
fn app_bundle_plists_give_the_macos_version() {
    use std::os::unix::fs::MetadataExt;
    let dir = TempDir::new("bundle");
    let macos = dir.0.join("Tool.app/Contents/MacOS");
    std::fs::create_dir_all(&macos).unwrap();
    let exe = macos.join("Tool");
    std::fs::write(&exe, common::macho64(true)).unwrap();
    std::fs::write(
        dir.0.join("Tool.app/Contents/Info.plist"),
        r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
        <key>CFBundleExecutable</key><string>Tool</string>
        <key>CFBundleIdentifier</key><string>com.example.tool</string>
        <key>CFBundleName</key><string>Tool</string>
        <key>CFBundleShortVersionString</key><string>3.1.4</string>
        <key>CFBundleVersion</key><string>314</string></dict></plist>"#,
    )
    .unwrap();
    let owner = std::fs::metadata(&exe).unwrap().uid();
    let mut o = opts(Platform::MacOs);
    o.exe_owner = Some(owner);
    let mut file = std::fs::File::open(&exe).unwrap();
    let id = identify(&mut file, exe.to_str().unwrap(), None, &o).unwrap();
    assert_eq!(id.version.declared_version.as_deref(), Some("3.1.4"));
    assert_eq!(id.version.source, VersionSource::PlistShort);
    assert_eq!(id.version.bundle_id.as_deref(), Some("com.example.tool"));

    // Another owner's plist is not trusted (unless root owns it).
    if owner != 0 {
        o.exe_owner = Some(owner + 1);
        let id = identify(&mut file, exe.to_str().unwrap(), None, &o).unwrap();
        assert_eq!(id.version.declared_version, None);
        assert_eq!(id.metadata_error, Some("malformed"));
    }

    // A symlinked Info.plist is refused.
    let plist = dir.0.join("Tool.app/Contents/Info.plist");
    let real = dir.0.join("elsewhere.plist");
    std::fs::rename(&plist, &real).unwrap();
    std::os::unix::fs::symlink(&real, &plist).unwrap();
    o.exe_owner = Some(owner);
    let id = identify(&mut file, exe.to_str().unwrap(), None, &o).unwrap();
    assert_eq!(id.version.declared_version, None);
}

#[test]
fn dpkg_gives_the_version_of_the_owning_package() {
    let dir = TempDir::new("dpkg");
    std::fs::create_dir_all(dir.0.join("info")).unwrap();
    std::fs::write(dir.0.join("info/other.list"), "/.\n/usr/bin/other\n").unwrap();
    std::fs::write(dir.0.join("info/tool:amd64.list"), "/.\n/bin\n/bin/tool\n").unwrap();
    std::fs::write(
        dir.0.join("status"),
        "Package: tool\nStatus: install ok installed\nArchitecture: arm64\nVersion: 0.1\n\n\
         Package: tool\nStatus: install ok installed\nArchitecture: amd64\n\
         Description: a tool\n Version: not this\nVersion: 1:2.3-4\n\n\
         Package: other\nStatus: deinstall ok config-files\nVersion: 9\n",
    )
    .unwrap();
    let mut o = opts(Platform::Linux);
    o.dpkg_root = dir.0.clone();
    let bin = common::elf64_with_package_note(r#"{"type":"deb"}"#);
    // The canonical path is under merged /usr; the package lists /bin/tool.
    let id = run(&bin, "/usr/bin/tool", &o);
    assert_eq!(id.version.declared_version.as_deref(), Some("1:2.3-4"));
    assert_eq!(id.version.source, VersionSource::Dpkg);
    assert_eq!(id.version.package_name.as_deref(), Some("tool"));
    // Not installed: no version.
    let id = run(&bin, "/usr/bin/other", &o);
    assert_eq!(id.version.declared_version, None);
    // An ELF note wins over dpkg.
    let id = run(&common::elf64_with_package_note(NOTE), "/usr/bin/tool", &o);
    assert_eq!(id.version.source, VersionSource::ElfNotePackage);
}

#[test]
fn interpreters_and_size_limits() {
    let id = run(b"\x7fELF", "/usr/bin/python3.12", &opts(Platform::Linux));
    assert!(id.flags.contains(RiskFlags::INTERPRETER));
    let mut o = opts(Platform::Linux);
    o.limits.max_file_size = 16;
    let err = identify(&mut Cursor::new(vec![0u8; 17]), "/x", None, &o).unwrap_err();
    assert!(matches!(err, IdentifyError::FileTooLarge));
    assert!(identify(&mut Cursor::new(vec![0u8; 16]), "/x", None, &o).is_ok());
}

#[test]
fn an_exhausted_budget_means_no_version() {
    let mut o = opts(Platform::Linux);
    o.limits = Limits {
        time_budget: Duration::ZERO,
        ..Limits::default()
    };
    std::thread::sleep(Duration::from_millis(2));
    let id = run(&common::elf64_with_package_note(NOTE), "/usr/bin/tool", &o);
    assert_eq!(id.version.declared_version, None);
    assert!(id.metadata_error.is_some());
    let mut o = opts(Platform::Linux);
    o.limits.max_metadata_bytes = 32;
    let id = run(&common::elf64_with_package_note(NOTE), "/usr/bin/tool", &o);
    assert_eq!(id.version.declared_version, None);
    assert_eq!(id.metadata_error, Some("too_much_data"));
}

/// Every prefix and thousands of deterministic byte mutations of every
/// fixture: identification never panics and never fails on metadata.
#[test]
fn truncated_and_mutated_binaries_never_panic() {
    let vs = common::version_info(&[("ProductVersion", "1.0"), ("ProductName", "T")]);
    let fixtures = [
        (common::elf64_with_package_note(NOTE), Platform::Linux),
        (common::elf32be_with_program_note(NOTE), Platform::Linux),
        (common::pe(Some(&vs), true), Platform::Windows),
        (common::macho64(true), Platform::MacOs),
        (
            common::fat(&[common::macho64(true), common::macho64(false)]),
            Platform::MacOs,
        ),
    ];
    let mut seed: u64 = 0x00f1_9a99;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for (bin, platform) in &fixtures {
        let o = opts(*platform);
        for cut in 0..bin.len() {
            identify(&mut Cursor::new(bin[..cut].to_vec()), "/x/y", None, &o).unwrap();
        }
        for _ in 0..2000 {
            let mut m = bin.clone();
            for _ in 0..=(next() % 4) {
                let at = usize::try_from(next() % m.len() as u64).unwrap();
                m[at] = u8::try_from(next() & 0xff).unwrap();
            }
            identify(&mut Cursor::new(m), "/x/y", None, &o).unwrap();
        }
    }
}
