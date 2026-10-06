//! Packaging must never destroy the host's identity: installs, upgrades and a
//! default uninstall keep `host-key.bin` / `svid-seed.bin` (CMIS pins the
//! machine key's public half and refuses any other key for the machine), and
//! only an explicit `--purge` deletes them.

use std::path::{Path, PathBuf};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel_to_manifest: &str) -> String {
    let path = manifest_dir().join(rel_to_manifest);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The lines of the `pkg-macos` Makefile recipe.
fn pkg_macos_recipe() -> Vec<String> {
    let makefile = read("../../Makefile");
    let mut lines = makefile
        .lines()
        .skip_while(|l| !l.starts_with("pkg-macos:"));
    let header = lines.next().expect("the Makefile has a pkg-macos target");
    assert!(header.starts_with("pkg-macos:"));
    lines
        .take_while(|l| {
            l.starts_with('\t')
                || l.starts_with('#')
                || l.is_empty()
                || l.starts_with("ifneq")
                || l.starts_with("endif")
        })
        .map(str::to_string)
        .collect()
}

#[test]
fn the_macos_package_does_not_own_the_config_or_state_directories() {
    // A payload entry under these directories would overwrite the operator's
    // configuration on upgrade, and would put the directory holding the
    // machine key into the receipt, where receipt-driven removal deletes it.
    let recipe = pkg_macos_recipe();
    assert!(
        recipe.iter().any(|l| l.contains("mia-uninstall")),
        "the package ships the identity-preserving uninstaller"
    );
    for line in recipe.iter().filter(|l| !l.trim_start().starts_with('#')) {
        for forbidden in [
            "$(MACOS_PKG_ROOT)/Library/Application Support/FerroGate",
            "$(MACOS_PKG_ROOT)/etc/ferrogate",
        ] {
            assert!(
                !line.contains(forbidden),
                "pkg-macos stages into {forbidden}: {line}"
            );
        }
    }
}

#[test]
fn no_install_or_upgrade_script_deletes_identity_material() {
    let scripts = [
        "dist/macos-scripts/postinstall",
        "dist/macos-scripts/restart-daemon",
        "dist/debian/postinst",
        "dist/debian/postrm",
        "nuget/tools/chocolateyInstall.ps1",
        "nuget/tools/chocolateyUninstall.ps1",
        "nsis/installer.nsi",
        "wix/mia.wxs",
    ];
    let removal = [
        "rm ",
        "rm\t",
        "Remove-Item",
        "Delete ",
        "RMDir",
        "RemoveFile",
        "RemoveFolder",
        "unlink",
    ];
    let identity = [
        "host-key",
        "svid-seed",
        "x509-svid",
        "Application Support/FerroGate",
        "CONFIG_DIR",
        "/var/lib/ferrogate",
        "ProgramData",
        "COMMONAPPDATA",
        "CommonAppData",
    ];
    for script in scripts {
        for (n, line) in read(script).lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with('#') || code.starts_with(';') || code.starts_with("<!--") {
                continue;
            }
            let removes = removal.iter().any(|r| code.contains(r));
            let touches = identity.iter().any(|i| code.contains(i));
            assert!(
                !(removes && touches),
                "{script}:{}: deletes identity material: {line}",
                n + 1
            );
        }
    }
}

#[cfg(unix)]
mod uninstall {
    use super::*;

    const KEY: &[u8] = b"sealed machine key bytes";
    const SEED: &[u8] = b"0123456789abcdef0123456789abcdef";

    struct Root(PathBuf);

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A fake installed system under a scratch root.
    fn installed(tag: &str) -> Root {
        let root = std::env::temp_dir().join(format!("mia-uninstall-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let files: [(&str, &[u8]); 11] = [
            ("usr/local/bin/mia", b"binary"),
            ("usr/local/bin/mia-uninstall", b"script"),
            ("usr/local/share/ferrogate/mia.toml.default", b"defaults"),
            ("Library/LaunchDaemons/com.ferrogate.mia.plist", b"plist"),
            (
                "Library/LaunchAgents/com.ferrogate.mia-tray.plist",
                b"plist",
            ),
            (
                "Applications/FerroGate MIA.app/Contents/MacOS/mia-tray",
                b"tray",
            ),
            ("Library/Application Support/FerroGate/host-key.bin", KEY),
            ("Library/Application Support/FerroGate/svid-seed.bin", SEED),
            (
                "Library/Application Support/FerroGate/mia.toml",
                b"operator config",
            ),
            ("etc/ferrogate/mia.env", b"operator env"),
            ("var/log/ferrogate/mia.log", b"log"),
        ];
        for (rel, bytes) in files {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, bytes).unwrap();
        }
        Root(root)
    }

    fn run(root: &Path, args: &[&str]) -> std::process::Output {
        std::process::Command::new("sh")
            .arg(manifest_dir().join("dist/macos/mia-uninstall"))
            .args(args)
            .env("FERROGATE_UNINSTALL_ROOT", root)
            .output()
            .expect("run sh")
    }

    fn state(root: &Path, file: &str) -> PathBuf {
        root.join("Library/Application Support/FerroGate")
            .join(file)
    }

    #[test]
    fn a_default_uninstall_keeps_the_machine_identity_and_configuration() {
        let root = installed("keep");
        let out = run(&root.0, &[]);
        assert!(out.status.success(), "{out:?}");

        // Programs are gone ...
        for gone in [
            "usr/local/bin/mia",
            "usr/local/bin/mia-uninstall",
            "usr/local/share/ferrogate",
            "Library/LaunchDaemons/com.ferrogate.mia.plist",
            "Library/LaunchAgents/com.ferrogate.mia-tray.plist",
            "Applications/FerroGate MIA.app",
        ] {
            assert!(!root.0.join(gone).exists(), "{gone} should be removed");
        }
        // ... the identity and the configuration are byte-for-byte intact, so
        // a reinstall comes back as the same host.
        assert_eq!(std::fs::read(state(&root.0, "host-key.bin")).unwrap(), KEY);
        assert_eq!(
            std::fs::read(state(&root.0, "svid-seed.bin")).unwrap(),
            SEED
        );
        assert_eq!(
            std::fs::read(state(&root.0, "mia.toml")).unwrap(),
            b"operator config"
        );
        assert!(root.0.join("etc/ferrogate/mia.env").exists());
        assert!(root.0.join("var/log/ferrogate/mia.log").exists());
    }

    #[test]
    fn only_an_explicit_purge_deletes_the_machine_identity() {
        let root = installed("purge");
        let out = run(&root.0, &["--purge"]);
        assert!(out.status.success(), "{out:?}");
        assert!(!root
            .0
            .join("Library/Application Support/FerroGate")
            .exists());
        assert!(!root.0.join("etc/ferrogate").exists());
        assert!(!root.0.join("var/log/ferrogate").exists());
    }

    #[test]
    fn an_unknown_flag_changes_nothing() {
        let root = installed("typo");
        let out = run(&root.0, &["--prune"]);
        assert_eq!(out.status.code(), Some(2), "{out:?}");
        assert!(root.0.join("usr/local/bin/mia").exists());
        assert_eq!(std::fs::read(state(&root.0, "host-key.bin")).unwrap(), KEY);
    }
}
