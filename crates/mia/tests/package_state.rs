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
mod linux_installer_groups {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::read;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("mia-installer-groups-{}-{tag}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn stub(dir: &Path, name: &str, body: &str) {
        let path = dir.join(name);
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn run_installer(script: &str, args: &[&str], tag: &str) -> String {
        let root = TempDir::new(tag);
        let bin = root.0.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let record = root.0.join("calls");

        // The hooks query only these account records in this controlled run.
        // They must see the service account and the three package groups as
        // already present, just as on an upgrade.
        stub(
            &bin,
            "getent",
            "#!/bin/sh\ncase \"$1:$2\" in\ngroup:ferrogate-clients) echo 'ferrogate-clients:x:4101:';;\ngroup:ferrogate-status) echo 'ferrogate-status:x:4102:';;\ngroup:ferrogate-operators) echo 'ferrogate-operators:x:4103:';;\npasswd:_ferrogate) exit 0;;\n*) exit 2;;\nesac\n",
        );
        stub(
            &bin,
            "usermod",
            "#!/bin/sh\nprintf 'usermod %s\\n' \"$*\" >>\"$FERROGATE_TEST_RECORD\"\n",
        );
        stub(&bin, "groupadd", "#!/bin/sh\nexit 0\n");
        stub(&bin, "useradd", "#!/bin/sh\nexit 0\n");
        // Prevent the hook from discovering real desktop sessions on the host.
        stub(&bin, "loginctl", "#!/bin/sh\nexit 0\n");

        let config_dir = root.0.join("etc/ferrogate");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(config_dir.join("mia.toml"), "log = 'info'\n").unwrap();
        let dropin_dir = root.0.join("etc/systemd/system/mia.service.d");

        let copy = root.0.join("installer.sh");
        let source = read(script)
            .replace("/etc/ferrogate", &config_dir.display().to_string())
            .replace(
                "/etc/systemd/system/mia.service.d",
                &dropin_dir.display().to_string(),
            )
            .replace(
                "/run/systemd/system",
                &root.0.join("no-systemd").display().to_string(),
            );
        fs::write(&copy, source).unwrap();

        let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
        let output = Command::new("sh")
            .arg(&copy)
            .args(args)
            .env("PATH", path)
            .env("FERROGATE_TEST_RECORD", &record)
            .output()
            .unwrap_or_else(|e| panic!("run {}: {e}", copy.display()));
        assert!(
            output.status.success(),
            "{} failed:\nstdout: {}\nstderr: {}",
            script,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        fs::read_to_string(record).unwrap_or_default()
    }

    #[test]
    fn linux_installers_enroll_the_service_account_in_the_status_group_on_upgrade() {
        for (script, args, tag) in [
            ("dist/debian/postinst", vec!["configure"], "deb"),
            ("dist/rpm/postinstall", Vec::new(), "rpm"),
        ] {
            let calls = run_installer(script, &args, tag);
            assert!(
                calls
                    .lines()
                    .any(|line| line == "usermod -aG ferrogate-status -- _ferrogate"),
                "{script} did not enroll _ferrogate in ferrogate-status: {calls:?}"
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

/// The Windows MSI puts the install directory on the system PATH (removed on
/// uninstall), registers the `mia` service to start automatically, and both
/// the MSI and the executables carry the FerroGate icon.
#[test]
fn the_windows_msi_sets_path_auto_start_and_icon() {
    let wxs = read("wix/mia.wxs");
    let element = |name: &str| -> String {
        let start = wxs
            .find(&format!("<{name} "))
            .unwrap_or_else(|| panic!("mia.wxs declares <{name}>"));
        let end = start + wxs[start..].find('>').expect("element is closed");
        wxs[start..end].to_string()
    };

    let env = element("Environment");
    for attr in [
        r#"Name="PATH""#,
        // Not [INSTALLDIR]: its trailing backslash would duplicate the entry
        // older installers wrote.
        r#"Value="[FerroGateDir]MIA""#,
        r#"Action="set""#,
        r#"Part="last""#,
        r#"System="yes""#,
        r#"Permanent="no""#,
    ] {
        assert!(env.contains(attr), "<Environment> lacks {attr}: {env}");
    }
    assert!(
        wxs.contains(r#"<ComponentRef Id="MiaPath" />"#),
        "the PATH component is part of the default feature"
    );

    let svc = element("ServiceInstall");
    for attr in [
        r#"Name="mia""#,
        r#"Start="auto""#,
        r#"Arguments="service run""#,
    ] {
        assert!(svc.contains(attr), "<ServiceInstall> lacks {attr}: {svc}");
    }
    assert!(element("ServiceControl").contains(r#"Start="install""#));

    // The host configuration (administrator-only %ProgramData%\FerroGate,
    // the pipe DACLs' local groups) runs as LocalSystem before the service
    // starts, and a failure aborts the install.
    let ca = element("CustomAction");
    for attr in [
        r#"Id="MiaSecureConfig""#,
        r#"FileKey="miaExe""#,
        r#"ExeCommand="service secure-config""#,
        r#"Execute="deferred""#,
        r#"Impersonate="no""#,
        r#"Return="check""#,
    ] {
        assert!(ca.contains(attr), "<CustomAction> lacks {attr}: {ca}");
    }
    let custom = element("Custom");
    assert!(
        custom.contains(r#"Action="MiaSecureConfig""#)
            && custom.contains(r#"Before="StartServices""#),
        "{custom}"
    );

    assert!(wxs.contains(r#"<Property Id="ARPPRODUCTICON" Value="FerroGateMia.ico" />"#));
    for build_rs in ["build.rs", "../mia-tray/build.rs"] {
        assert!(
            read(build_rs).contains("ferro_winres::embed_icon_for_windows_bins"),
            "{build_rs} embeds the icon into the Windows executables"
        );
    }
}
