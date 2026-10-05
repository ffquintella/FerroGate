//! `mia default-environment` (feature F08): show, set or clear the host's
//! default environment ([`crate::default_env`]) — the environment that serves
//! the helper API's well-known address. It is the privileged writer behind the
//! `mia-tray` actions "Set as default environment" and "Use mia.toml as
//! default", and is usable from scripts too.
//!
//! - `mia default-environment [show] [--json]` — the effective selection and
//!   where it came from (read-only; no privileges needed).
//! - `mia default-environment set <env> [--json]` — select `<env>`.
//! - `mia default-environment clear [--json]` — remove the selection, so
//!   `mia.toml` is the default environment again.
//!
//! `set` / `clear` may run elevated on behalf of a GUI, so:
//!
//! - they take **no path**: the only file ever written is
//!   [`environments_file_path`] in the root-owned system config directory;
//! - `<env>` passes the one shared validator
//!   ([`crate::default_env::validate_selection`]: a valid environment name,
//!   bounded, not the reserved `default`) and must name an environment whose
//!   `mia-<env>.toml` sits beside `environments.toml` in the system config
//!   directory (which the root daemon always scans);
//! - a selection that would make another environment's configuration fail to
//!   load (an explicit `helper.socket` on the well-known address) is refused
//!   before anything is written;
//! - the file is rendered by [`render_environments_file`] (the value is
//!   TOML-serialised, never spliced) and written atomically through
//!   [`crate::setup_apply::write_policy_file`]: temp file + `fsync` + rename,
//!   a symlink or non-regular target refused, mode [`ENVIRONMENTS_FILE_MODE`],
//!   owned by the writer, and a `ConfigChanged` record (key name
//!   `default_environment` only) appended to the local audit journal before
//!   the rename;
//! - an unchanged selection writes (and audits) nothing, and neither command
//!   needs the existing file to parse, so they can repair a broken one.
//!
//! The daemon reads the selection at startup only (a SIGHUP reload does not
//! move a bound listener), so a change takes effect when the agent restarts.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::Serialize;

use crate::config::{ConfigSource, DiscoveredConfig};
use crate::default_env::{
    environments_file_path, render_environments_file, DefaultSelection, SelectionSource,
    ENV_DEFAULT_ENVIRONMENT,
};

/// The mode `environments.toml` is written with: world-readable, because
/// every `mia` process — including `mia test` / `mia status` run by an
/// unprivileged user — must read it, and it holds no secret.
pub const ENVIRONMENTS_FILE_MODE: u32 = 0o644;

/// The key name recorded in the audit journal for a change.
const AUDIT_KEY: &str = "default_environment";

const USAGE: &str = "usage: mia default-environment [show] [--json]\n\
     \x20      mia default-environment set <env> [--json]\n\
     \x20      mia default-environment clear [--json]";

/// Run `mia default-environment`. `args` is everything after the subcommand.
pub fn run(args: &[String]) -> anyhow::Result<()> {
    let Some(opts) = Opts::parse(args)? else {
        return Ok(());
    };
    let file = environments_file_path();
    let env_value = std::env::var(ENV_DEFAULT_ENVIRONMENT).ok();
    match &opts.cmd {
        Cmd::Show => {
            let report = show_in(&file, env_value)?;
            print_show(&report, opts.json)
        }
        Cmd::Set(name) => {
            let discovered = crate::config::discover_environment_configs();
            let change = set_in(&file, name, &discovered)?;
            print_change(&change, env_value.is_some(), opts.json)
        }
        Cmd::Clear => {
            let change = clear_in(&file)?;
            print_change(&change, env_value.is_some(), opts.json)
        }
    }
}

/// The subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Cmd {
    Show,
    Set(String),
    Clear,
}

/// Parsed arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Opts {
    cmd: Cmd,
    json: bool,
}

impl Opts {
    /// Parse `args`; `Ok(None)` after printing `--help`. Anything starting
    /// with `-` is an option, so an environment name never is one.
    fn parse(args: &[String]) -> anyhow::Result<Option<Self>> {
        let mut json = false;
        let mut words = Vec::new();
        for arg in args {
            match arg.as_str() {
                "-h" | "--help" => {
                    println!("{USAGE}\n\nSee docs/mia.md (\"The default environment\").");
                    return Ok(None);
                }
                "--json" => json = true,
                a if a.starts_with('-') => {
                    anyhow::bail!("unknown option: {}\n\n{USAGE}", a.escape_debug())
                }
                a => words.push(a),
            }
        }
        let cmd = match words.as_slice() {
            [] | ["show"] => Cmd::Show,
            ["set", name] => Cmd::Set((*name).to_owned()),
            ["set"] => anyhow::bail!("`set` needs an environment name\n\n{USAGE}"),
            ["clear"] => Cmd::Clear,
            [other, ..] if !matches!(*other, "show" | "set" | "clear") => {
                anyhow::bail!("unknown command: {}\n\n{USAGE}", other.escape_debug())
            }
            _ => anyhow::bail!("too many arguments\n\n{USAGE}"),
        };
        Ok(Some(Self { cmd, json }))
    }
}

// ── show ─────────────────────────────────────────────────────────────────────

/// What `show` reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Report {
    /// The effective default environment (`None` ⇒ `mia.toml`).
    default_environment: Option<String>,
    /// Its display label (`default` for `mia.toml`).
    label: String,
    /// Where the selection came from: `built-in`, `file` or `env`.
    source: &'static str,
    /// The environments file consulted.
    file: PathBuf,
    /// The well-known helper address the default environment serves.
    well_known_address: PathBuf,
}

/// The `show` report for the environments file `file` and the variable's
/// value `env_value` (if set). Fails closed, exactly as the daemon would.
fn show_in(file: &Path, env_value: Option<String>) -> anyhow::Result<Report> {
    let sel = DefaultSelection::resolve(file, env_value)?;
    Ok(Report {
        default_environment: sel.environment().map(str::to_owned),
        label: sel.label().to_owned(),
        source: match sel.source() {
            SelectionSource::BuiltIn => "built-in",
            SelectionSource::File(_) => "file",
            SelectionSource::EnvVar => "env",
        },
        file: file.to_path_buf(),
        well_known_address: crate::config::default_helper_socket(None),
    })
}

fn print_show(report: &Report, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    match &report.default_environment {
        Some(env) => println!("default environment: {env} (mia-{env}.toml)"),
        None => println!("default environment: default (mia.toml)"),
    }
    let source = match report.source {
        "file" => format!("default_environment in {}", report.file.display()),
        "env" => format!(
            "${ENV_DEFAULT_ENVIRONMENT} (overrides {})",
            report.file.display()
        ),
        _ => format!("built-in (nothing selected in {})", report.file.display()),
    };
    println!("  source:     {source}");
    println!(
        "  serves:     {} (the well-known helper address)",
        report.well_known_address.display()
    );
    println!(
        "The running agent picks a change up when it restarts; `mia status` marks the \
         environment serving the address now."
    );
    Ok(())
}

// ── set / clear ──────────────────────────────────────────────────────────────

/// What `set` / `clear` did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Change {
    /// The environments file.
    path: PathBuf,
    /// The selection the file made before (`None`: none, or unreadable).
    previous: Option<String>,
    /// The selection it makes now (`None` ⇒ `mia.toml`).
    default_environment: Option<String>,
    /// Whether the file was written.
    changed: bool,
}

/// The selection `file` currently makes, if it can be read; `None` when it
/// selects nothing, is absent, or does not parse (`set` / `clear` then simply
/// replace it).
fn current_selection(file: &Path) -> Result<Option<String>, ()> {
    DefaultSelection::resolve(file, None)
        .map(|s| s.environment().map(str::to_owned))
        .map_err(|_| ())
}

/// Select `name` in the environments file `file`. `discovered` are the
/// environment configurations present on this host
/// ([`crate::config::discover_environment_configs`]), checked for conflicts.
///
/// `mia-<name>.toml` must sit **beside** `file` — in the system config
/// directory, which the daemon always scans. A per-user copy is not enough:
/// which home directory an elevated process sees varies by platform and
/// wrapper, and a selection the root daemon cannot find stops it at startup.
fn set_in(file: &Path, name: &str, discovered: &[DiscoveredConfig]) -> anyhow::Result<Change> {
    let selection = DefaultSelection::selected_in_file(file, name)?;
    // `name` is validated from here on: safe to echo verbatim.
    let env_file = file
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(crate::config::config_filename(Some(name)));
    anyhow::ensure!(
        std::fs::metadata(&env_file).is_ok_and(|m| m.is_file()),
        "{} does not exist: environment `{name}` must have its configuration in the system \
         config directory before it can be the default (e.g. `sudo mia setup -e {name}`)",
        env_file.display(),
    );
    refuse_conflicts(discovered, &selection)?;
    let previous = current_selection(file);
    if previous.as_ref().is_ok_and(|p| p.as_deref() == Some(name)) {
        return Ok(Change {
            path: file.to_path_buf(),
            previous: Some(name.to_owned()),
            default_environment: Some(name.to_owned()),
            changed: false,
        });
    }
    write(file, Some(name))?;
    Ok(Change {
        path: file.to_path_buf(),
        previous: previous.ok().flatten(),
        default_environment: Some(name.to_owned()),
        changed: true,
    })
}

/// Remove the selection from the environments file `file` (`mia.toml` is the
/// default again). An absent file, or one that already selects nothing, is
/// left alone.
fn clear_in(file: &Path) -> anyhow::Result<Change> {
    let unchanged = |previous| Change {
        path: file.to_path_buf(),
        previous,
        default_environment: None,
        changed: false,
    };
    match std::fs::symlink_metadata(file) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(unchanged(None)),
        Err(e) => return Err(e).with_context(|| format!("inspecting {}", file.display())),
        Ok(_) => {}
    }
    let previous = current_selection(file);
    if previous == Ok(None) {
        return Ok(unchanged(None));
    }
    write(file, None)?;
    Ok(Change {
        path: file.to_path_buf(),
        previous: previous.ok().flatten(),
        default_environment: None,
        changed: true,
    })
}

/// Refuse a `selection` under which some discovered environment that loads
/// today would fail to load — an explicit `helper.socket` (or
/// `FERROGATE_HELPER_SOCKET`, as this process sees it) claiming the
/// well-known address outside the selected environment. A configuration that
/// does not load anyway is not this command's concern; the daemon reports it.
fn refuse_conflicts(
    discovered: &[DiscoveredConfig],
    selection: &DefaultSelection,
) -> anyhow::Result<()> {
    let mut conflicts = Vec::new();
    for d in discovered {
        let source = ConfigSource {
            path: Some(d.path.clone()),
            environment: None,
            discovered_named_env: d.environment.is_some(),
        };
        let Ok((mut config, _)) = source.load_with(&DefaultSelection::unset()) else {
            // Not echoed: the parser's message can quote the file.
            eprintln!(
                "warning: {} does not load as it is, so it was not checked against the new \
                 selection (the agent reports it at startup)",
                d.path.display()
            );
            continue;
        };
        if let Err(e) = config.apply_default_selection(selection) {
            conflicts.push(format!("  {}: {e}", d.path.display()));
        }
    }
    anyhow::ensure!(
        conflicts.is_empty(),
        "refusing the selection: these configurations would no longer load (nothing was \
         written):\n{}",
        conflicts.join("\n")
    );
    Ok(())
}

/// Render and atomically write the environments file selecting
/// `environment`, audited.
fn write(file: &Path, environment: Option<&str>) -> anyhow::Result<()> {
    let rendered = render_environments_file(environment)?;
    crate::setup_apply::write_policy_file(
        file,
        rendered.as_bytes(),
        ENVIRONMENTS_FILE_MODE,
        vec![AUDIT_KEY.to_owned()],
    )
    .with_context(|| {
        format!(
            "writing {} (it lives in the system config directory: run this as root / \
             Administrator)",
            file.display()
        )
    })
}

fn print_change(change: &Change, env_override: bool, json: bool) -> anyhow::Result<()> {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "path": change.path,
                "previous": change.previous,
                "default_environment": change.default_environment,
                "changed": change.changed,
                "restart_required": change.changed,
                "env_override": env_override,
            })
        );
        return Ok(());
    }
    let what = change
        .default_environment
        .as_deref()
        .map_or_else(|| "default (mia.toml)".to_owned(), |e| format!("`{e}`"));
    if change.changed {
        println!(
            "✓ Default environment set to {what} in {}",
            change.path.display()
        );
        println!(
            "  Restart the agent to move the well-known helper address:  {}",
            crate::setup::restart_hint()
        );
    } else {
        println!("Default environment is already {what}; nothing written.");
    }
    if env_override {
        println!(
            "  note: ${ENV_DEFAULT_ENVIRONMENT} is set in this environment and overrides the file"
        );
    }
    if change.changed {
        println!(
            "  (${ENV_DEFAULT_ENVIRONMENT} in the service's own environment, e.g. mia.env, \
             would still override the file for the daemon.)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::default_env::ENVIRONMENTS_FILE_NAME;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mia-defenv-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// `mia.toml` (with `main_toml`) and `mia-prod.toml` in `dir`, as the
    /// daemon's discovery would report them.
    fn host(dir: &Path, main_toml: &str) -> Vec<DiscoveredConfig> {
        std::fs::write(dir.join("mia.toml"), main_toml).unwrap();
        std::fs::write(dir.join("mia-prod.toml"), "").unwrap();
        vec![
            DiscoveredConfig {
                environment: None,
                path: dir.join("mia.toml"),
            },
            DiscoveredConfig {
                environment: Some("prod".into()),
                path: dir.join("mia-prod.toml"),
            },
        ]
    }

    fn journal_lines(file: &Path) -> Vec<String> {
        std::fs::read_to_string(crate::audit_client::local_journal_for(file))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.contains(".tmp-"))
            .collect()
    }

    #[test]
    fn set_show_clear_round_trip() {
        let dir = scratch("round-trip");
        let file = dir.join(ENVIRONMENTS_FILE_NAME);
        let discovered = host(&dir, "");

        // Nothing selected yet.
        let r = show_in(&file, None).unwrap();
        assert_eq!(
            (r.default_environment.as_deref(), r.source),
            (None, "built-in")
        );
        assert_eq!(r.label, "default");

        // set: written atomically, 0644, audited by key name.
        let c = set_in(&file, "prod", &discovered).unwrap();
        assert!(c.changed);
        assert_eq!(c.default_environment.as_deref(), Some("prod"));
        assert_eq!(
            DefaultSelection::resolve(&file, None)
                .unwrap()
                .environment(),
            Some("prod")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, ENVIRONMENTS_FILE_MODE);
        }
        assert_eq!(leftovers(&dir), Vec::<String>::new());
        let journal = journal_lines(&file);
        assert_eq!(journal.len(), 1);
        assert!(
            journal[0].contains("\"default_environment\""),
            "{}",
            journal[0]
        );
        assert!(journal[0].contains(&file.display().to_string()));
        assert!(
            !journal[0].contains("\"prod\""),
            "values never reach the journal"
        );

        // show reports it, and the variable still wins.
        let r = show_in(&file, None).unwrap();
        assert_eq!(
            (r.default_environment.as_deref(), r.source),
            (Some("prod"), "file")
        );
        let r = show_in(&file, Some(String::new())).unwrap();
        assert_eq!((r.default_environment.as_deref(), r.source), (None, "env"));

        // Setting it again changes (and audits) nothing.
        let c = set_in(&file, "prod", &discovered).unwrap();
        assert!(!c.changed);
        assert_eq!(journal_lines(&file).len(), 1);

        // clear: mia.toml again, audited; a second clear is a no-op.
        let c = clear_in(&file).unwrap();
        assert!(c.changed);
        assert_eq!(c.previous.as_deref(), Some("prod"));
        assert_eq!(
            DefaultSelection::resolve(&file, None).unwrap(),
            DefaultSelection::unset()
        );
        assert_eq!(journal_lines(&file).len(), 2);
        assert!(!clear_in(&file).unwrap().changed);
        assert_eq!(journal_lines(&file).len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_rejects_bad_reserved_and_unknown_environments() {
        let dir = scratch("reject");
        let file = dir.join(ENVIRONMENTS_FILE_NAME);
        let mut discovered = host(&dir, "");
        // Even a discovered file named mia-default.toml cannot be selected.
        discovered.push(DiscoveredConfig {
            environment: Some("default".into()),
            path: dir.join("mia-default.toml"),
        });
        for bad in [
            "default",
            "../prod",
            "a/b",
            "a b",
            "",
            "prod\n",
            "x\u{1b}[31m",
            "staging",
        ] {
            let err = set_in(&file, bad, &discovered).unwrap_err();
            assert!(!file.exists(), "{bad:?} must write nothing");
            if bad == "staging" {
                assert!(format!("{err:#}").contains("mia-staging.toml"), "{err:#}");
            }
        }
        let long = "a".repeat(mia_status_proto::MAX_ENVIRONMENT_LEN + 1);
        assert!(set_in(&file, &long, &discovered).is_err());
        // A configuration found only elsewhere (e.g. a per-user directory)
        // is not enough: the daemon must find it beside environments.toml.
        let user_dir = dir.join("user");
        std::fs::create_dir_all(&user_dir).unwrap();
        std::fs::write(user_dir.join("mia-qa.toml"), "").unwrap();
        discovered.push(DiscoveredConfig {
            environment: Some("qa".into()),
            path: user_dir.join("mia-qa.toml"),
        });
        let err = set_in(&file, "qa", &discovered).unwrap_err();
        assert!(
            format!("{err:#}").contains("system config directory"),
            "{err:#}"
        );
        assert!(!file.exists());
        assert_eq!(journal_lines(&file), Vec::<String>::new());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn set_and_clear_refuse_a_symlinked_or_non_regular_target() {
        let dir = scratch("symlink");
        let discovered = host(&dir, "");
        let elsewhere = dir.join("elsewhere.toml");
        std::fs::write(&elsewhere, "default_environment = \"prod\"\n").unwrap();
        let file = dir.join(ENVIRONMENTS_FILE_NAME);
        std::os::unix::fs::symlink(&elsewhere, &file).unwrap();

        assert!(set_in(&file, "prod", &discovered).is_ok_and(|c| !c.changed));
        let err = clear_in(&file).unwrap_err();
        assert!(format!("{err:#}").contains("symbolic link"), "{err:#}");
        // Neither the link nor its target moved.
        assert!(std::fs::symlink_metadata(&file)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            std::fs::read_to_string(&elsewhere).unwrap(),
            "default_environment = \"prod\"\n"
        );
        std::fs::write(&elsewhere, "").unwrap();
        assert!(set_in(&file, "prod", &discovered).is_err());
        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "");
        assert_eq!(journal_lines(&file), Vec::<String>::new());

        // A directory where the file should be.
        let file = dir.join("as-dir").join(ENVIRONMENTS_FILE_NAME);
        std::fs::create_dir_all(&file).unwrap();
        assert!(set_in(&file, "prod", &discovered).is_err());
        assert!(clear_in(&file).is_err());
        assert_eq!(leftovers(&dir), Vec::<String>::new());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_refuses_a_selection_that_breaks_another_environment() {
        let dir = scratch("conflict");
        let file = dir.join(ENVIRONMENTS_FILE_NAME);
        // mia.toml claims the well-known address explicitly: selecting prod
        // would make it fail to load, so nothing is written.
        let well_known = crate::config::default_helper_socket(None);
        let main = format!(
            "[helper]\nsocket = {}\n",
            toml::Value::String(well_known.display().to_string())
        );
        let discovered = host(&dir, &main);
        if std::env::var_os("FERROGATE_HELPER_SOCKET").is_none() {
            let err = set_in(&file, "prod", &discovered).unwrap_err();
            assert!(format!("{err:#}").contains("mia.toml"), "{err:#}");
            assert!(!file.exists());
        }
        // A configuration that does not load anyway does not block it.
        std::fs::write(dir.join("mia.toml"), "this is not toml =").unwrap();
        assert!(set_in(&file, "prod", &discovered).unwrap().changed);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_and_clear_repair_a_malformed_file() {
        let dir = scratch("repair");
        let file = dir.join(ENVIRONMENTS_FILE_NAME);
        let discovered = host(&dir, "");
        std::fs::write(&file, "default_enviroment = \"prod\"\n").unwrap();
        assert!(show_in(&file, None).is_err(), "show fails closed");
        let c = clear_in(&file).unwrap();
        assert!(c.changed && c.previous.is_none());
        assert_eq!(
            DefaultSelection::resolve(&file, None).unwrap(),
            DefaultSelection::unset()
        );
        std::fs::write(&file, "garbage").unwrap();
        assert!(set_in(&file, "prod", &discovered).unwrap().changed);
        assert_eq!(
            show_in(&file, None).unwrap().default_environment.as_deref(),
            Some("prod")
        );
        // Clearing an absent file creates nothing.
        let absent = dir.join("sub").join(ENVIRONMENTS_FILE_NAME);
        assert!(!clear_in(&absent).unwrap().changed);
        assert!(!absent.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn option_parsing_is_a_closed_set() {
        let parse =
            |a: &[&str]| Opts::parse(&a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>());
        let ok = |a: &[&str]| parse(a).unwrap().unwrap();
        assert_eq!(ok(&[]).cmd, Cmd::Show);
        assert_eq!(
            ok(&["show", "--json"]),
            Opts {
                cmd: Cmd::Show,
                json: true
            }
        );
        assert_eq!(ok(&["set", "prod"]).cmd, Cmd::Set("prod".into()));
        assert!(ok(&["--json", "clear"]).json);
        assert_eq!(ok(&["clear"]).cmd, Cmd::Clear);
        for bad in [
            &["set"][..],
            &["set", "a", "b"],
            &["clear", "x"],
            &["show", "x"],
            &["frob"],
            &["set", "-x"],
            &["set", "--output", "/tmp/x"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        assert!(parse(&["--help"]).unwrap().is_none());
    }
}
