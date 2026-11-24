//! `ferrogate admin publishers …`: trusted publishers from the command
//! line (ADR-0006), a code-signing identity whose signed binaries every
//! MIA auto-approves. Request building, validation and display come from
//! `ferrogate_admin_client::publishers`, the code the tray shares (F20 §12).

//! The arguments are parsed, and the identity is read locally, **before**
//! any sign-in, so a typo or a bad certificate file never costs a TOTP
//! code. Adding carries a fresh per-operation TOTP proof after a typed
//! confirmation; removing needs a recent step-up (the shared dispatcher in
//! [`crate::admin`] handles `step_up_required`) and the short id typed back.

//! Everything the server returns is shown through `PublisherRow`, whose
//! strings are already cleaned for the terminal.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use ferrogate_admin_client::approvals::rules::new_idempotency_key;
use ferrogate_admin_client::publishers::draft::{remove_request, PublisherDraft};
use ferrogate_admin_client::publishers::inspect::{
    inspect_certificates, inspect_executable, Candidate,
};
use ferrogate_admin_client::publishers::proto::{
    AddTrustedPublisherResponse, ListTrustedPublishersRequest, RemoveTrustedPublisherResponse,
    TrustedPublisherInfo,
};
use ferrogate_admin_client::publishers::view::{find, PublisherRow};
use ferrogate_admin_client::publishers::{PinKind, SignatureKind};

use crate::admin::{flag_value, has_flag, printable, proof, Admin, Prompter};
use crate::{rpc_err, CmisError};

/// Largest certificate file read (a certificate is a few KiB).
const MAX_CERT_FILE: u64 = 64 * 1024;

/// The usage text of `ferrogate admin publishers`.
pub(crate) fn usage() -> &'static str {
    "ferrogate admin publishers — trusted publishers (ADR-0006)\n\
     \n\
     A trusted publisher is a code-signing identity whose signed binaries\n\
     every MIA auto-approves (every host, any user).\n\
     \n\
     \x20 publishers list [--all]            --all includes removed publishers\n\
     \x20 publishers show <id|short-id>\n\
     \x20 publishers add --label <text> [--pin leaf-cert|leaf-spki|subject]\n\
     \x20               [--anchor <n>] [--no-require-timestamp] [--expires-at <unix>] [--yes]\n\
     \x20               and exactly one source:\n\
     \x20                 --exe <path>                 read the signer of a signed executable\n\
     \x20                                              (macOS and Windows; --anchor picks the CA)\n\
     \x20                 --leaf-cert <file> --anchor-cert <file> --kind authenticode|apple\n\
     \x20                 --kind authenticode|apple --anchor-sha256 <hex> --pin-sha256 <hex>\n\
     \x20               shows what will be trusted, asks to confirm (or --yes), then needs a\n\
     \x20               fresh TOTP code. --pin defaults to leaf-spki; --anchor to 0\n\
     \x20 publishers remove <id|short-id> [--confirm <short-id>]\n\
     \x20               the short id (P-XXXXXXXX) is typed back unless --confirm gives it"
}

// ---- argument parsing --------------------------------------------------------------

/// Splits `args` into positional arguments, rejecting any `--flag` that is not
/// listed. `valued` flags consume the next argument, `switches` stand alone.
fn positionals(args: &[String], valued: &[&str], switches: &[&str]) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if valued.contains(&a.as_str()) {
            if it.next().is_none() {
                anyhow::bail!("{a} needs a value\n\n{}", usage());
            }
        } else if switches.contains(&a.as_str()) {
        } else if a.starts_with("--") {
            anyhow::bail!("unknown option {a}\n\n{}", usage());
        } else {
            out.push(a.clone());
        }
    }
    Ok(out)
}

/// The single positional `what` of an action.
fn one_positional(pos: Vec<String>, what: &str) -> anyhow::Result<String> {
    let mut it = pos.into_iter();
    match (it.next(), it.next()) {
        (Some(v), None) => Ok(v),
        _ => anyhow::bail!("expected exactly one {what}\n\n{}", usage()),
    }
}

fn number<T: std::str::FromStr>(args: &[String], name: &str) -> anyhow::Result<Option<T>> {
    flag_value(args, name)
        .map(|v| v.parse::<T>())
        .transpose()
        .map_err(|_| anyhow::anyhow!("{name} must be a number"))
}

fn required<T>(v: Option<T>, name: &str) -> anyhow::Result<T> {
    v.ok_or_else(|| anyhow::anyhow!("{name} is required\n\n{}", usage()))
}

fn pin_kind(name: &str) -> anyhow::Result<PinKind> {
    PinKind::parse(name)
        .ok_or_else(|| anyhow::anyhow!("unknown pin `{name}` (leaf-cert, leaf-spki, subject)"))
}

fn signature_kind(name: &str) -> anyhow::Result<SignatureKind> {
    SignatureKind::parse(name)
        .ok_or_else(|| anyhow::anyhow!("unknown kind `{name}` (authenticode, apple)"))
}

/// Where the identity of `publishers add` comes from.
#[derive(Debug, PartialEq, Eq)]
enum Source {
    /// A signed executable, verified by this machine's OS.
    Exe(PathBuf),
    /// A leaf and a CA certificate file.
    Files {
        kind: SignatureKind,
        leaf: PathBuf,
        anchor: PathBuf,
    },
    /// Digests only.
    Pins {
        kind: SignatureKind,
        anchor_hex: String,
        pin_hex: String,
    },
}

/// `publishers add` arguments.
#[derive(Debug, PartialEq, Eq)]
struct AddArgs {
    label: String,
    pin_kind: PinKind,
    anchor: usize,
    require_timestamp: bool,
    expires_at: Option<i64>,
    yes: bool,
    source: Source,
}

/// A parsed `publishers` action.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    List { include_removed: bool },
    Show(String),
    Add(Box<AddArgs>),
    Remove { id: String, confirm: Option<String> },
}

/// Parses `publishers <action> …` without touching the network.
fn parse(args: &[String]) -> anyhow::Result<Command> {
    let Some(action) = args.first() else {
        anyhow::bail!("publishers needs an action\n\n{}", usage());
    };
    let rest = &args[1..];
    match action.as_str() {
        "list" => {
            if !positionals(rest, &[], &["--all"])?.is_empty() {
                anyhow::bail!("list takes no argument\n\n{}", usage());
            }
            Ok(Command::List {
                include_removed: has_flag(rest, "--all"),
            })
        }
        "show" => Ok(Command::Show(one_positional(
            positionals(rest, &[], &[])?,
            "publisher id",
        )?)),
        "add" => parse_add(rest).map(|a| Command::Add(Box::new(a))),
        "remove" => Ok(Command::Remove {
            id: one_positional(positionals(rest, &["--confirm"], &[])?, "publisher id")?,
            confirm: flag_value(rest, "--confirm"),
        }),
        other => anyhow::bail!("unknown publishers action: {other}\n\n{}", usage()),
    }
}

fn parse_add(rest: &[String]) -> anyhow::Result<AddArgs> {
    let valued = [
        "--label",
        "--pin",
        "--anchor",
        "--expires-at",
        "--exe",
        "--leaf-cert",
        "--anchor-cert",
        "--kind",
        "--anchor-sha256",
        "--pin-sha256",
    ];
    if !positionals(rest, &valued, &["--no-require-timestamp", "--yes"])?.is_empty() {
        anyhow::bail!("add takes no positional argument\n\n{}", usage());
    }
    let label = required(flag_value(rest, "--label"), "--label")?;
    let anchor = number::<usize>(rest, "--anchor")?;
    let kind = flag_value(rest, "--kind")
        .map(|k| signature_kind(&k))
        .transpose()?;
    let (exe, leaf, anchor_cert) = (
        flag_value(rest, "--exe"),
        flag_value(rest, "--leaf-cert"),
        flag_value(rest, "--anchor-cert"),
    );
    let (anchor_hex, pin_hex) = (
        flag_value(rest, "--anchor-sha256"),
        flag_value(rest, "--pin-sha256"),
    );
    let groups = [
        exe.is_some(),
        leaf.is_some() || anchor_cert.is_some(),
        anchor_hex.is_some() || pin_hex.is_some(),
    ];
    match groups.iter().filter(|g| **g).count() {
        1 => {}
        0 => anyhow::bail!(
            "add needs exactly one source: --exe, --leaf-cert with --anchor-cert, or --anchor-sha256 with --pin-sha256\n\n{}",
            usage()
        ),
        _ => anyhow::bail!(
            "the sources --exe, --leaf-cert/--anchor-cert and --anchor-sha256/--pin-sha256 exclude each other"
        ),
    }
    let source = if let Some(path) = exe {
        if kind.is_some() {
            anyhow::bail!("--kind does not go with --exe: the executable says which it is");
        }
        Source::Exe(PathBuf::from(path))
    } else if groups[1] {
        Source::Files {
            kind: required(kind, "--kind")?,
            leaf: PathBuf::from(required(leaf, "--leaf-cert")?),
            anchor: PathBuf::from(required(anchor_cert, "--anchor-cert")?),
        }
    } else {
        if anchor.is_some() {
            anyhow::bail!("--anchor picks a CA certificate of --exe or --leaf-cert; give --anchor-sha256 instead");
        }
        Source::Pins {
            kind: required(kind, "--kind")?,
            anchor_hex: required(anchor_hex, "--anchor-sha256")?,
            pin_hex: required(pin_hex, "--pin-sha256")?,
        }
    };
    Ok(AddArgs {
        label,
        pin_kind: flag_value(rest, "--pin")
            .map(|p| pin_kind(&p))
            .transpose()?
            .unwrap_or(PinKind::LeafSpkiSha256),
        anchor: anchor.unwrap_or(0),
        require_timestamp: !has_flag(rest, "--no-require-timestamp"),
        expires_at: number::<i64>(rest, "--expires-at")?,
        yes: has_flag(rest, "--yes"),
        source,
    })
}

/// Checks `publishers <action> …` before signing in: the arguments, and for
/// `add` the identity and the draft (local file reads only, no network).
pub(crate) fn validate(args: &[String]) -> anyhow::Result<()> {
    if let Command::Add(a) = parse(args)? {
        prepare(&a)?;
    }
    Ok(())
}

// ---- reading the identity ------------------------------------------------------------

/// What `publishers add` is about to send, and what it was read from.
struct Prepared {
    draft: PublisherDraft,
    candidate: Option<Candidate>,
}

/// Reads a certificate file: a regular file of at most [`MAX_CERT_FILE`]
/// bytes (a directory, or anything larger, is refused).
fn read_cert_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    let shown = path.display();
    let meta = std::fs::metadata(path).map_err(|e| anyhow::anyhow!("{shown}: {e}"))?;
    if !meta.is_file() {
        anyhow::bail!("{shown} is not a regular file");
    }
    let mut buf = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_CERT_FILE + 1).read_to_end(&mut buf))
        .map_err(|e| anyhow::anyhow!("{shown}: {e}"))?;
    if buf.len() as u64 > MAX_CERT_FILE {
        anyhow::bail!(
            "{shown} is larger than {} KiB: not a certificate",
            MAX_CERT_FILE / 1024
        );
    }
    Ok(buf)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Reads the identity of `a`, builds its draft and checks it. Everything
/// here is local; nothing is sent.
fn prepare(a: &AddArgs) -> anyhow::Result<Prepared> {
    let (mut draft, candidate) = match &a.source {
        Source::Exe(path) => {
            let c = inspect_executable(path)?;
            (from_candidate(&c, a)?, Some(c))
        }
        Source::Files { kind, leaf, anchor } => {
            let c = inspect_certificates(*kind, &read_cert_file(leaf)?, &read_cert_file(anchor)?)?;
            (from_candidate(&c, a)?, Some(c))
        }
        Source::Pins {
            kind,
            anchor_hex,
            pin_hex,
        } => (
            PublisherDraft::from_pins(*kind, anchor_hex, a.pin_kind, pin_hex, &a.label)?,
            None,
        ),
    };
    draft.require_timestamp = a.require_timestamp;
    draft.expires_at = a.expires_at;
    let problems = draft.problems(now_unix());
    if !problems.is_empty() {
        let text: Vec<String> = problems.iter().map(ToString::to_string).collect();
        anyhow::bail!("{}", text.join("; "));
    }
    Ok(Prepared { draft, candidate })
}

fn from_candidate(c: &Candidate, a: &AddArgs) -> anyhow::Result<PublisherDraft> {
    PublisherDraft::from_candidate(c, a.anchor, a.pin_kind, &a.label).map_err(|e| {
        anyhow::anyhow!(
            "{e} (--anchor {} of {} available)",
            a.anchor,
            c.issuers.len()
        )
    })
}

// ---- printing ----------------------------------------------------------------------------

/// A unix time, or `never` when there is none.
fn when(t: Option<i64>) -> String {
    t.map_or_else(|| "never".to_string(), |t| format!("{t} (unix)"))
}

/// One line of a listing.
fn list_line(r: &PublisherRow) -> String {
    format!(
        "{}  {:<7} {:<12} {:<9} {}  expires {}",
        r.short_id,
        r.state,
        r.kind,
        r.pin_kind,
        r.title(),
        when(r.expires_at)
    )
}

/// Every field of a row, full digests included, as `name: value` pairs.
fn row_fields(r: &PublisherRow) -> Vec<(&'static str, String)> {
    let mut out = vec![
        ("id:", r.id.clone()),
        ("short_id:", r.short_id.clone()),
        ("state:", r.state.to_string()),
        ("label:", r.label.clone()),
        ("kind:", r.kind.to_string()),
        ("pin_kind:", r.pin_kind.to_string()),
        ("pin:", r.pin.clone()),
        ("anchor_sha256:", r.anchor_sha256.clone()),
    ];
    if !r.leaf_cert_sha256.is_empty() {
        out.push(("leaf_cert_sha256:", r.leaf_cert_sha256.clone()));
    }
    out.push((
        "require_timestamp:",
        if r.require_timestamp { "yes" } else { "no" }.to_string(),
    ));
    if !r.subject.is_empty() {
        out.push(("subject:", r.subject.clone()));
    }
    if !r.issuer.is_empty() {
        out.push(("issuer:", r.issuer.clone()));
    }
    out.push(("created_at:", format!("{} (unix)", r.created_at)));
    out.push(("created_by:", r.created_by.clone()));
    out.push(("expires_at:", when(r.expires_at)));
    if r.removed_at.is_some() || !r.removed_by.is_empty() {
        out.push(("removed_at:", when(r.removed_at)));
        out.push(("removed_by:", r.removed_by.clone()));
    }
    out
}

fn print_row(r: &PublisherRow) {
    for (name, value) in row_fields(r) {
        println!("{name:<20}{value}");
    }
}

// ---- execution -----------------------------------------------------------------------------

/// Runs `ferrogate admin publishers <action>` on a signed-in admin client.
pub(crate) async fn run(
    admin: &mut Admin,
    args: &[String],
    prompter: &Prompter,
) -> anyhow::Result<()> {
    match parse(args)? {
        Command::List { include_removed } => {
            for p in fetch(admin, include_removed).await? {
                println!("{}", list_line(&PublisherRow::of(&p)));
            }
            Ok(())
        }
        Command::Show(id) => {
            let all = fetch(admin, true).await?;
            let p = find(&all, &id)
                .ok_or_else(|| anyhow::anyhow!("no trusted publisher {}", printable(&id)))?;
            print_row(&PublisherRow::of(p));
            Ok(())
        }
        Command::Add(a) => add(admin, &a, prompter).await,
        Command::Remove { id, confirm } => remove(admin, &id, confirm, prompter).await,
    }
}

async fn fetch(
    admin: &mut Admin,
    include_removed: bool,
) -> anyhow::Result<Vec<TrustedPublisherInfo>> {
    Ok(admin
        .list_trusted_publishers(ListTrustedPublishersRequest { include_removed })
        .await
        .map_err(rpc_err)?
        .into_inner()
        .publishers)
}

/// `true` when `err` is CMIS refusing the second factor (not the session).
fn proof_rejected(err: &anyhow::Error) -> bool {
    err.chain().any(|e| {
        e.downcast_ref::<CmisError>().is_some_and(|c| {
            c.0.code() == tonic::Code::Unauthenticated && c.0.message() != "session_invalid"
        })
    })
}

async fn add(admin: &mut Admin, a: &AddArgs, prompter: &Prompter) -> anyhow::Result<()> {
    let Prepared { draft, candidate } = prepare(a)?;
    println!("About to trust this publisher:");
    for (name, value) in draft.confirmation(candidate.as_ref()) {
        println!("  {:<22}{value}", format!("{name}:"));
    }
    if !a.yes {
        if !prompter.is_tty() {
            anyhow::bail!("adding a publisher needs confirmation: re-run with --yes");
        }
        if !prompter.confirm("Add this trusted publisher for every host?")? {
            anyhow::bail!("not confirmed: nothing was added");
        }
    }
    let code = prompter.secret("TOTP code (fresh second factor to add a trusted publisher)")?;
    let mut req = draft.request(new_idempotency_key());
    req.proof = proof(code);
    let AddTrustedPublisherResponse { publisher } = match admin.add_trusted_publisher(req).await {
        Ok(r) => r.into_inner(),
        Err(s) => {
            let e = rpc_err(s);
            if proof_rejected(&e) {
                anyhow::bail!("the second factor was rejected: nothing was added");
            }
            return Err(e);
        }
    };
    match publisher {
        Some(p) => {
            let row = PublisherRow::of(&p);
            println!("added trusted publisher {} ({})", row.short_id, row.title());
            print_row(&row);
        }
        None => println!("trusted publisher added"),
    }
    Ok(())
}

async fn remove(
    admin: &mut Admin,
    id: &str,
    confirm: Option<String>,
    prompter: &Prompter,
) -> anyhow::Result<()> {
    let all = fetch(admin, false).await?;
    let p = find(&all, id)
        .ok_or_else(|| anyhow::anyhow!("no active trusted publisher {}", printable(id)))?;
    let row = PublisherRow::of(p);
    print_row(&row);
    // Asked on every run, the retry after a step-up included: no
    // process-wide memory of what was confirmed.
    let typed = match confirm {
        Some(c) => c,
        None => prompter.text(&format!(
            "Type {} to stop trusting this publisher on every host",
            row.confirm_phrase()
        ))?,
    };
    if !typed.trim().eq_ignore_ascii_case(row.confirm_phrase()) {
        anyhow::bail!(
            "confirmation does not match {}: nothing was removed",
            row.confirm_phrase()
        );
    }
    let req = remove_request(&p.publisher_id, new_idempotency_key())?;
    let RemoveTrustedPublisherResponse { publisher } = admin
        .remove_trusted_publisher(req)
        .await
        .map_err(rpc_err)?
        .into_inner();
    let done = publisher
        .as_ref()
        .map_or_else(|| row.clone(), PublisherRow::of);
    println!(
        "removed trusted publisher {} ({})",
        done.short_id,
        done.title()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    const PINS: &str = "add --label ACME --kind apple";

    fn pins_line(extra: &str) -> Vec<String> {
        args(&format!(
            "{PINS} --anchor-sha256 {} --pin-sha256 {} {extra}",
            "aa".repeat(32),
            "bb".repeat(32)
        ))
    }

    fn add_args(line: &[String]) -> AddArgs {
        match parse(line).unwrap() {
            Command::Add(a) => *a,
            other => panic!("not an add: {other:?}"),
        }
    }

    #[test]
    fn list_show_and_remove_parse() {
        assert_eq!(
            parse(&args("list")).unwrap(),
            Command::List {
                include_removed: false
            }
        );
        assert_eq!(
            parse(&args("list --all")).unwrap(),
            Command::List {
                include_removed: true
            }
        );
        assert_eq!(
            parse(&args("show P-0000BEEF")).unwrap(),
            Command::Show("P-0000BEEF".into())
        );
        assert_eq!(
            parse(&args("remove P-0000BEEF --confirm p-0000beef")).unwrap(),
            Command::Remove {
                id: "P-0000BEEF".into(),
                confirm: Some("p-0000beef".into())
            }
        );
        assert_eq!(
            parse(&args("remove abc")).unwrap(),
            Command::Remove {
                id: "abc".into(),
                confirm: None
            }
        );
    }

    #[test]
    fn the_pins_source_parses_with_safe_defaults() {
        let a = add_args(&pins_line(""));
        assert_eq!(a.pin_kind, PinKind::LeafSpkiSha256);
        assert!(a.require_timestamp && !a.yes);
        assert_eq!((a.anchor, a.expires_at), (0, None));
        assert!(matches!(
            a.source,
            Source::Pins {
                kind: SignatureKind::Apple,
                ..
            }
        ));
        let a = add_args(&pins_line(
            "--pin subject --no-require-timestamp --expires-at 4102444800 --yes",
        ));
        assert_eq!(a.pin_kind, PinKind::SubjectSha256);
        assert!(!a.require_timestamp && a.yes);
        assert_eq!(a.expires_at, Some(4_102_444_800));
    }

    #[test]
    fn the_file_and_exe_sources_parse() {
        let a = add_args(&args(
            "add --label ACME --leaf-cert leaf.pem --anchor-cert ca.pem --kind authenticode --anchor 0",
        ));
        assert_eq!(
            a.source,
            Source::Files {
                kind: SignatureKind::Authenticode,
                leaf: "leaf.pem".into(),
                anchor: "ca.pem".into()
            }
        );
        let a = add_args(&args("add --label ACME --exe /opt/acme/tool --anchor 1"));
        assert_eq!(a.source, Source::Exe("/opt/acme/tool".into()));
        assert_eq!(a.anchor, 1);
    }

    #[test]
    fn sources_must_be_exactly_one_and_complete() {
        for bad in [
            "add --label ACME",
            "add --label ACME --kind apple",
            "add --exe /x --leaf-cert l --anchor-cert a --kind apple",
            "add --label ACME --exe /x --anchor-sha256 aa --pin-sha256 bb",
            "add --label ACME --exe /x --kind apple",
            "add --label ACME --leaf-cert l --kind apple",
            "add --label ACME --anchor-cert a --kind apple",
            "add --label ACME --leaf-cert l --anchor-cert a",
            "add --label ACME --anchor-sha256 aa --pin-sha256 bb",
            "add --label ACME --kind apple --anchor-sha256 aa",
            "add --label ACME --kind apple --pin-sha256 bb",
            "add --exe /x",
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad}");
        }
        assert!(
            parse(&pins_line("--anchor 1")).is_err(),
            "no CA list to index"
        );
    }

    #[test]
    fn bad_values_and_unknown_flags_are_refused() {
        for bad in [
            "--pin sha1",
            "--pin",
            "--kind pgp",
            "--expires-at soon",
            "--anchor first",
            "--frobnicate",
            "--json",
            "stray",
        ] {
            assert!(parse(&pins_line(bad)).is_err(), "{bad}");
        }
        assert!(parse(&args("add --label ACME --kind pgp --exe /x")).is_err());
        for bad in [
            "",
            "frobnicate",
            "list now",
            "list --bogus",
            "show",
            "show a b",
            "remove",
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad}");
        }
        let err = parse(&args("frobnicate")).unwrap_err().to_string();
        assert!(err.contains("unknown publishers action"), "{err}");
    }

    #[test]
    fn typos_and_bad_drafts_fail_before_any_sign_in() {
        assert!(validate(&args("list")).is_ok());
        assert!(validate(&args("remove P-1")).is_ok());
        assert!(validate(&args("bogus")).is_err());
        assert!(validate(&pins_line("")).is_ok());
        let long = "x".repeat(129);
        assert!(validate(&args(&format!(
            "add --label {long} --kind apple --anchor-sha256 {} --pin-sha256 {}",
            "aa".repeat(32),
            "bb".repeat(32)
        )))
        .is_err());
        let e = validate(&args(
            "add --label ACME --kind apple --anchor-sha256 zz --pin-sha256 bb",
        ))
        .unwrap_err()
        .to_string();
        assert!(e.contains("SHA-256"), "{e}");
        let e = validate(&pins_line("--expires-at 5"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("future"), "{e}");
        let e = validate(&args(
            "add --label ACME --leaf-cert /nonexistent/leaf --anchor-cert /nonexistent/ca --kind apple",
        ))
        .unwrap_err()
        .to_string();
        assert!(e.contains("/nonexistent/leaf"), "{e}");
    }

    #[test]
    fn certificate_files_are_read_bounded_and_never_a_directory() {
        let dir = std::env::temp_dir().join(format!("ferrogate-cli-pub-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let big = dir.join("big.pem");
        std::fs::write(&big, vec![b'A'; 64 * 1024 + 1]).unwrap();
        let ok = dir.join("ok.pem");
        std::fs::write(&ok, vec![b'A'; 64 * 1024]).unwrap();
        assert!(read_cert_file(&big).is_err(), "one byte over the bound");
        assert_eq!(read_cert_file(&ok).unwrap().len(), 64 * 1024);
        assert!(read_cert_file(&dir).is_err(), "a directory");
        assert!(read_cert_file(&dir.join("missing")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rows_print_cleaned_and_in_full() {
        let info = TrustedPublisherInfo {
            publisher_id: "0190f0aa-0000-7000-8000-00000000beef".into(),
            kind: 1,
            anchor_sha256: vec![0xaa; 32],
            pin_kind: 2,
            pin: vec![0xbb; 32],
            require_timestamp: true,
            label: "ACME\u{1b}[31m".into(),
            subject: "CN=ACME".into(),
            created_at: 7,
            state: 2,
            removed_at: 9,
            removed_by_admin_id: "admin-2".into(),
            ..TrustedPublisherInfo::default()
        };
        let row = PublisherRow::of(&info);
        let line = list_line(&row);
        assert!(line.starts_with("P-0000BEEF  removed"), "{line}");
        assert!(
            line.contains("authenticode") && line.contains("leaf-spki"),
            "{line}"
        );
        assert!(
            line.contains("expires never") && !line.contains('\u{1b}'),
            "{line}"
        );
        let fields = row_fields(&row);
        let get = |k: &str| fields.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone());
        assert_eq!(get("pin:").unwrap(), "bb".repeat(32));
        assert_eq!(get("anchor_sha256:").unwrap(), "aa".repeat(32));
        assert_eq!(get("removed_by:").unwrap(), "admin-2");
        assert!(get("leaf_cert_sha256:").is_none(), "added by pins");
    }

    #[test]
    fn only_a_refused_second_factor_reads_as_rejected() {
        let e = rpc_err(tonic::Status::unauthenticated("invalid_credentials"));
        assert!(proof_rejected(&e));
        let e = rpc_err(tonic::Status::unauthenticated("session_invalid"));
        assert!(!proof_rejected(&e));
        let e = rpc_err(tonic::Status::already_exists("publisher_exists"));
        assert!(!proof_rejected(&e));
    }
}
