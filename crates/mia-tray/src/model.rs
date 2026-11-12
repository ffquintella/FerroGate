//! Pure state → presentation mapping.
//!
//! The daemon decides the [`AgentState`]; the tray only maps it to an icon,
//! a title, an explanation and recovery suggestions (the table in
//! `docs/features/F18-mia-tray.md`), and builds the menu as plain data
//! ([`MenuNode`]) that the GUI turns into native menu items. Nothing here does
//! I/O, so all of it is unit-tested headlessly.

use mia_status_proto::{
    error_codes, AgentState, AllowlistState, AttestBackend, StatusSnapshot, StoreBackend,
};

use crate::actions::{Action, Doc, EnvName};
use crate::client::{
    Observation, Source, ACCESS_DENIED_CODE, ENDPOINT_DOWN_CODE, NOT_INSTALLED_CODE,
};
use crate::i18n::{fill, Lang, Msg};
use crate::text::{display_safe, human_duration, MAX_FIELD_CHARS};

/// Icon colours (the spec's table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IconColor {
    /// Absent / not configured.
    Grey,
    /// Attesting.
    Blue,
    /// Healthy.
    Green,
    /// Degraded: retrying, stale CRL, allowlist problems, SVID expiring.
    Yellow,
    /// Broken: not enrolled, pin mismatch, TPM, IMA.
    Red,
}

/// The glyph drawn over the icon's disc, so the state never rests on
/// colour alone (F23 §2; WCAG 1.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Glyph {
    /// ✓ — healthy.
    Check,
    /// … — attesting (static: the icon never blinks).
    Busy,
    /// ! — degraded, or not configured.
    Bang,
    /// × — broken.
    Cross,
    /// – — not installed or not running.
    Dash,
}

impl Glyph {
    /// The same glyph as text, for the window's state badge.
    #[must_use]
    pub fn text(self) -> &'static str {
        match self {
            Self::Check => "✔",
            Self::Busy => "…",
            Self::Bang => "!",
            Self::Cross => "✖",
            Self::Dash => "–",
        }
    }
}

/// How a state looks in the tray.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Presentation {
    /// Icon colour.
    pub color: IconColor,
    /// The glyph over it.
    pub glyph: Glyph,
}

/// The icon for `state`.
#[must_use]
pub fn presentation(state: AgentState) -> Presentation {
    let (color, glyph) = match state {
        AgentState::NotInstalled | AgentState::NotRunning => (IconColor::Grey, Glyph::Dash),
        AgentState::NotConfigured => (IconColor::Grey, Glyph::Bang),
        AgentState::Attesting => (IconColor::Blue, Glyph::Busy),
        AgentState::CmisUnreachable
        | AgentState::CrlStale
        | AgentState::AllowlistMissing
        | AgentState::AllowlistInvalid
        | AgentState::SvidExpiring => (IconColor::Yellow, Glyph::Bang),
        AgentState::NotEnrolled
        | AgentState::PinMismatch
        | AgentState::TpmUnavailable
        | AgentState::ImaDisabled => (IconColor::Red, Glyph::Cross),
        AgentState::Healthy => (IconColor::Green, Glyph::Check),
    };
    Presentation { color, glyph }
}

/// The state's short title.
#[must_use]
pub fn title(state: AgentState) -> Msg {
    match state {
        AgentState::NotInstalled => Msg::StateNotInstalled,
        AgentState::NotRunning => Msg::StateNotRunning,
        AgentState::NotConfigured => Msg::StateNotConfigured,
        AgentState::Attesting => Msg::StateAttesting,
        AgentState::CmisUnreachable => Msg::StateCmisUnreachable,
        AgentState::NotEnrolled => Msg::StateNotEnrolled,
        AgentState::PinMismatch => Msg::StatePinMismatch,
        AgentState::TpmUnavailable => Msg::StateTpmUnavailable,
        AgentState::ImaDisabled => Msg::StateImaDisabled,
        AgentState::CrlStale => Msg::StateCrlStale,
        AgentState::AllowlistMissing => Msg::StateAllowlistMissing,
        AgentState::AllowlistInvalid => Msg::StateAllowlistInvalid,
        AgentState::SvidExpiring => Msg::StateSvidExpiring,
        AgentState::Healthy => Msg::StateHealthy,
    }
}

/// The state's explanation.
#[must_use]
pub fn explanation(state: AgentState) -> Msg {
    match state {
        AgentState::NotInstalled => Msg::ExplainNotInstalled,
        AgentState::NotRunning => Msg::ExplainNotRunning,
        AgentState::NotConfigured => Msg::ExplainNotConfigured,
        AgentState::Attesting => Msg::ExplainAttesting,
        AgentState::CmisUnreachable => Msg::ExplainCmisUnreachable,
        AgentState::NotEnrolled => Msg::ExplainNotEnrolled,
        AgentState::PinMismatch => Msg::ExplainPinMismatch,
        AgentState::TpmUnavailable => Msg::ExplainTpmUnavailable,
        AgentState::ImaDisabled => Msg::ExplainImaDisabled,
        AgentState::CrlStale => Msg::ExplainCrlStale,
        AgentState::AllowlistMissing => Msg::ExplainAllowlistMissing,
        AgentState::AllowlistInvalid => Msg::ExplainAllowlistInvalid,
        AgentState::SvidExpiring => Msg::ExplainSvidExpiring,
        AgentState::Healthy => Msg::ExplainHealthy,
    }
}

/// Setup-wizard steps a recovery can open at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WizardStep {
    /// CMIS endpoint / SRV / pin.
    Cmis,
    /// The SPKI pin field specifically.
    Pins,
    /// Attestation backend and logging.
    Attestation,
}

/// One suggested recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Recovery {
    /// Run a fixed command.
    Run(Action),
    /// Open the setup wizard.
    OpenWizard(WizardStep),
    /// Copy the machine identifiers for an operator.
    CopyMachineIds,
    /// Open a document.
    Read(Doc),
}

impl Recovery {
    /// The label.
    #[must_use]
    pub fn label(self, lang: Lang) -> String {
        match self {
            Self::Run(a) => a.label().text(lang).to_string(),
            Self::OpenWizard(WizardStep::Cmis) => Msg::RecoveryOpenWizard.text(lang).to_string(),
            Self::OpenWizard(WizardStep::Pins) => {
                Msg::RecoveryOpenWizardPins.text(lang).to_string()
            }
            Self::OpenWizard(WizardStep::Attestation) => {
                Msg::RecoveryOpenWizardAttestation.text(lang).to_string()
            }
            Self::CopyMachineIds => Msg::RecoveryCopyIds.text(lang).to_string(),
            Self::Read(doc) => fill(
                Msg::MenuReadDoc.text(lang),
                &[("doc", doc.label().text(lang))],
            ),
        }
    }
}

/// Every error code this tray version knows (daemon codes plus its own).
#[must_use]
pub fn is_known_error_code(code: &str) -> bool {
    use error_codes as c;
    [
        c::CMIS_NOT_CONFIGURED,
        c::CMIS_MISCONFIGURED,
        c::HELPER_NOT_CONFIGURED,
        c::CMIS_UNREACHABLE,
        c::ATTESTATION_FAILED,
        c::HOST_REJECTED,
        c::PIN_MISMATCH,
        c::TPM_UNAVAILABLE,
        c::IMA_DISABLED,
        c::CRL_STALE,
        c::ALLOWLIST_MISSING,
        c::ALLOWLIST_INVALID,
        c::ALLOWLIST_EXPIRED,
        c::SVID_RENEWAL_DUE,
        c::SVID_EXPIRED,
        c::NOT_RUNNING,
        ACCESS_DENIED_CODE,
        ENDPOINT_DOWN_CODE,
        NOT_INSTALLED_CODE,
    ]
    .contains(&code)
}

/// The recoveries for a snapshot: the spec's table, plus "run self-test" for
/// any error code this tray does not recognise (newer daemons).
#[must_use]
pub fn recoveries(snapshot: &StatusSnapshot) -> Vec<Recovery> {
    use Recovery::{CopyMachineIds, OpenWizard, Read, Run};
    let code = snapshot.last_error.as_ref().map(|e| e.code.as_str());
    if code == Some(ACCESS_DENIED_CODE) {
        return vec![Read(Doc::Tray)];
    }
    if code == Some(ENDPOINT_DOWN_CODE) {
        // Starting a running service fails; a restart lets it create the
        // missing status group and bind the endpoint again.
        return vec![Run(Action::ServiceRestart), Read(Doc::Tray)];
    }
    let mut out = match snapshot.state {
        AgentState::NotInstalled => vec![Read(Doc::Install)],
        AgentState::NotRunning => vec![Run(Action::ServiceStart), Read(Doc::Install)],
        AgentState::NotConfigured => vec![OpenWizard(WizardStep::Cmis)],
        AgentState::Attesting | AgentState::Healthy => vec![],
        AgentState::CmisUnreachable => vec![Run(Action::RunSelfTest), Read(Doc::Networking)],
        AgentState::NotEnrolled => vec![CopyMachineIds, Read(Doc::Enrollment)],
        AgentState::PinMismatch => vec![OpenWizard(WizardStep::Pins), Read(Doc::Pins)],
        AgentState::TpmUnavailable => vec![
            Run(Action::RunSelfTest),
            OpenWizard(WizardStep::Attestation),
            Read(Doc::Tpm),
        ],
        AgentState::ImaDisabled => vec![Read(Doc::Hardening)],
        AgentState::CrlStale => vec![Run(Action::RunSelfTest), Read(Doc::CrlStale)],
        AgentState::AllowlistMissing | AgentState::AllowlistInvalid => {
            vec![Run(Action::ResyncAllowlist), Read(Doc::Allowlist)]
        }
        AgentState::SvidExpiring => {
            vec![Run(Action::RunSelfTest), Run(Action::ServiceRestart)]
        }
    };
    if code.is_some_and(|c| !is_known_error_code(c)) && !out.contains(&Run(Action::RunSelfTest)) {
        out.insert(0, Run(Action::RunSelfTest));
    }
    out
}

/// The snapshot whose state is worst (highest severity; ties keep the first).
#[must_use]
pub fn worst(snapshots: &[StatusSnapshot]) -> Option<&StatusSnapshot> {
    snapshots.iter().reduce(|a, b| {
        if b.state.severity() > a.state.severity() {
            b
        } else {
            a
        }
    })
}

/// Display label of a snapshot's environment.
#[must_use]
pub fn env_label(snapshot: &StatusSnapshot, lang: Lang) -> String {
    snapshot.environment.as_deref().map_or_else(
        || Msg::DefaultEnvironment.text(lang).to_string(),
        |e| display_safe(e, 64),
    )
}

/// The `-e` argument for a snapshot's environment (`None` = default; also
/// `None` if the daemon reported a name the shared validator rejects, so it
/// is never passed to a command).
#[must_use]
pub fn env_arg(snapshot: &StatusSnapshot) -> Option<EnvName> {
    snapshot
        .environment
        .as_deref()
        .and_then(|e| EnvName::parse(e).ok())
}

/// The title for a snapshot, honouring the tray-side access-denied code.
#[must_use]
pub fn snapshot_title(snapshot: &StatusSnapshot) -> Msg {
    match snapshot.last_error.as_ref().map(|e| e.code.as_str()) {
        Some(ACCESS_DENIED_CODE) => Msg::StateAccessDenied,
        Some(ENDPOINT_DOWN_CODE) => Msg::StateEndpointDown,
        _ => title(snapshot.state),
    }
}

/// The explanation for a snapshot (access denied / unknown code aware).
#[must_use]
pub fn snapshot_explanation(snapshot: &StatusSnapshot) -> Msg {
    match snapshot.last_error.as_ref().map(|e| e.code.as_str()) {
        Some(ACCESS_DENIED_CODE) => Msg::ExplainAccessDenied,
        Some(ENDPOINT_DOWN_CODE) => Msg::ExplainEndpointDown,
        Some(c) if !is_known_error_code(c) => Msg::ExplainUnknownError,
        _ => explanation(snapshot.state),
    }
}

fn relative(delta: i64, lang: Lang) -> String {
    if delta >= 0 {
        fill(Msg::DetailIn.text(lang), &[("d", &human_duration(delta))])
    } else {
        fill(Msg::DetailAgo.text(lang), &[("d", &human_duration(-delta))])
    }
}

/// The per-environment detail lines (all daemon-provided text escaped).
#[must_use]
pub fn detail_lines(s: &StatusSnapshot, now: i64, lang: Lang) -> Vec<String> {
    let t = |m: Msg| m.text(lang);
    let mut out = vec![format!(
        "{}: {} ({})",
        t(Msg::DetailState),
        t(snapshot_title(s)),
        fill(t(Msg::DetailFor), &[("d", &human_duration(now - s.since))])
    )];
    if s.default_address {
        out.push(t(Msg::DetailDefaultAddress).to_string());
    }
    if let Some(e) = &s.last_error {
        out.push(format!(
            "{}: {} ({})",
            t(Msg::DetailProblem),
            display_safe(&e.message, 200),
            display_safe(&e.code, 64)
        ));
    }
    if let Some(svid) = &s.svid {
        out.push(format!(
            "{}: {} — {}",
            t(Msg::DetailIdentity),
            display_safe(&svid.spiffe_id, MAX_FIELD_CHARS),
            fill(
                t(Msg::DetailSvidTimes),
                &[
                    ("expires", &relative(svid.not_after - now, lang)),
                    ("renews", &relative(svid.renew_at - now, lang)),
                ]
            )
        ));
    }
    if let Some(node) = &s.cmis_node {
        out.push(format!(
            "{}: {}",
            t(Msg::DetailCmisNode),
            display_safe(node, 256)
        ));
    }
    out.push(format!(
        "{}: {}",
        t(Msg::DetailCrlAge),
        s.crl_age_secs.map_or_else(
            || t(Msg::DetailCrlNone).to_string(),
            |a| human_duration(i64::from(a))
        )
    ));
    let allowlist = match s.allowlist {
        AllowlistState::Missing => t(Msg::AllowlistMissingShort).to_string(),
        AllowlistState::Invalid => t(Msg::AllowlistInvalidShort).to_string(),
        AllowlistState::Loaded { entries, not_after } => fill(
            t(Msg::AllowlistLoaded),
            &[
                ("n", &entries.to_string()),
                ("when", &relative(not_after - now, lang)),
            ],
        ),
    };
    out.push(format!("{}: {allowlist}", t(Msg::DetailAllowlist)));
    let backend = match s.attest_backend {
        AttestBackend::Auto => t(Msg::BackendAuto),
        AttestBackend::Tpm => "tpm",
        AttestBackend::HostKey => "host-key",
        AttestBackend::VirtualTpm => t(Msg::BackendVirtualTpm),
    };
    out.push(format!("{}: {backend}", t(Msg::DetailAttestation)));
    if let Some(store) = s.x509_store {
        let name = match store {
            StoreBackend::Tpm => "tpm",
            StoreBackend::MachineKey => "machine-key",
            StoreBackend::SecureEnclave => "secure-enclave",
        };
        out.push(format!("{}: {name}", t(Msg::DetailX509Store)));
    }
    if !s.version.is_empty() {
        out.push(format!(
            "{}: mia {}",
            t(Msg::DetailAgent),
            display_safe(&s.version, 64)
        ));
    }
    out
}

/// One environment in the tray menu / status window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvView {
    /// Environment label.
    pub label: String,
    /// Its `-e` argument.
    pub env: Option<EnvName>,
    /// Its state.
    pub state: AgentState,
    /// `"<label>: <title>"`.
    pub headline: String,
    /// Detail lines.
    pub details: Vec<String>,
    /// Suggested recoveries.
    pub recoveries: Vec<Recovery>,
    /// This environment serves the helper API's well-known default address
    /// (the daemon's `default_address`): the marker in [`Self::headline`].
    pub default_address: bool,
    /// The default-environment action offered for it ([`default_choice`]).
    pub default_choice: Option<Recovery>,
}

/// The name `mia` reserves for the `mia.toml` environment's label
/// (`mia status -e default`); it can never be selected as the default.
const RESERVED_ENVIRONMENT: &str = "default";

/// The default-environment action for a snapshot: "Use mia.toml as default"
/// for the `mia.toml` environment, "Set as default environment" for a named
/// one. Offered only when the agent itself reported the snapshot (`source` is
/// not [`Source::Synthesised`]), only for an environment that does not
/// already serve the well-known address, and never for a name the shared
/// validator rejects or the reserved `default`.
#[must_use]
pub fn default_choice(s: &StatusSnapshot, source: Source) -> Option<Recovery> {
    if s.default_address || source == Source::Synthesised {
        return None;
    }
    match s.environment.as_deref() {
        None => Some(Recovery::Run(Action::ClearDefaultEnvironment)),
        Some(RESERVED_ENVIRONMENT) => None,
        Some(e) => EnvName::parse(e)
            .ok()
            .map(|_| Recovery::Run(Action::SetDefaultEnvironment)),
    }
}

/// Everything the tray shows for one observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayView {
    /// The icon (worst state wins).
    pub presentation: Presentation,
    /// The worst state.
    pub worst: AgentState,
    /// Tooltip / menu header.
    pub headline: String,
    /// Where the data came from.
    pub source: Source,
    /// Per environment.
    pub envs: Vec<EnvView>,
}

/// Build the view for `obs`.
#[must_use]
pub fn tray_view(obs: &Observation, now: i64, lang: Lang) -> TrayView {
    let envs: Vec<EnvView> = obs
        .snapshots
        .iter()
        .map(|s| {
            let label = env_label(s, lang);
            let mut recs = recoveries(s);
            // A name the shared validator rejects is never turned into
            // `-e <env>` — and never silently replaced by the default
            // environment either: only documentation links remain.
            let valid_name = s
                .environment
                .as_deref()
                .is_none_or(|e| EnvName::parse(e).is_ok());
            if !valid_name {
                recs.retain(|r| matches!(r, Recovery::Read(_)));
            }
            let marker = if s.default_address {
                format!(" {}", Msg::MarkerDefaultAddress.text(lang))
            } else {
                String::new()
            };
            EnvView {
                headline: format!("{label}{marker}: {}", snapshot_title(s).text(lang)),
                label,
                env: env_arg(s),
                state: s.state,
                details: detail_lines(s, now, lang),
                recoveries: recs,
                default_address: s.default_address,
                default_choice: default_choice(s, obs.source),
            }
        })
        .collect();
    let worst_snapshot = worst(&obs.snapshots);
    let worst_state = worst_snapshot.map_or(AgentState::NotRunning, |s| s.state);
    let headline = match (worst_snapshot, envs.len()) {
        (Some(s), 1) => format!(
            "{} — {}",
            Msg::AppName.text(lang),
            snapshot_title(s).text(lang)
        ),
        (Some(s), _) => format!(
            "{} — {} ({})",
            Msg::AppName.text(lang),
            snapshot_title(s).text(lang),
            env_label(s, lang)
        ),
        (None, _) => Msg::AppName.text(lang).to_string(),
    };
    TrayView {
        presentation: presentation(worst_state),
        worst: worst_state,
        headline,
        source: obs.source,
        envs,
    }
}

// ── Menu model ───────────────────────────────────────────────────────────────

/// Which window a menu entry opens (the main window, at a tab).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowKind {
    /// Status overview.
    Status,
    /// Recovery panel.
    Recovery,
    /// Recovery panel, running the self-test immediately.
    SelfTest,
    /// Setup wizard.
    Setup,
    /// Setup wizard at the pin field.
    SetupPins,
    /// Setup wizard at the attestation step.
    SetupAttestation,
    /// Log viewer.
    Logs,
}

impl WindowKind {
    /// Every kind.
    pub const ALL: [Self; 7] = [
        Self::Status,
        Self::Recovery,
        Self::SelfTest,
        Self::Setup,
        Self::SetupPins,
        Self::SetupAttestation,
        Self::Logs,
    ];

    /// The `--window <kind>` argument.
    #[must_use]
    pub fn as_arg(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Recovery => "recovery",
            Self::SelfTest => "self-test",
            Self::Setup => "setup",
            Self::SetupPins => "setup-pins",
            Self::SetupAttestation => "setup-attestation",
            Self::Logs => "logs",
        }
    }

    /// Parse a `--window` argument (closed set).
    #[must_use]
    pub fn from_arg(arg: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_arg() == arg)
    }
}

/// What a menu entry does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuCommand {
    /// Open a window.
    Open(WindowKind),
    /// Run a recovery for an environment.
    Recover(Recovery, Option<EnvName>),
    /// Start the separate administrator client (`mia-tray-admin`, F22). A
    /// unit variant on purpose: the command line is fixed
    /// ([`crate::actions::admin_client_spec`]) and nothing the menu shows
    /// can reach it.
    OpenAdminClient,
    /// Quit the tray.
    Quit,
}

/// A menu as plain data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuNode {
    /// A disabled text line.
    Label(String),
    /// A clickable entry.
    Item(String, MenuCommand),
    /// A submenu.
    Submenu(String, Vec<MenuNode>),
    /// A separator.
    Separator,
}

/// The [`MenuCommand`] for a recovery (wizard recoveries open a window).
#[must_use]
pub fn recovery_command(r: Recovery, env: Option<EnvName>) -> MenuCommand {
    match r {
        Recovery::OpenWizard(WizardStep::Cmis) => MenuCommand::Open(WindowKind::Setup),
        Recovery::OpenWizard(WizardStep::Pins) => MenuCommand::Open(WindowKind::SetupPins),
        Recovery::OpenWizard(WizardStep::Attestation) => {
            MenuCommand::Open(WindowKind::SetupAttestation)
        }
        Recovery::Run(Action::RunSelfTest) => MenuCommand::Open(WindowKind::SelfTest),
        other => MenuCommand::Recover(other, env),
    }
}

/// The tray menu for `view` (F23 §3): the summary, the latest notice,
/// the worst environment's recoveries (the primary commands), "Open
/// FerroGate…", the environments only when there are several, "Review
/// approvals…" only when `admin_client` (the administrator client was found
/// beside the tray and passed the trust rule,
/// [`crate::locate::locate_admin_client`]), then Setup and Quit.
/// Inapplicable entries are left out, never shown disabled.
#[must_use]
pub fn menu_model(
    view: &TrayView,
    lang: Lang,
    notice_line: Option<&str>,
    admin_client: bool,
) -> Vec<MenuNode> {
    let t = |m: Msg| m.text(lang).to_string();
    let mut menu = vec![MenuNode::Label(view.headline.clone())];
    if let Some(line) = notice_line {
        menu.push(MenuNode::Label(line.to_string()));
    }
    menu.push(MenuNode::Separator);
    // The primary commands: the worst environment's recoveries.
    if let Some(env) = view
        .envs
        .iter()
        .filter(|e| e.state == view.worst)
        .find(|e| !e.recoveries.is_empty())
    {
        for r in &env.recoveries {
            let label = if view.envs.len() > 1 {
                fill(
                    Msg::MenuForEnv.text(lang),
                    &[("action", &r.label(lang)), ("env", &env.label)],
                )
            } else {
                r.label(lang)
            };
            menu.push(MenuNode::Item(label, recovery_command(*r, env.env.clone())));
        }
        menu.push(MenuNode::Separator);
    }
    menu.push(MenuNode::Item(
        t(Msg::MenuOpenMain),
        MenuCommand::Open(WindowKind::Status),
    ));
    if view.envs.len() > 1 {
        let envs = view.envs.iter().map(|env| env_node(env, lang)).collect();
        menu.push(MenuNode::Submenu(t(Msg::MenuEnvironments), envs));
    }
    if admin_client {
        menu.push(MenuNode::Item(
            t(Msg::MenuReviewApprovals),
            MenuCommand::OpenAdminClient,
        ));
    }
    menu.push(MenuNode::Separator);
    menu.push(MenuNode::Item(
        t(Msg::MenuSetup),
        MenuCommand::Open(WindowKind::Setup),
    ));
    menu.push(MenuNode::Item(t(Msg::MenuQuit), MenuCommand::Quit));
    menu
}

/// One environment in the "Environments" submenu: a submenu of its
/// actions, or a plain line when it has none.
fn env_node(env: &EnvView, lang: Lang) -> MenuNode {
    let mut actions: Vec<MenuNode> = env
        .recoveries
        .iter()
        .map(|r| MenuNode::Item(r.label(lang), recovery_command(*r, env.env.clone())))
        .collect();
    if let Some(r) = env.default_choice {
        if !actions.is_empty() {
            actions.push(MenuNode::Separator);
        }
        actions.push(MenuNode::Item(
            r.label(lang),
            recovery_command(r, env.env.clone()),
        ));
    }
    if actions.is_empty() {
        MenuNode::Label(env.headline.clone())
    } else {
        MenuNode::Submenu(env.headline.clone(), actions)
    }
}

// ── Dispatch planning ────────────────────────────────────────────────────────

/// What the tray does for a menu command or a notification click, decided
/// without I/O so it is unit-tested; `gui::tray` carries it out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayEffect {
    /// Leave the loop.
    Quit,
    /// Show the main window at this tab (reusing an open one).
    ShowWindow(WindowKind),
    /// Start or raise the administrator client.
    OpenAdminClient,
    /// Run a fixed action for an environment; `copy_ids` copies the parsed
    /// machine identifiers afterwards.
    RunAction {
        /// The action.
        action: Action,
        /// Its environment.
        env: Option<EnvName>,
        /// Copy the machine identifiers when it succeeds.
        copy_ids: bool,
    },
    /// Open a document from the fixed table.
    OpenDoc(Doc),
}

/// The effect of a menu command.
#[must_use]
pub fn plan(cmd: &MenuCommand) -> TrayEffect {
    match cmd {
        MenuCommand::Quit => TrayEffect::Quit,
        MenuCommand::Open(kind) => TrayEffect::ShowWindow(*kind),
        MenuCommand::OpenAdminClient => TrayEffect::OpenAdminClient,
        MenuCommand::Recover(Recovery::Run(action), env) => TrayEffect::RunAction {
            action: *action,
            env: env.clone(),
            copy_ids: false,
        },
        MenuCommand::Recover(Recovery::CopyMachineIds, _) => TrayEffect::RunAction {
            action: Action::ShowMachineId,
            env: None,
            copy_ids: true,
        },
        MenuCommand::Recover(Recovery::Read(doc), _) => TrayEffect::OpenDoc(*doc),
        // `recovery_command` already maps these to windows; kept total.
        MenuCommand::Recover(Recovery::OpenWizard(step), _) => TrayEffect::ShowWindow(match step {
            WizardStep::Cmis => WindowKind::Setup,
            WizardStep::Pins => WindowKind::SetupPins,
            WizardStep::Attestation => WindowKind::SetupAttestation,
        }),
    }
}

/// The effect of activating a notification that leads to `target`.
#[must_use]
pub fn plan_target(target: crate::notice::Target) -> TrayEffect {
    match target {
        crate::notice::Target::Window(kind) => TrayEffect::ShowWindow(kind),
        crate::notice::Target::Approvals => TrayEffect::OpenAdminClient,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::synthesised;
    use mia_status_proto::{ErrorSummary, SvidSummary};

    fn snap(state: AgentState, env: Option<&str>, code: Option<&str>) -> StatusSnapshot {
        let mut s = synthesised(state, code.unwrap_or("x"), "msg", 100);
        s.environment = env.map(str::to_string);
        if code.is_none() {
            s.last_error = None;
        }
        s
    }

    /// The spec's table, row by row: icon and recovery actions for every
    /// `AgentState`.
    #[test]
    fn every_agent_state_maps_to_the_documented_icon_and_recoveries() {
        use Glyph::{Bang, Busy, Check, Cross, Dash};
        use IconColor::{Blue, Green, Grey, Red, Yellow};
        use Recovery::{CopyMachineIds, OpenWizard, Read, Run};
        let table: [(AgentState, IconColor, Glyph, Vec<Recovery>); 14] = [
            (
                AgentState::NotInstalled,
                Grey,
                Dash,
                vec![Read(Doc::Install)],
            ),
            (
                AgentState::NotRunning,
                Grey,
                Dash,
                vec![Run(Action::ServiceStart), Read(Doc::Install)],
            ),
            (
                AgentState::NotConfigured,
                Grey,
                Bang,
                vec![OpenWizard(WizardStep::Cmis)],
            ),
            (AgentState::Attesting, Blue, Busy, vec![]),
            (
                AgentState::CmisUnreachable,
                Yellow,
                Bang,
                vec![Run(Action::RunSelfTest), Read(Doc::Networking)],
            ),
            (
                AgentState::NotEnrolled,
                Red,
                Cross,
                vec![CopyMachineIds, Read(Doc::Enrollment)],
            ),
            (
                AgentState::PinMismatch,
                Red,
                Cross,
                vec![OpenWizard(WizardStep::Pins), Read(Doc::Pins)],
            ),
            (
                AgentState::TpmUnavailable,
                Red,
                Cross,
                vec![
                    Run(Action::RunSelfTest),
                    OpenWizard(WizardStep::Attestation),
                    Read(Doc::Tpm),
                ],
            ),
            (
                AgentState::ImaDisabled,
                Red,
                Cross,
                vec![Read(Doc::Hardening)],
            ),
            (
                AgentState::CrlStale,
                Yellow,
                Bang,
                vec![Run(Action::RunSelfTest), Read(Doc::CrlStale)],
            ),
            (
                AgentState::AllowlistMissing,
                Yellow,
                Bang,
                vec![Run(Action::ResyncAllowlist), Read(Doc::Allowlist)],
            ),
            (
                AgentState::AllowlistInvalid,
                Yellow,
                Bang,
                vec![Run(Action::ResyncAllowlist), Read(Doc::Allowlist)],
            ),
            (
                AgentState::SvidExpiring,
                Yellow,
                Bang,
                vec![Run(Action::RunSelfTest), Run(Action::ServiceRestart)],
            ),
            (AgentState::Healthy, Green, Check, vec![]),
        ];
        assert_eq!(table.len(), AgentState::ALL.len());
        for (state, color, glyph, recs) in table {
            let p = presentation(state);
            assert_eq!(p.color, color, "{state:?}");
            assert_eq!(p.glyph, glyph, "{state:?}");
            assert_eq!(recoveries(&snap(state, None, None)), recs, "{state:?}");
            assert_ne!(title(state).text(Lang::Pt), "", "{state:?}");
        }
    }

    #[test]
    fn unknown_error_codes_render_generically_with_self_test() {
        let s = snap(AgentState::AllowlistMissing, None, Some("from_the_future"));
        let r = recoveries(&s);
        assert_eq!(r[0], Recovery::Run(Action::RunSelfTest));
        assert_eq!(snapshot_explanation(&s), Msg::ExplainUnknownError);
        // Known codes keep the state's own explanation.
        let s = snap(AgentState::CrlStale, None, Some(error_codes::CRL_STALE));
        assert_eq!(snapshot_explanation(&s), Msg::ExplainCrlStale);
    }

    #[test]
    fn endpoint_down_offers_a_restart_not_a_start() {
        let s = snap(AgentState::NotRunning, None, Some(ENDPOINT_DOWN_CODE));
        assert_eq!(snapshot_title(&s), Msg::StateEndpointDown);
        assert_eq!(snapshot_explanation(&s), Msg::ExplainEndpointDown);
        assert_eq!(
            recoveries(&s),
            vec![
                Recovery::Run(Action::ServiceRestart),
                Recovery::Read(Doc::Tray)
            ]
        );
    }

    #[test]
    fn access_denied_is_its_own_message() {
        let s = snap(AgentState::NotRunning, None, Some(ACCESS_DENIED_CODE));
        assert_eq!(snapshot_title(&s), Msg::StateAccessDenied);
        assert_eq!(recoveries(&s), vec![Recovery::Read(Doc::Tray)]);
    }

    #[test]
    fn worst_state_wins_across_environments() {
        let obs = Observation {
            snapshots: vec![
                snap(AgentState::Healthy, None, None),
                snap(
                    AgentState::CrlStale,
                    Some("prod"),
                    Some(error_codes::CRL_STALE),
                ),
                snap(AgentState::Attesting, Some("dev"), None),
            ],
            source: Source::Endpoint,
        };
        let v = tray_view(&obs, 200, Lang::En);
        assert_eq!(v.worst, AgentState::CrlStale);
        assert_eq!(v.presentation.color, IconColor::Yellow);
        assert!(v.headline.contains("(prod)"));
        let menu = menu_model(&v, Lang::En, Some("Last action: x — done"), false);
        // One "Environments" submenu holding the three, and the worst one's
        // recoveries on top with the environment passed along.
        let subs: Vec<&MenuNode> = menu
            .iter()
            .filter(|n| matches!(n, MenuNode::Submenu(..)))
            .collect();
        assert!(
            matches!(subs.as_slice(), [MenuNode::Submenu(t, kids)] if t == "Environments" && kids.len() == 3)
        );
        // The primary command comes right after the summary lines.
        assert_eq!(
            menu[3],
            MenuNode::Item(
                "Run self-test (prod)".into(),
                MenuCommand::Open(WindowKind::SelfTest)
            )
        );
        assert!(menu.contains(&MenuNode::Item(
            "Run self-test (prod)".into(),
            MenuCommand::Open(WindowKind::SelfTest)
        )));
        assert!(menu.contains(&MenuNode::Item(
            "Read: CRL-stale runbook (prod)".into(),
            MenuCommand::Recover(
                Recovery::Read(Doc::CrlStale),
                Some(EnvName::parse("prod").unwrap())
            )
        )));
        assert!(matches!(
            menu.last(),
            Some(MenuNode::Item(_, MenuCommand::Quit))
        ));
        assert!(menu.contains(&MenuNode::Label("Last action: x — done".into())));
    }

    #[test]
    fn details_show_the_snapshot_and_escape_daemon_text() {
        let mut s = snap(AgentState::Healthy, Some("prod"), None);
        s.svid = Some(SvidSummary {
            spiffe_id: "spiffe://td/host/u".into(),
            not_after: 100 + 3600,
            renew_at: 100 + 600,
        });
        s.cmis_node = Some("cmis1:8443\n[fake line]".into());
        s.crl_age_secs = Some(42);
        s.allowlist = AllowlistState::Loaded {
            entries: 3,
            not_after: 100 + 86_400,
        };
        s.x509_store = Some(StoreBackend::MachineKey);
        s.version = "0.21.6".into();
        s.last_error = Some(ErrorSummary {
            code: "c".into(),
            message: "m\u{202e}x".into(),
        });
        let lines = detail_lines(&s, 100, Lang::En);
        let all = lines.join("\n");
        assert!(all.contains("spiffe://td/host/u — expires in 1h0m, renews in 10m"));
        assert!(all.contains("CMIS node: cmis1:8443\\n[fake line]"));
        assert!(all.contains("CRL age: 42s"));
        assert!(all.contains("loaded (3 entries, expires in 1d0h)"));
        assert!(all.contains("X.509 store: machine-key"));
        assert!(all.contains("mia 0.21.6"));
        assert!(all.contains("m\\u{202e}x"));
        assert!(!lines.iter().any(|l| l.contains('\n')));
        let pt = detail_lines(&s, 100, Lang::Pt).join("\n");
        assert!(pt.contains("Idade da CRL: 42s"));
    }

    #[test]
    fn invalid_daemon_environment_names_are_never_passed_on() {
        let s = snap(AgentState::Healthy, Some("../etc"), None);
        assert_eq!(env_arg(&s), None);
        // …and its command recoveries are dropped rather than retargeted at
        // the default environment.
        let bad = snap(AgentState::AllowlistMissing, Some("../etc"), None);
        let obs = Observation {
            snapshots: vec![bad],
            source: Source::Endpoint,
        };
        let v = tray_view(&obs, 100, Lang::En);
        assert_eq!(v.envs[0].recoveries, vec![Recovery::Read(Doc::Allowlist)]);
        assert_eq!(
            env_arg(&snap(AgentState::Healthy, Some("prod"), None))
                .unwrap()
                .as_str(),
            "prod"
        );
    }

    #[test]
    fn the_default_address_is_marked_and_the_others_can_take_it() {
        let main = snap(AgentState::Healthy, None, None);
        let mut prod = snap(AgentState::Healthy, Some("prod"), None);
        prod.default_address = true;
        let staging = snap(AgentState::Healthy, Some("staging"), None);
        let reserved = snap(AgentState::Healthy, Some("default"), None);
        let obs = Observation {
            snapshots: vec![main, prod, staging, reserved],
            source: Source::Endpoint,
        };
        let v = tray_view(&obs, 100, Lang::En);
        let staging_env = Some(EnvName::parse("staging").unwrap());

        // Only the environment that serves the address carries the marker
        // (headline) and the detail line.
        assert_eq!(v.envs[1].headline, "prod [default address]: Healthy");
        assert!(v.envs[1].default_address);
        assert!(v.envs[1].details[1].starts_with("Helper API: serves the well-known"));
        for i in [0, 2, 3] {
            assert!(!v.envs[i].headline.contains("[default address]"), "{i}");
            assert!(!v.envs[i].default_address);
            assert!(!v.envs[i].details.join("\n").contains("well-known"));
        }
        // The holder is offered nothing; mia.toml can take the address back;
        // a named environment can take it; the reserved name cannot.
        assert_eq!(v.envs[1].default_choice, None);
        assert_eq!(
            v.envs[0].default_choice,
            Some(Recovery::Run(Action::ClearDefaultEnvironment))
        );
        assert_eq!(
            v.envs[2].default_choice,
            Some(Recovery::Run(Action::SetDefaultEnvironment))
        );
        assert_eq!(v.envs[3].default_choice, None);

        // In the menu: inside each environment's submenu, with the name passed
        // along; never among the top-level (worst-state) recoveries.
        let menu = menu_model(&v, Lang::En, None, false);
        let envs = menu
            .iter()
            .find_map(|n| match n {
                MenuNode::Submenu(h, kids) if h == "Environments" => Some(kids.clone()),
                _ => None,
            })
            .unwrap();
        let submenu = |label: &str| {
            envs.iter()
                .find_map(|n| match n {
                    MenuNode::Submenu(h, kids) if h.starts_with(label) => Some(kids.clone()),
                    _ => None,
                })
                .unwrap()
        };
        assert!(submenu("staging").contains(&MenuNode::Item(
            "Set as default environment".into(),
            MenuCommand::Recover(Recovery::Run(Action::SetDefaultEnvironment), staging_env)
        )));
        assert!(submenu("default:").contains(&MenuNode::Item(
            "Use mia.toml as default".into(),
            MenuCommand::Recover(Recovery::Run(Action::ClearDefaultEnvironment), None)
        )));
        // The holder has no action at all: a plain line, not a submenu.
        assert!(envs.contains(&MenuNode::Label("prod [default address]: Healthy".into())));
        assert!(!menu.iter().any(|n| matches!(
            n,
            MenuNode::Item(_, MenuCommand::Recover(Recovery::Run(a), _))
                if a.applies_on_restart()
        )));

        // Portuguese marker.
        let pt = tray_view(&obs, 100, Lang::Pt);
        assert_eq!(pt.envs[1].headline, "prod [endereço padrão]: Saudável");

        // Not offered without the agent's own report, nor for a name the
        // shared validator rejects.
        let synthesised = Observation {
            snapshots: vec![snap(AgentState::NotRunning, None, Some("not_running"))],
            source: Source::Synthesised,
        };
        assert_eq!(
            tray_view(&synthesised, 100, Lang::En).envs[0].default_choice,
            None
        );
        let bad = snap(AgentState::Healthy, Some("../etc"), None);
        assert_eq!(default_choice(&bad, Source::Endpoint), None);
        assert_eq!(
            default_choice(&snap(AgentState::Healthy, Some("qa"), None), Source::Cli),
            Some(Recovery::Run(Action::SetDefaultEnvironment))
        );
    }

    #[test]
    fn window_kinds_round_trip() {
        for k in WindowKind::ALL {
            assert_eq!(WindowKind::from_arg(k.as_arg()), Some(k));
        }
        assert_eq!(WindowKind::from_arg("--evil"), None);
    }

    /// "Admin client…" is offered only when the caller found the binary in a
    /// trusted place, in both languages, and never in any other menu.
    #[test]
    fn the_admin_client_item_appears_only_when_it_was_located_and_trusted() {
        let obs = Observation {
            snapshots: vec![snap(AgentState::Healthy, None, None)],
            source: Source::Endpoint,
        };
        for lang in [Lang::En, Lang::Pt] {
            let v = tray_view(&obs, 100, lang);
            let item = MenuNode::Item(
                Msg::MenuReviewApprovals.text(lang).to_string(),
                MenuCommand::OpenAdminClient,
            );
            let without = menu_model(&v, lang, None, false);
            let with = menu_model(&v, lang, None, true);
            assert!(!without.contains(&item));
            assert!(!without
                .iter()
                .any(|n| matches!(n, MenuNode::Item(_, MenuCommand::OpenAdminClient))));
            assert!(with.contains(&item));
            // The item is the only difference, and Quit stays last.
            assert_eq!(with.len(), without.len() + 1);
            assert!(matches!(
                with.last(),
                Some(MenuNode::Item(_, MenuCommand::Quit))
            ));
        }
        assert_ne!(
            Msg::MenuReviewApprovals.text(Lang::En),
            Msg::MenuReviewApprovals.text(Lang::Pt)
        );
    }

    /// A healthy single-environment menu is short: summary, the default
    /// action, Setup, Quit — no detail lines, Logs or self-test.
    #[test]
    fn a_healthy_menu_has_only_what_applies() {
        let obs = Observation {
            snapshots: vec![snap(AgentState::Healthy, None, None)],
            source: Source::Endpoint,
        };
        for lang in Lang::ALL {
            let v = tray_view(&obs, 100, lang);
            let menu = menu_model(&v, lang, None, false);
            assert_eq!(
                menu,
                vec![
                    MenuNode::Label(v.headline.clone()),
                    MenuNode::Separator,
                    MenuNode::Item(
                        Msg::MenuOpenMain.text(lang).into(),
                        MenuCommand::Open(WindowKind::Status)
                    ),
                    MenuNode::Separator,
                    MenuNode::Item(
                        Msg::MenuSetup.text(lang).into(),
                        MenuCommand::Open(WindowKind::Setup)
                    ),
                    MenuNode::Item(Msg::MenuQuit.text(lang).into(), MenuCommand::Quit),
                ],
                "{lang:?}"
            );
        }
    }

    /// A stopped agent puts the fix first, before "Open FerroGate…".
    #[test]
    fn the_fix_is_the_first_command() {
        let obs = Observation {
            snapshots: vec![snap(AgentState::NotRunning, None, Some("not_running"))],
            source: Source::Synthesised,
        };
        let v = tray_view(&obs, 100, Lang::En);
        let menu = menu_model(&v, Lang::En, Some("Start — running…"), false);
        let first_item = menu
            .iter()
            .find(|n| matches!(n, MenuNode::Item(..)))
            .unwrap();
        assert_eq!(
            first_item,
            &MenuNode::Item(
                Action::ServiceStart.label().text(Lang::En).into(),
                MenuCommand::Recover(Recovery::Run(Action::ServiceStart), None)
            )
        );
        assert_eq!(menu[1], MenuNode::Label("Start — running…".into()));
    }

    #[test]
    fn every_menu_command_plans_one_effect() {
        let prod = Some(EnvName::parse("prod").unwrap());
        assert_eq!(plan(&MenuCommand::Quit), TrayEffect::Quit);
        assert_eq!(
            plan(&MenuCommand::Open(WindowKind::Logs)),
            TrayEffect::ShowWindow(WindowKind::Logs)
        );
        assert_eq!(
            plan(&MenuCommand::OpenAdminClient),
            TrayEffect::OpenAdminClient
        );
        assert_eq!(
            plan(&MenuCommand::Recover(
                Recovery::Run(Action::ServiceRestart),
                prod.clone()
            )),
            TrayEffect::RunAction {
                action: Action::ServiceRestart,
                env: prod.clone(),
                copy_ids: false
            }
        );
        // Copying the identifiers never takes an environment.
        assert_eq!(
            plan(&MenuCommand::Recover(
                Recovery::CopyMachineIds,
                prod.clone()
            )),
            TrayEffect::RunAction {
                action: Action::ShowMachineId,
                env: None,
                copy_ids: true
            }
        );
        assert_eq!(
            plan(&MenuCommand::Recover(Recovery::Read(Doc::Pins), prod)),
            TrayEffect::OpenDoc(Doc::Pins)
        );
        for (step, kind) in [
            (WizardStep::Cmis, WindowKind::Setup),
            (WizardStep::Pins, WindowKind::SetupPins),
            (WizardStep::Attestation, WindowKind::SetupAttestation),
        ] {
            assert_eq!(
                plan(&MenuCommand::Recover(Recovery::OpenWizard(step), None)),
                TrayEffect::ShowWindow(kind)
            );
            // …and the menu itself already opens the window directly.
            assert_eq!(
                recovery_command(Recovery::OpenWizard(step), None),
                MenuCommand::Open(kind)
            );
        }
        assert_eq!(
            plan_target(crate::notice::Target::Approvals),
            TrayEffect::OpenAdminClient
        );
        assert_eq!(
            plan_target(crate::notice::Target::Window(WindowKind::Status)),
            TrayEffect::ShowWindow(WindowKind::Status)
        );
    }

    #[test]
    fn window_kinds_serialise_as_their_argument() {
        for k in WindowKind::ALL {
            let json = serde_json::to_string(&k).unwrap();
            assert_eq!(json, format!("\"{}\"", k.as_arg()));
        }
    }
}
