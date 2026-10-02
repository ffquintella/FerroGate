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
use crate::client::{Observation, Source, ACCESS_DENIED_CODE, NOT_INSTALLED_CODE};
use crate::i18n::{fill, Lang, Msg};
use crate::text::{display_safe, human_duration, MAX_FIELD_CHARS};

/// Icon colours (the spec's table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IconColor {
    /// Absent / not configured.
    Grey,
    /// Attesting (animated).
    Blue,
    /// Healthy.
    Green,
    /// Degraded: retrying, stale CRL, allowlist problems, SVID expiring.
    Yellow,
    /// Broken: not enrolled, pin mismatch, TPM, IMA.
    Red,
}

/// How a state looks in the tray.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Presentation {
    /// Icon colour.
    pub color: IconColor,
    /// The "!" badge (`NotConfigured`).
    pub badge: bool,
    /// Pulsing icon (`Attesting`).
    pub animated: bool,
}

/// The icon for `state`.
#[must_use]
pub fn presentation(state: AgentState) -> Presentation {
    let (color, badge, animated) = match state {
        AgentState::NotInstalled | AgentState::NotRunning => (IconColor::Grey, false, false),
        AgentState::NotConfigured => (IconColor::Grey, true, false),
        AgentState::Attesting => (IconColor::Blue, false, true),
        AgentState::CmisUnreachable
        | AgentState::CrlStale
        | AgentState::AllowlistMissing
        | AgentState::AllowlistInvalid
        | AgentState::SvidExpiring => (IconColor::Yellow, false, false),
        AgentState::NotEnrolled
        | AgentState::PinMismatch
        | AgentState::TpmUnavailable
        | AgentState::ImaDisabled => (IconColor::Red, false, false),
        AgentState::Healthy => (IconColor::Green, false, false),
    };
    Presentation {
        color,
        badge,
        animated,
    }
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
    if snapshot
        .last_error
        .as_ref()
        .is_some_and(|e| e.code == ACCESS_DENIED_CODE)
    {
        Msg::StateAccessDenied
    } else {
        title(snapshot.state)
    }
}

/// The explanation for a snapshot (access denied / unknown code aware).
#[must_use]
pub fn snapshot_explanation(snapshot: &StatusSnapshot) -> Msg {
    match snapshot.last_error.as_ref().map(|e| e.code.as_str()) {
        Some(ACCESS_DENIED_CODE) => Msg::ExplainAccessDenied,
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
            EnvView {
                headline: format!("{label}: {}", snapshot_title(s).text(lang)),
                label,
                env: env_arg(s),
                state: s.state,
                details: detail_lines(s, now, lang),
                recoveries: recs,
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

/// Which window a menu entry opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// The tray menu for `view`. `last_action` is a status line for the most
/// recent action (already localised).
#[must_use]
pub fn menu_model(view: &TrayView, lang: Lang, last_action: Option<&str>) -> Vec<MenuNode> {
    let t = |m: Msg| m.text(lang).to_string();
    let mut menu = vec![MenuNode::Label(view.headline.clone()), MenuNode::Separator];
    for env in &view.envs {
        let mut children: Vec<MenuNode> =
            env.details.iter().cloned().map(MenuNode::Label).collect();
        if !env.recoveries.is_empty() {
            children.push(MenuNode::Separator);
            for r in &env.recoveries {
                children.push(MenuNode::Item(
                    r.label(lang),
                    recovery_command(*r, env.env.clone()),
                ));
            }
        }
        menu.push(MenuNode::Submenu(env.headline.clone(), children));
    }
    // Recovery for the worst environment directly in the top menu.
    if let Some(env) = view
        .envs
        .iter()
        .filter(|e| e.state == view.worst)
        .find(|e| !e.recoveries.is_empty())
    {
        menu.push(MenuNode::Separator);
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
    }
    menu.push(MenuNode::Separator);
    menu.push(MenuNode::Item(
        t(Msg::MenuOpenStatus),
        MenuCommand::Open(WindowKind::Status),
    ));
    menu.push(MenuNode::Item(
        t(Msg::MenuSetup),
        MenuCommand::Open(WindowKind::Setup),
    ));
    menu.push(MenuNode::Item(
        t(Msg::MenuLogs),
        MenuCommand::Open(WindowKind::Logs),
    ));
    menu.push(MenuNode::Item(
        t(Msg::MenuRunSelfTest),
        MenuCommand::Open(WindowKind::SelfTest),
    ));
    if let Some(line) = last_action {
        menu.push(MenuNode::Separator);
        menu.push(MenuNode::Label(line.to_string()));
    }
    menu.push(MenuNode::Separator);
    menu.push(MenuNode::Item(t(Msg::MenuQuit), MenuCommand::Quit));
    menu
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
        use IconColor::{Blue, Green, Grey, Red, Yellow};
        use Recovery::{CopyMachineIds, OpenWizard, Read, Run};
        let table: [(AgentState, IconColor, bool, Vec<Recovery>); 14] = [
            (
                AgentState::NotInstalled,
                Grey,
                false,
                vec![Read(Doc::Install)],
            ),
            (
                AgentState::NotRunning,
                Grey,
                false,
                vec![Run(Action::ServiceStart), Read(Doc::Install)],
            ),
            (
                AgentState::NotConfigured,
                Grey,
                true,
                vec![OpenWizard(WizardStep::Cmis)],
            ),
            (AgentState::Attesting, Blue, false, vec![]),
            (
                AgentState::CmisUnreachable,
                Yellow,
                false,
                vec![Run(Action::RunSelfTest), Read(Doc::Networking)],
            ),
            (
                AgentState::NotEnrolled,
                Red,
                false,
                vec![CopyMachineIds, Read(Doc::Enrollment)],
            ),
            (
                AgentState::PinMismatch,
                Red,
                false,
                vec![OpenWizard(WizardStep::Pins), Read(Doc::Pins)],
            ),
            (
                AgentState::TpmUnavailable,
                Red,
                false,
                vec![
                    Run(Action::RunSelfTest),
                    OpenWizard(WizardStep::Attestation),
                    Read(Doc::Tpm),
                ],
            ),
            (
                AgentState::ImaDisabled,
                Red,
                false,
                vec![Read(Doc::Hardening)],
            ),
            (
                AgentState::CrlStale,
                Yellow,
                false,
                vec![Run(Action::RunSelfTest), Read(Doc::CrlStale)],
            ),
            (
                AgentState::AllowlistMissing,
                Yellow,
                false,
                vec![Run(Action::ResyncAllowlist), Read(Doc::Allowlist)],
            ),
            (
                AgentState::AllowlistInvalid,
                Yellow,
                false,
                vec![Run(Action::ResyncAllowlist), Read(Doc::Allowlist)],
            ),
            (
                AgentState::SvidExpiring,
                Yellow,
                false,
                vec![Run(Action::RunSelfTest), Run(Action::ServiceRestart)],
            ),
            (AgentState::Healthy, Green, false, vec![]),
        ];
        assert_eq!(table.len(), AgentState::ALL.len());
        for (state, color, badge, recs) in table {
            let p = presentation(state);
            assert_eq!(p.color, color, "{state:?}");
            assert_eq!(p.badge, badge, "{state:?}");
            assert_eq!(p.animated, state == AgentState::Attesting);
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
        let menu = menu_model(&v, Lang::En, Some("Last action: x — done"));
        // One submenu per environment, and the worst one's recoveries on top
        // with the environment passed along.
        assert_eq!(
            menu.iter()
                .filter(|n| matches!(n, MenuNode::Submenu(..)))
                .count(),
            3
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
    fn window_kinds_round_trip() {
        for k in WindowKind::ALL {
            assert_eq!(WindowKind::from_arg(k.as_arg()), Some(k));
        }
        assert_eq!(WindowKind::from_arg("--evil"), None);
    }
}
