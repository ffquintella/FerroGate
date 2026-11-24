//! "Trusted publishers" (ADR-0006, F22), headless: the list with a "show
//! removed" switch and a detail page, adding a publisher from a signed
//! executable or from certificate files (a form, a review page, then a
//! fresh second factor), and removing one by typing its short id.

//! Nothing is sent without the review page and a fresh second factor: the
//! panel only hands the flow a request, and the flow asks for the factor.
//! A removal needs a recent step-up; the same request (same idempotency
//! key) is sent once more after it. Only cleaned [`PublisherRow`] strings
//! are kept, never a raw server record. The panel holds no secret.

use std::io::Read;
use std::path::{Path, PathBuf};

use ferrogate_admin_client::approvals::rules::{new_idempotency_key, EXPIRY_DAYS};
use ferrogate_admin_client::display::inert;
use ferrogate_admin_client::error::ClientError;
use ferrogate_admin_client::perm;
use ferrogate_admin_client::publishers::draft::{
    remove_request, DraftError, PublisherDraft, MAX_LABEL,
};
use ferrogate_admin_client::publishers::inspect::{
    inspect_certificates, inspect_executable, Candidate, InspectError, Source,
};
use ferrogate_admin_client::publishers::proto::{
    AddTrustedPublisherRequest, RemoveTrustedPublisherRequest, TrustedPublisherInfo,
};
use ferrogate_admin_client::publishers::view::{hex32, PublisherRow};
use ferrogate_admin_client::publishers::{PinKind, SignatureKind};
use serde::Serialize;

use super::session::Cmd;
use super::views::{refusal, Refusal};
use crate::text::display_safe;

/// Most rows kept from one list.
pub const MAX_ROWS: usize = 200;
/// Most bytes read from a certificate file (one more than the parser's
/// limit, so an oversized file is refused rather than cut).
pub const MAX_CERT_FILE: u64 = 64 * 1024 + 1;
/// Longest subject shown in a list of anchors, in characters.
pub const MAX_SUBJECT: usize = 200;
/// The pin choices, in the order the form lists them (the first is the
/// default: it survives a renewal that keeps the key).
pub const PIN_KINDS: [PinKind; 3] = [
    PinKind::LeafSpkiSha256,
    PinKind::LeafCertSha256,
    PinKind::SubjectSha256,
];
/// The signature technologies the certificate source can be.
pub const KINDS: [SignatureKind; 2] = [SignatureKind::Authenticode, SignatureKind::Apple];
/// `VerifyError::reason` of a platform without a verifier.
const UNSUPPORTED: &str = "publisher-unsupported";

/// What the panel shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Screen {
    /// The list.
    List,
    /// One publisher, every field.
    Detail,
    /// Where the publisher's identity is read from.
    Source,
    /// Label, anchor, pin, timestamp and expiry.
    Form,
    /// What will be sent, to confirm.
    Review,
    /// Confirming a removal by typing its short id.
    Remove,
}

/// Why an identity could not be read locally, by kind only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectFailure {
    /// This platform cannot verify executable signatures.
    Unsupported,
    /// The OS did not accept the signature (the stable reason code).
    Signature(&'static str),
    /// A file could not be read or was too large.
    Unreadable,
    /// A file is not a certificate.
    NotCertificate,
    /// No CA certificate above the signing certificate.
    NoIssuer,
}

/// A blocking local read the window runs off its UI thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectJob {
    /// A signed executable the OS verifies.
    Executable(PathBuf),
    /// A signing certificate file and a CA certificate file.
    Certificates {
        /// Signature technology of the certificates.
        kind: SignatureKind,
        /// The signing (leaf) certificate file.
        leaf: PathBuf,
        /// The CA certificate file.
        anchor: PathBuf,
    },
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, InspectFailure> {
    let file = std::fs::File::open(path).map_err(|_| InspectFailure::Unreadable)?;
    if !file.metadata().is_ok_and(|m| m.is_file()) {
        return Err(InspectFailure::Unreadable);
    }
    let mut bytes = Vec::new();
    file.take(MAX_CERT_FILE)
        .read_to_end(&mut bytes)
        .map_err(|_| InspectFailure::Unreadable)?;
    Ok(bytes)
}

fn failure(e: &InspectError) -> InspectFailure {
    match e {
        InspectError::Signature(v) if v.reason() == UNSUPPORTED => InspectFailure::Unsupported,
        InspectError::Signature(v) => InspectFailure::Signature(v.reason()),
        InspectError::Certificate => InspectFailure::NotCertificate,
        InspectError::NoIssuer => InspectFailure::NoIssuer,
    }
}

impl InspectJob {
    /// Do the read (file I/O and OS calls: never on the UI thread).
    ///
    /// # Errors
    /// Why the identity could not be read.
    pub fn run(self) -> Result<Candidate, InspectFailure> {
        match self {
            Self::Executable(path) => inspect_executable(&path).map_err(|e| failure(&e)),
            Self::Certificates { kind, leaf, anchor } => {
                let leaf = read_bounded(&leaf)?;
                let anchor = read_bounded(&anchor)?;
                inspect_certificates(kind, &leaf, &anchor).map_err(|e| failure(&e))
            }
        }
    }
}

/// A change on the form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormChoice {
    /// The anchor CA at this index of the candidate's issuers.
    Anchor(usize),
    /// What to pin.
    Pin(PinKind),
    /// Require a trusted timestamp.
    Timestamp(bool),
    /// Expiry (index into `EXPIRY_DAYS`).
    Expiry(usize),
}

/// A button of the panel (the ones that need no file dialog).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PubAction {
    /// Show or hide removed publishers (reloads the list).
    ToggleRemoved,
    /// Reload the list.
    Refresh,
    /// Open the publisher at this row.
    Open(usize),
    /// One page back (a form is dropped, nothing is sent).
    Back,
    /// Abandon the add or the removal: back to the list, nothing sent.
    Cancel,
    /// "Add…": choose the source.
    StartAdd,
    /// The certificate source's signature technology.
    Kind(SignatureKind),
    /// A change on the form.
    Choose(FormChoice),
    /// "Review": the form to the review page.
    Review,
    /// "Confirm" on the review page: asks for a fresh second factor.
    Confirm,
    /// "Remove…" on the row at this index.
    StartRemove(usize),
    /// "Remove" on the confirmation: needs the typed short id.
    ConfirmRemove,
}

/// What the form refuses, as the window words it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FormProblem {
    /// The label is empty or too long.
    Label,
    /// The anchor is not one of the listed CA certificates.
    Anchor,
    /// A digest is malformed.
    Digest,
    /// The expiry is not in the future.
    Expiry,
    /// The publisher id is invalid.
    Id,
}

fn problem(e: DraftError) -> FormProblem {
    match e {
        DraftError::Label => FormProblem::Label,
        DraftError::Anchor => FormProblem::Anchor,
        DraftError::Digest(_) => FormProblem::Digest,
        DraftError::Expiry => FormProblem::Expiry,
        DraftError::Id => FormProblem::Id,
    }
}

/// A risk the review page warns about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Warning {
    /// The pin is a subject name.
    SubjectPin,
    /// The anchor is a root CA.
    RootAnchor,
    /// The signature has no timestamp but one is required.
    NoTimestamp,
    /// Any other warning, as the shared API words it (English).
    Other(String),
}

/// One line of the review page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewLine {
    /// The label (inert).
    Label(String),
    /// The signature technology.
    Kind(&'static str),
    /// The publisher's subject (inert).
    Publisher(String),
    /// The leaf's issuer (inert).
    Issuer(String),
    /// The leaf certificate's SHA-256, hex.
    Thumbprint(String),
    /// What is pinned: the kind and the digest.
    Pins(String),
    /// The anchor CA's SHA-256, hex.
    Anchor(String),
    /// A trusted timestamp is required.
    Timestamp(bool),
    /// Where the rule applies.
    Scope,
    /// Expiry (Unix seconds; `None`: never).
    Expires(Option<i64>),
    /// A risk to look at twice.
    Warning(Warning),
    /// A line this client has no wording for: label and value.
    Other(String, String),
}

fn warning(text: &str) -> Warning {
    if text.starts_with("pins a subject name") {
        Warning::SubjectPin
    } else if text.starts_with("the anchor is a root CA") {
        Warning::RootAnchor
    } else if text.contains("has no timestamp") {
        Warning::NoTimestamp
    } else {
        Warning::Other(inert(text, 300))
    }
}

fn review_lines(draft: &PublisherDraft, candidate: &Candidate) -> Vec<ReviewLine> {
    let mut out = Vec::new();
    for (key, value) in draft.confirmation(Some(candidate)) {
        let value = inert(&value, 600);
        match key {
            "label" => out.push(ReviewLine::Label(value)),
            "kind" => out.push(ReviewLine::Kind(draft.kind.as_str())),
            "publisher" => out.push(ReviewLine::Publisher(value)),
            "issuer" => out.push(ReviewLine::Issuer(value)),
            "thumbprint (SHA-256)" => out.push(ReviewLine::Thumbprint(value)),
            "pins" => out.push(ReviewLine::Pins(value)),
            "anchor CA (SHA-256)" => out.push(ReviewLine::Anchor(value)),
            "timestamp" => out.push(ReviewLine::Timestamp(draft.require_timestamp)),
            "scope" => {
                out.push(ReviewLine::Scope);
                out.push(ReviewLine::Expires(draft.expires_at));
            }
            "warning" => out.push(ReviewLine::Warning(warning(&value))),
            other => out.push(ReviewLine::Other(other.to_string(), value)),
        }
    }
    out
}

/// A CA certificate offered as the anchor (inert).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnchorRow {
    /// Its subject.
    pub subject: String,
    /// Its SHA-256, hex.
    pub sha256: String,
    /// Self-signed: a root CA.
    pub root: bool,
}

/// The form as drawn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FormView {
    /// The label typed.
    pub label: String,
    /// Longest label, in characters.
    pub label_max: usize,
    /// The publisher's subject (inert).
    pub subject: String,
    /// The signing certificate's SHA-256, hex.
    pub thumbprint: String,
    /// Where the identity came from: the OS verified a signed executable.
    pub from_executable: bool,
    /// The signature carries a trusted timestamp (executables only).
    pub timestamped: bool,
    /// The anchor choices, nearest issuer first.
    pub anchors: Vec<AnchorRow>,
    /// The anchor chosen.
    pub anchor: usize,
    /// The pin chosen (`leaf-spki`, `leaf-cert`, `subject`).
    pub pin_kind: &'static str,
    /// Require a trusted timestamp.
    pub require_timestamp: bool,
    /// The expiry chosen (index into `EXPIRY_DAYS`).
    pub expiry: usize,
    /// What is wrong with the form now; the review waits until it is empty.
    pub problems: Vec<FormProblem>,
}

/// The source screen as drawn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceView {
    /// The certificate source's signature technology.
    pub kind: &'static str,
    /// The leaf certificate file chosen (name only, inert).
    pub leaf: Option<String>,
    /// The CA certificate file chosen (name only, inert).
    pub anchor: Option<String>,
    /// A read is running.
    pub inspecting: bool,
    /// Why the last read failed.
    pub error: Option<InspectFailure>,
    /// Both certificate files are chosen and nothing is running.
    pub can_read_certificates: bool,
}

/// The removal confirmation as drawn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoveView {
    /// The publisher (inert).
    pub title: String,
    /// The short id that must be typed.
    pub phrase: String,
    /// What was typed (not a secret).
    pub typed: String,
    /// The typed text matches.
    pub confirmed: bool,
    /// A confirmation was refused for not matching.
    pub mismatch: bool,
}

/// What the last add or removal came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Added; the new publisher's short id when the server returned it.
    Added(Option<String>),
    /// Removed.
    Removed,
    /// Refused by the server (or unreachable); nothing changed.
    Refused(Refusal),
    /// The server asked for a step-up again right after one.
    StepUpAgain,
    /// Cancelled before the second factor or the step-up; nothing sent.
    NotSent,
}

/// What the window draws. Holds no secret; every string is inert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[allow(clippy::struct_excessive_bools)] // A flat view model: one flag per control.
pub struct PublishersView {
    /// The page shown.
    pub screen: Screen,
    /// The listed publishers.
    pub rows: Vec<PublisherRow>,
    /// Whether the list arrived.
    pub loaded: bool,
    /// Removed publishers are listed too.
    pub show_removed: bool,
    /// The publisher opened.
    pub detail: Option<PublisherRow>,
    /// The source screen.
    pub source: SourceView,
    /// The form, once an identity was read.
    pub form: Option<FormView>,
    /// The review page's lines.
    pub review: Option<Vec<ReviewLine>>,
    /// The removal confirmation.
    pub remove: Option<RemoveView>,
    /// The last add or removal's outcome.
    pub outcome: Option<Outcome>,
    /// Why the last read of the list failed.
    pub error: Option<Refusal>,
    /// An add or a removal waits for its factor, step-up or answer.
    pub pending: bool,
    /// May add and remove (`publisher.manage`).
    pub can_manage: bool,
}

/// What the flow must do after a reply.
pub enum PubEvent {
    /// Nothing.
    None,
    /// Send this command to the worker.
    Send(Cmd),
    /// The removal needs a step-up first; then [`PublishersPanel::resend`].
    StepUp,
    /// The server ended the session.
    SessionEnded,
}

static_assertions::assert_not_impl_any!(PubEvent: std::fmt::Debug, std::fmt::Display, Clone);

struct Form {
    candidate: Candidate,
    label: String,
    anchor: usize,
    pin_kind: PinKind,
    require_timestamp: bool,
    expiry: usize,
}

impl Form {
    fn new(candidate: Candidate) -> Self {
        Self {
            candidate,
            label: String::new(),
            anchor: 0,
            pin_kind: PIN_KINDS[0],
            require_timestamp: true,
            expiry: 0,
        }
    }

    fn draft(&self, now: i64) -> Result<PublisherDraft, DraftError> {
        let mut d = PublisherDraft::from_candidate(
            &self.candidate,
            self.anchor,
            self.pin_kind,
            &self.label,
        )?;
        d.require_timestamp = self.require_timestamp;
        d.expires_at = EXPIRY_DAYS
            .get(self.expiry)
            .copied()
            .filter(|days| *days > 0)
            .map(|days| now.saturating_add(days.saturating_mul(86_400)));
        Ok(d)
    }

    fn problems(&self, now: i64) -> Vec<DraftError> {
        match self.draft(now) {
            Ok(d) => d.problems(now),
            Err(e) => vec![e],
        }
    }
}

struct SourceState {
    kind: SignatureKind,
    leaf: Option<PathBuf>,
    anchor: Option<PathBuf>,
    inspecting: bool,
    error: Option<InspectFailure>,
}

struct RemoveState {
    row: PublisherRow,
    typed: String,
    mismatch: bool,
    /// The page the removal was started from (Cancel goes back to it).
    from: Screen,
}

struct PendingRemove {
    request: RemoveTrustedPublisherRequest,
    stepped_up: bool,
}

static_assertions::assert_not_impl_any!(PublishersPanel: std::fmt::Debug, std::fmt::Display, Clone);

/// The panel's state.
pub struct PublishersPanel {
    permissions: Option<Vec<String>>,
    screen: Screen,
    rows: Vec<PublisherRow>,
    loaded: bool,
    show_removed: bool,
    selected: Option<usize>,
    source: SourceState,
    form: Option<Form>,
    review: Option<PublisherDraft>,
    remove: Option<RemoveState>,
    pending_remove: Option<PendingRemove>,
    /// A confirmed add waits for its fresh second factor or its answer.
    adding: bool,
    outcome: Option<Outcome>,
    error: Option<Refusal>,
}

fn push_bounded(field: &mut String, text: &str, max: usize) {
    for c in text.chars().filter(|c| !c.is_control()) {
        if field.chars().count() >= max {
            break;
        }
        field.push(c);
    }
}

fn typed_matches(row: &PublisherRow, typed: &str) -> bool {
    typed.trim().eq_ignore_ascii_case(row.confirm_phrase())
}

fn file_name(path: &Path) -> String {
    let name = path.file_name().map_or_else(
        || path.to_string_lossy().into_owned(),
        |n| n.to_string_lossy().into_owned(),
    );
    display_safe(&name, 128)
}

impl PublishersPanel {
    /// An empty panel; `permissions` are the session's (`None` unknown:
    /// everything is offered and the server decides).
    #[must_use]
    pub fn new(permissions: Option<Vec<String>>) -> Self {
        Self {
            permissions,
            screen: Screen::List,
            rows: Vec::new(),
            loaded: false,
            show_removed: false,
            selected: None,
            source: SourceState {
                kind: if cfg!(target_os = "macos") {
                    SignatureKind::Apple
                } else {
                    SignatureKind::Authenticode
                },
                leaf: None,
                anchor: None,
                inspecting: false,
                error: None,
            },
            form: None,
            review: None,
            remove: None,
            pending_remove: None,
            adding: false,
            outcome: None,
            error: None,
        }
    }

    /// Whether the session's permissions are known.
    #[must_use]
    pub fn knows_permissions(&self) -> bool {
        self.permissions.is_some()
    }

    fn can(&self, permission: &str) -> bool {
        self.permissions
            .as_ref()
            .is_none_or(|p| p.iter().any(|x| x == permission))
    }

    /// May add and remove publishers.
    #[must_use]
    pub fn can_manage(&self) -> bool {
        self.can(perm::PUBLISHER_MANAGE)
    }

    /// An add waits for its second factor or answer, or a removal for its
    /// step-up or answer.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.adding || self.pending_remove.is_some()
    }

    /// Whether typing goes to a field of the panel now.
    #[must_use]
    pub fn editing(&self) -> bool {
        matches!(self.screen, Screen::Form | Screen::Remove)
    }

    /// The command that loads the list.
    #[must_use]
    pub fn reload(&mut self) -> Cmd {
        self.error = None;
        Cmd::ListPublishers {
            include_removed: self.show_removed,
        }
    }

    /// `WhoAmI`'s permissions; then the list (unless the account may not
    /// list publishers, which the server would refuse too).
    #[must_use]
    pub fn on_permissions(&mut self, result: Result<Vec<String>, ClientError>) -> PubEvent {
        match result {
            Ok(p) => self.permissions = Some(p),
            Err(ClientError::SessionEnded) => return PubEvent::SessionEnded,
            // Unknown: everything is offered and the server decides.
            Err(_) => {}
        }
        if !self.can(perm::PUBLISHER_LIST) {
            self.error = Some(Refusal::NotAllowed);
            return PubEvent::None;
        }
        PubEvent::Send(self.reload())
    }

    /// The server's list.
    pub fn on_listed(
        &mut self,
        result: Result<Vec<TrustedPublisherInfo>, ClientError>,
    ) -> PubEvent {
        match result {
            Ok(list) => {
                self.rows = list.iter().take(MAX_ROWS).map(PublisherRow::of).collect();
                self.loaded = true;
                self.error = None;
                self.selected = self.selected.filter(|i| *i < self.rows.len());
                if self.screen == Screen::Detail && self.selected.is_none() {
                    self.screen = Screen::List;
                }
                PubEvent::None
            }
            Err(ClientError::SessionEnded) => PubEvent::SessionEnded,
            Err(e) => {
                self.error = Some(refusal(&e));
                PubEvent::None
            }
        }
    }

    /// A button pressed. Returns the command to send, if any; leaving a
    /// page never sends anything.
    pub fn act(&mut self, action: PubAction, now: i64) -> Option<Cmd> {
        if self.has_pending() {
            return None;
        }
        match action {
            PubAction::ToggleRemoved if self.screen == Screen::List => {
                self.show_removed = !self.show_removed;
                self.selected = None;
                return Some(self.reload());
            }
            PubAction::Refresh if self.screen == Screen::List => return Some(self.reload()),
            PubAction::Open(i) if self.screen == Screen::List && i < self.rows.len() => {
                self.selected = Some(i);
                self.outcome = None;
                self.screen = Screen::Detail;
            }
            PubAction::Back => self.back(),
            PubAction::Cancel => self.cancel(),
            PubAction::StartAdd => self.start_add(),
            PubAction::Kind(kind) if self.screen == Screen::Source && !self.source.inspecting => {
                self.source.kind = kind;
            }
            PubAction::Choose(choice) => self.choose(choice),
            PubAction::Review => {
                let _ = self.review(now);
            }
            PubAction::StartRemove(i) => self.start_remove(i),
            PubAction::ConfirmRemove => return self.confirm_remove(),
            // "Confirm" is `confirm`: the flow asks for the second factor.
            _ => {}
        }
        None
    }

    /// One page back; whatever the page held is dropped and nothing is
    /// sent. Not while something waits for an answer.
    pub fn back(&mut self) {
        if self.has_pending() {
            return;
        }
        self.screen = match self.screen {
            Screen::List | Screen::Detail => {
                self.selected = None;
                Screen::List
            }
            Screen::Source => {
                self.source.inspecting = false;
                self.source.error = None;
                Screen::List
            }
            Screen::Form => {
                self.form = None;
                Screen::Source
            }
            Screen::Review => {
                self.review = None;
                Screen::Form
            }
            Screen::Remove => match self.remove.take().map(|r| r.from) {
                Some(Screen::Detail) if self.selected.is_some() => Screen::Detail,
                _ => {
                    self.selected = None;
                    Screen::List
                }
            },
        };
    }

    /// Abandon whatever is being added or removed: everything typed or
    /// read is dropped and nothing is sent. Not while something waits for
    /// an answer.
    pub fn cancel(&mut self) {
        if self.has_pending() {
            return;
        }
        self.form = None;
        self.review = None;
        self.remove = None;
        self.source.inspecting = false;
        self.source.error = None;
        self.selected = None;
        self.screen = Screen::List;
    }

    fn start_add(&mut self) {
        if !self.can_manage() || !matches!(self.screen, Screen::List | Screen::Detail) {
            return;
        }
        self.outcome = None;
        self.source.leaf = None;
        self.source.anchor = None;
        self.source.error = None;
        self.source.inspecting = false;
        self.screen = Screen::Source;
    }

    fn begin_inspect(&mut self, job: InspectJob) -> Option<InspectJob> {
        if self.screen != Screen::Source || self.source.inspecting || !self.can_manage() {
            return None;
        }
        self.source.error = None;
        self.source.inspecting = true;
        Some(job)
    }

    /// An executable was chosen: the read to run off the UI thread.
    pub fn start_executable(&mut self, path: PathBuf) -> Option<InspectJob> {
        self.begin_inspect(InspectJob::Executable(path))
    }

    /// The signing certificate file was chosen.
    pub fn set_leaf(&mut self, path: PathBuf) {
        if self.screen == Screen::Source && !self.source.inspecting {
            self.source.leaf = Some(path);
        }
    }

    /// The CA certificate file was chosen.
    pub fn set_anchor(&mut self, path: PathBuf) {
        if self.screen == Screen::Source && !self.source.inspecting {
            self.source.anchor = Some(path);
        }
    }

    /// Both certificate files are chosen: the read to run off the UI thread.
    pub fn start_certificates(&mut self) -> Option<InspectJob> {
        let leaf = self.source.leaf.clone()?;
        let anchor = self.source.anchor.clone()?;
        let kind = self.source.kind;
        self.begin_inspect(InspectJob::Certificates { kind, leaf, anchor })
    }

    /// A read finished. Dropped when none is awaited (the panel moved on,
    /// or the window locked meanwhile).
    pub fn inspected(&mut self, result: Result<Candidate, InspectFailure>) {
        if !std::mem::take(&mut self.source.inspecting) || self.screen != Screen::Source {
            return;
        }
        match result {
            Ok(candidate) => {
                self.form = Some(Form::new(candidate));
                self.screen = Screen::Form;
            }
            Err(e) => self.source.error = Some(e),
        }
    }

    fn choose(&mut self, choice: FormChoice) {
        let (Screen::Form, Some(form)) = (self.screen, &mut self.form) else {
            return;
        };
        match choice {
            FormChoice::Anchor(i) if i < form.candidate.issuers.len() => form.anchor = i,
            FormChoice::Pin(kind) if PIN_KINDS.contains(&kind) => form.pin_kind = kind,
            FormChoice::Timestamp(on) => form.require_timestamp = on,
            FormChoice::Expiry(i) if i < EXPIRY_DAYS.len() => form.expiry = i,
            _ => {}
        }
    }

    /// Typed or pasted text, for the page's one field: the label on the
    /// form, the short id on a removal.
    pub fn type_text(&mut self, text: &str) {
        if self.has_pending() {
            return;
        }
        match (self.screen, &mut self.form, &mut self.remove) {
            (Screen::Form, Some(form), _) => push_bounded(&mut form.label, text, MAX_LABEL),
            (Screen::Remove, _, Some(r)) => {
                r.mismatch = false;
                push_bounded(&mut r.typed, text, 32);
            }
            _ => {}
        }
    }

    /// `Backspace`.
    pub fn backspace(&mut self) {
        if self.has_pending() {
            return;
        }
        match (self.screen, &mut self.form, &mut self.remove) {
            (Screen::Form, Some(form), _) => {
                form.label.pop();
            }
            (Screen::Remove, _, Some(r)) => {
                r.mismatch = false;
                r.typed.pop();
            }
            _ => {}
        }
    }

    /// `Enter`: the form goes to its review page, a matching removal is
    /// sent. Never confirms an add: that is the button.
    pub fn enter(&mut self, now: i64) -> Option<Cmd> {
        match self.screen {
            Screen::Form => {
                let _ = self.review(now);
                None
            }
            Screen::Remove => self.confirm_remove(),
            _ => None,
        }
    }

    /// The form to the review page; `false` while the form has problems.
    pub fn review(&mut self, now: i64) -> bool {
        if self.screen != Screen::Form || self.has_pending() {
            return false;
        }
        let Some(form) = &self.form else {
            return false;
        };
        match form.draft(now) {
            Ok(draft) if draft.problems(now).is_empty() => {
                self.review = Some(draft);
                self.screen = Screen::Review;
                true
            }
            _ => false,
        }
    }

    /// "Confirm" on the review page: the request (no proof, no secret) the
    /// flow sends once a fresh second factor is given. A new idempotency
    /// key each time; the flow reuses the request for its retries. `None`
    /// unless an add is confirmable now.
    pub fn confirm(&mut self, now: i64) -> Option<Box<AddTrustedPublisherRequest>> {
        if self.screen != Screen::Review || self.has_pending() || !self.can_manage() {
            return None;
        }
        let draft = self.review.as_ref()?;
        if !draft.problems(now).is_empty() {
            // Time passed (an expiry): back to the form, nothing sent.
            self.review = None;
            self.screen = Screen::Form;
            return None;
        }
        let request = draft.request(new_idempotency_key());
        self.adding = true;
        self.outcome = None;
        Some(Box::new(request))
    }

    /// The second-factor prompt was closed: nothing was sent.
    pub fn add_cancelled(&mut self) {
        if std::mem::take(&mut self.adding) {
            self.outcome = Some(Outcome::NotSent);
        }
    }

    /// An add's answer. A refusal leaves the review page (nothing changed);
    /// success closes the form and reloads the list.
    pub fn on_added(
        &mut self,
        result: Result<Option<TrustedPublisherInfo>, ClientError>,
    ) -> PubEvent {
        if !std::mem::take(&mut self.adding) {
            return PubEvent::None;
        }
        match result {
            Ok(info) => {
                self.form = None;
                self.review = None;
                self.screen = Screen::List;
                self.outcome = Some(Outcome::Added(
                    info.as_ref().map(|p| PublisherRow::of(p).short_id),
                ));
                PubEvent::Send(self.reload())
            }
            Err(ClientError::SessionEnded) => PubEvent::SessionEnded,
            Err(e) => {
                self.outcome = Some(Outcome::Refused(refusal(&e)));
                PubEvent::None
            }
        }
    }

    fn start_remove(&mut self, index: usize) {
        if !self.can_manage() || !matches!(self.screen, Screen::List | Screen::Detail) {
            return;
        }
        let Some(row) = self.rows.get(index).filter(|r| r.state == "active") else {
            return;
        };
        self.remove = Some(RemoveState {
            row: row.clone(),
            typed: String::new(),
            mismatch: false,
            from: self.screen,
        });
        self.outcome = None;
        self.screen = Screen::Remove;
    }

    fn confirm_remove(&mut self) -> Option<Cmd> {
        if self.screen != Screen::Remove || self.has_pending() || !self.can_manage() {
            return None;
        }
        let state = self.remove.as_mut()?;
        if !typed_matches(&state.row, &state.typed) {
            state.mismatch = true;
            return None;
        }
        let Ok(request) = remove_request(&state.row.id, new_idempotency_key()) else {
            self.outcome = Some(Outcome::Refused(Refusal::Invalid));
            self.finish_remove();
            return None;
        };
        self.outcome = None;
        self.pending_remove = Some(PendingRemove {
            request: request.clone(),
            stepped_up: false,
        });
        Some(Cmd::RemovePublisher(Box::new(request)))
    }

    fn finish_remove(&mut self) {
        self.remove = None;
        self.selected = None;
        self.screen = Screen::List;
    }

    /// After a successful step-up: the waiting removal once more, with the
    /// same idempotency key.
    pub fn resend(&mut self) -> Option<Cmd> {
        let p = self.pending_remove.as_mut()?;
        p.stepped_up = true;
        Some(Cmd::RemovePublisher(Box::new(p.request.clone())))
    }

    /// The step-up was cancelled: the waiting removal is dropped unsent.
    pub fn drop_pending(&mut self) {
        if self.pending_remove.take().is_some() {
            self.outcome = Some(Outcome::NotSent);
            self.finish_remove();
        }
    }

    /// A removal's answer. A `step_up_required` one keeps the request for
    /// the single retry after the step-up.
    pub fn on_removed(
        &mut self,
        result: Result<Option<TrustedPublisherInfo>, ClientError>,
    ) -> PubEvent {
        let Some(pending) = self.pending_remove.take() else {
            return PubEvent::None;
        };
        match result {
            Ok(_) => {
                self.outcome = Some(Outcome::Removed);
                self.finish_remove();
                PubEvent::Send(self.reload())
            }
            Err(ClientError::SessionEnded) => PubEvent::SessionEnded,
            Err(e) if e.needs_step_up() && !pending.stepped_up => {
                self.pending_remove = Some(pending);
                PubEvent::StepUp
            }
            Err(e) if e.needs_step_up() => {
                self.outcome = Some(Outcome::StepUpAgain);
                self.finish_remove();
                PubEvent::None
            }
            Err(e) => {
                self.outcome = Some(Outcome::Refused(refusal(&e)));
                self.finish_remove();
                PubEvent::Send(self.reload())
            }
        }
    }

    fn form_view(form: &Form, now: i64) -> FormView {
        let c = &form.candidate;
        FormView {
            label: form.label.clone(),
            label_max: MAX_LABEL,
            subject: inert(&c.leaf.subject, MAX_SUBJECT),
            thumbprint: hex32(&c.leaf.cert_sha256),
            from_executable: c.source == Source::Executable,
            timestamped: c.timestamped,
            anchors: c
                .issuers
                .iter()
                .map(|i| AnchorRow {
                    subject: inert(&i.subject, MAX_SUBJECT),
                    sha256: hex32(&i.cert_sha256),
                    root: i.subject == i.issuer,
                })
                .collect(),
            anchor: form.anchor,
            pin_kind: form.pin_kind.as_str(),
            require_timestamp: form.require_timestamp,
            expiry: form.expiry,
            problems: form.problems(now).into_iter().map(problem).collect(),
        }
    }

    /// What the window draws at `now` (Unix seconds).
    #[must_use]
    pub fn view(&self, now: i64) -> PublishersView {
        let name = |p: &Option<PathBuf>| p.as_deref().map(file_name);
        PublishersView {
            screen: self.screen,
            rows: self.rows.clone(),
            loaded: self.loaded,
            show_removed: self.show_removed,
            detail: self.selected.and_then(|i| self.rows.get(i)).cloned(),
            source: SourceView {
                kind: self.source.kind.as_str(),
                leaf: name(&self.source.leaf),
                anchor: name(&self.source.anchor),
                inspecting: self.source.inspecting,
                error: self.source.error,
                can_read_certificates: !self.source.inspecting
                    && self.source.leaf.is_some()
                    && self.source.anchor.is_some(),
            },
            form: self.form.as_ref().map(|f| Self::form_view(f, now)),
            review: match (&self.review, &self.form) {
                (Some(draft), Some(form)) if self.screen == Screen::Review => {
                    Some(review_lines(draft, &form.candidate))
                }
                _ => None,
            },
            remove: self.remove.as_ref().map(|r| RemoveView {
                title: r.row.title(),
                phrase: r.row.confirm_phrase().to_string(),
                typed: r.typed.clone(),
                confirmed: typed_matches(&r.row, &r.typed),
                mismatch: r.mismatch,
            }),
            outcome: self.outcome.clone(),
            error: self.error,
            pending: self.has_pending(),
            can_manage: self.can_manage(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferro_codesign::testing::TestChain;
    use ferrogate_admin_client::error::RpcError;

    const NOW: i64 = 1_800_000_000;
    const MANAGE: &[&str] = &[perm::PUBLISHER_LIST, perm::PUBLISHER_MANAGE];

    fn perms(p: &[&str]) -> Option<Vec<String>> {
        Some(p.iter().map(|s| (*s).to_string()).collect())
    }

    fn candidate() -> Candidate {
        let chain = TestChain::new("ACME Corp");
        inspect_certificates(SignatureKind::Apple, &chain.leaf_der, &chain.ca_der).unwrap()
    }

    fn info(id: &str, state: u32) -> TrustedPublisherInfo {
        TrustedPublisherInfo {
            publisher_id: id.into(),
            label: "ACME \u{202e}gpj".into(),
            subject: "CN=ACME".into(),
            kind: 2,
            pin_kind: 2,
            pin: vec![0xab; 32],
            state,
            ..TrustedPublisherInfo::default()
        }
    }

    const ID: &str = "0190f0aa-0000-7000-8000-00000000beef";

    fn listed(p: &mut PublishersPanel) {
        let _ = p.on_listed(Ok(vec![
            info(ID, 1),
            info("0190f0aa-0000-7000-8000-00000000cafe", 2),
        ]));
    }

    /// A panel on the form with a candidate read from test certificates.
    fn on_the_form(p: &mut PublishersPanel) {
        listed(p);
        p.act(PubAction::StartAdd, NOW);
        let job = p.start_executable(PathBuf::from("/opt/tool")).unwrap();
        assert!(matches!(job, InspectJob::Executable(_)));
        p.inspected(Ok(candidate()));
        assert_eq!(p.view(NOW).screen, Screen::Form);
    }

    fn on_the_review(p: &mut PublishersPanel) {
        on_the_form(p);
        p.type_text("ACME signing");
        assert!(p.review(NOW));
    }

    fn step_up_required() -> ClientError {
        ClientError::Other(RpcError::local(
            ferrogate_admin_client::error::Code::FailedPrecondition,
            "step_up_required",
        ))
    }

    #[test]
    fn the_list_holds_cleaned_rows_and_the_removed_switch_reloads() {
        let mut p = PublishersPanel::new(perms(MANAGE));
        assert!(matches!(
            p.reload(),
            Cmd::ListPublishers {
                include_removed: false
            }
        ));
        listed(&mut p);
        let v = p.view(NOW);
        assert_eq!(v.rows.len(), 2);
        assert!(
            !v.rows[0].label.contains('\u{202e}'),
            "inert: {:?}",
            v.rows[0].label
        );
        assert_eq!(v.rows[0].short_id, "P-0000BEEF");
        let Some(Cmd::ListPublishers { include_removed }) = p.act(PubAction::ToggleRemoved, NOW)
        else {
            panic!("a reload");
        };
        assert!(include_removed && p.view(NOW).show_removed);
        assert!(p.act(PubAction::Open(1), NOW).is_none());
        let d = p.view(NOW).detail.unwrap();
        assert_eq!((d.state, d.short_id.as_str()), ("removed", "P-0000CAFE"));
        p.back();
        assert_eq!(p.view(NOW).screen, Screen::List);
    }

    #[test]
    fn add_goes_list_source_form_review_and_only_confirm_makes_a_request() {
        let mut p = PublishersPanel::new(perms(MANAGE));
        on_the_form(&mut p);
        // The form blocks the review while its label is empty.
        assert_eq!(p.view(NOW).form.unwrap().problems, vec![FormProblem::Label]);
        assert!(!p.review(NOW));
        assert_eq!(p.view(NOW).screen, Screen::Form);
        p.type_text("  ACME signing\n");
        assert_eq!(
            p.view(NOW).form.unwrap().problems,
            Vec::<FormProblem>::new()
        );
        p.act(PubAction::Review, NOW);
        let v = p.view(NOW);
        assert_eq!(v.screen, Screen::Review);
        let lines = v.review.unwrap();
        assert!(lines.contains(&ReviewLine::Label("ACME signing".into())));
        assert!(lines
            .iter()
            .any(|l| matches!(l, ReviewLine::Publisher(s) if s.contains("ACME Corp"))));
        assert!(lines
            .iter()
            .any(|l| matches!(l, ReviewLine::Thumbprint(t) if t.len() == 64)));
        assert!(lines.contains(&ReviewLine::Warning(Warning::RootAnchor)));
        // Certificate files carry no signature, so no timestamp warning.
        assert!(!lines.contains(&ReviewLine::Warning(Warning::NoTimestamp)));
        // Enter and the other buttons never confirm.
        assert!(p.enter(NOW).is_none() && !p.has_pending());
        let req = p.confirm(NOW).expect("confirm makes the request");
        assert!(req.proof.is_none() && !req.idempotency_key.is_empty());
        assert_eq!((req.label.as_str(), req.pin_kind), ("ACME signing", 2));
        assert!(p.has_pending(), "waits for the fresh factor");
        assert!(p.confirm(NOW).is_none(), "not twice");
        let added = info(ID, 1);
        let PubEvent::Send(Cmd::ListPublishers { .. }) = p.on_added(Ok(Some(added))) else {
            panic!("the list reloads");
        };
        let v = p.view(NOW);
        assert_eq!(v.screen, Screen::List);
        assert_eq!(v.outcome, Some(Outcome::Added(Some("P-0000BEEF".into()))));
    }

    #[test]
    fn the_review_wording_covers_every_warning_the_shared_api_makes() {
        // An untimestamped executable: the one source that can lack a timestamp.
        let mut c = candidate();
        c.source = ferrogate_admin_client::publishers::inspect::Source::Executable;
        c.timestamped = false;
        let mut d = PublisherDraft::from_candidate(&c, 0, PinKind::SubjectSha256, "x").unwrap();
        d.require_timestamp = true;
        let lines = review_lines(&d, &c);
        let warnings: Vec<_> = lines
            .iter()
            .filter_map(|l| match l {
                ReviewLine::Warning(w) => Some(w.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            warnings,
            vec![
                Warning::SubjectPin,
                Warning::RootAnchor,
                Warning::NoTimestamp
            ]
        );
        assert!(
            !lines.iter().any(|l| matches!(l, ReviewLine::Other(..))),
            "{lines:?}"
        );
        assert!(lines.contains(&ReviewLine::Scope) && lines.contains(&ReviewLine::Expires(None)));
    }

    #[test]
    fn cancel_at_each_step_sends_nothing() {
        let mut p = PublishersPanel::new(perms(MANAGE));
        on_the_review(&mut p);
        for want in [Screen::Form, Screen::Source, Screen::List] {
            assert!(p.act(PubAction::Back, NOW).is_none());
            assert_eq!(p.view(NOW).screen, want);
            assert!(!p.has_pending());
        }
        // Cancel from the review drops everything at once.
        on_the_review(&mut p);
        assert!(p.act(PubAction::Cancel, NOW).is_none());
        let v = p.view(NOW);
        assert!(v.screen == Screen::List && v.form.is_none() && v.review.is_none());
        // After the review's Confirm, closing the factor prompt sends nothing.
        on_the_review(&mut p);
        assert!(p.confirm(NOW).is_some());
        p.add_cancelled();
        assert!(!p.has_pending());
        let v = p.view(NOW);
        assert_eq!(
            (v.screen, v.outcome),
            (Screen::Review, Some(Outcome::NotSent))
        );
        // A refusal keeps the review and sends nothing more.
        assert!(p.confirm(NOW).is_some());
        let PubEvent::None = p.on_added(Err(ClientError::Rejected)) else {
            panic!("no event");
        };
        assert_eq!(
            p.view(NOW).outcome,
            Some(Outcome::Refused(Refusal::ServerError))
        );
        assert_eq!(p.view(NOW).screen, Screen::Review);
    }

    #[test]
    fn a_read_that_lands_after_leaving_the_source_is_dropped() {
        let mut p = PublishersPanel::new(perms(MANAGE));
        listed(&mut p);
        p.act(PubAction::StartAdd, NOW);
        assert!(p.start_executable("/a".into()).is_some());
        assert!(
            p.start_executable("/b".into()).is_none(),
            "one read at a time"
        );
        p.back();
        p.inspected(Ok(candidate()));
        assert_eq!(p.view(NOW).screen, Screen::List);
        assert!(p.view(NOW).form.is_none());
        // A failure is shown by kind and the source stays.
        p.act(PubAction::StartAdd, NOW);
        let _ = p.start_executable("/a".into());
        p.inspected(Err(InspectFailure::Unsupported));
        let v = p.view(NOW);
        assert_eq!(
            (v.screen, v.source.error),
            (Screen::Source, Some(InspectFailure::Unsupported))
        );
        assert!(!v.source.inspecting);
    }

    #[test]
    fn the_certificate_source_needs_both_files_and_takes_a_kind() {
        let mut p = PublishersPanel::new(perms(MANAGE));
        p.act(PubAction::StartAdd, NOW);
        assert!(p.start_certificates().is_none());
        p.set_leaf("/certs/leaf.pem".into());
        assert!(p.start_certificates().is_none() && !p.view(NOW).source.can_read_certificates);
        p.set_anchor("/certs/ca.pem".into());
        p.act(PubAction::Kind(SignatureKind::Authenticode), NOW);
        let v = p.view(NOW).source;
        assert_eq!(
            (v.kind, v.leaf.as_deref(), v.anchor.as_deref()),
            ("authenticode", Some("leaf.pem"), Some("ca.pem"))
        );
        assert!(v.can_read_certificates);
        assert_eq!(
            p.start_certificates(),
            Some(InspectJob::Certificates {
                kind: SignatureKind::Authenticode,
                leaf: "/certs/leaf.pem".into(),
                anchor: "/certs/ca.pem".into(),
            })
        );
    }

    #[test]
    fn certificate_files_are_read_with_a_bound_and_named_failures() {
        let dir = tempfile::tempdir().unwrap();
        let chain = TestChain::new("ACME Corp");
        let (leaf, ca) = (dir.path().join("leaf.der"), dir.path().join("ca.der"));
        std::fs::write(&leaf, &chain.leaf_der).unwrap();
        std::fs::write(&ca, &chain.ca_der).unwrap();
        let job = |kind, leaf: &Path, anchor: &Path| InspectJob::Certificates {
            kind,
            leaf: leaf.into(),
            anchor: anchor.into(),
        };
        let c = job(SignatureKind::Apple, &leaf, &ca).run().unwrap();
        assert!(c.leaf.subject.contains("ACME Corp"));
        let missing = dir.path().join("nope");
        assert_eq!(
            job(SignatureKind::Apple, &missing, &ca).run(),
            Err(InspectFailure::Unreadable)
        );
        assert_eq!(
            job(SignatureKind::Apple, dir.path(), &ca).run(),
            Err(InspectFailure::Unreadable),
            "a directory is not a file"
        );
        let junk = dir.path().join("junk");
        std::fs::write(&junk, b"not a certificate").unwrap();
        assert_eq!(
            job(SignatureKind::Apple, &junk, &ca).run(),
            Err(InspectFailure::NotCertificate)
        );
        let big = dir.path().join("big");
        std::fs::write(&big, vec![0u8; 200 * 1024]).unwrap();
        assert_eq!(
            job(SignatureKind::Apple, &big, &ca).run(),
            Err(InspectFailure::NotCertificate),
            "read up to the bound, then refused by the parser"
        );
    }

    #[test]
    fn a_platform_without_a_verifier_names_it_and_a_bad_path_fails() {
        let r = InspectJob::Executable("/definitely/not/here".into()).run();
        assert!(matches!(
            r,
            Err(InspectFailure::Unsupported | InspectFailure::Signature(_))
        ));
        assert_eq!(failure(&InspectError::NoIssuer), InspectFailure::NoIssuer);
    }

    #[test]
    fn the_form_offers_each_issuer_and_changes_what_the_draft_pins() {
        let mut p = PublishersPanel::new(perms(MANAGE));
        on_the_form(&mut p);
        // A second issuer, to choose among.
        if let Some(f) = &mut p.form {
            let mut second = f.candidate.issuers[0].clone();
            second.cert_sha256 = [9; 32];
            second.subject = "CN=Intermediate\u{202e}".into();
            f.candidate.issuers.push(second);
        }
        let v = p.view(NOW).form.unwrap();
        assert_eq!(v.anchors.len(), 2);
        assert!(v.anchors[0].root && !v.anchors[1].root);
        assert!(!v.anchors[1].subject.contains('\u{202e}'));
        assert_eq!(
            (v.anchor, v.pin_kind, v.require_timestamp, v.expiry),
            (0, "leaf-spki", true, 0)
        );
        p.act(PubAction::Choose(FormChoice::Anchor(1)), NOW);
        p.act(PubAction::Choose(FormChoice::Anchor(7)), NOW);
        p.act(
            PubAction::Choose(FormChoice::Pin(PinKind::LeafCertSha256)),
            NOW,
        );
        p.act(PubAction::Choose(FormChoice::Timestamp(false)), NOW);
        p.act(PubAction::Choose(FormChoice::Expiry(2)), NOW);
        p.type_text("ACME");
        assert!(p.review(NOW));
        let req = p.confirm(NOW).unwrap();
        assert_eq!(req.anchor_sha256, vec![9; 32]);
        assert_eq!(req.pin_kind, 1);
        assert!(!req.require_timestamp);
        assert_eq!(req.expires_at, NOW + 90 * 86_400);
    }

    #[test]
    fn an_overlong_label_cannot_be_typed_and_control_characters_are_dropped() {
        let mut p = PublishersPanel::new(perms(MANAGE));
        on_the_form(&mut p);
        p.type_text(&"x".repeat(MAX_LABEL + 50));
        p.type_text("\u{1b}[31m\n");
        let v = p.view(NOW).form.unwrap();
        assert!(v.label.chars().count() <= MAX_LABEL);
        assert!(!v.label.contains('\u{1b}'));
        p.backspace();
        assert_eq!(
            p.view(NOW).form.unwrap().label.chars().count(),
            MAX_LABEL - 1
        );
    }

    #[test]
    fn a_removal_needs_the_exact_short_id_then_steps_up_once_with_the_same_key() {
        let mut p = PublishersPanel::new(perms(MANAGE));
        listed(&mut p);
        // A removed publisher cannot be removed again.
        p.act(PubAction::StartRemove(1), NOW);
        assert_eq!(p.view(NOW).screen, Screen::List);
        p.act(PubAction::StartRemove(0), NOW);
        let v = p.view(NOW);
        assert_eq!(v.screen, Screen::Remove);
        assert_eq!(v.remove.unwrap().phrase, "P-0000BEEF");
        assert!(
            p.act(PubAction::ConfirmRemove, NOW).is_none(),
            "nothing typed"
        );
        assert!(p.view(NOW).remove.unwrap().mismatch);
        p.type_text("P-0000BEEE");
        assert!(p.enter(NOW).is_none(), "a near miss is refused");
        assert!(!p.view(NOW).remove.unwrap().confirmed);
        p.backspace();
        p.type_text("F");
        assert!(p.view(NOW).remove.unwrap().confirmed);
        let Some(Cmd::RemovePublisher(first)) = p.act(PubAction::ConfirmRemove, NOW) else {
            panic!("sent");
        };
        assert_eq!(first.publisher_id, ID);
        assert!(p.has_pending());
        let PubEvent::StepUp = p.on_removed(Err(step_up_required())) else {
            panic!("a step-up is asked");
        };
        assert!(p.has_pending(), "kept for the retry");
        let Some(Cmd::RemovePublisher(again)) = p.resend() else {
            panic!("resent");
        };
        assert_eq!(first.idempotency_key, again.idempotency_key);
        // A second step-up demand right after one is not retried.
        let PubEvent::None = p.on_removed(Err(step_up_required())) else {
            panic!("no event");
        };
        assert_eq!(p.view(NOW).outcome, Some(Outcome::StepUpAgain));
        assert!(!p.has_pending() && p.resend().is_none());
    }

    #[test]
    fn a_removal_outcome_reloads_and_a_cancelled_step_up_sends_nothing_more() {
        let mut p = PublishersPanel::new(perms(MANAGE));
        listed(&mut p);
        p.act(PubAction::StartRemove(0), NOW);
        p.type_text("p-0000beef");
        assert!(p.enter(NOW).is_some(), "case does not matter");
        let PubEvent::Send(Cmd::ListPublishers { .. }) = p.on_removed(Ok(None)) else {
            panic!("the list reloads");
        };
        assert_eq!(p.view(NOW).outcome, Some(Outcome::Removed));
        assert_eq!(p.view(NOW).screen, Screen::List);
        // Cancelled step-up: dropped unsent.
        p.act(PubAction::StartRemove(0), NOW);
        p.type_text("P-0000BEEF");
        assert!(p.enter(NOW).is_some());
        let PubEvent::StepUp = p.on_removed(Err(step_up_required())) else {
            panic!("step-up");
        };
        p.drop_pending();
        assert!(!p.has_pending() && p.resend().is_none());
        assert_eq!(p.view(NOW).outcome, Some(Outcome::NotSent));
        assert_eq!(p.view(NOW).screen, Screen::List);
        // Back from the confirmation sends nothing either.
        p.act(PubAction::StartRemove(0), NOW);
        assert!(p.act(PubAction::Back, NOW).is_none());
        assert_eq!(p.view(NOW).screen, Screen::List);
    }

    #[test]
    fn without_publisher_manage_add_and_remove_are_hidden_and_refused() {
        let mut p = PublishersPanel::new(perms(&[perm::PUBLISHER_LIST]));
        listed(&mut p);
        assert!(!p.view(NOW).can_manage);
        p.act(PubAction::StartAdd, NOW);
        assert_eq!(p.view(NOW).screen, Screen::List);
        p.act(PubAction::StartRemove(0), NOW);
        assert_eq!(p.view(NOW).screen, Screen::List);
        assert!(p.start_executable("/x".into()).is_none());
        // Unknown permissions offer everything: the server decides.
        assert!(PublishersPanel::new(None).can_manage());
        assert!(PublishersPanel::new(perms(MANAGE)).can_manage());
    }

    #[test]
    fn without_publisher_list_nothing_is_requested() {
        let mut p = PublishersPanel::new(None);
        let PubEvent::None = p.on_permissions(Ok(vec!["app_request.list".into()])) else {
            panic!("no list asked");
        };
        assert_eq!(p.view(NOW).error, Some(Refusal::NotAllowed));
        let mut p = PublishersPanel::new(None);
        let PubEvent::Send(Cmd::ListPublishers { .. }) =
            p.on_permissions(Ok(vec![perm::PUBLISHER_LIST.into()]))
        else {
            panic!("the list is asked");
        };
        let mut p = PublishersPanel::new(None);
        let PubEvent::SessionEnded = p.on_permissions(Err(ClientError::SessionEnded)) else {
            panic!("ended");
        };
    }

    #[test]
    fn a_dead_session_ends_and_other_failures_are_by_kind_only() {
        let mut p = PublishersPanel::new(perms(MANAGE));
        let PubEvent::SessionEnded = p.on_listed(Err(ClientError::SessionEnded)) else {
            panic!("ended");
        };
        let PubEvent::None = p.on_listed(Err(ClientError::Connect("secret host".into()))) else {
            panic!("none");
        };
        assert_eq!(p.view(NOW).error, Some(Refusal::Unreachable));
        assert!(!format!("{:?}", p.view(NOW)).contains("secret host"));
        // Answers nobody waits for are ignored.
        assert!(matches!(p.on_added(Ok(None)), PubEvent::None));
        assert!(matches!(p.on_removed(Ok(None)), PubEvent::None));
    }
}
