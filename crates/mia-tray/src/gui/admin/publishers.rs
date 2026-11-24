//! Trusted publishers (ADR-0006), drawn from the inert [`PublishersView`]:
//! the list, a detail page with every field, the source choice, the add
//! form, its review page, and the typed removal confirmation.

//! Every string shown comes from the cleaned view model (never a raw
//! server record). Typed fields are painted boxes, never `egui` text
//! widgets, like the rest of the window; digests are selectable text with
//! a copy button.

use eframe::egui;
use ferrogate_admin_client::approvals::rules::EXPIRY_DAYS;
use ferrogate_admin_client::publishers::view::PublisherRow;
use ferrogate_admin_client::publishers::SignatureKind;

use super::views::{refusal_text, when};
use super::{field_box, Action};
use crate::admin::publishers::{
    FormChoice, FormProblem, FormView, InspectFailure, Outcome, PubAction, PublishersView,
    RemoveView, ReviewLine, Screen, SourceView, Warning, KINDS, PIN_KINDS,
};
use crate::i18n::{fill, Lang, Msg};

fn act(action: PubAction) -> Action {
    Action::Publisher(action)
}

fn expires(lang: Lang, at: Option<i64>) -> String {
    at.map_or_else(|| Msg::AdminNoExpiry.text(lang).to_string(), when)
}

fn kind_name(lang: Lang, kind: SignatureKind) -> &'static str {
    match kind {
        SignatureKind::Authenticode => Msg::AdminPubKindAuthenticode.text(lang),
        SignatureKind::Apple => Msg::AdminPubKindApple.text(lang),
    }
}

fn state_name(lang: Lang, state: &str) -> &'static str {
    if state == "removed" {
        Msg::AdminPubStateRemoved.text(lang)
    } else {
        Msg::AdminPubStateActive.text(lang)
    }
}

fn outcome_text(lang: Lang, o: &Outcome) -> (String, bool) {
    match o {
        Outcome::Added(Some(id)) => (fill(Msg::AdminPubOutAdded.text(lang), &[("id", id)]), false),
        Outcome::Added(None) => (Msg::AdminPubOutAddedNoId.text(lang).to_string(), false),
        Outcome::Removed => (Msg::AdminPubOutRemoved.text(lang).to_string(), false),
        Outcome::Refused(r) => (refusal_text(lang, *r).to_string(), true),
        Outcome::StepUpAgain => (Msg::AdminOutStepUpAgain.text(lang).to_string(), true),
        Outcome::NotSent => (Msg::AdminOutNotSent.text(lang).to_string(), false),
    }
}

fn outcome(ui: &mut egui::Ui, lang: Lang, v: &PublishersView) {
    if let Some(o) = &v.outcome {
        let (text, bad) = outcome_text(lang, o);
        if bad {
            ui.colored_label(ui.visuals().error_fg_color, text);
        } else {
            ui.label(text);
        }
    }
}

/// A labelled value as selectable text; a digest also gets a copy button.
fn field(ui: &mut egui::Ui, lang: Lang, label: Msg, value: &str, mono: bool) {
    ui.label(egui::RichText::new(label.text(lang)).strong());
    let shown = if value.is_empty() { "—" } else { value };
    ui.horizontal_wrapped(|ui| {
        let text = if mono {
            egui::RichText::new(shown).monospace()
        } else {
            egui::RichText::new(shown)
        };
        ui.add(egui::Label::new(text).selectable(true));
        if mono && !value.is_empty() && ui.small_button(Msg::AdminPubCopy.text(lang)).clicked() {
            ui.ctx().copy_text(value.to_string());
        }
    });
}

/// Draw the panel.
pub(super) fn panel(
    ui: &mut egui::Ui,
    lang: Lang,
    v: &PublishersView,
    idle: bool,
    actions: &mut Vec<Action>,
) {
    ui.heading(Msg::AdminPubOpen.text(lang));
    ui.add_space(4.0);
    match v.screen {
        Screen::List => list(ui, lang, v, idle, actions),
        Screen::Detail => detail(ui, lang, v, idle, actions),
        Screen::Source => source(ui, lang, v, idle, actions),
        Screen::Form => {
            if let Some(f) = &v.form {
                form(ui, lang, f, idle, actions);
            }
        }
        Screen::Review => review(ui, lang, v, idle, actions),
        Screen::Remove => {
            if let Some(r) = &v.remove {
                remove(ui, lang, r, idle, actions);
            }
        }
    }
}

fn list(ui: &mut egui::Ui, lang: Lang, v: &PublishersView, idle: bool, actions: &mut Vec<Action>) {
    ui.label(Msg::AdminPubIntro.text(lang));
    ui.add_space(4.0);
    outcome(ui, lang, v);
    if let Some(e) = v.error {
        ui.colored_label(ui.visuals().error_fg_color, refusal_text(lang, e));
    } else if !v.loaded {
        ui.weak(Msg::AdminLoading.text(lang));
    }
    ui.horizontal_wrapped(|ui| {
        let mut on = v.show_removed;
        let toggle = egui::Checkbox::new(&mut on, Msg::AdminPubShowRemoved.text(lang));
        if ui.add_enabled(idle && !v.pending, toggle).changed() {
            actions.push(act(PubAction::ToggleRemoved));
        }
        if ui
            .add_enabled(
                idle && !v.pending,
                egui::Button::new(Msg::ButtonRefresh.text(lang)),
            )
            .clicked()
        {
            actions.push(act(PubAction::Refresh));
        }
        if v.can_manage
            && ui
                .add_enabled(
                    idle && !v.pending,
                    egui::Button::new(Msg::AdminPubAdd.text(lang)),
                )
                .clicked()
        {
            actions.push(act(PubAction::StartAdd));
        }
        if ui
            .add_enabled(
                idle && !v.pending,
                egui::Button::new(Msg::AdminBack.text(lang)),
            )
            .clicked()
        {
            actions.push(Action::ClosePublishers);
        }
    });
    if v.loaded && v.rows.is_empty() {
        ui.weak(Msg::AdminPubNone.text(lang));
    }
    for (i, row) in v.rows.iter().enumerate() {
        ui.separator();
        ui.strong(row.title());
        ui.weak(fill(
            Msg::AdminPubRowMeta.text(lang),
            &[
                ("id", &row.short_id),
                ("kind", row.kind),
                ("pin", row.pin_kind),
                ("state", state_name(lang, row.state)),
                ("expires", &expires(lang, row.expires_at)),
            ],
        ));
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    idle,
                    egui::Button::new(Msg::AdminPubDetails.text(lang)).small(),
                )
                .clicked()
            {
                actions.push(act(PubAction::Open(i)));
            }
            if v.can_manage
                && row.state == "active"
                && ui
                    .add_enabled(
                        idle && !v.pending,
                        egui::Button::new(Msg::AdminPubRemoveOpen.text(lang)).small(),
                    )
                    .clicked()
            {
                actions.push(act(PubAction::StartRemove(i)));
            }
        });
    }
}

/// Every field of one publisher.
fn rows_of(lang: Lang, d: &PublisherRow) -> Vec<(Msg, String, bool)> {
    let yes_no = |on: bool| {
        if on {
            Msg::AdminPubRequired
        } else {
            Msg::AdminPubNotRequired
        }
        .text(lang)
        .to_string()
    };
    let mut rows = vec![
        (Msg::AdminPubFLabel, d.label.clone(), false),
        (Msg::AdminPubFSubject, d.subject.clone(), false),
        (Msg::AdminPubFIssuer, d.issuer.clone(), false),
        (Msg::AdminPubFShortId, d.short_id.clone(), true),
        (Msg::AdminPubFId, d.id.clone(), true),
        (Msg::AdminPubFKind, d.kind.to_string(), false),
        (Msg::AdminPubFPinKind, d.pin_kind.to_string(), false),
        (Msg::AdminPubFPin, d.pin.clone(), true),
        (Msg::AdminPubFAnchor, d.anchor_sha256.clone(), true),
        (Msg::AdminPubFLeaf, d.leaf_cert_sha256.clone(), true),
        (Msg::AdminPubFTimestamp, yes_no(d.require_timestamp), false),
        (Msg::AdminPubFCreated, when(d.created_at), false),
        (Msg::AdminPubFCreatedBy, d.created_by.clone(), false),
        (Msg::AdminPubFExpires, expires(lang, d.expires_at), false),
        (
            Msg::AdminPubFState,
            state_name(lang, d.state).to_string(),
            false,
        ),
    ];
    if let Some(at) = d.removed_at {
        rows.push((Msg::AdminPubFRemoved, when(at), false));
        rows.push((Msg::AdminPubFRemovedBy, d.removed_by.clone(), false));
    }
    rows
}

fn detail(
    ui: &mut egui::Ui,
    lang: Lang,
    v: &PublishersView,
    idle: bool,
    actions: &mut Vec<Action>,
) {
    let Some(d) = &v.detail else {
        return;
    };
    outcome(ui, lang, v);
    for (label, value, mono) in rows_of(lang, d) {
        field(ui, lang, label, &value, mono);
    }
    ui.add_space(6.0);
    ui.horizontal_wrapped(|ui| {
        if ui
            .add_enabled(idle, egui::Button::new(Msg::AdminBack.text(lang)))
            .clicked()
        {
            actions.push(act(PubAction::Back));
        }
        let index = v.rows.iter().position(|r| r.id == d.id);
        if let (true, "active", Some(i)) = (v.can_manage, d.state, index) {
            if ui
                .add_enabled(idle, egui::Button::new(Msg::AdminPubRemoveOpen.text(lang)))
                .clicked()
            {
                actions.push(act(PubAction::StartRemove(i)));
            }
        }
    });
}

fn inspect_error(lang: Lang, e: InspectFailure) -> String {
    match e {
        InspectFailure::Unsupported => Msg::AdminPubErrUnsupported.text(lang).to_string(),
        InspectFailure::Signature(reason) => {
            fill(Msg::AdminPubErrSignature.text(lang), &[("reason", reason)])
        }
        InspectFailure::Unreadable => Msg::AdminPubErrUnreadable.text(lang).to_string(),
        InspectFailure::NotCertificate => Msg::AdminPubErrCert.text(lang).to_string(),
        InspectFailure::NoIssuer => Msg::AdminPubErrNoIssuer.text(lang).to_string(),
    }
}

fn source(
    ui: &mut egui::Ui,
    lang: Lang,
    v: &PublishersView,
    idle: bool,
    actions: &mut Vec<Action>,
) {
    let s: &SourceView = &v.source;
    let free = idle && !s.inspecting;
    ui.label(egui::RichText::new(Msg::AdminPubSourceTitle.text(lang)).strong());
    ui.add_space(4.0);
    ui.label(Msg::AdminPubFromExe.text(lang));
    ui.weak(Msg::AdminPubFromExeHint.text(lang));
    if ui
        .add_enabled(free, egui::Button::new(Msg::AdminPubPickExe.text(lang)))
        .clicked()
    {
        actions.push(Action::PubPickExecutable);
    }
    ui.separator();
    ui.label(Msg::AdminPubFromCerts.text(lang));
    ui.weak(Msg::AdminPubFromCertsHint.text(lang));
    ui.horizontal_wrapped(|ui| {
        for kind in KINDS {
            if ui
                .radio(s.kind == kind.as_str(), kind_name(lang, kind))
                .clicked()
                && free
            {
                actions.push(act(PubAction::Kind(kind)));
            }
        }
    });
    for (pick, msg, chosen) in [
        (Action::PubPickLeaf, Msg::AdminPubPickLeaf, &s.leaf),
        (Action::PubPickAnchor, Msg::AdminPubPickCa, &s.anchor),
    ] {
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(free, egui::Button::new(msg.text(lang)))
                .clicked()
            {
                actions.push(pick);
            }
            match chosen {
                Some(name) => ui.label(name),
                None => ui.weak(Msg::AdminPubNoFile.text(lang)),
            };
        });
    }
    if ui
        .add_enabled(
            free && s.can_read_certificates,
            egui::Button::new(Msg::AdminPubReadCerts.text(lang)),
        )
        .clicked()
    {
        actions.push(Action::PubReadCerts);
    }
    if s.inspecting {
        ui.label(Msg::AdminPubInspecting.text(lang));
    }
    if let Some(e) = s.error {
        ui.colored_label(ui.visuals().error_fg_color, inspect_error(lang, e));
    }
    ui.add_space(6.0);
    if ui
        .add_enabled(idle, egui::Button::new(Msg::AdminCancel.text(lang)))
        .clicked()
    {
        actions.push(act(PubAction::Cancel));
    }
}

fn problem_text(lang: Lang, p: FormProblem, max: usize) -> String {
    match p {
        FormProblem::Label => fill(
            Msg::AdminPubProbLabel.text(lang),
            &[("max", &max.to_string())],
        ),
        FormProblem::Anchor => Msg::AdminPubProbAnchor.text(lang).to_string(),
        FormProblem::Digest => Msg::AdminPubProbDigest.text(lang).to_string(),
        FormProblem::Expiry => Msg::AdminPubProbExpiry.text(lang).to_string(),
        FormProblem::Id => Msg::AdminPubProbId.text(lang).to_string(),
    }
}

fn form(ui: &mut egui::Ui, lang: Lang, f: &FormView, idle: bool, actions: &mut Vec<Action>) {
    let choose = |actions: &mut Vec<Action>, c: FormChoice| actions.push(act(PubAction::Choose(c)));
    ui.label(egui::RichText::new(Msg::AdminPubFormTitle.text(lang)).strong());
    field(ui, lang, Msg::AdminPubFSubject, &f.subject, false);
    field(ui, lang, Msg::AdminPubFLeaf, &f.thumbprint, true);
    ui.add_space(4.0);
    ui.label(fill(
        Msg::AdminPubLabelField.text(lang),
        &[("max", &f.label_max.to_string())],
    ));
    field_box(ui, &f.label, true);
    ui.add_space(4.0);
    ui.label(Msg::AdminPubAnchorField.text(lang));
    for (i, a) in f.anchors.iter().enumerate() {
        let mut text = a.subject.clone();
        if a.root {
            text = format!("{text} ({})", Msg::AdminPubAnchorRoot.text(lang));
        }
        if ui.radio(f.anchor == i, text).clicked() {
            choose(actions, FormChoice::Anchor(i));
        }
        ui.add(
            egui::Label::new(egui::RichText::new(&a.sha256).monospace().weak()).selectable(true),
        );
    }
    ui.add_space(4.0);
    ui.label(Msg::AdminPubPinField.text(lang));
    for kind in PIN_KINDS {
        let msg = match kind.as_str() {
            "leaf-spki" => Msg::AdminPubPinSpki,
            "leaf-cert" => Msg::AdminPubPinCert,
            _ => Msg::AdminPubPinSubject,
        };
        if ui
            .radio(f.pin_kind == kind.as_str(), msg.text(lang))
            .clicked()
        {
            choose(actions, FormChoice::Pin(kind));
        }
    }
    let mut on = f.require_timestamp;
    if ui
        .checkbox(&mut on, Msg::AdminPubTimestampCheck.text(lang))
        .changed()
    {
        choose(actions, FormChoice::Timestamp(on));
    }
    ui.label(Msg::AdminPubExpiryField.text(lang));
    ui.horizontal_wrapped(|ui| {
        for (i, days) in EXPIRY_DAYS.iter().enumerate() {
            let text = if *days == 0 {
                Msg::AdminPubExpiryNever.text(lang).to_string()
            } else {
                fill(Msg::AdminExpiryDays.text(lang), &[("n", &days.to_string())])
            };
            if ui.radio(f.expiry == i, text).clicked() {
                choose(actions, FormChoice::Expiry(i));
            }
        }
    });
    for p in &f.problems {
        ui.colored_label(
            ui.visuals().error_fg_color,
            problem_text(lang, *p, f.label_max),
        );
    }
    ui.add_space(6.0);
    ui.horizontal_wrapped(|ui| {
        if ui
            .add_enabled(
                idle && f.problems.is_empty(),
                egui::Button::new(Msg::AdminPubReview.text(lang)),
            )
            .clicked()
        {
            actions.push(act(PubAction::Review));
        }
        if ui
            .add_enabled(idle, egui::Button::new(Msg::AdminBack.text(lang)))
            .clicked()
        {
            actions.push(act(PubAction::Back));
        }
        if ui
            .add_enabled(idle, egui::Button::new(Msg::AdminCancel.text(lang)))
            .clicked()
        {
            actions.push(act(PubAction::Cancel));
        }
    });
}

fn warning_text(lang: Lang, w: &Warning) -> String {
    match w {
        Warning::SubjectPin => Msg::AdminPubWarnSubject.text(lang).to_string(),
        Warning::RootAnchor => Msg::AdminPubWarnRoot.text(lang).to_string(),
        Warning::NoTimestamp => Msg::AdminPubWarnNoTimestamp.text(lang).to_string(),
        Warning::Other(text) => text.clone(),
    }
}

fn review(
    ui: &mut egui::Ui,
    lang: Lang,
    v: &PublishersView,
    idle: bool,
    actions: &mut Vec<Action>,
) {
    ui.label(egui::RichText::new(Msg::AdminPubReviewTitle.text(lang)).strong());
    ui.label(Msg::AdminPubReviewNote.text(lang));
    ui.add_space(4.0);
    outcome(ui, lang, v);
    let mut warnings = Vec::new();
    for line in v.review.iter().flatten() {
        match line {
            ReviewLine::Label(s) => field(ui, lang, Msg::AdminPubFLabel, s, false),
            ReviewLine::Kind(s) => field(ui, lang, Msg::AdminPubFKind, s, false),
            ReviewLine::Publisher(s) => field(ui, lang, Msg::AdminPubFSubject, s, false),
            ReviewLine::Issuer(s) => field(ui, lang, Msg::AdminPubFIssuer, s, false),
            ReviewLine::Thumbprint(s) => field(ui, lang, Msg::AdminPubFLeaf, s, true),
            ReviewLine::Pins(s) => field(ui, lang, Msg::AdminPubRPins, s, true),
            ReviewLine::Anchor(s) => field(ui, lang, Msg::AdminPubFAnchor, s, true),
            ReviewLine::Timestamp(on) => {
                let msg = if *on {
                    Msg::AdminPubRequired
                } else {
                    Msg::AdminPubNotRequired
                };
                field(ui, lang, Msg::AdminPubFTimestamp, msg.text(lang), false);
            }
            ReviewLine::Scope => {
                field(
                    ui,
                    lang,
                    Msg::AdminPubRScope,
                    Msg::AdminPubScopeAll.text(lang),
                    false,
                );
            }
            ReviewLine::Expires(at) => {
                field(ui, lang, Msg::AdminPubFExpires, &expires(lang, *at), false);
            }
            ReviewLine::Warning(w) => warnings.push(warning_text(lang, w)),
            ReviewLine::Other(key, value) => {
                ui.label(format!("{key}: {value}"));
            }
        }
    }
    for w in warnings {
        ui.colored_label(
            ui.visuals().warn_fg_color,
            format!("{}: {w}", Msg::AdminPubWarning.text(lang)),
        );
    }
    ui.add_space(6.0);
    ui.horizontal_wrapped(|ui| {
        if ui
            .add_enabled(
                idle && !v.pending,
                egui::Button::new(Msg::AdminRegConfirm.text(lang)),
            )
            .clicked()
        {
            actions.push(act(PubAction::Confirm));
        }
        if ui
            .add_enabled(
                idle && !v.pending,
                egui::Button::new(Msg::AdminBack.text(lang)),
            )
            .clicked()
        {
            actions.push(act(PubAction::Back));
        }
        if ui
            .add_enabled(
                idle && !v.pending,
                egui::Button::new(Msg::AdminCancel.text(lang)),
            )
            .clicked()
        {
            actions.push(act(PubAction::Cancel));
        }
    });
}

fn remove(ui: &mut egui::Ui, lang: Lang, r: &RemoveView, idle: bool, actions: &mut Vec<Action>) {
    ui.label(
        egui::RichText::new(fill(
            Msg::AdminPubRemoveTitle.text(lang),
            &[("title", &r.title)],
        ))
        .strong(),
    );
    ui.label(Msg::AdminPubRemoveWarn.text(lang));
    ui.label(fill(
        Msg::AdminPubRemoveType.text(lang),
        &[("phrase", &r.phrase)],
    ));
    field_box(ui, &r.typed, true);
    if r.mismatch {
        ui.colored_label(
            ui.visuals().error_fg_color,
            Msg::AdminPubRemoveMismatch.text(lang),
        );
    }
    ui.add_space(6.0);
    ui.horizontal_wrapped(|ui| {
        if ui
            .add_enabled(
                idle && r.confirmed,
                egui::Button::new(Msg::AdminPubRemoveSend.text(lang)),
            )
            .clicked()
        {
            actions.push(act(PubAction::ConfirmRemove));
        }
        if ui
            .add_enabled(idle, egui::Button::new(Msg::AdminCancel.text(lang)))
            .clicked()
        {
            actions.push(act(PubAction::Back));
        }
    });
}
