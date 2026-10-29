//! Requests and Approvals (F22 §4), drawn from the inert [`ViewsView`]:
//! the lists with search and filters, the details, and the decision dialog
//! with its wide-scope confirmation and review page.

//! Server text is plain `egui` text (no markup, links or web view), already
//! made inert by the headless model. Typed fields are painted boxes, never
//! `egui` text widgets, like the rest of the window.

use eframe::egui;
use ferrogate_admin_client::approvals::filters::{POLICIES, PRESETS, REQUEST_KINDS};
use ferrogate_admin_client::approvals::rules::{
    ApprovalChange, DENY_REASONS, EDIT_EXPIRY_DAYS, EXPIRY_DAYS, REVOKE_REASONS,
};
use ferrogate_admin_client::timefmt;

use super::{field_box, Action};
use crate::admin::decide::{
    Choice, DecisionError, DecisionField, DecisionKind, DecisionStage, DecisionView, ReviewLine,
};
use crate::admin::views::{
    origin_names, policy_names, ApprovalDetail, ApprovalRow, FilterChoice, FilterField,
    FiltersView, Outcome, Refusal, RequestDetail, Screen, Tab, ViewAction, ViewsView,
};
use crate::i18n::{fill, Lang, Msg};

/// The latest Unix time shown as a date (a hostile value stays readable).
const MAX_DATE: i64 = 253_402_300_799;

fn when(secs: i64) -> String {
    if secs <= 0 {
        "—".to_string()
    } else {
        timefmt::datetime(secs.min(MAX_DATE))
    }
}

fn expiry(lang: Lang, secs: i64) -> String {
    if secs <= 0 {
        Msg::AdminNoExpiry.text(lang).to_string()
    } else {
        when(secs)
    }
}

fn view(action: ViewAction) -> Action {
    Action::View(action)
}

fn state_name(lang: Lang, tab: Tab, state: u32) -> &'static str {
    let msg = match (tab, state) {
        (Tab::Requests, 1) => Msg::AdminReqPending,
        (Tab::Requests, 2) => Msg::AdminReqApproved,
        (Tab::Requests, 3) => Msg::AdminReqAutoApproved,
        (Tab::Requests, 4) => Msg::AdminReqDenied,
        (Tab::Requests, 5) => Msg::AdminReqExpired,
        (Tab::Approvals, 1) => Msg::AdminApActive,
        (Tab::Approvals, 2) => Msg::AdminApExpired,
        (Tab::Approvals, 3) => Msg::AdminApRevoked,
        _ => return "?",
    };
    msg.text(lang)
}

fn refusal_text(lang: Lang, r: Refusal) -> &'static str {
    match r {
        Refusal::NotAllowed => Msg::AdminRefNotAllowed.text(lang),
        Refusal::Invalid => Msg::AdminRefInvalid.text(lang),
        Refusal::NotPossibleNow => Msg::AdminRefNotPossible.text(lang),
        Refusal::ChangedConcurrently => Msg::AdminRefChanged.text(lang),
        Refusal::NotFound => Msg::AdminRefNotFound.text(lang),
        Refusal::Unreachable => Msg::AdminUnreachable.text(lang),
        Refusal::ServerError => Msg::AdminServerError.text(lang),
    }
}

fn outcome_lines(lang: Lang, o: &Outcome) -> Vec<String> {
    match o {
        Outcome::Approved {
            approval,
            generation,
            revoked,
            same_actor,
        } => {
            let mut out = vec![fill(
                Msg::AdminOutApproved.text(lang),
                &[("id", approval), ("gen", &generation.to_string())],
            )];
            if !revoked.is_empty() {
                out.push(fill(
                    Msg::AdminOutAlsoRevoked.text(lang),
                    &[("ids", &revoked.join(", "))],
                ));
            }
            if *same_actor {
                out.push(Msg::AdminSameActor.text(lang).to_string());
            }
            out
        }
        Outcome::Denied => vec![Msg::AdminOutDenied.text(lang).to_string()],
        Outcome::Updated(g) => vec![fill(
            Msg::AdminOutUpdated.text(lang),
            &[("gen", &g.to_string())],
        )],
        Outcome::Revoked(g) => vec![fill(
            Msg::AdminOutRevoked.text(lang),
            &[("gen", &g.to_string())],
        )],
        Outcome::Frozen(true) => vec![Msg::AdminOutFrozen.text(lang).to_string()],
        Outcome::Frozen(false) => vec![Msg::AdminOutUnfrozen.text(lang).to_string()],
        Outcome::Refused(r) => vec![
            refusal_text(lang, *r).to_string(),
            Msg::AdminNothingChanged.text(lang).to_string(),
        ],
        Outcome::StepUpAgain => vec![Msg::AdminOutStepUpAgain.text(lang).to_string()],
        Outcome::NotSent => vec![Msg::AdminOutNotSent.text(lang).to_string()],
        Outcome::RevokedMeanwhile => vec![Msg::AdminOutRevokedMeanwhile.text(lang).to_string()],
    }
}

/// Draw the views.
pub(super) fn panel(
    ui: &mut egui::Ui,
    lang: Lang,
    v: &ViewsView,
    idle: bool,
    actions: &mut Vec<Action>,
) {
    let free = idle && !v.pending;
    ui.horizontal(|ui| {
        for (tab, msg) in [
            (Tab::Requests, Msg::AdminRequestsOpen),
            (Tab::Approvals, Msg::AdminApprovalsOpen),
        ] {
            if ui
                .add_enabled(free, egui::Button::selectable(v.tab == tab, msg.text(lang)))
                .clicked()
            {
                actions.push(view(ViewAction::Tab(tab)));
            }
        }
        if ui
            .add_enabled(free, egui::Button::new(Msg::ButtonRefresh.text(lang)))
            .clicked()
        {
            actions.push(view(ViewAction::Refresh));
        }
        if v.screen == Screen::List
            && v.filters.is_none()
            && ui
                .add_enabled(free, egui::Button::new(Msg::AdminFiltersOpen.text(lang)))
                .clicked()
        {
            actions.push(view(ViewAction::OpenFilters));
        }
        if ui
            .add_enabled(free, egui::Button::new(Msg::AdminClose.text(lang)))
            .clicked()
        {
            actions.push(Action::CloseViews);
        }
    });
    ui.weak(&v.summary);
    if let Some(o) = &v.outcome {
        ui.group(|ui| {
            for line in outcome_lines(lang, o) {
                ui.label(line);
            }
            if ui.small_button(Msg::AdminDismiss.text(lang)).clicked() {
                actions.push(view(ViewAction::DismissOutcome));
            }
        });
    }
    if let Some(e) = v.error {
        ui.colored_label(ui.visuals().error_fg_color, refusal_text(lang, e));
    }
    ui.add_space(4.0);
    if let Some(d) = &v.decision {
        decision(ui, lang, d, free, actions);
        return;
    }
    if let Some(f) = &v.filters {
        filters(ui, lang, v.tab, f, free, actions);
        return;
    }
    match v.screen {
        Screen::List => list(ui, lang, v, free, actions),
        Screen::Request => {
            if let Some(r) = &v.request {
                request(ui, lang, v, r, free, actions);
            }
        }
        Screen::Approval => {
            if let Some(a) = &v.approval {
                approval(ui, lang, v, a, free, actions);
            }
        }
    }
}

#[allow(clippy::too_many_lines)] // one control group per filter field.
fn filters(
    ui: &mut egui::Ui,
    lang: Lang,
    tab: Tab,
    f: &FiltersView,
    free: bool,
    actions: &mut Vec<Action>,
) {
    let states: &[Msg] = match tab {
        Tab::Requests => &[
            Msg::AdminReqPending,
            Msg::AdminReqApproved,
            Msg::AdminReqAutoApproved,
            Msg::AdminReqDenied,
            Msg::AdminReqExpired,
        ],
        Tab::Approvals => &[Msg::AdminApActive, Msg::AdminApExpired, Msg::AdminApRevoked],
    };
    ui.label(Msg::AdminFilterState.text(lang));
    ui.horizontal_wrapped(|ui| {
        for (i, (msg, on)) in states.iter().zip(&f.states).enumerate() {
            let mut checked = *on;
            if ui.checkbox(&mut checked, msg.text(lang)).changed() {
                actions.push(view(ViewAction::Filter(FilterChoice::State(i, checked))));
            }
        }
    });
    ui.label(Msg::AdminFilterOrigin.text(lang));
    ui.horizontal_wrapped(|ui| {
        for (i, (name, on)) in origin_names(tab).iter().zip(&f.origins).enumerate() {
            let mut checked = *on;
            if ui.checkbox(&mut checked, *name).changed() {
                actions.push(view(ViewAction::Filter(FilterChoice::Origin(i, checked))));
            }
        }
    });
    match tab {
        Tab::Requests => {
            ui.label(Msg::AdminFilterKind.text(lang));
            ui.horizontal(|ui| {
                for (i, name) in REQUEST_KINDS.iter().enumerate() {
                    if ui.radio(f.kind == i, *name).clicked() {
                        actions.push(view(ViewAction::Filter(FilterChoice::Kind(i))));
                    }
                }
            });
        }
        Tab::Approvals => {
            ui.label(Msg::AdminFilterPolicy.text(lang));
            ui.horizontal(|ui| {
                for (i, (name, on)) in policy_names().iter().zip(&f.policies).enumerate() {
                    let mut checked = *on;
                    if ui.checkbox(&mut checked, *name).changed() {
                        actions.push(view(ViewAction::Filter(FilterChoice::Policy(i, checked))));
                    }
                }
            });
            ui.label(Msg::AdminFilterPreset.text(lang));
            ui.horizontal_wrapped(|ui| {
                for (i, name) in PRESETS.iter().enumerate() {
                    if ui.radio(f.preset == i, *name).clicked() {
                        actions.push(view(ViewAction::Filter(FilterChoice::Preset(i))));
                    }
                }
            });
            let mut superseded = f.superseded;
            if ui
                .checkbox(&mut superseded, Msg::AdminFilterSuperseded.text(lang))
                .changed()
            {
                actions.push(view(ViewAction::Filter(FilterChoice::Superseded(
                    superseded,
                ))));
            }
        }
    }
    let mut ascending = f.ascending;
    if ui
        .checkbox(&mut ascending, Msg::AdminFilterOldest.text(lang))
        .changed()
    {
        actions.push(view(ViewAction::Filter(FilterChoice::Ascending(ascending))));
    }
    for (field, value) in &f.fields {
        let label = match (field, tab) {
            (FilterField::Text, _) => Msg::AdminFilterText,
            (FilterField::Path, _) => Msg::AdminFilterPath,
            (FilterField::Product, _) => Msg::AdminFilterProduct,
            (FilterField::Version, _) => Msg::AdminFilterVersion,
            (FilterField::Host, _) => Msg::AdminFilterHost,
            (FilterField::User, _) => Msg::AdminFilterUser,
            (FilterField::Sha, _) => Msg::AdminFilterSha,
            (FilterField::From, Tab::Requests) => Msg::AdminFilterFrom,
            (FilterField::From, Tab::Approvals) => Msg::AdminFilterAfter,
            (FilterField::To, Tab::Requests) => Msg::AdminFilterTo,
            (FilterField::To, Tab::Approvals) => Msg::AdminFilterBefore,
            (FilterField::Lineage, _) => Msg::AdminFilterLineage,
        };
        let mark = if f.invalid.contains(field) {
            " ⚠"
        } else {
            ""
        };
        ui.label(format!("{}{mark}", label.text(lang)));
        if field_box(ui, value, f.focus == Some(*field)).clicked() {
            actions.push(view(ViewAction::FocusFilter(*field)));
        }
    }
    if !f.invalid.is_empty() {
        ui.colored_label(
            ui.visuals().error_fg_color,
            Msg::AdminFilterInvalid.text(lang),
        );
    }
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        if ui
            .add_enabled(free, egui::Button::new(Msg::AdminApplyFilters.text(lang)))
            .clicked()
        {
            actions.push(view(ViewAction::ApplyFilters));
        }
        if ui
            .add_enabled(free, egui::Button::new(Msg::AdminResetFilters.text(lang)))
            .clicked()
        {
            actions.push(view(ViewAction::ResetFilters));
        }
        if ui.button(Msg::AdminCancel.text(lang)).clicked() {
            actions.push(view(ViewAction::CloseFilters));
        }
    });
}

fn list(ui: &mut egui::Ui, lang: Lang, v: &ViewsView, free: bool, actions: &mut Vec<Action>) {
    if !v.loaded {
        ui.weak(Msg::AdminLoading.text(lang));
        return;
    }
    let empty = match v.tab {
        Tab::Requests => v.requests.is_empty(),
        Tab::Approvals => v.approvals.is_empty(),
    };
    if empty {
        ui.weak(Msg::AdminNoRows.text(lang));
    }
    egui::Grid::new(("admin-list", v.tab == Tab::Requests))
        .striped(true)
        .show(ui, |ui| match v.tab {
            Tab::Requests => {
                for (i, r) in v.requests.iter().enumerate() {
                    ui.label(&r.short_id);
                    ui.label(state_name(lang, Tab::Requests, r.state));
                    ui.label(&r.path);
                    ui.label(&r.version);
                    ui.label(&r.host);
                    ui.label(&r.user);
                    ui.label(when(r.submitted_at));
                    ui.label(if r.warnings > 0 {
                        format!("⚠{}", r.warnings)
                    } else {
                        String::new()
                    });
                    if ui
                        .add_enabled(free, egui::Button::new(Msg::AdminOpen.text(lang)).small())
                        .clicked()
                    {
                        actions.push(view(ViewAction::OpenRequest(i)));
                    }
                    ui.end_row();
                }
            }
            Tab::Approvals => {
                for (i, a) in v.approvals.iter().enumerate() {
                    approval_cells(ui, lang, a);
                    if ui
                        .add_enabled(free, egui::Button::new(Msg::AdminOpen.text(lang)).small())
                        .clicked()
                    {
                        actions.push(view(ViewAction::OpenApproval(i)));
                    }
                    ui.end_row();
                }
            }
        });
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                free && v.page > 1,
                egui::Button::new(Msg::AdminPrevPage.text(lang)),
            )
            .clicked()
        {
            actions.push(view(ViewAction::PrevPage));
        }
        ui.label(fill(
            Msg::AdminPage.text(lang),
            &[("n", &v.page.to_string())],
        ));
        if ui
            .add_enabled(
                free && v.has_next,
                egui::Button::new(Msg::AdminNextPage.text(lang)),
            )
            .clicked()
        {
            actions.push(view(ViewAction::NextPage));
        }
    });
}

fn approval_cells(ui: &mut egui::Ui, lang: Lang, a: &ApprovalRow) {
    ui.label(&a.short_id);
    let mut state = state_name(lang, Tab::Approvals, a.state).to_string();
    if a.superseded {
        state = format!("{state} · {}", Msg::AdminSuperseded.text(lang));
    }
    ui.label(state);
    ui.label(format!("{} (r{})", a.path, a.revision));
    ui.label(&a.host);
    ui.label(if a.any_user {
        Msg::AdminScopeAny.text(lang).to_string()
    } else {
        a.user.clone()
    });
    ui.label(POLICIES[usize::from(a.auto_update)]);
    ui.label(expiry(lang, a.expires_at));
}

/// One `label: value` line.
fn field(ui: &mut egui::Ui, lang: Lang, label: Msg, value: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.strong(label.text(lang));
        ui.label(value);
    });
}

#[allow(clippy::too_many_lines)] // one line per field of the record (F21 §3).
fn request(
    ui: &mut egui::Ui,
    lang: Lang,
    v: &ViewsView,
    r: &RequestDetail,
    free: bool,
    actions: &mut Vec<Action>,
) {
    ui.heading(fill(
        Msg::AdminRequestTitle.text(lang),
        &[("id", &r.row.short_id)],
    ));
    field(
        ui,
        lang,
        Msg::AdminFieldState,
        state_name(lang, Tab::Requests, r.row.state),
    );
    field(ui, lang, Msg::AdminFieldPath, &r.row.path);
    field(ui, lang, Msg::AdminFieldSha, &r.sha);
    field(ui, lang, Msg::AdminFieldVersion, &r.row.version);
    if !r.product.is_empty() {
        field(ui, lang, Msg::AdminFieldProduct, &r.product);
    }
    field(ui, lang, Msg::AdminFieldHost, &r.row.host);
    field(ui, lang, Msg::AdminFieldUser, &r.row.user);
    field(ui, lang, Msg::AdminFieldRequester, &r.requester);
    if !r.reason.is_empty() {
        field(ui, lang, Msg::AdminFieldReason, &r.reason);
    }
    let signer = if r.signer.is_empty() {
        Msg::AdminUnsigned.text(lang).to_string()
    } else if r.signer_valid {
        r.signer.clone()
    } else {
        fill(Msg::AdminSignerInvalid.text(lang), &[("signer", &r.signer)])
    };
    field(ui, lang, Msg::AdminFieldSigner, &signer);
    field(
        ui,
        lang,
        Msg::AdminFieldSubmitted,
        &when(r.row.submitted_at),
    );
    if r.row.state == 1 {
        field(
            ui,
            lang,
            Msg::AdminFieldPendingUntil,
            &when(r.pending_expires_at),
        );
    } else {
        field(ui, lang, Msg::AdminFieldDecided, &when(r.decided_at));
    }
    if !r.decision_message.is_empty() {
        field(ui, lang, Msg::AdminFieldMessage, &r.decision_message);
    }
    if !r.warnings.is_empty() {
        ui.colored_label(
            ui.visuals().warn_fg_color,
            format!(
                "{}: ⚠ {}",
                Msg::AdminFieldWarnings.text(lang),
                r.warnings.join(" · ")
            ),
        );
    }
    if r.path_protected {
        ui.label(Msg::AdminPathProtected.text(lang));
    }
    if r.lineage_frozen {
        ui.label(Msg::AdminFrozen.text(lang));
    }
    if r.same_actor {
        ui.label(Msg::AdminSameActor.text(lang));
    }
    ui.add_space(6.0);
    ui.horizontal_wrapped(|ui| {
        let pending = r.row.state == 1;
        if pending
            && v.can_approve
            && ui
                .add_enabled(free, egui::Button::new(Msg::AdminApprove.text(lang)))
                .clicked()
        {
            actions.push(view(ViewAction::Decide(DecisionKind::Approve)));
        }
        if pending
            && v.can_deny
            && ui
                .add_enabled(free, egui::Button::new(Msg::AdminDeny.text(lang)))
                .clicked()
        {
            actions.push(view(ViewAction::Decide(DecisionKind::Deny)));
        }
        if v.can_update
            && ui
                .add_enabled(free, egui::Button::new(Msg::AdminFreeze.text(lang)))
                .clicked()
        {
            actions.push(view(ViewAction::Decide(DecisionKind::Freeze)));
        }
        if ui
            .add_enabled(
                free,
                egui::Button::new(Msg::AdminLineageApprovals.text(lang)),
            )
            .clicked()
        {
            actions.push(view(ViewAction::LineageApprovals));
        }
        if ui
            .add_enabled(free, egui::Button::new(Msg::AdminBack.text(lang)))
            .clicked()
        {
            actions.push(view(ViewAction::Back));
        }
    });
    if !r.lineage.is_empty() {
        ui.add_space(6.0);
        ui.strong(Msg::AdminLineageApprovals.text(lang));
        egui::Grid::new("admin-lineage")
            .striped(true)
            .show(ui, |ui| {
                for (i, a) in r.lineage.iter().enumerate() {
                    approval_cells(ui, lang, a);
                    if ui
                        .add_enabled(free, egui::Button::new(Msg::AdminOpen.text(lang)).small())
                        .clicked()
                    {
                        actions.push(view(ViewAction::OpenLineageApproval(i)));
                    }
                    ui.end_row();
                }
            });
    }
}

#[allow(clippy::too_many_lines)] // one line per field of the record (F21 §3).
fn approval(
    ui: &mut egui::Ui,
    lang: Lang,
    v: &ViewsView,
    a: &ApprovalDetail,
    free: bool,
    actions: &mut Vec<Action>,
) {
    ui.heading(fill(
        Msg::AdminApprovalTitle.text(lang),
        &[("id", &a.row.short_id)],
    ));
    let mut state = state_name(lang, Tab::Approvals, a.row.state).to_string();
    if a.row.superseded {
        state = format!("{state} · {}", Msg::AdminSuperseded.text(lang));
    }
    field(ui, lang, Msg::AdminFieldState, &state);
    field(
        ui,
        lang,
        Msg::AdminFieldPath,
        &format!("{} (r{})", a.row.path, a.row.revision),
    );
    field(ui, lang, Msg::AdminFieldSha, &a.sha);
    if !a.product.is_empty() {
        field(ui, lang, Msg::AdminFieldProduct, &a.product);
    }
    field(ui, lang, Msg::AdminFieldHost, &a.row.host);
    field(ui, lang, Msg::AdminFieldUser, &a.row.user);
    let pick = |on: bool, yes: Msg, no: Msg| if on { yes } else { no }.text(lang);
    field(
        ui,
        lang,
        Msg::AdminFieldPolicy,
        pick(
            a.row.auto_update,
            Msg::AdminPolicyAuto,
            Msg::AdminPolicyManual,
        ),
    );
    field(
        ui,
        lang,
        Msg::AdminFieldContinuity,
        pick(
            a.path_user_continuity,
            Msg::AdminContinuityLoose,
            Msg::AdminContinuityAnchored,
        ),
    );
    field(
        ui,
        lang,
        Msg::AdminFieldScope,
        pick(a.row.any_user, Msg::AdminScopeAny, Msg::AdminScopeUser),
    );
    field(
        ui,
        lang,
        Msg::AdminFieldPathMatch,
        pick(a.any_path, Msg::AdminPathAny, Msg::AdminPathExact),
    );
    field(ui, lang, Msg::AdminFieldCreated, &when(a.created_at));
    field(
        ui,
        lang,
        Msg::AdminFieldExpires,
        &expiry(lang, a.row.expires_at),
    );
    if a.revoked_at > 0 {
        field(ui, lang, Msg::AdminFieldRevoked, &when(a.revoked_at));
    }
    if !a.note.is_empty() {
        field(ui, lang, Msg::AdminFieldNote, &a.note);
    }
    field(
        ui,
        lang,
        Msg::AdminFieldRowVersion,
        &a.row_version.to_string(),
    );
    field(ui, lang, Msg::AdminFieldRevisions, &a.revisions.to_string());
    ui.add_space(6.0);
    ui.horizontal_wrapped(|ui| {
        let live = a.row.state != 3;
        if live
            && v.can_update
            && ui
                .add_enabled(free, egui::Button::new(Msg::AdminEdit.text(lang)))
                .clicked()
        {
            actions.push(view(ViewAction::Decide(DecisionKind::Edit)));
        }
        if live
            && v.can_revoke
            && ui
                .add_enabled(free, egui::Button::new(Msg::AdminRevoke.text(lang)))
                .clicked()
        {
            actions.push(view(ViewAction::Decide(DecisionKind::Revoke)));
        }
        if v.can_update
            && ui
                .add_enabled(free, egui::Button::new(Msg::AdminFreeze.text(lang)))
                .clicked()
        {
            actions.push(view(ViewAction::Decide(DecisionKind::Freeze)));
        }
        if ui
            .add_enabled(free, egui::Button::new(Msg::AdminBack.text(lang)))
            .clicked()
        {
            actions.push(view(ViewAction::Back));
        }
    });
}

fn choose(actions: &mut Vec<Action>, c: Choice) {
    actions.push(view(ViewAction::Choose(c)));
}

/// Two radio buttons for a two-way choice.
fn two_way(
    ui: &mut egui::Ui,
    lang: Lang,
    label: Msg,
    on: bool,
    (no, yes): (Msg, Msg),
    pick: fn(bool) -> Choice,
    actions: &mut Vec<Action>,
) {
    ui.label(label.text(lang));
    ui.horizontal_wrapped(|ui| {
        if ui.radio(!on, no.text(lang)).clicked() {
            choose(actions, pick(false));
        }
        if ui.radio(on, yes.text(lang)).clicked() {
            choose(actions, pick(true));
        }
    });
}

fn change_name(lang: Lang, c: ApprovalChange) -> &'static str {
    match c {
        ApprovalChange::State => Msg::AdminFieldState,
        ApprovalChange::UpdatePolicy => Msg::AdminFieldPolicy,
        ApprovalChange::Continuity => Msg::AdminFieldContinuity,
        ApprovalChange::Expires => Msg::AdminFieldExpires,
        ApprovalChange::UserScope => Msg::AdminFieldScope,
        ApprovalChange::PathMatch => Msg::AdminFieldPathMatch,
        ApprovalChange::Note => Msg::AdminFieldNote,
    }
    .text(lang)
}

#[allow(clippy::too_many_lines)] // one section per decision kind.
fn decision_form(ui: &mut egui::Ui, lang: Lang, d: &DecisionView, actions: &mut Vec<Action>) {
    match d.kind {
        DecisionKind::Approve | DecisionKind::Edit => {
            two_way(
                ui,
                lang,
                Msg::AdminFieldPolicy,
                d.auto_update,
                (Msg::AdminPolicyManual, Msg::AdminPolicyAuto),
                Choice::AutoUpdate,
                actions,
            );
            two_way(
                ui,
                lang,
                Msg::AdminFieldContinuity,
                d.path_user_continuity,
                (Msg::AdminContinuityAnchored, Msg::AdminContinuityLoose),
                Choice::PathUserContinuity,
                actions,
            );
        }
        _ => {}
    }
    match d.kind {
        DecisionKind::Approve => {
            two_way(
                ui,
                lang,
                Msg::AdminFieldScope,
                d.any_user,
                (Msg::AdminScopeUser, Msg::AdminScopeAny),
                Choice::AnyUser,
                actions,
            );
            two_way(
                ui,
                lang,
                Msg::AdminFieldPathMatch,
                d.any_path,
                (Msg::AdminPathExact, Msg::AdminPathAny),
                Choice::AnyPath,
                actions,
            );
            ui.label(Msg::AdminFieldExpires.text(lang));
            ui.horizontal_wrapped(|ui| {
                for (i, days) in EXPIRY_DAYS.iter().enumerate() {
                    let text = if *days == 0 {
                        Msg::AdminExpiryDefault.text(lang).to_string()
                    } else {
                        fill(Msg::AdminExpiryDays.text(lang), &[("n", &days.to_string())])
                    };
                    if ui.radio(d.expiry == i, text).clicked() {
                        choose(actions, Choice::Expiry(i));
                    }
                }
            });
            if !d.also.is_empty() {
                ui.label(Msg::AdminAlsoRevoke.text(lang));
                for (i, row) in d.also.iter().enumerate() {
                    let mut on = row.checked;
                    let mut text = format!("r{} {}", row.revision, row.short_id);
                    if row.superseded {
                        text = format!("{text} ({})", Msg::AdminSuperseded.text(lang));
                    }
                    if ui.checkbox(&mut on, text).changed() {
                        choose(actions, Choice::AlsoRevoke(i, on));
                    }
                }
                reasons(
                    ui,
                    lang,
                    Msg::AdminRevokeReason,
                    &REVOKE_REASONS,
                    d.revoke_reason,
                    Choice::RevokeReason,
                    actions,
                );
            }
        }
        DecisionKind::Edit => {
            ui.label(fill(
                "{label} ({now})",
                &[
                    ("label", Msg::AdminFieldExpires.text(lang)),
                    ("now", &expiry(lang, d.current_expires_at)),
                ],
            ));
            ui.horizontal_wrapped(|ui| {
                let mut options = vec![Msg::AdminExpiryKeep.text(lang).to_string()];
                options.extend(
                    EDIT_EXPIRY_DAYS.iter().map(|n| {
                        fill(Msg::AdminExpiryFromNow.text(lang), &[("n", &n.to_string())])
                    }),
                );
                options.push(Msg::AdminExpiryNone.text(lang).to_string());
                for (i, text) in options.into_iter().enumerate() {
                    if ui.radio(d.edit_expiry == i, text).clicked() {
                        choose(actions, Choice::EditExpiry(i));
                    }
                }
            });
            if d.narrow_user_offered {
                let mut on = d.narrow_user;
                if ui
                    .checkbox(&mut on, Msg::AdminNarrowUser.text(lang))
                    .changed()
                {
                    choose(actions, Choice::NarrowUser(on));
                }
            }
            if d.narrow_path_offered {
                let mut on = d.narrow_path;
                if ui
                    .checkbox(&mut on, Msg::AdminNarrowPath.text(lang))
                    .changed()
                {
                    choose(actions, Choice::NarrowPath(on));
                }
            }
        }
        DecisionKind::Deny => {
            reasons(
                ui,
                lang,
                Msg::AdminDenyReason,
                &DENY_REASONS,
                d.deny_reason,
                Choice::DenyReason,
                actions,
            );
            ui.label(Msg::AdminDenyMessage.text(lang));
            text_field(ui, &d.message, d, DecisionField::Message, actions);
        }
        DecisionKind::Revoke => {
            reasons(
                ui,
                lang,
                Msg::AdminRevokeReason,
                &REVOKE_REASONS,
                d.revoke_reason,
                Choice::RevokeReason,
                actions,
            );
            ui.label(fill(
                Msg::AdminTypeShortId.text(lang),
                &[("id", &d.short_id)],
            ));
            text_field(ui, &d.confirm, d, DecisionField::Confirm, actions);
        }
        DecisionKind::Freeze => {
            ui.horizontal_wrapped(|ui| {
                if ui.radio(d.frozen, Msg::AdminFreezeOn.text(lang)).clicked() {
                    choose(actions, Choice::Frozen(true));
                }
                if ui
                    .radio(!d.frozen, Msg::AdminFreezeOff.text(lang))
                    .clicked()
                {
                    choose(actions, Choice::Frozen(false));
                }
            });
        }
    }
    if matches!(d.kind, DecisionKind::Approve | DecisionKind::Edit) {
        ui.label(Msg::AdminNoteLabel.text(lang));
        text_field(ui, &d.note, d, DecisionField::Note, actions);
    }
}

fn reasons(
    ui: &mut egui::Ui,
    lang: Lang,
    label: Msg,
    names: &[&str],
    chosen: usize,
    pick: fn(usize) -> Choice,
    actions: &mut Vec<Action>,
) {
    ui.label(label.text(lang));
    ui.horizontal_wrapped(|ui| {
        for (i, name) in names.iter().enumerate() {
            if ui.radio(chosen == i, *name).clicked() {
                choose(actions, pick(i));
            }
        }
    });
}

fn text_field(
    ui: &mut egui::Ui,
    text: &str,
    d: &DecisionView,
    field: DecisionField,
    actions: &mut Vec<Action>,
) {
    if field_box(ui, text, d.focus == Some(field)).clicked() {
        actions.push(view(ViewAction::FocusDecision(field)));
    }
}

fn decision_title(lang: Lang, d: &DecisionView) -> String {
    let msg = match d.kind {
        DecisionKind::Approve => Msg::AdminDecideApprove,
        DecisionKind::Deny => Msg::AdminDecideDeny,
        DecisionKind::Edit => Msg::AdminDecideEdit,
        DecisionKind::Revoke => Msg::AdminDecideRevoke,
        DecisionKind::Freeze => Msg::AdminDecideFreeze,
    };
    fill(msg.text(lang), &[("id", &d.short_id)])
}

#[allow(clippy::too_many_lines)] // one arm per review line.
fn review_line(lang: Lang, line: &ReviewLine) -> String {
    let kv = |label: Msg, value: &str| format!("{}: {value}", label.text(lang));
    let pick = |on: bool, yes: Msg, no: Msg| if on { yes } else { no }.text(lang);
    let none = Msg::AdminReviewNone.text(lang);
    let change = |field: Msg, from: &str, to: &str| {
        fill(
            Msg::AdminReviewChange.text(lang),
            &[("field", field.text(lang)), ("from", from), ("to", to)],
        )
    };
    match line {
        ReviewLine::Path(p) => kv(Msg::AdminFieldPath, p),
        ReviewLine::Sha(s) => kv(Msg::AdminFieldSha, s),
        ReviewLine::User(u) => kv(Msg::AdminFieldUser, u),
        ReviewLine::Policy(on) => kv(
            Msg::AdminFieldPolicy,
            pick(*on, Msg::AdminPolicyAuto, Msg::AdminPolicyManual),
        ),
        ReviewLine::Continuity(on) => kv(
            Msg::AdminFieldContinuity,
            pick(*on, Msg::AdminContinuityLoose, Msg::AdminContinuityAnchored),
        ),
        ReviewLine::Scope(on) => kv(
            Msg::AdminFieldScope,
            pick(*on, Msg::AdminScopeAny, Msg::AdminScopeUser),
        ),
        ReviewLine::PathMatch(on) => kv(
            Msg::AdminFieldPathMatch,
            pick(*on, Msg::AdminPathAny, Msg::AdminPathExact),
        ),
        ReviewLine::Expires(0) => kv(Msg::AdminFieldExpires, Msg::AdminExpiryDefault.text(lang)),
        ReviewLine::Expires(t) => kv(Msg::AdminFieldExpires, &when(*t)),
        ReviewLine::Note(n) | ReviewLine::Message(n) => {
            let label = if matches!(line, ReviewLine::Note(_)) {
                Msg::AdminFieldNote
            } else {
                Msg::AdminFieldMessage
            };
            kv(label, if n.is_empty() { none } else { n })
        }
        ReviewLine::AlsoRevoke(ids, reason) => fill(
            Msg::AdminReviewAlso.text(lang),
            &[("ids", &ids.join(", ")), ("reason", reason)],
        ),
        ReviewLine::Warnings(w) => fill(
            Msg::AdminReviewWarnings.text(lang),
            &[("list", &format!("⚠ {}", w.join(" · ")))],
        ),
        ReviewLine::DenyReason(r) => kv(Msg::AdminDenyReason, r),
        ReviewLine::RowVersion(n) => kv(Msg::AdminFieldRowVersion, &n.to_string()),
        ReviewLine::EditPolicy(from, to) => change(
            Msg::AdminFieldPolicy,
            pick(*from, Msg::AdminPolicyAuto, Msg::AdminPolicyManual),
            pick(*to, Msg::AdminPolicyAuto, Msg::AdminPolicyManual),
        ),
        ReviewLine::EditContinuity(from, to) => change(
            Msg::AdminFieldContinuity,
            pick(
                *from,
                Msg::AdminContinuityLoose,
                Msg::AdminContinuityAnchored,
            ),
            pick(*to, Msg::AdminContinuityLoose, Msg::AdminContinuityAnchored),
        ),
        ReviewLine::EditExpires(from, to) => change(
            Msg::AdminFieldExpires,
            &expiry(lang, *from),
            &to.map_or_else(|| Msg::AdminNoExpiry.text(lang).to_string(), when),
        ),
        ReviewLine::EditNote(n) => kv(
            Msg::AdminFieldNote,
            n.as_deref().unwrap_or(Msg::AdminReviewRemoved.text(lang)),
        ),
        ReviewLine::NarrowUser => Msg::AdminReviewNarrowUser.text(lang).to_string(),
        ReviewLine::NarrowPath => Msg::AdminReviewNarrowPath.text(lang).to_string(),
        ReviewLine::RevokeReason(r) => kv(Msg::AdminRevokeReason, r),
        ReviewLine::Lineage(l) => kv(Msg::AdminFieldLineage, l),
        ReviewLine::Freeze(true) => Msg::AdminReviewFreeze.text(lang).to_string(),
        ReviewLine::Freeze(false) => Msg::AdminReviewUnfreeze.text(lang).to_string(),
    }
}

#[allow(clippy::too_many_lines)] // one section per stage of the dialog.
fn decision(
    ui: &mut egui::Ui,
    lang: Lang,
    d: &DecisionView,
    free: bool,
    actions: &mut Vec<Action>,
) {
    ui.group(|ui| {
        ui.heading(decision_title(lang, d));
        if !d.path.is_empty() {
            let mut line = d.path.clone();
            for part in [&d.version, &d.host, &d.user] {
                if !part.is_empty() {
                    line = format!("{line} · {part}");
                }
            }
            ui.label(line);
        }
        if !d.warnings.is_empty() {
            ui.colored_label(
                ui.visuals().warn_fg_color,
                format!("⚠ {}", d.warnings.join(" · ")),
            );
        }
        if let Some(changes) = &d.changed_meanwhile {
            let names: Vec<&str> = changes.iter().map(|c| change_name(lang, *c)).collect();
            ui.colored_label(
                ui.visuals().warn_fg_color,
                fill(
                    Msg::AdminChangedMeanwhile.text(lang),
                    &[("fields", &names.join(", "))],
                ),
            );
        }
        ui.add_space(4.0);
        match d.stage {
            DecisionStage::Form => {
                decision_form(ui, lang, d, actions);
                if let Some(e) = d.error {
                    let msg = match e {
                        DecisionError::AnyUserNeedsProtectedPath => Msg::AdminErrAnyUser,
                        DecisionError::NothingToChange => Msg::AdminErrNothing,
                        DecisionError::ShortIdMismatch => Msg::AdminErrShortId,
                    };
                    ui.colored_label(ui.visuals().error_fg_color, msg.text(lang));
                }
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            free,
                            egui::Button::new(Msg::AdminDecisionContinue.text(lang)),
                        )
                        .clicked()
                    {
                        actions.push(view(ViewAction::DecisionNext));
                    }
                    if ui.button(Msg::AdminCancel.text(lang)).clicked() {
                        actions.push(view(ViewAction::CancelDecision));
                    }
                });
            }
            DecisionStage::WideConfirm => {
                if d.any_user && d.kind == DecisionKind::Approve {
                    ui.colored_label(ui.visuals().warn_fg_color, Msg::AdminWideAnyUser.text(lang));
                }
                if d.path_user_continuity {
                    ui.colored_label(ui.visuals().warn_fg_color, Msg::AdminWideLoose.text(lang));
                }
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(free, egui::Button::new(Msg::AdminAcceptWide.text(lang)))
                        .clicked()
                    {
                        actions.push(view(ViewAction::DecisionNext));
                    }
                    if ui.button(Msg::AdminBack.text(lang)).clicked() {
                        actions.push(view(ViewAction::DecisionBack));
                    }
                    if ui.button(Msg::AdminCancel.text(lang)).clicked() {
                        actions.push(view(ViewAction::CancelDecision));
                    }
                });
            }
            DecisionStage::Review => {
                ui.strong(Msg::AdminReviewTitle.text(lang));
                for line in &d.review {
                    ui.label(review_line(lang, line));
                }
                ui.weak(Msg::AdminReviewSync.text(lang));
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            free,
                            egui::Button::new(Msg::AdminDecisionConfirm.text(lang)),
                        )
                        .clicked()
                    {
                        actions.push(view(ViewAction::DecisionConfirm));
                    }
                    if ui.button(Msg::AdminBack.text(lang)).clicked() {
                        actions.push(view(ViewAction::DecisionBack));
                    }
                    if ui.button(Msg::AdminCancel.text(lang)).clicked() {
                        actions.push(view(ViewAction::CancelDecision));
                    }
                });
            }
        }
    });
}
