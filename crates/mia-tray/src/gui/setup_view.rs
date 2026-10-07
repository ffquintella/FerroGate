//! The Setup tab: the graphical front end of `mia setup --dump / --check /
//! --apply`.
//!
//! Flow: load (`--dump --editable`; the system file through the OS consent
//! prompt where elevated output can be captured) → edit with local validation
//! → "Check with mia" (`--check` on a private `0600` draft) → "Apply" (enabled
//! only for exactly the draft `mia` accepted; `--apply --user` directly, or
//! the system file through the OS consent prompt) → reload the configuration
//! to show the change. The tray never writes the configuration itself.

use std::collections::BTreeMap;
use std::sync::Arc;

use eframe::egui::{self, RichText};

use super::job::{take, Job};
use super::status_view::color32;
use super::Shared;
use crate::actions::{
    self, apply_invocation, check_invocation, dump_invocation, ApplyOptions,
    EnrollmentKeyFingerprint, EnvName, Outcome, Scope,
};
use crate::client::Observation;
use crate::i18n::{fill, Lang, Msg};
use crate::model::{IconColor, WizardStep};
use crate::process::run_bounded;
use crate::wizard::{
    combine, draft_base_dir, parse_apply, parse_check, parse_dump,
    render_with_enrollment_public_key, validate_enrollment_public_key, validate_for_apply,
    write_draft, ApplyReport, CheckReport, Field, LoadError, Loaded, Step, Values, BACKEND_CHOICES,
    MAX_ANSWER_LEN, MAX_ENROLLMENT_PUBLIC_KEY_LEN,
};

/// What an apply produced.
struct ApplyDone {
    outcome: Result<Outcome, Msg>,
    report: Option<ApplyReport>,
    problems: Vec<(String, String)>,
    details: String,
}

#[derive(Default)]
#[allow(clippy::struct_excessive_bools)] // independent form switches
pub(crate) struct SetupView {
    scope: Scope,
    env_text: String,
    requested: bool,
    load_job: Option<Job<Result<Loaded, LoadError>>>,
    loaded: Option<Loaded>,
    load_error: Option<LoadError>,
    editable: bool,
    values: Values,
    focus: Option<WizardStep>,
    focus_pending: bool,
    check_job: Option<Job<Result<(String, CheckReport), Msg>>>,
    checked: Option<(String, CheckReport)>,
    check_error: Option<Msg>,
    apply_job: Option<Job<ApplyDone>>,
    applied: Option<ApplyDone>,
    reload: bool,
    fetch_key: bool,
    enrollment_public_key: String,
    expected_key_fingerprint: String,
    /// The file the editable values belong to — (scope, environment) as
    /// loaded. Check / Apply are disabled while the selector differs, and
    /// Apply always writes this target, never the current selection.
    target: Option<(Scope, Option<EnvName>)>,
    /// The target of the load in flight (or of the last failed load).
    pending_target: Option<(Scope, Option<EnvName>)>,
}

/// Load the editable configuration: `mia setup --dump --json --editable`,
/// with administrator consent for the protected system file on Linux/macOS.
/// If variables override anything, run again without them so the draft keeps
/// the file's own values.
fn load(shared: &Shared, scope: Scope, env: Option<&EnvName>) -> Result<Loaded, LoadError> {
    let failed = |detail: &str| LoadError::DumpFailed {
        detail: detail.to_string(),
    };
    let os = shared.os.ok_or_else(|| failed("unsupported platform"))?;
    let inv = dump_invocation(scope, env, os);
    let spec = actions::spec(&inv, os, &shared.tools).map_err(|e| failed(&e.to_string()))?;
    let out = run_bounded(spec.command(), inv.limits).map_err(|e| failed(&e.to_string()))?;
    let effective = parse_dump(&out)?;
    let file_only = if effective.override_vars.is_empty() {
        None
    } else {
        let mut cmd = spec.command();
        for var in &effective.override_vars {
            cmd.env_remove(var);
        }
        let out = run_bounded(cmd, inv.limits).map_err(|e| failed(&e.to_string()))?;
        Some(parse_dump(&out)?)
    };
    Ok(combine(effective, file_only))
}

impl SetupView {
    /// Open the wizard at a step.
    pub(crate) fn focus(&mut self, step: Option<WizardStep>) {
        self.focus = step;
        self.focus_pending = step.is_some();
    }

    /// Load once (on first open).
    pub(crate) fn ensure_loaded(&mut self, ctx: &egui::Context, shared: &Shared) {
        if !self.requested {
            self.start_load(ctx, shared);
        }
    }

    fn environment(&self) -> Result<Option<EnvName>, Msg> {
        let t = self.env_text.trim();
        if t.is_empty() {
            Ok(None)
        } else {
            EnvName::parse(t).map(Some).map_err(|e| e.message())
        }
    }

    fn start_load(&mut self, ctx: &egui::Context, shared: &Shared) {
        let Ok(env) = self.environment() else {
            return;
        };
        self.requested = true;
        self.load_error = None;
        self.checked = None;
        self.pending_target = Some((self.scope, env.clone()));
        let shared = shared.clone();
        let scope = self.scope;
        self.load_job = Some(Job::spawn(Some(ctx.clone()), move || {
            load(&shared, scope, env.as_ref())
        }));
    }

    /// Collect finished jobs; `true` after a successful apply.
    pub(crate) fn poll(&mut self, ctx: &egui::Context, shared: &Shared) -> bool {
        if let Some(result) = take(&mut self.load_job) {
            match result {
                Ok(loaded) => {
                    self.values = loaded.values.clone();
                    self.loaded = Some(loaded);
                    self.editable = true;
                    self.target = self.pending_target.take();
                }
                Err(e) => {
                    tracing::warn!(error = %e, "could not load the configuration");
                    self.load_error = Some(e);
                    self.loaded = None;
                    self.editable = false;
                }
            }
        }
        if let Some(result) = take(&mut self.check_job) {
            match result {
                Ok(c) => {
                    self.checked = Some(c);
                    self.check_error = None;
                }
                Err(m) => {
                    self.checked = None;
                    self.check_error = Some(m);
                }
            }
        }
        if let Some(done) = take(&mut self.apply_job) {
            let ok = matches!(done.outcome, Ok(Outcome::Succeeded));
            self.applied = Some(done);
            if ok {
                // Reload: the wizard now shows what was written.
                self.start_load(ctx, shared);
                return true;
            }
        }
        false
    }

    fn start_check(&mut self, ctx: &egui::Context, shared: &Shared) {
        let text =
            render_with_enrollment_public_key(&self.values, Some(&self.enrollment_public_key));
        let os = shared.os;
        let tools = Arc::clone(&shared.tools);
        self.check_error = None;
        self.check_job = Some(Job::spawn(Some(ctx.clone()), move || {
            let os = os.ok_or(Msg::ErrorUnsupported)?;
            let draft = write_draft(&draft_base_dir(), &text).map_err(|e| {
                tracing::warn!(error = %e, "could not stage the draft");
                Msg::ErrorStartFailed
            })?;
            let inv = check_invocation(draft.path()).map_err(|e| e.message())?;
            let r = actions::run(&inv, os, &tools).map_err(|e| e.message())?;
            let report = parse_check(&r.captured).map_err(|_| Msg::ErrorUnexpectedOutput)?;
            drop(draft);
            Ok((text, report))
        }));
    }

    fn start_apply(&mut self, ctx: &egui::Context, shared: &Shared) {
        // The file the values were loaded from — not whatever the selector
        // shows now.
        let Some((scope, env)) = self.target.clone() else {
            return;
        };
        let install_enrollment_key =
            self.fetch_key || !self.enrollment_public_key.trim().is_empty();
        let expected_enrollment_key_fingerprint = if install_enrollment_key {
            let text = self.expected_key_fingerprint.trim();
            if text.is_empty() {
                None
            } else {
                let Ok(fingerprint) = EnrollmentKeyFingerprint::parse(text) else {
                    return;
                };
                Some(fingerprint)
            }
        } else {
            None
        };
        let text =
            render_with_enrollment_public_key(&self.values, Some(&self.enrollment_public_key));
        let opts = ApplyOptions {
            scope,
            environment: env,
            reload: self.reload && scope == Scope::System,
            fetch_enrollment_key: self.fetch_key,
            expected_enrollment_key_fingerprint,
        };
        let os = shared.os;
        let tools = Arc::clone(&shared.tools);
        self.applied = None;
        self.apply_job = Some(Job::spawn(Some(ctx.clone()), move || {
            let fail = |m: Msg| ApplyDone {
                outcome: Err(m),
                report: None,
                problems: Vec::new(),
                details: String::new(),
            };
            let Some(os) = os else {
                return fail(Msg::ErrorUnsupported);
            };
            let draft = match write_draft(&draft_base_dir(), &text) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(error = %e, "could not stage the draft");
                    return fail(Msg::ErrorStartFailed);
                }
            };
            let result = apply_invocation(draft.path(), &opts)
                .and_then(|inv| actions::run(&inv, os, &tools));
            // Removes the private directory — including the draft an
            // elevated `mia` deliberately leaves to its owner.
            drop(draft);
            match result {
                Err(e) => fail(e.message()),
                Ok(r) => ApplyDone {
                    outcome: Ok(r.outcome),
                    report: parse_apply(&r.captured.stdout),
                    problems: if r.outcome == Outcome::Succeeded {
                        Vec::new()
                    } else {
                        parse_check(&r.captured)
                            .map(|c| c.errors)
                            .unwrap_or_default()
                    },
                    details: crate::text::output_text(&r.captured.stderr),
                },
            }
        }));
    }

    #[allow(clippy::too_many_lines)] // one linear form; splitting obscures it
    pub(crate) fn ui(&mut self, ui: &mut egui::Ui, shared: &Shared, _obs: Option<&Observation>) {
        let lang = shared.lang;
        let ctx = ui.ctx().clone();
        let red = color32(IconColor::Red);

        ui.horizontal_wrapped(|ui| {
            ui.label(Msg::SetupTarget.text(lang));
            ui.radio_value(&mut self.scope, Scope::System, Msg::ScopeSystem.text(lang));
            ui.radio_value(&mut self.scope, Scope::User, Msg::ScopeUser.text(lang));
        });
        let env = self.environment();
        ui.horizontal(|ui| {
            ui.label(Msg::LabelEnvironment.text(lang));
            ui.add(
                egui::TextEdit::singleline(&mut self.env_text)
                    .char_limit(mia_status_proto::MAX_ENVIRONMENT_LEN)
                    .hint_text(Msg::DefaultEnvironment.text(lang))
                    .desired_width(160.0),
            );
            let busy = self.load_job.is_some();
            if ui
                .add_enabled(
                    !busy && env.is_ok(),
                    egui::Button::new(Msg::SetupLoad.text(lang)),
                )
                .clicked()
            {
                self.start_load(&ctx, shared);
            }
            if busy {
                ui.spinner();
                ui.label(Msg::SetupLoading.text(lang));
            }
        });
        if let Err(m) = &env {
            ui.colored_label(red, m.text(lang));
        }
        if let Some(err) = &self.load_error {
            if !self.editable {
                ui.colored_label(red, Msg::SetupLoadFailed.text(lang));
                if let LoadError::DumpFailed { detail } = err {
                    if !detail.is_empty() {
                        egui::CollapsingHeader::new(Msg::LabelOutput.text(lang))
                            .id_salt("load-detail")
                            .show(ui, |ui| ui.label(RichText::new(detail).monospace()));
                    }
                }
                if ui.button(Msg::SetupStartFromDefaults.text(lang)).clicked() {
                    self.values = Values::default();
                    self.editable = true;
                    self.target = self.pending_target.take();
                }
            }
        }
        if let Some(l) = &self.loaded {
            let path = crate::text::display_safe(&l.path, 512);
            let mut line = fill(Msg::SetupFile.text(lang), &[("path", &path)]);
            if !l.exists {
                line.push(' ');
                line.push_str(Msg::SetupFileAbsent.text(lang));
            }
            ui.label(RichText::new(line).weak());
        }
        if !self.editable {
            return;
        }
        ui.separator();

        let install_enrollment_key =
            self.fetch_key || !self.enrollment_public_key.trim().is_empty();
        let field_errors = validate_for_apply(&self.values, install_enrollment_key);
        let overridden: BTreeMap<Field, String> = self
            .loaded
            .as_ref()
            .map(|l| l.overridden.clone())
            .unwrap_or_default();
        let effective = self
            .loaded
            .as_ref()
            .map(|l| l.effective.clone())
            .unwrap_or_default();
        egui::ScrollArea::vertical()
            .max_height(ui.available_height() - 140.0)
            .show(ui, |ui| {
                for step in Step::ALL {
                    let focused = matches!(
                        (self.focus, step),
                        (Some(WizardStep::Pins | WizardStep::Cmis), Step::Cmis)
                            | (Some(WizardStep::Attestation), Step::Attestation)
                    );
                    egui::CollapsingHeader::new(RichText::new(step.title().text(lang)).strong())
                        .id_salt(("step", step.title()))
                        .default_open(self.focus.is_none() || focused)
                        .show(ui, |ui| {
                            for f in Field::ALL
                                .into_iter()
                                .filter(|f| f.step() == step && f.applies_here())
                            {
                                self.field_ui(ui, lang, f, &overridden, &effective, &field_errors);
                            }
                        });
                }
            });

        ui.separator();
        ui.horizontal_wrapped(|ui| {
            ui.add_enabled(
                self.scope == Scope::System,
                egui::Checkbox::new(&mut self.reload, Msg::SetupReload.text(lang)),
            );
        });
        // Field edits and the fetch checkbox happen inside the scroll area, so
        // recompute before enabling Check / Apply in this same frame.
        let install_enrollment_key =
            self.fetch_key || !self.enrollment_public_key.trim().is_empty();
        let errors = validate_for_apply(&self.values, install_enrollment_key);
        let public_key_error = validate_enrollment_public_key(&self.enrollment_public_key).is_err()
            || (!self.enrollment_public_key.trim().is_empty() && self.scope != Scope::System);
        let fingerprint_error = install_enrollment_key
            && !self.expected_key_fingerprint.trim().is_empty()
            && EnrollmentKeyFingerprint::parse(&self.expected_key_fingerprint).is_err();
        let selected = env.clone().ok().map(|e| (self.scope, e));
        let on_target = selected.is_some() && selected == self.target;
        if !on_target {
            ui.colored_label(
                color32(IconColor::Yellow),
                Msg::SetupTargetChanged.text(lang),
            );
        }
        let rendered =
            render_with_enrollment_public_key(&self.values, Some(&self.enrollment_public_key));
        let checked_ok = self
            .checked
            .as_ref()
            .is_some_and(|(text, r)| r.ok && *text == rendered);
        ui.horizontal(|ui| {
            let can_check = errors.is_empty()
                && !public_key_error
                && !fingerprint_error
                && self.check_job.is_none()
                && on_target;
            if ui
                .add_enabled(can_check, egui::Button::new(Msg::SetupCheck.text(lang)))
                .clicked()
            {
                self.start_check(&ctx, shared);
            }
            if self.check_job.is_some() {
                ui.spinner();
            }
            let can_apply = errors.is_empty()
                && !fingerprint_error
                && !public_key_error
                && checked_ok
                && self.apply_job.is_none()
                && on_target;
            let mut apply =
                ui.add_enabled(can_apply, egui::Button::new(Msg::SetupApply.text(lang)));
            if self.scope == Scope::System {
                apply = apply.on_hover_text(Msg::NoteElevation.text(lang));
            }
            if apply.clicked() {
                self.start_apply(&ctx, shared);
            }
            if self.apply_job.is_some() {
                ui.spinner();
            }
        });
        if !errors.is_empty() || fingerprint_error || public_key_error {
            ui.colored_label(red, Msg::SetupFixErrors.text(lang));
        } else if !checked_ok && self.apply_job.is_none() && self.applied.is_none() {
            ui.label(RichText::new(Msg::SetupNeedsCheck.text(lang)).weak());
        }
        if let Some(m) = self.check_error {
            ui.colored_label(red, m.text(lang));
        }
        if let Some((text, report)) = &self.checked {
            if *text == rendered {
                if report.ok {
                    ui.colored_label(color32(IconColor::Green), Msg::SetupCheckOk.text(lang));
                } else {
                    ui.colored_label(red, Msg::SetupCheckRejected.text(lang));
                    for (key, message) in &report.errors {
                        ui.label(RichText::new(format!("  {key}: {message}")).monospace());
                    }
                }
            }
        }
        if let Some(done) = &self.applied {
            apply_result_ui(ui, lang, done);
        }
    }

    fn field_ui(
        &mut self,
        ui: &mut egui::Ui,
        lang: Lang,
        f: Field,
        overridden: &BTreeMap<Field, String>,
        effective: &Values,
        errors: &[(Field, Msg)],
    ) {
        let (label, help) = f.texts();
        let read_only = overridden.get(&f);
        ui.add_space(4.0);
        if f.is_bool() {
            let mut on = if read_only.is_some() {
                effective.flag(f)
            } else {
                self.values.flag(f)
            };
            let resp = ui.add_enabled(
                read_only.is_none(),
                egui::Checkbox::new(&mut on, label.text(lang)),
            );
            if resp.changed() {
                self.values.set(f, on.to_string());
            }
        } else {
            ui.label(RichText::new(label.text(lang)).strong());
            if read_only.is_some() {
                let mut shown = effective.get(f).to_string();
                ui.add_enabled(
                    false,
                    egui::TextEdit::singleline(&mut shown).desired_width(f32::INFINITY),
                );
            } else if f == Field::AttestationBackend {
                let current = self.values.get(f).to_string();
                let selected = if current.is_empty() {
                    "auto".to_string()
                } else {
                    current
                };
                egui::ComboBox::from_id_salt("backend")
                    .selected_text(selected.clone())
                    .show_ui(ui, |ui| {
                        for choice in BACKEND_CHOICES {
                            if ui.selectable_label(selected == choice, choice).clicked() {
                                self.values.set(f, choice);
                            }
                        }
                    });
            } else {
                let value = self.values.0.entry(f).or_default();
                let resp = ui.add(
                    egui::TextEdit::singleline(value)
                        .char_limit(MAX_ANSWER_LEN)
                        .desired_width(f32::INFINITY),
                );
                if self.focus_pending
                    && f == Field::CmisSpkiPin
                    && self.focus == Some(WizardStep::Pins)
                {
                    resp.request_focus();
                    resp.scroll_to_me(Some(egui::Align::Center));
                    self.focus_pending = false;
                }
            }
        }
        if let Some(var) = read_only {
            ui.label(RichText::new(fill(Msg::SetupReadOnly.text(lang), &[("var", var)])).weak());
        }
        ui.label(RichText::new(help.text(lang)).small().weak());
        if f == Field::AllowlistKey {
            let response = ui.checkbox(&mut self.fetch_key, Msg::SetupFetchKey.text(lang));
            if response.changed() && self.fetch_key && read_only.is_none() {
                self.enrollment_public_key.clear();
                if let Some(path) = self.loaded.as_ref().map(|loaded| loaded.path.as_str()) {
                    self.values
                        .ensure_allowlist_key_destination(std::path::Path::new(path));
                }
            }
            ui.label(RichText::new(Msg::FieldEnrollmentPublicKey.text(lang)).strong());
            let can_paste = self.scope == Scope::System && !self.fetch_key;
            let response = ui.add_enabled(
                can_paste,
                egui::TextEdit::multiline(&mut self.enrollment_public_key)
                    .char_limit(MAX_ENROLLMENT_PUBLIC_KEY_LEN)
                    .desired_rows(3)
                    .desired_width(f32::INFINITY),
            );
            if response.changed() && !self.enrollment_public_key.trim().is_empty() {
                if let Some(path) = self.loaded.as_ref().map(|loaded| loaded.path.as_str()) {
                    self.values
                        .ensure_allowlist_key_destination(std::path::Path::new(path));
                }
            }
            ui.label(
                RichText::new(Msg::HelpEnrollmentPublicKey.text(lang))
                    .small()
                    .weak(),
            );
            if self.scope != Scope::System && !self.enrollment_public_key.trim().is_empty() {
                ui.colored_label(
                    color32(IconColor::Red),
                    Msg::EnrollmentPublicKeySystemOnly.text(lang),
                );
            } else if validate_enrollment_public_key(&self.enrollment_public_key).is_err() {
                ui.colored_label(
                    color32(IconColor::Red),
                    Msg::ValEnrollmentPublicKey.text(lang),
                );
            }
            if self.fetch_key || !self.enrollment_public_key.trim().is_empty() {
                ui.label(RichText::new(Msg::FieldEnrollmentKeyFingerprint.text(lang)).strong());
                ui.add(
                    egui::TextEdit::singleline(&mut self.expected_key_fingerprint)
                        .char_limit(MAX_ANSWER_LEN)
                        .desired_width(f32::INFINITY),
                );
                ui.label(
                    RichText::new(Msg::HelpEnrollmentKeyFingerprint.text(lang))
                        .small()
                        .weak(),
                );
                if !self.expected_key_fingerprint.trim().is_empty()
                    && EnrollmentKeyFingerprint::parse(&self.expected_key_fingerprint).is_err()
                {
                    ui.colored_label(
                        color32(IconColor::Red),
                        Msg::ValEnrollmentKeyFingerprint.text(lang),
                    );
                }
            }
        }
        for (_, m) in errors.iter().filter(|(ef, _)| *ef == f) {
            ui.colored_label(color32(IconColor::Red), m.text(lang));
        }
    }
}

fn apply_result_ui(ui: &mut egui::Ui, lang: Lang, done: &ApplyDone) {
    match done.outcome {
        Err(m) => {
            ui.colored_label(color32(IconColor::Red), m.text(lang));
        }
        Ok(Outcome::Succeeded) => {
            ui.colored_label(color32(IconColor::Green), Msg::SetupApplied.text(lang));
            if let Some(r) = &done.report {
                if !r.changed_keys.is_empty() {
                    ui.label(RichText::new(r.changed_keys.join(", ")).monospace());
                }
                if let Some(e) = &r.error {
                    ui.colored_label(color32(IconColor::Yellow), e);
                }
            }
        }
        Ok(outcome) => {
            let color = if outcome == Outcome::Cancelled {
                IconColor::Grey
            } else {
                IconColor::Red
            };
            ui.colored_label(
                color32(color),
                format!(
                    "{}: {}",
                    Msg::ActionApplySetup.text(lang),
                    outcome.label().text(lang)
                ),
            );
            for (key, message) in &done.problems {
                ui.label(RichText::new(format!("  {key}: {message}")).monospace());
            }
            if !done.details.is_empty() {
                egui::CollapsingHeader::new(Msg::LabelOutput.text(lang))
                    .id_salt("apply-detail")
                    .show(ui, |ui| ui.label(RichText::new(&done.details).monospace()));
            }
        }
    }
}
