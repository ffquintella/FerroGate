//! The Recovery tab: the closed set of actions, run in the background with
//! their results shown inline, plus "copy machine identifiers" and the
//! documentation links.

use std::collections::HashMap;
use std::sync::Arc;

use eframe::egui::{self, Color32, RichText};

use super::job::{take, Job};
use super::status_view::{color32, recovery_button};
use super::window::{open_doc, Intent};
use super::Shared;
use crate::actions::{
    self, invocation, Action, ActionError, ActionResult, Doc, EnvName, Os, Outcome, Privilege,
};
use crate::client::Observation;
use crate::i18n::{Lang, Msg};
use crate::model::{tray_view, IconColor};
use crate::selftest::SelfTest;
use crate::text::output_text;

type RunResult = Result<ActionResult, ActionError>;

/// A finished action, kept for display.
struct Finished {
    result: RunResult,
    self_test: Option<SelfTest>,
}

#[derive(Default)]
pub(crate) struct RecoveryView {
    env: Option<EnvName>,
    jobs: HashMap<Action, Job<RunResult>>,
    results: HashMap<Action, Finished>,
    copy_job: Option<Job<RunResult>>,
    copy_notice: Option<Msg>,
    last_self_test: Option<SelfTest>,
}

impl RecoveryView {
    /// Start `action` for `env` (ignored while it is already running).
    pub(crate) fn run(
        &mut self,
        ctx: &egui::Context,
        shared: &Shared,
        action: Action,
        env: Option<EnvName>,
    ) {
        if self.jobs.contains_key(&action) {
            return;
        }
        let Some(os) = shared.os else {
            self.results.insert(
                action,
                Finished {
                    result: Err(ActionError::Unsupported),
                    self_test: None,
                },
            );
            return;
        };
        let tools = Arc::clone(&shared.tools);
        let job = Job::spawn(Some(ctx.clone()), move || {
            actions::run(&invocation(action, env.as_ref(), os), os, &tools)
        });
        self.jobs.insert(action, job);
    }

    /// Run `mia machine-id` and copy the result.
    pub(crate) fn copy_ids(&mut self, ctx: &egui::Context, shared: &Shared) {
        if self.copy_job.is_some() {
            return;
        }
        let Some(os) = shared.os else {
            self.copy_notice = Some(Msg::ErrorUnsupported);
            return;
        };
        let tools = Arc::clone(&shared.tools);
        self.copy_notice = None;
        self.copy_job = Some(Job::spawn(Some(ctx.clone()), move || {
            actions::run(&invocation(Action::ShowMachineId, None, os), os, &tools)
        }));
    }

    /// The most recent self-test (for the diagnostics bundle).
    pub(crate) fn last_self_test(&self) -> Option<&SelfTest> {
        self.last_self_test.as_ref()
    }

    /// Collect finished jobs; `true` when a state-changing action finished.
    pub(crate) fn poll(&mut self, ctx: &egui::Context) -> bool {
        let mut changed = false;
        let actions: Vec<Action> = self.jobs.keys().copied().collect();
        for action in actions {
            let mut slot = self.jobs.remove(&action);
            match take(&mut slot) {
                Some(result) => {
                    let self_test = match (&result, action) {
                        (Ok(r), Action::RunSelfTest) => crate::selftest::parse(&r.captured.stdout),
                        _ => None,
                    };
                    if let Some(st) = &self_test {
                        self.last_self_test = Some(st.clone());
                    }
                    changed |= action.privilege() == Privilege::Admin;
                    self.results.insert(action, Finished { result, self_test });
                }
                None => {
                    if let Some(job) = slot {
                        self.jobs.insert(action, job);
                    }
                }
            }
        }
        if let Some(result) = take(&mut self.copy_job) {
            self.copy_notice = Some(match result {
                Ok(r) if r.outcome == Outcome::Succeeded => {
                    match actions::parse_machine_id(&r.captured.stdout) {
                        Some(id) => {
                            ctx.copy_text(format!("mia machine-id: {id}"));
                            Msg::CopiedIds
                        }
                        None => Msg::ErrorUnexpectedOutput,
                    }
                }
                Ok(_) => Msg::OutcomeFailed,
                Err(e) => e.message(),
            });
        }
        changed
    }

    /// The environment selector: the default plus every validated name the
    /// agent reported.
    fn env_selector(&mut self, ui: &mut egui::Ui, lang: Lang, obs: Option<&Observation>) {
        let names: Vec<EnvName> = obs
            .into_iter()
            .flat_map(|o| o.snapshots.iter())
            .filter_map(crate::model::env_arg)
            .collect();
        ui.horizontal(|ui| {
            ui.label(Msg::LabelEnvironment.text(lang));
            let shown = self
                .env
                .as_ref()
                .map_or(Msg::DefaultEnvironment.text(lang), EnvName::as_str)
                .to_string();
            egui::ComboBox::from_id_salt("recovery-env")
                .selected_text(shown)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.env, None, Msg::DefaultEnvironment.text(lang));
                    for n in names {
                        let label = n.as_str().to_string();
                        ui.selectable_value(&mut self.env, Some(n), label);
                    }
                });
        });
    }

    pub(crate) fn ui(
        &mut self,
        ui: &mut egui::Ui,
        shared: &Shared,
        obs: Option<&Observation>,
    ) -> Option<Intent> {
        let lang = shared.lang;
        let mut out = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            self.env_selector(ui, lang, obs);

            if let Some(obs) = obs {
                let view = tray_view(obs, crate::unix_now(), lang);
                if let Some(env) = view
                    .envs
                    .iter()
                    .filter(|e| e.state == view.worst)
                    .find(|e| !e.recoveries.is_empty())
                {
                    ui.add_space(6.0);
                    ui.label(RichText::new(Msg::LabelSuggested.text(lang)).strong());
                    ui.label(RichText::new(&env.headline).color(color32(view.presentation.color)));
                    ui.horizontal_wrapped(|ui| {
                        for r in &env.recoveries {
                            if let Some(i) = recovery_button(ui, shared, *r, env.env.as_ref()) {
                                out = Some(i);
                            }
                        }
                    });
                }
            }

            ui.add_space(8.0);
            ui.separator();
            ui.label(RichText::new(Msg::LabelAllActions.text(lang)).strong());
            for action in Action::ALL {
                ui.horizontal(|ui| {
                    let running = self.jobs.contains_key(&action);
                    let env = action
                        .takes_environment()
                        .then(|| self.env.clone())
                        .flatten();
                    let mut button =
                        ui.add_enabled(!running, egui::Button::new(action.label().text(lang)));
                    if action.privilege() == Privilege::Admin {
                        button = button.on_hover_text(Msg::NoteElevation.text(lang));
                    }
                    if button.clicked() {
                        out = Some(Intent::Run(action, env));
                    }
                    if running {
                        ui.spinner();
                    }
                });
                if let Some(done) = self.results.get(&action) {
                    finished_ui(ui, lang, shared.os, action, done);
                }
            }
            ui.horizontal(|ui| {
                let busy = self.copy_job.is_some();
                if ui
                    .add_enabled(!busy, egui::Button::new(Msg::RecoveryCopyIds.text(lang)))
                    .clicked()
                {
                    out = Some(Intent::CopyIds);
                }
                if busy {
                    ui.spinner();
                }
                if let Some(m) = self.copy_notice {
                    ui.label(m.text(lang));
                }
            });

            ui.add_space(8.0);
            ui.separator();
            ui.label(RichText::new(Msg::LabelDocs.text(lang)).strong());
            ui.horizontal_wrapped(|ui| {
                for doc in Doc::ALL {
                    if ui.link(doc.label().text(lang)).clicked() {
                        open_doc(shared, doc);
                    }
                }
            });
        });
        out
    }
}

fn outcome_color(outcome: Outcome) -> Color32 {
    match outcome {
        Outcome::Succeeded => color32(IconColor::Green),
        Outcome::Cancelled => color32(IconColor::Grey),
        Outcome::TimedOut | Outcome::NotAuthorized => color32(IconColor::Yellow),
        Outcome::Failed(_) => color32(IconColor::Red),
    }
}

/// One action's result: the friendly outcome first, the raw output folded
/// away under "Output".
fn finished_ui(ui: &mut egui::Ui, lang: Lang, os: Option<Os>, action: Action, done: &Finished) {
    ui.indent(("result", action.label()), |ui| match &done.result {
        Err(e) => {
            ui.colored_label(color32(IconColor::Red), e.message().text(lang));
        }
        Ok(r) => {
            ui.colored_label(outcome_color(r.outcome), r.outcome.label().text(lang));
            if r.outcome == Outcome::Succeeded && action.applies_on_restart() {
                ui.label(Msg::NoteRestartToApply.text(lang));
            }
            if let Some(st) = &done.self_test {
                self_test_ui(ui, lang, st);
            }
            let mut text = output_text(&r.captured.stdout);
            let err = output_text(&r.captured.stderr);
            if !err.is_empty() {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(&err);
            }
            if text.is_empty() && os == Some(Os::Windows) && action.privilege() == Privilege::Admin
            {
                // UAC-elevated processes cannot hand their output back.
                ui.label(RichText::new(Msg::NoteElevation.text(lang)).weak());
            } else if !text.is_empty() {
                egui::CollapsingHeader::new(Msg::LabelOutput.text(lang))
                    .id_salt(("output", action.label()))
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .id_salt(("output-scroll", action.label()))
                            .max_height(220.0)
                            .show(ui, |ui| ui.label(RichText::new(text).monospace()));
                    });
            }
        }
    });
}

/// The parsed self-test: one line per check, hints under failures.
pub(crate) fn self_test_ui(ui: &mut egui::Ui, lang: Lang, st: &SelfTest) {
    let (msg, color) = if st.passed {
        (Msg::SelfTestPassed, IconColor::Green)
    } else {
        (Msg::SelfTestFailed, IconColor::Red)
    };
    ui.colored_label(color32(color), msg.text(lang));
    for check in &st.checks {
        let color = match check.status.as_str() {
            "ok" => color32(IconColor::Green),
            "FAIL" => color32(IconColor::Red),
            "warn" => color32(IconColor::Yellow),
            _ => color32(IconColor::Grey),
        };
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(&check.status).monospace().color(color));
            ui.label(RichText::new(&check.step).strong());
            ui.label(&check.detail);
        });
        if check.failed() {
            for hint in &check.hints {
                ui.label(RichText::new(format!("    {hint}")).weak());
            }
        }
    }
}
