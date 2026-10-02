//! The Status tab: one collapsible block per environment.

use eframe::egui::{self, RichText};

use super::window::Intent;
use super::Shared;
use crate::actions::{EnvName, Privilege};
use crate::client::{Observation, Source};
use crate::i18n::Msg;
use crate::model::{presentation, snapshot_explanation, tray_view, IconColor, Recovery};

/// The egui colour for an icon colour.
pub(crate) fn color32(c: IconColor) -> egui::Color32 {
    let [r, g, b] = crate::icon::rgb(c);
    egui::Color32::from_rgb(r, g, b)
}

/// Map a recovery to what the window should do.
pub(crate) fn intent(r: Recovery, env: Option<EnvName>) -> Intent {
    match r {
        Recovery::Run(a) => Intent::Run(a, env),
        Recovery::OpenWizard(step) => Intent::Setup(step),
        Recovery::CopyMachineIds => Intent::CopyIds,
        Recovery::Read(doc) => Intent::Read(doc),
    }
}

/// A recovery button (admin actions say they will prompt).
pub(crate) fn recovery_button(
    ui: &mut egui::Ui,
    shared: &Shared,
    r: Recovery,
    env: Option<&EnvName>,
) -> Option<Intent> {
    let lang = shared.lang;
    let mut resp = ui.button(r.label(lang));
    if matches!(r, Recovery::Run(a) if a.privilege() == Privilege::Admin) {
        resp = resp.on_hover_text(Msg::NoteElevation.text(lang));
    }
    resp.clicked().then(|| intent(r, env.cloned()))
}

pub(crate) fn ui(ui: &mut egui::Ui, shared: &Shared, obs: Option<&Observation>) -> Option<Intent> {
    let lang = shared.lang;
    let mut out = None;
    let Some(obs) = obs else {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(Msg::StatusNoData.text(lang));
        });
        return None;
    };
    let view = tray_view(obs, crate::unix_now(), lang);
    ui.horizontal(|ui| {
        ui.heading(RichText::new(&view.headline).color(color32(view.presentation.color)));
        if ui.button(Msg::ButtonRefresh.text(lang)).clicked() {
            out = Some(Intent::Refresh);
        }
    });
    let source = match view.source {
        Source::Endpoint => Msg::SourceEndpoint,
        Source::Cli => Msg::SourceCli,
        Source::Synthesised => Msg::SourceSynthesised,
    };
    ui.label(
        RichText::new(format!(
            "{}: {}",
            Msg::DetailSource.text(lang),
            source.text(lang)
        ))
        .weak(),
    );
    ui.separator();
    egui::ScrollArea::vertical().show(ui, |ui| {
        for (env, snapshot) in view.envs.iter().zip(&obs.snapshots) {
            let color = color32(presentation(env.state).color);
            egui::CollapsingHeader::new(RichText::new(&env.headline).color(color).strong())
                .id_salt(("env", &env.label))
                .default_open(true)
                .show(ui, |ui| {
                    ui.label(snapshot_explanation(snapshot).text(lang));
                    ui.add_space(4.0);
                    for line in &env.details {
                        ui.label(RichText::new(line).monospace());
                    }
                    if !env.recoveries.is_empty() {
                        ui.add_space(4.0);
                        ui.horizontal_wrapped(|ui| {
                            for r in &env.recoveries {
                                if let Some(i) = recovery_button(ui, shared, *r, env.env.as_ref()) {
                                    out = Some(i);
                                }
                            }
                        });
                    }
                });
        }
    });
    out
}
