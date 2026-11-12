//! The Status tab: one card per environment, plus the state badge and
//! recovery buttons the window header reuses.

use eframe::egui::{self, RichText};

use super::window::Intent;
use super::Shared;
use crate::actions::{EnvName, Privilege};
use crate::client::Observation;
use crate::i18n::Msg;
use crate::model::{
    presentation, snapshot_explanation, tray_view, IconColor, Presentation, Recovery,
};

/// The egui colour for an icon colour.
pub(crate) fn color32(c: IconColor) -> egui::Color32 {
    let [r, g, b] = crate::icon::rgb(c);
    egui::Color32::from_rgb(r, g, b)
}

fn rgb32([r, g, b]: [u8; 3]) -> egui::Color32 {
    egui::Color32::from_rgb(r, g, b)
}

/// A state badge: glyph and text on the state colour (never colour alone;
/// text contrast at least 4.5:1, see `icon::badge_rgb`).
pub(crate) fn badge(ui: &mut egui::Ui, look: Presentation, text: &str) -> egui::Response {
    egui::Frame::new()
        .fill(rgb32(crate::icon::badge_rgb(look.color)))
        .corner_radius(12u8)
        .inner_margin(egui::Margin::symmetric(10, 3))
        .show(ui, |ui| {
            ui.label(
                RichText::new(format!("{} {text}", look.glyph.text()))
                    .color(rgb32(crate::icon::glyph_rgb(look.color)))
                    .strong(),
            )
        })
        .response
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
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for (env, snapshot) in view.envs.iter().zip(&obs.snapshots) {
                egui::Frame::group(ui.style())
                    .inner_margin(egui::Margin::same(10))
                    .corner_radius(8u8)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal_wrapped(|ui| {
                            badge(
                                ui,
                                presentation(env.state),
                                crate::model::snapshot_title(snapshot).text(lang),
                            );
                            ui.label(RichText::new(&env.label).strong());
                            if env.default_address {
                                ui.weak(Msg::MarkerDefaultAddress.text(lang));
                            }
                        });
                        ui.label(snapshot_explanation(snapshot).text(lang));
                        let mut buttons: Vec<Recovery> = env.recoveries.clone();
                        buttons.extend(env.default_choice);
                        if !buttons.is_empty() {
                            ui.horizontal_wrapped(|ui| {
                                for r in buttons {
                                    if let Some(i) =
                                        recovery_button(ui, shared, r, env.env.as_ref())
                                    {
                                        out = Some(i);
                                    }
                                }
                            });
                        }
                        egui::CollapsingHeader::new(Msg::LabelDetails.text(lang))
                            .id_salt(("env-details", &env.label))
                            .default_open(view.envs.len() == 1)
                            .show(ui, |ui| {
                                for line in &env.details {
                                    ui.add(
                                        egui::Label::new(RichText::new(line).monospace()).wrap(),
                                    );
                                }
                            });
                    });
                ui.add_space(8.0);
            }
        });
    out
}
