//! The "admin server" screen (F22 §2), drawn from the headless
//! [`ServerView`]. Its fields are painted by [`field_box`] like every other
//! field of the window; keystrokes reach [`crate::admin::server`] directly.

use eframe::egui;
use ferrogate_admin_client::config::PinProblem;
use ferrogate_admin_client::endpoint::EndpointProblem;

use super::{field_box, Action};
use crate::admin::server::{ConfirmView, SaveProblem, ServerField, ServerStage, ServerView};
use crate::i18n::{fill, Lang, Msg};
use crate::text::display_safe;

fn endpoint_text(lang: Lang, p: EndpointProblem) -> &'static str {
    match p {
        EndpointProblem::TooLong => Msg::AdminServerTooLong.text(lang),
        EndpointProblem::NotHttps => Msg::AdminServerNotHttps.text(lang),
        EndpointProblem::NotUrl => Msg::AdminServerNotUrl.text(lang),
        EndpointProblem::NoHost => Msg::AdminServerNoHost.text(lang),
        EndpointProblem::PathOrQuery => Msg::AdminServerPath.text(lang),
        EndpointProblem::NoPort => Msg::AdminServerNoPort.text(lang),
    }
}

fn pin_text(lang: Lang, p: PinProblem) -> String {
    match p {
        PinProblem::Empty => Msg::AdminServerPinEmpty.text(lang).to_string(),
        PinProblem::NotHex => Msg::AdminServerPinHex.text(lang).to_string(),
        PinProblem::Length(n) => fill(
            Msg::AdminServerPinLength.text(lang),
            &[("n", &n.to_string())],
        ),
    }
}

fn save_text(lang: Lang, p: SaveProblem) -> &'static str {
    match p {
        SaveProblem::NoUserDir => Msg::AdminServerNoDir.text(lang),
        SaveProblem::Untrusted => Msg::AdminServerUntrusted.text(lang),
        SaveProblem::WriteFailed => Msg::AdminServerWriteFailed.text(lang),
        SaveProblem::StillUnusable => Msg::AdminServerStillUnusable.text(lang),
    }
}

/// Draw the screen; `missing` is why no server is usable now (escaped).
pub(super) fn screen(
    ui: &mut egui::Ui,
    lang: Lang,
    v: &ServerView,
    missing: Option<&str>,
    actions: &mut Vec<Action>,
) {
    ui.heading(Msg::AdminServerTitle.text(lang));
    ui.add_space(6.0);
    if let Some(why) = missing {
        ui.colored_label(ui.visuals().warn_fg_color, Msg::AdminNoServer.text(lang));
        if !why.is_empty() {
            ui.weak(why);
        }
        ui.add_space(4.0);
    }
    for (set, msg) in [
        (v.env_endpoint, Msg::AdminServerEnvEndpoint),
        (v.env_pin, Msg::AdminServerEnvPin),
    ] {
        if set {
            ui.colored_label(ui.visuals().warn_fg_color, msg.text(lang));
        }
    }
    match (&v.stage, &v.confirm) {
        (ServerStage::Confirm, Some(c)) => confirm(ui, lang, c, actions),
        _ => form(ui, lang, v, actions),
    }
    if let Some(p) = v.save_problem {
        ui.colored_label(ui.visuals().error_fg_color, save_text(lang, p));
    }
}

fn form(ui: &mut egui::Ui, lang: Lang, v: &ServerView, actions: &mut Vec<Action>) {
    ui.label(Msg::AdminServerIntro.text(lang));
    ui.add_space(8.0);
    ui.label(Msg::AdminServerEndpoint.text(lang));
    let shown = display_safe(&v.endpoint, 600);
    if field_box(ui, &shown, v.focus == ServerField::Endpoint).clicked() {
        actions.push(Action::FocusServer(ServerField::Endpoint));
    }
    if let Some(p) = v.endpoint_problem {
        ui.colored_label(ui.visuals().error_fg_color, endpoint_text(lang, p));
    }
    ui.add_space(4.0);
    ui.label(Msg::AdminServerPin.text(lang));
    let shown = display_safe(&v.pin, 300);
    if field_box(ui, &shown, v.focus == ServerField::Pin).clicked() {
        actions.push(Action::FocusServer(ServerField::Pin));
    }
    if let Some(p) = v.pin_problem {
        ui.colored_label(ui.visuals().error_fg_color, pin_text(lang, p));
    }
    ui.weak(Msg::AdminServerPinHint.text(lang));
    if let Some(path) = &v.target {
        ui.weak(fill(
            Msg::AdminServerTarget.text(lang),
            &[("path", &display_safe(&path.display().to_string(), 300))],
        ));
    }
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                v.can_save,
                egui::Button::new(Msg::AdminServerSave.text(lang)),
            )
            .clicked()
        {
            actions.push(Action::ServerSave);
        }
        if v.can_cancel && ui.button(Msg::AdminCancel.text(lang)).clicked() {
            actions.push(Action::ServerCancel);
        }
    });
}

/// The endpoint and pins of one side of the confirmation.
fn values(ui: &mut egui::Ui, lang: Lang, endpoint: Option<&str>, pins: &[String]) {
    let none = Msg::AdminServerNone.text(lang);
    ui.label(fill(
        Msg::AdminServerEndpointLine.text(lang),
        &[(
            "endpoint",
            &endpoint.map_or_else(|| none.to_string(), |e| display_safe(e, 600)),
        )],
    ));
    if pins.is_empty() {
        ui.label(fill(Msg::AdminServerPinLine.text(lang), &[("pin", none)]));
    }
    for pin in pins {
        ui.monospace(fill(
            Msg::AdminServerPinLine.text(lang),
            &[("pin", &display_safe(pin, 200))],
        ));
    }
}

fn confirm(ui: &mut egui::Ui, lang: Lang, c: &ConfirmView, actions: &mut Vec<Action>) {
    ui.label(egui::RichText::new(Msg::AdminServerConfirmTitle.text(lang)).strong());
    ui.add_space(6.0);
    ui.group(|ui| {
        ui.label(fill(
            Msg::AdminServerCurrent.text(lang),
            &[("path", &display_safe(&c.path.display().to_string(), 300))],
        ));
        match &c.old {
            Some((endpoint, pins)) => values(ui, lang, endpoint.as_deref(), pins),
            None => {
                ui.colored_label(
                    ui.visuals().warn_fg_color,
                    Msg::AdminServerUnreadable.text(lang),
                );
            }
        }
    });
    ui.group(|ui| {
        ui.label(Msg::AdminServerNew.text(lang));
        values(ui, lang, Some(&c.endpoint), std::slice::from_ref(&c.pin));
    });
    if !c.replaces {
        ui.weak(Msg::AdminServerShadows.text(lang));
    }
    if c.keeps_other_keys {
        ui.weak(Msg::AdminServerKeeps.text(lang));
    }
    ui.label(Msg::AdminServerCompare.text(lang));
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        if ui.button(Msg::AdminServerReplace.text(lang)).clicked() {
            actions.push(Action::ServerConfirm);
        }
        if ui.button(Msg::AdminBack.text(lang)).clicked() {
            actions.push(Action::ServerBack);
        }
    });
}
