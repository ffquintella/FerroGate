//! The enrollment wizard's window (F22 §3a item 1), drawn from the
//! secret-free [`EnrollView`]; the seed is painted through [`super::seed`].

use eframe::egui;

use super::{field_box, seed, Action};
use crate::admin::enroll::{EnrollError, EnrollField, EnrollStage, EnrollView};
use crate::admin::seed::SeedDisplay;
use crate::i18n::{fill, Lang, Msg};

/// A masked field (dots from a length); a click focuses it.
fn masked(
    ui: &mut egui::Ui,
    len: usize,
    v: &EnrollView,
    field: EnrollField,
    actions: &mut Vec<Action>,
) {
    if field_box(ui, &"•".repeat(len), v.focus == field).clicked() {
        actions.push(Action::FocusEnroll(field));
    }
}

fn error_text(lang: Lang, e: EnrollError) -> &'static str {
    match e {
        EnrollError::MissingToken => Msg::AdminEnrollMissingToken.text(lang),
        EnrollError::BootstrapToken => Msg::AdminEnrollBootstrap.text(lang),
        EnrollError::PasswordTooShort => Msg::AdminPasswordShort.text(lang),
        EnrollError::PasswordMismatch => Msg::AdminPasswordMismatch.text(lang),
        EnrollError::NoFactor => Msg::AdminNoFactor.text(lang),
        EnrollError::BadCode => Msg::AdminBadCode.text(lang),
        EnrollError::KeyUnavailable => Msg::AdminKeyUnavailable.text(lang),
    }
}

/// Draw the wizard.
pub(super) fn wizard(
    ui: &mut egui::Ui,
    lang: Lang,
    v: &EnrollView,
    shown: Option<&SeedDisplay<'_>>,
    idle: bool,
    actions: &mut Vec<Action>,
) {
    ui.heading(Msg::AdminEnrollTitle.text(lang));
    ui.add_space(6.0);
    match v.stage {
        EnrollStage::Token => {
            ui.label(Msg::AdminEnrollToken.text(lang));
            masked(ui, v.token_len, v, EnrollField::Token, actions);
            ui.weak(Msg::AdminEnrollTokenHint.text(lang));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        v.can_continue && idle,
                        egui::Button::new(Msg::AdminContinue.text(lang)),
                    )
                    .clicked()
                {
                    actions.push(Action::EnrollContinue);
                }
                if ui
                    .add_enabled(idle, egui::Button::new(Msg::AdminBack.text(lang)))
                    .clicked()
                {
                    actions.push(Action::CloseEnrollment);
                }
            });
        }
        EnrollStage::Details => details(ui, lang, v, shown, idle, actions),
    }
    if let Some(e) = v.error {
        ui.colored_label(ui.visuals().error_fg_color, error_text(lang, e));
    }
}

fn details(
    ui: &mut egui::Ui,
    lang: Lang,
    v: &EnrollView,
    shown: Option<&SeedDisplay<'_>>,
    idle: bool,
    actions: &mut Vec<Action>,
) {
    let name = if v.display_name.is_empty() || v.display_name == v.username {
        v.username.clone()
    } else {
        format!("{} ({})", v.username, v.display_name)
    };
    ui.label(fill(Msg::AdminEnrollAccount.text(lang), &[("name", &name)]));
    ui.add_space(4.0);
    ui.label(fill(
        Msg::AdminNewPassword.text(lang),
        &[("n", &v.password_min_len.to_string())],
    ));
    masked(ui, v.password_len, v, EnrollField::Password, actions);
    ui.label(Msg::AdminConfirmPassword.text(lang));
    masked(ui, v.confirm_len, v, EnrollField::Confirm, actions);
    ui.weak(Msg::AdminPasswordRules.text(lang));
    if v.totp_offered {
        ui.separator();
        ui.label(Msg::AdminTotpScan.text(lang));
        if let Some(s) = shown {
            seed::paint(ui, s);
        }
        let toggle = if v.seed_text_shown {
            Msg::AdminSeedHideText
        } else {
            Msg::AdminSeedShowText
        };
        if ui.small_button(toggle.text(lang)).clicked() {
            actions.push(Action::ToggleSeedText);
        }
        ui.label(Msg::AdminTotpConfirm.text(lang));
        masked(ui, v.code_len, v, EnrollField::Code, actions);
    }
    if v.reset_only {
        ui.separator();
        ui.label(Msg::AdminCurrentCode.text(lang));
        masked(ui, v.code_len, v, EnrollField::Code, actions);
    }
    if v.key_offered {
        ui.separator();
        ui.label(Msg::AdminKeySection.text(lang));
        if v.key_registered {
            ui.label(Msg::AdminKeyRegisteredOk.text(lang));
        } else {
            ui.label(Msg::AdminKeyLabel.text(lang));
            if field_box(ui, &v.label, v.focus == EnrollField::Label).clicked() {
                actions.push(Action::FocusEnroll(EnrollField::Label));
            }
            if ui
                .add_enabled(
                    v.can_register_key && idle,
                    egui::Button::new(Msg::AdminRegisterKey.text(lang)),
                )
                .clicked()
            {
                actions.push(Action::EnrollRegisterKey);
            }
            if !v.key_available {
                ui.weak(Msg::AdminKeyUnavailable.text(lang));
            }
        }
    }
    if v.totp_offered || v.key_offered {
        ui.weak(Msg::AdminEnrollOneFactor.text(lang));
    }
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                v.can_finish && idle,
                egui::Button::new(Msg::AdminEnrollFinish.text(lang)),
            )
            .clicked()
        {
            actions.push(Action::EnrollFinish);
        }
        if ui
            .add_enabled(idle, egui::Button::new(Msg::AdminCancel.text(lang)))
            .clicked()
        {
            actions.push(Action::CloseEnrollment);
        }
    });
}
