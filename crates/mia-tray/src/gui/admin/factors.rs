//! "My account → Second factors" (F22 §3a items 2 and 3), drawn from the
//! secret-free [`FactorsView`]: the list with escaped labels, the add and
//! remove forms, and the restricted key-registration screen.

use eframe::egui;
use ferrogate_admin_client::factors::FactorMethod;

use super::{field_box, seed, Action};
use crate::admin::factors::{FactorField, FactorRow, FactorsView, PanelError, PanelMode};
use crate::admin::login::Submission;
use crate::admin::seed::SeedDisplay;
use crate::i18n::{fill, Lang, Msg};

/// `YYYY-MM-DD` of Unix seconds; a dash for 0.
fn day(lang: Lang, secs: i64) -> String {
    if secs <= 0 {
        return Msg::AdminUnknownDate.text(lang).to_string();
    }
    // A hostile value stays a four-digit year.
    let secs = secs.min(253_402_300_799);
    let stamp = crate::text::rfc3339_utc_ms(secs.saturating_mul(1000));
    stamp.get(..10).unwrap_or(&stamp).to_string()
}

fn name(lang: Lang, row: &FactorRow) -> String {
    match row.method {
        FactorMethod::Totp => Msg::AdminFactorTotp.text(lang).to_string(),
        FactorMethod::SecurityKey => fill(Msg::AdminFactorKey.text(lang), &[("label", &row.label)]),
    }
}

fn error_text(lang: Lang, e: PanelError) -> &'static str {
    match e {
        PanelError::LastFactor => Msg::AdminLastFactor.text(lang),
        PanelError::BadCode => Msg::AdminBadCode.text(lang),
        PanelError::KeyUnavailable => Msg::AdminKeyUnavailable.text(lang),
        PanelError::NotOffered => Msg::AdminNotOffered.text(lang),
    }
}

/// Draw the panel.
pub(super) fn panel(
    ui: &mut egui::Ui,
    lang: Lang,
    v: &FactorsView,
    shown: Option<&SeedDisplay<'_>>,
    idle: bool,
    actions: &mut Vec<Action>,
) {
    if v.restricted {
        ui.heading(Msg::AdminRestrictedTitle.text(lang));
        ui.label(Msg::AdminRestrictedHint.text(lang));
    } else {
        ui.heading(Msg::AdminFactorsTitle.text(lang));
    }
    ui.add_space(6.0);
    match v.mode {
        PanelMode::List => list(ui, lang, v, idle, actions),
        PanelMode::AddTotp => {
            ui.label(Msg::AdminAddTotpHint.text(lang));
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
            masked(ui, v.new_code_len, v, FactorField::NewCode, actions);
            confirm(ui, lang, v, idle, actions);
        }
        PanelMode::AddKey => {
            ui.label(Msg::AdminAddKeyHint.text(lang));
            ui.label(Msg::AdminKeyLabel.text(lang));
            if field_box(ui, &v.label, v.focus == FactorField::Label).clicked() {
                actions.push(Action::FocusFactor(FactorField::Label));
            }
            confirm(ui, lang, v, idle, actions);
        }
        PanelMode::Remove => {
            let label = v.removing.clone().unwrap_or_default();
            ui.label(fill(
                Msg::AdminRemoveConfirm.text(lang),
                &[("label", &label)],
            ));
            confirm(ui, lang, v, idle, actions);
        }
    }
    if let Some(e) = v.error {
        ui.colored_label(ui.visuals().error_fg_color, error_text(lang, e));
    }
}

fn masked(
    ui: &mut egui::Ui,
    len: usize,
    v: &FactorsView,
    field: FactorField,
    actions: &mut Vec<Action>,
) {
    if field_box(ui, &"•".repeat(len), v.focus == field).clicked() {
        actions.push(Action::FocusFactor(field));
    }
}

fn list(ui: &mut egui::Ui, lang: Lang, v: &FactorsView, idle: bool, actions: &mut Vec<Action>) {
    if !v.restricted {
        if !v.loaded {
            ui.weak(Msg::AdminLoading.text(lang));
        }
        for row in &v.rows {
            ui.horizontal(|ui| {
                ui.label(name(lang, row));
                ui.weak(fill(
                    Msg::AdminFactorDates.text(lang),
                    &[
                        ("added", &day(lang, row.created_at)),
                        ("used", &day(lang, row.last_used_at)),
                    ],
                ));
                if v.rows.len() > 1
                    && ui
                        .add_enabled(idle, egui::Button::new(Msg::AdminRemove.text(lang)).small())
                        .clicked()
                {
                    actions.push(Action::RemoveFactor(row.factor_id.clone()));
                }
            });
        }
        ui.add_space(6.0);
    }
    ui.horizontal(|ui| {
        if !v.restricted
            && ui
                .add_enabled(
                    v.can_add_totp && idle,
                    egui::Button::new(Msg::AdminAddTotp.text(lang)),
                )
                .clicked()
        {
            actions.push(Action::AddFactor(FactorMethod::Totp));
        }
        let add_key = if v.restricted {
            Msg::AdminRegisterKey
        } else {
            Msg::AdminAddKey
        };
        if ui
            .add_enabled(v.can_add_key && idle, egui::Button::new(add_key.text(lang)))
            .clicked()
        {
            actions.push(Action::AddFactor(FactorMethod::SecurityKey));
        }
        if !v.restricted
            && ui
                .add_enabled(idle, egui::Button::new(Msg::AdminBack.text(lang)))
                .clicked()
        {
            actions.push(Action::CloseFactors);
        }
    });
    if !v.key_available {
        ui.weak(Msg::AdminKeyUnavailable.text(lang));
    }
}

/// The proof fields and buttons of a form, as the session allows.
fn confirm(ui: &mut egui::Ui, lang: Lang, v: &FactorsView, idle: bool, actions: &mut Vec<Action>) {
    let code_proof = v.proof_by_code && v.mode != PanelMode::AddTotp;
    if code_proof {
        ui.label(Msg::AdminProofCode.text(lang));
        masked(ui, v.proof_len, v, FactorField::Proof, actions);
    }
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        if code_proof
            && ui
                .add_enabled(
                    idle && v.proof_len >= 6,
                    egui::Button::new(Msg::AdminConfirmWithCode.text(lang)),
                )
                .clicked()
        {
            actions.push(Action::SubmitFactor(Submission::Code));
        }
        if v.proof_by_key
            && ui
                .add_enabled(idle, egui::Button::new(Msg::AdminConfirmWithKey.text(lang)))
                .clicked()
        {
            actions.push(Action::SubmitFactor(Submission::SecurityKey));
        }
        if ui
            .add_enabled(idle, egui::Button::new(Msg::AdminCancel.text(lang)))
            .clicked()
        {
            actions.push(Action::CancelFactorForm);
        }
    });
}
