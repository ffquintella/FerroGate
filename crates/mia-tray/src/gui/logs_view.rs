//! The Logs tab: follows the daemon's redacted ring buffer through
//! `LogTailReq` (no access to the root-owned log file or the journal is
//! needed), with level / environment / text filters, pause/follow, "open full
//! log" and "save diagnostics bundle".

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{self, RichText};
use mia_status_proto::{Level, LogTailResp};

use super::job::{take, Job};
use super::recovery_view::RecoveryView;
use super::status_view::color32;
use super::Shared;
use crate::actions::{self, invocation, Action, ActionError, Os};
use crate::bundle::{self, BundleInput, BUNDLE_RECORDS};
use crate::client::{fetch_logs, ClientError, Observation, Source};
use crate::i18n::{fill, Msg};
use crate::logview::{
    environments, render_record, Entry, EnvFilter, Filter, Follower, LogBuffer, MAX_KEPT,
    MAX_SEARCH_LEN,
};
use crate::model::IconColor;

/// Follow interval while the agent answers / while it does not.
const FOLLOW_EVERY: Duration = Duration::from_secs(1);
const RETRY_EVERY: Duration = Duration::from_secs(5);

#[derive(Default)]
pub(crate) struct LogsView {
    follower: Follower,
    buffer: LogBuffer,
    pending: Vec<Entry>,
    paused: bool,
    filter: Filter,
    job: Option<Job<Result<LogTailResp, ClientError>>>,
    last_fetch: Option<Instant>,
    more: bool,
    unavailable: bool,
    bundle_job: Option<Job<Result<PathBuf, ()>>>,
    bundle_msg: Option<Msg>,
    viewer_msg: Option<Msg>,
}

impl LogsView {
    /// Fold in replies and fetch the next page when due (only while the tab
    /// is shown).
    pub(crate) fn poll(&mut self, ctx: &egui::Context, shared: &Shared, active: bool) {
        if let Some(result) = take(&mut self.job) {
            match result {
                Ok(resp) => {
                    self.unavailable = false;
                    let ingested = self.follower.ingest(resp);
                    self.more = ingested.more;
                    if self.paused {
                        self.pending.extend(ingested.entries);
                        if self.pending.len() > MAX_KEPT {
                            let excess = self.pending.len() - MAX_KEPT;
                            self.pending.drain(..excess);
                        }
                    } else {
                        self.buffer.extend(ingested.entries);
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "log tail unavailable");
                    self.unavailable = true;
                    self.more = false;
                }
            }
        }
        if let Some(result) = take(&mut self.bundle_job) {
            self.bundle_msg = Some(if result.is_ok() {
                Msg::LogsBundleSaved
            } else {
                Msg::LogsBundleFailed
            });
        }
        let every = if self.unavailable {
            RETRY_EVERY
        } else {
            FOLLOW_EVERY
        };
        let due = self.more || self.last_fetch.is_none_or(|t| t.elapsed() >= every);
        if active && self.job.is_none() && due {
            let endpoint = Arc::clone(&shared.endpoint);
            let since = self.follower.since_seq();
            self.last_fetch = Some(Instant::now());
            self.more = false;
            self.job = Some(Job::spawn(Some(ctx.clone()), move || {
                fetch_logs(endpoint.as_ref(), since)
            }));
        }
    }

    fn resume(&mut self) {
        self.paused = false;
        self.buffer.extend(std::mem::take(&mut self.pending));
    }

    fn save_bundle(
        &mut self,
        ctx: &egui::Context,
        shared: &Shared,
        obs: Option<&Observation>,
        recovery: &RecoveryView,
    ) {
        let Some(path) = rfd::FileDialog::new()
            .set_file_name("mia-diagnostics.txt")
            .add_filter("Text", &["txt"])
            .save_file()
        else {
            return;
        };
        let snapshots = obs.map(|o| o.snapshots.clone()).unwrap_or_default();
        let source = match obs.map(|o| o.source) {
            Some(Source::Endpoint) => "status endpoint",
            Some(Source::Cli) => "mia status --json",
            _ => "agent not reachable",
        };
        let records = self.buffer.last_records(BUNDLE_RECORDS);
        let previous = recovery.last_self_test().map(|s| s.document.clone());
        let os = shared.os;
        let tools = Arc::clone(&shared.tools);
        self.bundle_msg = None;
        self.bundle_job = Some(Job::spawn(Some(ctx.clone()), move || {
            // Use the last self-test, or run one now.
            let (self_test, note) = match previous {
                Some(doc) => (Some(doc), None),
                None => match os.ok_or(ActionError::Unsupported).and_then(|os| {
                    actions::run(&invocation(Action::RunSelfTest, None, os), os, &tools)
                }) {
                    Ok(r) => match crate::selftest::parse(&r.captured.stdout) {
                        Some(st) => (Some(st.document), None),
                        None => (
                            None,
                            Some("mia test --json produced no document".to_string()),
                        ),
                    },
                    Err(e) => (None, Some(e.to_string())),
                },
            };
            let text = bundle::render(&BundleInput {
                generated_at_ms: crate::unix_now_ms(),
                platform: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
                snapshots: &snapshots,
                source: source.to_string(),
                self_test: self_test.as_ref(),
                self_test_note: note,
                records: &records,
            });
            bundle::write(&path, &text).map(|()| path).map_err(|e| {
                tracing::warn!(error = %e, "could not write the diagnostics bundle");
            })
        }));
    }

    #[allow(clippy::too_many_lines)] // toolbar + list; one screen
    pub(crate) fn ui(
        &mut self,
        ui: &mut egui::Ui,
        shared: &Shared,
        obs: Option<&Observation>,
        recovery: &RecoveryView,
    ) {
        let lang = shared.lang;
        let ctx = ui.ctx().clone();
        ui.horizontal_wrapped(|ui| {
            ui.label(Msg::LogsLevel.text(lang));
            egui::ComboBox::from_id_salt("log-level")
                .selected_text(self.filter.min_level.as_str())
                .show_ui(ui, |ui| {
                    for level in [
                        Level::Error,
                        Level::Warn,
                        Level::Info,
                        Level::Debug,
                        Level::Trace,
                    ] {
                        ui.selectable_value(&mut self.filter.min_level, level, level.as_str());
                    }
                });
            ui.label(Msg::LabelEnvironment.text(lang));
            let env_label = match &self.filter.environment {
                EnvFilter::All => Msg::LogsAll.text(lang).to_string(),
                EnvFilter::Default => Msg::DefaultEnvironment.text(lang).to_string(),
                EnvFilter::Named(n) => crate::text::display_safe(n, 64),
            };
            egui::ComboBox::from_id_salt("log-env")
                .selected_text(env_label)
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut self.filter.environment,
                        EnvFilter::All,
                        Msg::LogsAll.text(lang),
                    );
                    ui.selectable_value(
                        &mut self.filter.environment,
                        EnvFilter::Default,
                        Msg::DefaultEnvironment.text(lang),
                    );
                    for name in environments(&self.buffer) {
                        let label = crate::text::display_safe(&name, 64);
                        ui.selectable_value(
                            &mut self.filter.environment,
                            EnvFilter::Named(name),
                            label,
                        );
                    }
                });
            ui.label(Msg::LogsSearch.text(lang));
            ui.add(
                egui::TextEdit::singleline(&mut self.filter.text)
                    .char_limit(MAX_SEARCH_LEN)
                    .desired_width(160.0),
            );
            let mut follow = !self.paused;
            if ui
                .checkbox(&mut follow, Msg::LogsFollow.text(lang))
                .changed()
            {
                if follow {
                    self.resume();
                } else {
                    self.paused = true;
                }
            }
            if self.paused {
                ui.label(fill(
                    Msg::LogsPaused.text(lang),
                    &[("n", &self.pending.len().to_string())],
                ));
            }
        });
        ui.horizontal_wrapped(|ui| {
            if ui.button(Msg::LogsOpenFull.text(lang)).clicked() {
                let opened = shared
                    .os
                    .ok_or(ActionError::Unsupported)
                    .and_then(actions::open_full_log_spec)
                    .and_then(|spec| actions::spawn_detached(&spec));
                self.viewer_msg = opened.err().map(|e| {
                    tracing::warn!(error = %e, "could not open the full log");
                    Msg::LogsNoViewer
                });
            }
            let busy = self.bundle_job.is_some();
            if ui
                .add_enabled(!busy, egui::Button::new(Msg::LogsSaveBundle.text(lang)))
                .clicked()
            {
                self.save_bundle(&ctx, shared, obs, recovery);
            }
            if busy {
                ui.spinner();
            }
            if let Some(m) = self.bundle_msg {
                ui.label(m.text(lang));
            }
        });
        if shared.os == Some(Os::Linux) {
            ui.label(
                RichText::new(Msg::LogsJournalNote.text(lang))
                    .small()
                    .weak(),
            );
        }
        if let Some(m) = self.viewer_msg {
            ui.colored_label(color32(IconColor::Yellow), m.text(lang));
        }
        if self.unavailable {
            ui.colored_label(color32(IconColor::Yellow), Msg::LogsUnavailable.text(lang));
        }
        ui.separator();

        let rows: Vec<&Entry> = self
            .buffer
            .iter()
            .filter(|e| self.filter.matches(e))
            .collect();
        let row_height = ui.text_style_height(&egui::TextStyle::Monospace);
        egui::ScrollArea::both()
            .id_salt("log-rows")
            .stick_to_bottom(!self.paused)
            .auto_shrink([false, false])
            .show_rows(ui, row_height, rows.len(), |ui, range| {
                for entry in &rows[range] {
                    let text = match entry {
                        Entry::Record(r) => {
                            let color = match r.level {
                                Level::Error => color32(IconColor::Red),
                                Level::Warn => color32(IconColor::Yellow),
                                Level::Info => ui.visuals().text_color(),
                                Level::Debug | Level::Trace => ui.visuals().weak_text_color(),
                            };
                            RichText::new(render_record(r)).monospace().color(color)
                        }
                        Entry::Gap(n) => {
                            RichText::new(fill(Msg::LogsGap.text(lang), &[("n", &n.to_string())]))
                                .monospace()
                                .italics()
                        }
                        Entry::Restarted => RichText::new(Msg::LogsRestarted.text(lang))
                            .monospace()
                            .italics(),
                    };
                    ui.add(egui::Label::new(text).truncate());
                }
            });
    }
}
