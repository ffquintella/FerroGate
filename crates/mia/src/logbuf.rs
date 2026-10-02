//! `logbuf` — a bounded, redacting in-memory ring buffer of the daemon's own
//! log records, served through the status endpoint (feature F18).
//!
//! [`LogBufferLayer`] is a `tracing_subscriber` layer. It is installed *under*
//! the daemon's global (reloadable) filter, so it only ever sees records the
//! daemon's own `log` directive already enables — a status client cannot raise
//! the verbosity.
//!
//! **Redaction happens before insertion.** A record keeps its level,
//! timestamp, target, environment and message; every structured field passes
//! through [`redact_field`] first:
//!
//! - fields whose *name* marks them sensitive (`token`, `svid`, `key`,
//!   `secret`, `pin`, `jwk`, `dpop`, `authorization`, `jws`, `jti`, `sig`,
//!   `password`, `cookie`, `seed`, `bin_sha`, and the exact names `pid` /
//!   `uid`) are masked;
//! - raw byte blobs (`record_bytes`, or a `Debug` rendering that is a list of
//!   integers) are masked;
//! - every remaining value — and the message — is scrubbed of anything that
//!   looks like a compact JWS, a long hex string (hashes, pins, `jti`s) or a
//!   long base64 blob, has control characters escaped, and is truncated to
//!   [`MAX_VALUE_BYTES`].
//!
//! Records on the [`AUDIT_TARGET`] target (the helper-API audit stream, whose
//! events carry caller pid/uid/binary hashes and token `jti`s) are never
//! buffered at all.
//!
//! Capacity is bounded twice — by record count and by an approximate byte
//! total — and either limit set to `0` disables the buffer. Every record gets
//! a monotonic `seq`; a reader that falls behind learns how many records it
//! missed from [`LogTailResp::dropped`].

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use mia_status_proto::{Level, LogField, LogRecord, LogTailResp};
use tracing::field::{Field, Visit};
use tracing::span;
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// The `tracing` target the daemon logs helper-API audit events under. The
/// ring buffer drops this target entirely: audit events carry caller
/// identities and token `jti`s that must never reach a status client.
pub const AUDIT_TARGET: &str = "mia::audit";

/// Longest rendered value (and message) kept, in bytes.
pub const MAX_VALUE_BYTES: usize = 512;

/// Most structured fields kept per record; the rest are dropped.
pub const MAX_FIELDS: usize = 16;

/// Longest field name kept, in bytes.
const MAX_NAME_BYTES: usize = 64;

/// Fixed per-record overhead added to the byte accounting.
const RECORD_OVERHEAD: usize = 64;

/// Marker substituted for a masked value.
pub const REDACTED: &str = "[redacted]";

/// Substrings that mark a field *name* as sensitive (matched
/// case-insensitively).
const SENSITIVE_NAME_PARTS: &[&str] = &[
    "token",
    "svid",
    "key",
    "secret",
    "pin",
    "jwk",
    "dpop",
    "authorization",
    "jws",
    "jti",
    "sig",
    "password",
    "passwd",
    "cookie",
    "credential",
    "seed",
    "bin_sha",
    "nonce",
];

/// Field names that are sensitive only as an exact match (caller identities
/// from the helper audit stream).
const SENSITIVE_EXACT_NAMES: &[&str] = &[
    "pid",
    "uid",
    "caller_pid",
    "caller_uid",
    "peer_pid",
    "peer_uid",
];

/// The bounded ring buffer. Cheap to share (`Arc`); every operation holds the
/// lock briefly and never logs while holding it.
#[derive(Debug)]
pub struct LogBuffer {
    inner: Mutex<Inner>,
    buffer_id: u64,
    max_records: usize,
    max_bytes: usize,
}

#[derive(Debug, Default)]
struct Inner {
    records: VecDeque<(LogRecord, usize)>,
    bytes: usize,
    next_seq: u64,
}

impl LogBuffer {
    /// A buffer holding at most `max_records` records and about `max_bytes`
    /// bytes. Either limit `0` makes a disabled buffer that stores nothing.
    #[must_use]
    pub fn new(max_records: usize, max_bytes: usize) -> Arc<Self> {
        use getrandom::SysRng;
        use rand_core::{Rng as _, UnwrapErr};
        Arc::new(Self {
            inner: Mutex::new(Inner::default()),
            buffer_id: UnwrapErr(SysRng).next_u64(),
            max_records,
            max_bytes,
        })
    }

    /// Whether the buffer stores anything at all.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.max_records > 0 && self.max_bytes > 0
    }

    /// This run's buffer identity (see [`LogTailResp::buffer_id`]).
    #[must_use]
    pub fn buffer_id(&self) -> u64 {
        self.buffer_id
    }

    /// Append an already-redacted record, assigning its `seq` and evicting the
    /// oldest records until both limits hold. A record larger than the whole
    /// byte budget is counted (its `seq` is consumed) but not stored.
    pub fn push(&self, mut record: LogRecord) {
        if !self.is_enabled() {
            return;
        }
        let size = record_size(&record);
        let Ok(mut inner) = self.inner.lock() else {
            return; // a poisoned lock only loses buffered diagnostics
        };
        record.seq = inner.next_seq;
        inner.next_seq = inner.next_seq.saturating_add(1);
        if size > self.max_bytes {
            return;
        }
        while inner.records.len() >= self.max_records || inner.bytes + size > self.max_bytes {
            match inner.records.pop_front() {
                Some((_, evicted)) => inner.bytes -= evicted,
                None => break,
            }
        }
        inner.bytes += size;
        inner.records.push_back((record, size));
    }

    /// Records with `seq >= since_seq` at `min_level` or more severe, oldest
    /// first: at most `max` of them and at most about `byte_budget` bytes.
    #[must_use]
    pub fn tail(
        &self,
        since_seq: u64,
        min_level: Level,
        max: usize,
        byte_budget: usize,
    ) -> LogTailResp {
        let Ok(inner) = self.inner.lock() else {
            return LogTailResp {
                records: Vec::new(),
                next_seq: since_seq,
                dropped: 0,
                buffer_id: self.buffer_id,
            };
        };
        // Everything below `oldest` that the reader had not seen is gone.
        let oldest = inner.records.front().map_or(inner.next_seq, |(r, _)| r.seq);
        let dropped = oldest.saturating_sub(since_seq);
        let mut records = Vec::new();
        let mut used = 0usize;
        // The cursor advances past filtered-out records too, so a follower
        // does not re-scan them, but stops at the first record that does not
        // fit so nothing is skipped.
        let mut next_seq = since_seq.max(oldest);
        let mut cut_short = false;
        for (record, size) in inner.records.iter().filter(|(r, _)| r.seq >= since_seq) {
            if record.level.passes(min_level) {
                if records.len() >= max || used + size > byte_budget {
                    cut_short = true;
                    break;
                }
                used += size;
                records.push(record.clone());
            }
            next_seq = record.seq + 1;
        }
        if !cut_short {
            // Fully caught up, including any oversize record whose `seq` was
            // consumed without being stored.
            next_seq = next_seq.max(inner.next_seq);
        }
        LogTailResp {
            records,
            next_seq,
            dropped,
            buffer_id: self.buffer_id,
        }
    }
}

/// Approximate heap size of a record, for the byte limit.
fn record_size(r: &LogRecord) -> usize {
    RECORD_OVERHEAD
        + r.target.len()
        + r.message.len()
        + r.environment.as_ref().map_or(0, String::len)
        + r.fields
            .iter()
            .map(|f| f.name.len() + f.value.len() + 16)
            .sum::<usize>()
}

/// The `tracing_subscriber` layer feeding a [`LogBuffer`].
#[derive(Debug, Clone)]
pub struct LogBufferLayer {
    buffer: Arc<LogBuffer>,
}

impl LogBufferLayer {
    /// A layer appending every record it sees to `buffer`.
    #[must_use]
    pub fn new(buffer: Arc<LogBuffer>) -> Self {
        Self { buffer }
    }
}

/// The environment label a span carries (`environment = ...`), stored in the
/// span's extensions so events inside it can be attributed.
struct SpanEnvironment(String);

/// Collects a span's `environment` field.
struct EnvVisitor(Option<String>);

impl Visit for EnvVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "environment" {
            self.0 = Some(sanitize_value(value));
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "environment" {
            let mut s = String::new();
            let _ = write!(s, "{value:?}");
            self.0 = Some(sanitize_value(s.trim_matches('"')));
        }
    }
}

/// Collects an event's message and fields, redacting as it goes.
#[derive(Default)]
struct EventVisitor {
    message: String,
    fields: Vec<LogField>,
}

impl EventVisitor {
    fn push(&mut self, field: &Field, raw: &str, is_bytes: bool) {
        if field.name() == "message" {
            self.message = sanitize_value(raw);
            return;
        }
        if self.fields.len() >= MAX_FIELDS {
            return;
        }
        let name = truncate(field.name(), MAX_NAME_BYTES).to_string();
        let value = if is_bytes {
            REDACTED.to_string()
        } else {
            redact_field(&name, raw)
        };
        self.fields.push(LogField { name, value });
    }
}

impl Visit for EventVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field, value, false);
    }

    fn record_bytes(&mut self, field: &Field, _value: &[u8]) {
        self.push(field, "", true);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        // Render once, bounded: a hostile or huge Debug impl is cut at a few
        // KiB before any scanning happens.
        let mut s = BoundedString::new(4 * MAX_VALUE_BYTES);
        let _ = write!(s, "{value:?}");
        self.push(field, &s.0, false);
    }
}

/// A `fmt::Write` sink that stops accepting text past a byte cap.
struct BoundedString(String, usize);

impl BoundedString {
    fn new(cap: usize) -> Self {
        Self(String::new(), cap)
    }
}

impl std::fmt::Write for BoundedString {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let room = self.1.saturating_sub(self.0.len());
        if room == 0 {
            return Ok(());
        }
        self.0.push_str(truncate(s, room));
        Ok(())
    }
}

impl<S> Layer<S> for LogBufferLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        if !self.buffer.is_enabled() {
            return;
        }
        let mut v = EnvVisitor(None);
        attrs.record(&mut v);
        if let (Some(env), Some(span)) = (v.0, ctx.span(id)) {
            span.extensions_mut().insert(SpanEnvironment(env));
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        if !self.buffer.is_enabled() {
            return;
        }
        let meta = event.metadata();
        if meta.target() == AUDIT_TARGET || meta.target().starts_with("mia::audit::") {
            return;
        }
        let mut v = EventVisitor::default();
        event.record(&mut v);
        let environment = ctx.event_scope(event).and_then(|scope| {
            scope.from_root().fold(None, |found, span| {
                span.extensions()
                    .get::<SpanEnvironment>()
                    .map(|e| e.0.clone())
                    .or(found)
            })
        });
        self.buffer.push(LogRecord {
            seq: 0,
            ts_ms: now_ms(),
            level: map_level(*meta.level()),
            target: truncate(meta.target(), MAX_NAME_BYTES).to_string(),
            environment,
            message: v.message,
            fields: v.fields,
        });
    }
}

/// Map a `tracing` level onto the wire level.
#[must_use]
pub fn map_level(level: tracing::Level) -> Level {
    match level {
        tracing::Level::ERROR => Level::Error,
        tracing::Level::WARN => Level::Warn,
        tracing::Level::INFO => Level::Info,
        tracing::Level::DEBUG => Level::Debug,
        tracing::Level::TRACE => Level::Trace,
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Whether a field name marks its value as sensitive.
#[must_use]
pub fn is_sensitive_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_EXACT_NAMES.contains(&lower.as_str())
        || SENSITIVE_NAME_PARTS.iter().any(|p| lower.contains(p))
}

/// Redact one structured field: a sensitive name or a byte-blob rendering is
/// masked outright; anything else is scrubbed, escaped and truncated.
#[must_use]
pub fn redact_field(name: &str, raw: &str) -> String {
    if is_sensitive_name(name) || looks_like_byte_list(raw) {
        return REDACTED.to_string();
    }
    sanitize_value(raw)
}

/// Scrub secret-looking runs out of free text, escape control characters and
/// truncate to [`MAX_VALUE_BYTES`].
#[must_use]
pub fn sanitize_value(raw: &str) -> String {
    let scrubbed = scrub_secrets(raw);
    let escaped = escape_control(&scrubbed);
    if escaped.len() > MAX_VALUE_BYTES {
        let mut t = truncate(&escaped, MAX_VALUE_BYTES - 3).to_string();
        t.push_str("...");
        t
    } else {
        escaped
    }
}

/// `Debug` of a `Vec<u8>` / `[u8; N]` renders as `[1, 2, 3, ...]`: treat a
/// bracketed list of eight or more integers as a byte blob.
fn looks_like_byte_list(s: &str) -> bool {
    let t = s.trim();
    let Some(inner) = t.strip_prefix('[').and_then(|r| r.strip_suffix(']')) else {
        return false;
    };
    let parts: Vec<&str> = inner.split(',').map(str::trim).collect();
    parts.len() >= 8
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Characters that can appear inside a base64 / base64url / hex run. `=` is
/// a separator, not part of a run, so `jti=<hex>` is judged on the `<hex>`
/// (base64 padding is irrelevant to the decision).
fn is_blob_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '_' | '-')
}

/// Whether one maximal blob-character run looks like secret material: a long
/// hex string (≥ 32 hex digits — SHA-2 digests, SPKI pins, 128-bit `jti`s), or
/// a long (≥ 40 chars) base64-ish run mixing upper case, lower case and
/// digits (key / token / signature encodings).
fn is_secretish_run(run: &str) -> bool {
    let core = run.trim_matches(|c| c == '-' || c == '_' || c == '/');
    if core.len() >= 32 && core.bytes().all(|b| b.is_ascii_hexdigit()) {
        return true;
    }
    if core.len() >= 40 {
        let upper = core.bytes().any(|b| b.is_ascii_uppercase());
        let lower = core.bytes().any(|b| b.is_ascii_lowercase());
        let digit = core.bytes().any(|b| b.is_ascii_digit());
        return upper && lower && digit;
    }
    false
}

/// Replace every secret-looking run in `s` with [`REDACTED`]. Dots split runs,
/// so each segment of a compact JWS (header.payload.signature) is judged on
/// its own — the long payload and signature segments are always caught.
fn scrub_secrets(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if is_secretish_run(run) {
            out.push_str(REDACTED);
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in s.chars() {
        if is_blob_char(c) {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

/// Escape control characters (newlines, escapes, NUL, ...) so a record can
/// never forge extra log lines or terminal sequences in a viewer.
fn escape_control(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

/// Truncate to at most `max` bytes on a `char` boundary.
fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::prelude::*;

    fn buffered(records: usize, bytes: usize, f: impl FnOnce()) -> Arc<LogBuffer> {
        let buf = LogBuffer::new(records, bytes);
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::filter::LevelFilter::INFO)
            .with(LogBufferLayer::new(Arc::clone(&buf)));
        tracing::subscriber::with_default(subscriber, f);
        buf
    }

    /// A fake compact JWS assembled at runtime from its decoded segments, so the
    /// source holds no literal `eyJ…` token for secret scanners to flag.
    fn fake_jws(header: &str, payload: &str, signature: &str) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        [header, payload, signature]
            .map(|segment| URL_SAFE_NO_PAD.encode(segment))
            .join(".")
    }

    fn all(buf: &LogBuffer) -> Vec<LogRecord> {
        buf.tail(0, Level::Trace, usize::MAX, usize::MAX).records
    }

    #[test]
    fn logbuf_redacts_sensitive_fields() {
        let jws = fake_jws(
            r#"{"alg":"EdDSA","kid":"cmis-1"}"#,
            r#"{"sub":"spiffe://ferrogate.test/host/abc","exp":1700000000}"#,
            "signature-bytes-that-are-long-enough-to-be-redacted",
        );
        let jws = jws.as_str();
        let pin = "a".repeat(96);
        let jti = "0123456789abcdef0123456789abcdef";
        let buf = buffered(100, 1 << 20, || {
            tracing::info!(
                token = jws,
                svid = "x",
                spki_pin = %pin,
                private_key = "-----BEGIN PRIVATE KEY-----",
                secret = "hunter2",
                jwk = "{}",
                dpop = "proof",
                authorization = "Bearer abc",
                pid = 4242,
                uid = 1000,
                bin_sha = "deadbeef",
                blob = ?vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9],
                error = %format!("bad token {jws} with jti {jti}"),
                path = "/var/lib/ferrogate/x",
                "minted {jws} for line\nforged"
            );
        });
        let recs = all(&buf);
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        let serialized = serde_json::to_string(r).unwrap();
        // None of the secret values survive anywhere in the record.
        for secret in [
            jws,
            pin.as_str(),
            jti,
            "hunter2",
            "BEGIN PRIVATE",
            "Bearer abc",
            "deadbeef",
            "proof",
        ] {
            assert!(
                !serialized.contains(secret),
                "leaked {secret:?}: {serialized}"
            );
        }
        for name in [
            "token",
            "svid",
            "spki_pin",
            "private_key",
            "secret",
            "jwk",
            "dpop",
            "authorization",
            "pid",
            "uid",
            "bin_sha",
            "blob",
        ] {
            let f = r.fields.iter().find(|f| f.name == name).unwrap();
            assert_eq!(f.value, REDACTED, "{name}");
        }
        // Non-sensitive fields are kept; secret-looking runs inside free text
        // are scrubbed; control characters are escaped.
        let path = r.fields.iter().find(|f| f.name == "path").unwrap();
        assert_eq!(path.value, "/var/lib/ferrogate/x");
        let err = r.fields.iter().find(|f| f.name == "error").unwrap();
        assert!(err.value.starts_with("bad token "), "{}", err.value);
        assert!(err.value.contains(REDACTED));
        assert!(!r.message.contains('\n'));
        assert!(r.message.contains("\\nforged"));
    }

    #[test]
    fn audit_target_is_never_buffered() {
        let buf = buffered(100, 1 << 20, || {
            tracing::info!(target: AUDIT_TARGET, event = "LocalGrant { pid: 1, uid: 2 }", "helper-api audit event");
            tracing::info!("kept");
        });
        let recs = all(&buf);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].message, "kept");
    }

    #[test]
    fn only_enabled_levels_are_buffered() {
        let buf = buffered(100, 1 << 20, || {
            tracing::debug!("filtered by the INFO directive");
            tracing::info!("info");
            tracing::error!("error");
        });
        let recs = all(&buf);
        assert_eq!(
            recs.iter().map(|r| r.message.as_str()).collect::<Vec<_>>(),
            ["info", "error"]
        );
        // min_level filtering on read.
        let errs = buf.tail(0, Level::Warn, 100, usize::MAX).records;
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].level, Level::Error);
    }

    #[test]
    fn environment_comes_from_the_enclosing_span() {
        let buf = buffered(100, 1 << 20, || {
            let span = tracing::info_span!("env", environment = %"staging");
            let _g = span.enter();
            tracing::info!("inside");
        });
        assert_eq!(all(&buf)[0].environment.as_deref(), Some("staging"));
    }

    #[test]
    fn ring_buffer_is_bounded_and_counts_drops() {
        let buf = buffered(3, 1 << 20, || {
            for i in 0..10 {
                tracing::info!("record {i}");
            }
        });
        let resp = buf.tail(0, Level::Trace, 100, usize::MAX);
        assert_eq!(resp.records.len(), 3);
        assert_eq!(resp.records[0].seq, 7);
        assert_eq!(resp.dropped, 7);
        assert_eq!(resp.next_seq, 10);
        // Following from next_seq yields nothing new and no drops.
        let again = buf.tail(resp.next_seq, Level::Trace, 100, usize::MAX);
        assert!(again.records.is_empty());
        assert_eq!(again.dropped, 0);
        assert_eq!(again.next_seq, 10);
        assert_eq!(again.buffer_id, resp.buffer_id);
    }

    #[test]
    fn byte_budget_bounds_the_buffer_and_the_reply() {
        let buf = buffered(10_000, 2_000, || {
            for i in 0..100 {
                tracing::info!(n = i, "a reasonably sized message to fill the budget");
            }
        });
        let resp = buf.tail(0, Level::Trace, 1000, usize::MAX);
        assert!(resp.records.len() < 100);
        let total: usize = resp.records.iter().map(record_size).sum();
        assert!(total <= 2_000);
        // A small reply budget pages without skipping.
        let first = buf.tail(0, Level::Trace, 2, usize::MAX);
        assert_eq!(first.records.len(), 2);
        let second = buf.tail(first.next_seq, Level::Trace, 2, usize::MAX);
        assert_eq!(second.records[0].seq, first.records[1].seq + 1);
    }

    #[test]
    fn zero_capacity_disables_the_buffer() {
        let buf = buffered(0, 1 << 20, || tracing::error!("nope"));
        assert!(!buf.is_enabled());
        assert!(all(&buf).is_empty());
        let buf = buffered(10, 0, || tracing::error!("nope"));
        assert!(all(&buf).is_empty());
    }

    #[test]
    fn values_are_truncated_and_escaped() {
        let long = "x".repeat(5000);
        let v = sanitize_value(&long);
        assert!(v.len() <= MAX_VALUE_BYTES);
        assert_eq!(sanitize_value("a\u{1b}[31mb"), "a\\u{1b}[31mb");
        // Multi-byte characters are cut on a boundary.
        let v = sanitize_value(&"é".repeat(400));
        assert!(v.len() <= MAX_VALUE_BYTES);
    }

    #[test]
    fn values_glued_with_equals_are_scrubbed() {
        let jti = "0123456789abcdef0123456789abcdef";
        let out = sanitize_value(&format!("refused jti={jti} sha256={}", "ab".repeat(32)));
        assert!(!out.contains(jti), "{out}");
        assert!(!out.contains(&"ab".repeat(32)), "{out}");
        assert!(out.starts_with("refused jti="));
    }

    #[test]
    fn ordinary_text_is_not_over_scrubbed() {
        for keep in [
            "spiffe://ferrogate.test/host/11111111-1111-8111-8111-111111111111",
            "https://cmis.example.com:8443",
            "/Library/Application Support/FerroGate/run/mia.sock",
            "could not reach CMIS; skipping allowlist fetch",
        ] {
            assert_eq!(sanitize_value(keep), keep);
        }
    }
}
