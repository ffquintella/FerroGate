//! MIA-side audit forwarder (feature F07).
//!
//! [`forward`] encodes an [`AuditEvent`] to canonical CBOR and submits it to
//! the CMIS `AppendAuditEvent` RPC. CMIS appends it to the per-shard Merkle
//! tree and seals a fresh STH; the returned leaf index lets the caller fetch
//! an inclusion proof for the event later.
//!
//! Local helper-API events (`LocalGrant`, `LocalDenied`) flow here: the
//! [`crate::helper`] server (F08) pushes one event per request onto an `mpsc`
//! channel, and a forwarder task drains it through [`forward`] to CMIS,
//! decoupling token-minting latency from the audit network path.
//!
//! One-shot CLI commands have no daemon channel to push onto. They record
//! their events with [`append_local`] instead: an append-only JSON-lines
//! journal beside the file they changed (today: `ConfigChanged` from
//! `mia setup`, feature F18). Forwarding that journal to CMIS is a follow-up.

use ferro_audit::{event, AuditEvent, EventCodecError};
use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_proto::v1::AppendAuditRequest;
use tonic::transport::Channel;

/// Failure modes for the audit forwarder.
#[derive(Debug, thiserror::Error)]
pub enum AuditForwardError {
    /// CBOR encoding of the event failed.
    #[error("encode: {0}")]
    Encode(#[from] EventCodecError),
    /// The RPC failed.
    #[error("transport: {0}")]
    Transport(#[from] tonic::Status),
}

/// Forward `event` to CMIS and return the leaf index it was appended at.
pub async fn forward(
    client: &mut MachineIdentityClient<Channel>,
    event: &AuditEvent,
) -> Result<u64, AuditForwardError> {
    let bytes = event::encode(event)?;
    let resp = client
        .append_audit_event(AppendAuditRequest { event_cbor: bytes })
        .await?
        .into_inner();
    Ok(resp.leaf_index)
}

/// File name of the local audit journal kept beside a configuration file.
pub const LOCAL_JOURNAL_NAME: &str = "config-audit.jsonl";

/// The local audit journal for events about `config_path`: a
/// [`LOCAL_JOURNAL_NAME`] file in the same directory (so it inherits that
/// directory's protection — root-owned for the system configuration).
#[must_use]
pub fn local_journal_for(config_path: &std::path::Path) -> std::path::PathBuf {
    config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(
            || std::path::PathBuf::from(LOCAL_JOURNAL_NAME),
            |p| p.join(LOCAL_JOURNAL_NAME),
        )
}

/// Append `event` to the local JSON-lines journal at `journal`, one
/// `{"ts": <unix secs>, "event": {...}}` object per line, opened in append
/// mode (created `0640` on Unix) and flushed to disk before returning.
///
/// A failure is returned, never swallowed: callers must not report a change
/// as done when its audit record could not be written.
pub fn append_local(journal: &std::path::Path, event: &AuditEvent) -> std::io::Result<()> {
    use std::io::Write as _;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let line = serde_json::json!({ "ts": ts, "event": event });
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o640);
    }
    let mut f = opts.open(journal)?;
    let mut bytes = serde_json::to_vec(&line).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    f.write_all(&bytes)?;
    f.sync_data()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_journal_appends_one_json_line_per_event() {
        let dir = std::env::temp_dir().join(format!("mia-audit-local-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let journal = local_journal_for(&dir.join("mia.toml"));
        assert_eq!(journal, dir.join(LOCAL_JOURNAL_NAME));
        for n in 0..2 {
            append_local(
                &journal,
                &AuditEvent::ConfigChanged {
                    path: format!("/etc/ferrogate/mia-{n}.toml"),
                    by_uid: 1000,
                    keys: vec!["cmis.endpoint".into()],
                },
            )
            .unwrap();
        }
        let text = std::fs::read_to_string(&journal).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let v: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(v["event"]["type"], "ConfigChanged");
        assert_eq!(v["event"]["keys"][0], "cmis.endpoint");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
