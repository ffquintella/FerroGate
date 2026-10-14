//! MIA-side audit forwarder (feature F07).
//!
//! [`forward`] encodes an [`AuditEvent`] to canonical CBOR and submits it to
//! the CMIS `AppendAuditEvent` RPC. CMIS appends it to the per-shard Merkle
//! tree and seals a fresh STH; the returned leaf index lets the caller fetch
//! an inclusion proof for the event later.
//!
//! Since F20 Phase 0 every forward is **host-authenticated** (F19 §7.1
//! `HostCallAuth`): the request carries an [`AuditForwardDoc`]
//! `{v, host_uuid, issued_at, nonce, event_sha384}` signed with the host's
//! machine key under `ferrogate-audit-forward-v1`, plus the SVID that binds
//! that key (`cnf.jkt`). CMIS refuses unsigned, stale, replayed or tampered
//! forwards, forwards from revoked hosts, CMIS-side event types and hosts
//! over their rate limit. Each call signs a fresh document with a new random
//! nonce, so a retry after `rate_limited` is a new call, not a replay.
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
use ferro_proto::v1::{AppendAuditRequest, HostCallAuth};
use ferro_svid::host_call::{self, AuditForwardDoc, HostCallDocError, AUDIT_FORWARD_CONTEXT};
use tonic::transport::Channel;

/// Failure modes for the audit forwarder.
#[derive(Debug, thiserror::Error)]
pub enum AuditForwardError {
    /// CBOR encoding of the event failed.
    #[error("encode: {0}")]
    Encode(#[from] EventCodecError),
    /// CBOR encoding of the host proof document failed.
    #[error("proof document: {0}")]
    Doc(#[from] HostCallDocError),
    /// The machine key refused to sign the proof.
    #[error("sign: {0}")]
    Sign(#[from] ferro_sep::SepError),
    /// The RPC failed.
    #[error("transport: {0}")]
    Transport(#[from] tonic::Status),
}

/// The host credentials that authenticate an `AppendAuditEvent` call: the
/// machine key, the SVID bound to it through `cnf.jkt`, and the host UUID
/// that SVID names (the last segment of `spiffe://<td>/host/<uuid>`).
pub struct HostProofSigner<'a> {
    /// The machine key (Secure Enclave or software) the SVID is bound to.
    pub key: &'a (dyn ferro_sep::MachineKey + Sync),
    /// The host's current compact-JWS SVID.
    pub svid_jws: &'a str,
    /// The host UUID the SVID names.
    pub host_uuid: &'a str,
}

/// Build the host-signed `AppendAuditEvent` request for `event_cbor`, issued
/// at `issued_at` with `nonce`. [`forward`] calls it with the current time and
/// a fresh random nonce; it is public so the proof can be checked offline.
pub fn signed_request(
    event_cbor: Vec<u8>,
    signer: &HostProofSigner<'_>,
    issued_at: i64,
    nonce: [u8; host_call::NONCE_LEN],
) -> Result<AppendAuditRequest, AuditForwardError> {
    let doc = AuditForwardDoc::new(signer.host_uuid, issued_at, nonce, &event_cbor);
    let doc = host_call::encode_audit_forward(&doc)?;
    let sig = signer
        .key
        .sign(&host_call::signing_input(AUDIT_FORWARD_CONTEXT, &doc))?;
    Ok(AppendAuditRequest {
        event_cbor,
        auth: Some(HostCallAuth {
            svid_jws: signer.svid_jws.to_string(),
            sep_pub: signer.key.public_spki_der(),
            sig,
        }),
        doc,
    })
}

/// Forward `event` to CMIS, host-signed by `signer`, and return the leaf
/// index it was appended at.
pub async fn forward(
    client: &mut MachineIdentityClient<Channel>,
    event: &AuditEvent,
    signer: &HostProofSigner<'_>,
) -> Result<u64, AuditForwardError> {
    use rand_core::{Rng as _, UnwrapErr};
    let bytes = event::encode(event)?;
    let mut nonce = [0u8; host_call::NONCE_LEN];
    UnwrapErr(getrandom::SysRng).fill_bytes(&mut nonce);
    let issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    let request = signed_request(bytes, signer, issued_at, nonce)?;
    let resp = client.append_audit_event(request).await?.into_inner();
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
    use ferro_sep::MachineKey as _;

    /// The request carries a proof CMIS can verify: the signature covers
    /// `ferrogate-audit-forward-v1 ‖ doc` under the presented key, and the
    /// document names the host and binds these exact event bytes.
    #[test]
    fn signed_request_carries_a_verifiable_host_proof() {
        let key = ferro_sep::SoftwareMachineKey::generate().unwrap();
        let signer = HostProofSigner {
            key: &key,
            svid_jws: "header.claims.sig",
            host_uuid: "1b4e28ba-2fa1-4d2a-883f-0016d3cca427",
        };
        let event_cbor = event::encode(&AuditEvent::LocalDenied {
            pid: 7,
            uid: 1000,
            bin_sha: ferro_audit::Hash384([1; 48]),
            reason: "not_allowlisted".into(),
        })
        .unwrap();
        let req = signed_request(event_cbor.clone(), &signer, 1_700_000_000, [9; 16]).unwrap();

        assert_eq!(req.event_cbor, event_cbor);
        let auth = req.auth.expect("a host proof");
        assert_eq!(auth.svid_jws, "header.claims.sig");
        assert_eq!(auth.sep_pub, key.public_spki_der());
        ferro_sep::verify_p256(
            &auth.sep_pub,
            &host_call::signing_input(AUDIT_FORWARD_CONTEXT, &req.doc),
            &auth.sig,
        )
        .expect("signature over context ‖ doc");
        let doc = host_call::decode_audit_forward(&req.doc).unwrap();
        assert_eq!(doc.host_uuid, "1b4e28ba-2fa1-4d2a-883f-0016d3cca427");
        assert_eq!(doc.issued_at, 1_700_000_000);
        assert_eq!(doc.nonce, [9; 16]);
        assert!(doc.binds_event(&event_cbor));
    }

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
