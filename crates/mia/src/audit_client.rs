//! MIA-side audit forwarder (feature F07).
//!
//! [`forward`] encodes an [`AuditEvent`] to canonical CBOR and submits it to
//! the CMIS `AppendAuditEvent` RPC. CMIS appends it to the per-shard Merkle
//! tree and seals a fresh STH; the returned leaf index lets the caller fetch
//! an inclusion proof for the event later.
//!
//! Local helper-API events (`LocalGrant`, `LocalDenied`) land here once F08
//! ships; for now the forwarder lets MIA emit any of the documented event
//! variants for tests and bring-up.

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
