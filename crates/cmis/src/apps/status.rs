//! `GetAppRequestStatus` (F19 §7.1, §7.3): the state of a host's own
//! requests. Ids of other hosts and unknown ids are silently omitted, so the
//! lookup is no cross-host oracle; the ledger query is scoped to the
//! authenticated host.

use ferro_proto::v1::{AppRequestStatus, GetAppRequestStatusResponse};
use ferro_raft::apps::RequestState;
use ferro_svid::app_docs::AppStatusDoc;
use tonic::Status;

use super::intake::wire_state;
use super::ledger_status;
use crate::host_auth::AuthenticatedHost;
use crate::state::CmisState;

/// Answer a status document from an authenticated host.
pub async fn status(
    state: &CmisState,
    host: &AuthenticatedHost,
    doc: &AppStatusDoc,
) -> Result<GetAppRequestStatusResponse, Status> {
    let ids: Vec<String> = doc
        .request_ids
        .iter()
        .map(|b| uuid::Uuid::from_bytes(*b).to_string())
        .collect();
    let rows = state
        .cluster()
        .app_requests_of_host(&host.host_uuid, &ids)
        .await
        .map_err(ledger_status)?;
    let items = rows
        .into_iter()
        .map(|r| {
            let denied = r.state == RequestState::Denied;
            AppRequestStatus {
                request_id: r.request_id,
                state: wire_state(r.state).into(),
                approval_id: r.resulting_approval_id.unwrap_or_default(),
                revision: u32::try_from(r.revision).unwrap_or(0),
                decided_at: r.decided_at.unwrap_or_default(),
                deny_reason_code: if denied {
                    u32::try_from(r.decision_reason_code.unwrap_or_default()).unwrap_or(0)
                } else {
                    0
                },
                deny_message: if denied {
                    r.decision_message.unwrap_or_default()
                } else {
                    String::new()
                },
            }
        })
        .collect();
    Ok(GetAppRequestStatusResponse { items })
}
