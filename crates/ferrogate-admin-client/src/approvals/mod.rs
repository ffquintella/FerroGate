//! Request and approval administration (F19 §7, F21 §3–§6, F22 §4), shared
//! by the TUI and the tray admin client: the reads (`ListAppRequests`,
//! `GetAppRequest`, `ListApprovals`, `GetApproval`), the decisions and edits
//! ([`Mutation`]), the decision [`rules`] and the list [`filters`].

//! A mutation carries no secret, so a front end keeps it for the single
//! retry after a step-up (F20 §7 "S"), with the same idempotency key.

pub mod filters;
pub mod rules;

/// The protocol messages these calls take and return, so front ends need no
/// `ferro-proto` dependency of their own.
pub mod proto {
    pub use ferro_proto::admin_v1::{
        approve_app_request_request, AppBinaryInfo, AppRequestInfo, AppUser, ApprovalInfo,
        ApprovalRevisionInfo, ApprovalTerms, ApproveAppRequestRequest, ApproveAppRequestResponse,
        DenyAppRequestRequest, DenyAppRequestResponse, GetAppRequestResponse, GetApprovalResponse,
        ListAppRequestsRequest, ListAppRequestsResponse, ListApprovalsRequest,
        ListApprovalsResponse, PageRequest, RevokeApprovalRequest, RevokeApprovalResponse,
        SetLineageAutoUpdateFrozenRequest, UpdateApprovalRequest, UpdateApprovalResponse,
    };
}

use std::time::Duration;

use ferro_proto::admin_v1::{
    ApproveAppRequestRequest, ApproveAppRequestResponse, DenyAppRequestRequest,
    DenyAppRequestResponse, GetAppRequestRequest, GetAppRequestResponse, GetApprovalRequest,
    GetApprovalResponse, ListAppRequestsRequest, ListAppRequestsResponse, ListApprovalsRequest,
    ListApprovalsResponse, RevokeApprovalRequest, RevokeApprovalResponse,
    SetLineageAutoUpdateFrozenRequest, UpdateApprovalRequest, UpdateApprovalResponse,
};

use crate::client::{authenticated_error, Admin, AdminSession};
use crate::error::{ClientError, RpcError};
use crate::transport::within;

/// Longest request or approval id sent back to the server, in bytes.
pub const MAX_RECORD_ID_LEN: usize = 64;

/// A decision or edit (step-up operations, F20 §7 "S").
#[derive(Debug, Clone, PartialEq)]
pub enum Mutation {
    /// `ApproveAppRequest`.
    Approve(ApproveAppRequestRequest),
    /// `DenyAppRequest`.
    Deny(DenyAppRequestRequest),
    /// `UpdateApproval`.
    Update(UpdateApprovalRequest),
    /// `RevokeApproval`.
    Revoke(RevokeApprovalRequest),
    /// `SetLineageAutoUpdateFrozen`.
    Freeze(SetLineageAutoUpdateFrozenRequest),
}

impl Mutation {
    /// The idempotency key the request carries.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        match self {
            Self::Approve(r) => &r.idempotency_key,
            Self::Deny(r) => &r.idempotency_key,
            Self::Update(r) => &r.idempotency_key,
            Self::Revoke(r) => &r.idempotency_key,
            Self::Freeze(r) => &r.idempotency_key,
        }
    }
}

/// The outcome of a [`Mutation`].
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)] // one value per mutation; callers box it.
pub enum Mutated {
    /// `ApproveAppRequest`.
    Approved(ApproveAppRequestResponse),
    /// `DenyAppRequest`.
    Denied(DenyAppRequestResponse),
    /// `UpdateApproval`.
    Updated(UpdateApprovalResponse),
    /// `RevokeApproval`.
    Revoked(RevokeApprovalResponse),
    /// `SetLineageAutoUpdateFrozen` (the new state).
    Frozen(bool),
}

/// Whether `id` looks like a request or approval id CMIS issues: short and
/// printable ASCII. Others are never sent back.
#[must_use]
pub fn valid_record_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_RECORD_ID_LEN && id.bytes().all(|b| b.is_ascii_graphic())
}

/// Send `m` on `admin` within `timeout`.
///
/// # Errors
/// The server's status.
pub async fn send(
    admin: &mut Admin,
    timeout: Duration,
    m: Mutation,
) -> Result<Mutated, tonic::Status> {
    match m {
        Mutation::Approve(r) => within(timeout, admin.approve_app_request(r))
            .await
            .map(|x| Mutated::Approved(x.into_inner())),
        Mutation::Deny(r) => within(timeout, admin.deny_app_request(r))
            .await
            .map(|x| Mutated::Denied(x.into_inner())),
        Mutation::Update(r) => within(timeout, admin.update_approval(r))
            .await
            .map(|x| Mutated::Updated(x.into_inner())),
        Mutation::Revoke(r) => within(timeout, admin.revoke_approval(r))
            .await
            .map(|x| Mutated::Revoked(x.into_inner())),
        Mutation::Freeze(r) => {
            let frozen = r.frozen;
            within(timeout, admin.set_lineage_auto_update_frozen(r))
                .await
                .map(|_| Mutated::Frozen(frozen))
        }
    }
}

/// `ListAppRequests` on `admin` within `timeout`.
///
/// # Errors
/// The server's status.
pub async fn list_requests(
    admin: &mut Admin,
    timeout: Duration,
    req: ListAppRequestsRequest,
) -> Result<ListAppRequestsResponse, tonic::Status> {
    within(timeout, admin.list_app_requests(req))
        .await
        .map(tonic::Response::into_inner)
}

/// `GetAppRequest` on `admin` within `timeout`.
///
/// # Errors
/// The server's status.
pub async fn get_request(
    admin: &mut Admin,
    timeout: Duration,
    request_id: String,
) -> Result<GetAppRequestResponse, tonic::Status> {
    within(
        timeout,
        admin.get_app_request(GetAppRequestRequest { request_id }),
    )
    .await
    .map(tonic::Response::into_inner)
}

/// `ListApprovals` on `admin` within `timeout`.
///
/// # Errors
/// The server's status.
pub async fn list_approvals(
    admin: &mut Admin,
    timeout: Duration,
    req: ListApprovalsRequest,
) -> Result<ListApprovalsResponse, tonic::Status> {
    within(timeout, admin.list_approvals(req))
        .await
        .map(tonic::Response::into_inner)
}

/// `GetApproval` on `admin` within `timeout`.
///
/// # Errors
/// The server's status.
pub async fn get_approval(
    admin: &mut Admin,
    timeout: Duration,
    approval_id: String,
) -> Result<GetApprovalResponse, tonic::Status> {
    within(
        timeout,
        admin.get_approval(GetApprovalRequest { approval_id }),
    )
    .await
    .map(tonic::Response::into_inner)
}

fn bad_id() -> ClientError {
    ClientError::Other(RpcError::local(tonic::Code::InvalidArgument, "invalid id"))
}

impl AdminSession {
    /// The typed client of a signed-in session, and the RPC deadline.
    async fn signed_in(&mut self) -> Result<(Admin, Duration), ClientError> {
        if !self.has_session() {
            return Err(ClientError::SessionEnded);
        }
        let timeout = self.config().rpc_timeout;
        let admin = self.admin().await.map_err(ClientError::Connect)?;
        Ok((admin, timeout))
    }

    /// `ListAppRequests`.
    ///
    /// # Errors
    /// [`ClientError::SessionEnded`] (token wiped) or another error.
    pub async fn list_requests(
        &mut self,
        req: ListAppRequestsRequest,
    ) -> Result<ListAppRequestsResponse, ClientError> {
        let r = async {
            let (mut admin, timeout) = self.signed_in().await?;
            list_requests(&mut admin, timeout, req)
                .await
                .map_err(|s| authenticated_error(&s))
        }
        .await;
        self.finish(r)
    }

    /// `GetAppRequest`; a malformed id is refused here (nothing sent).
    ///
    /// # Errors
    /// [`ClientError::SessionEnded`] (token wiped) or another error.
    pub async fn get_request(
        &mut self,
        request_id: &str,
    ) -> Result<GetAppRequestResponse, ClientError> {
        if !valid_record_id(request_id) {
            return Err(bad_id());
        }
        let r = async {
            let (mut admin, timeout) = self.signed_in().await?;
            get_request(&mut admin, timeout, request_id.to_string())
                .await
                .map_err(|s| authenticated_error(&s))
        }
        .await;
        self.finish(r)
    }

    /// `ListApprovals`.
    ///
    /// # Errors
    /// [`ClientError::SessionEnded`] (token wiped) or another error.
    pub async fn list_approvals(
        &mut self,
        req: ListApprovalsRequest,
    ) -> Result<ListApprovalsResponse, ClientError> {
        let r = async {
            let (mut admin, timeout) = self.signed_in().await?;
            list_approvals(&mut admin, timeout, req)
                .await
                .map_err(|s| authenticated_error(&s))
        }
        .await;
        self.finish(r)
    }

    /// `GetApproval`; a malformed id is refused here (nothing sent).
    ///
    /// # Errors
    /// [`ClientError::SessionEnded`] (token wiped) or another error.
    pub async fn get_approval(
        &mut self,
        approval_id: &str,
    ) -> Result<GetApprovalResponse, ClientError> {
        if !valid_record_id(approval_id) {
            return Err(bad_id());
        }
        let r = async {
            let (mut admin, timeout) = self.signed_in().await?;
            get_approval(&mut admin, timeout, approval_id.to_string())
                .await
                .map_err(|s| authenticated_error(&s))
        }
        .await;
        self.finish(r)
    }

    /// Send a decision or edit. A `step_up_required` answer
    /// ([`ClientError::needs_step_up`]) leaves the caller to step up and
    /// send the same `m` (same idempotency key) once more.
    ///
    /// # Errors
    /// [`ClientError::SessionEnded`] (token wiped) or another error; a
    /// concurrent change of an approval is `Other` with code `ABORTED`.
    pub async fn mutate(&mut self, m: Mutation) -> Result<Mutated, ClientError> {
        let r = async {
            let (mut admin, timeout) = self.signed_in().await?;
            send(&mut admin, timeout, m)
                .await
                .map_err(|s| authenticated_error(&s))
        }
        .await;
        self.finish(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientConfig;
    use crate::transport::{CONNECT_TIMEOUT, RPC_TIMEOUT};
    use ferro_crypto::pin::SpkiPin;

    fn session() -> AdminSession {
        AdminSession::new(ClientConfig {
            endpoint: "https://127.0.0.1:1".into(),
            pins: vec![SpkiPin::from_hex(&"a".repeat(96)).unwrap()],
            device_token_path: None,
            connect_timeout: CONNECT_TIMEOUT,
            rpc_timeout: RPC_TIMEOUT,
            client_kind: crate::client_kind::TRAY,
        })
    }

    #[test]
    fn record_ids_are_short_and_printable() {
        assert!(valid_record_id("0190f0aa-0000-7000-8000-00000000beef"));
        for bad in ["", "a b", "x\u{1b}[2J", &"a".repeat(65)] {
            assert!(!valid_record_id(bad), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn without_a_session_nothing_is_sent() {
        let mut s = session();
        let m = Mutation::Freeze(rules::freeze_request("lin", true, "k".into()));
        assert_eq!(m.idempotency_key(), "k");
        assert_eq!(s.mutate(m).await, Err(ClientError::SessionEnded));
        assert_eq!(
            s.list_requests(ListAppRequestsRequest::default()).await,
            Err(ClientError::SessionEnded)
        );
        assert_eq!(s.get_approval("a-1").await, Err(ClientError::SessionEnded));
        assert!(matches!(
            s.get_request("bad id").await,
            Err(ClientError::Other(e)) if e.code == tonic::Code::InvalidArgument
        ));
    }
}
