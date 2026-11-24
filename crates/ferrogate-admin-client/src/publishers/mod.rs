//! Trusted publishers (ADR-0006): the one client API the `ferrogate` CLI and
//! the tray admin client share. Reading an identity locally ([`inspect`]),
//! building and checking requests ([`draft`]), showing records ([`view`]),
//! and the three RPCs, which CMIS authorizes like any admin call (F20 §7).

//! Adding needs `publisher.manage` and a fresh second factor on every call
//! (a step-up window never replaces it); removing needs `publisher.manage`
//! and a recent step-up. There is no other path: a MIA, or an application
//! asking it for access, cannot reach these RPCs.

pub mod draft;
pub mod inspect;
pub mod view;

/// The protocol messages, so front ends need no `ferro-proto` dependency.
pub mod proto {
    pub use ferro_proto::admin_v1::{
        AddTrustedPublisherRequest, AddTrustedPublisherResponse, ListTrustedPublishersRequest,
        ListTrustedPublishersResponse, RemoveTrustedPublisherRequest,
        RemoveTrustedPublisherResponse, TrustedPublisherInfo,
    };
}

use std::time::Duration;

pub use ferro_codesign::{CertFacts, PinKind, SignatureKind};

use ferro_proto::admin_v1::{
    AddTrustedPublisherRequest, ListTrustedPublishersRequest, RemoveTrustedPublisherRequest,
    TrustedPublisherInfo,
};

use crate::client::{authenticated_error, Admin, AdminSession, Factor};
use crate::error::ClientError;
use crate::transport::within;

/// `ListTrustedPublishers` on `admin` within `timeout`.
///
/// # Errors
/// The server's status.
pub async fn list(
    admin: &mut Admin,
    timeout: Duration,
    include_removed: bool,
) -> Result<Vec<TrustedPublisherInfo>, tonic::Status> {
    within(
        timeout,
        admin.list_trusted_publishers(ListTrustedPublishersRequest { include_removed }),
    )
    .await
    .map(|r| r.into_inner().publishers)
}

/// `AddTrustedPublisher` on `admin` within `timeout`, as `req` is (with its
/// proof).
///
/// # Errors
/// The server's status.
pub async fn add(
    admin: &mut Admin,
    timeout: Duration,
    req: AddTrustedPublisherRequest,
) -> Result<Option<TrustedPublisherInfo>, tonic::Status> {
    within(timeout, admin.add_trusted_publisher(req))
        .await
        .map(|r| r.into_inner().publisher)
}

/// `RemoveTrustedPublisher` on `admin` within `timeout`.
///
/// # Errors
/// The server's status.
pub async fn remove(
    admin: &mut Admin,
    timeout: Duration,
    req: RemoveTrustedPublisherRequest,
) -> Result<Option<TrustedPublisherInfo>, tonic::Status> {
    within(timeout, admin.remove_trusted_publisher(req))
        .await
        .map(|r| r.into_inner().publisher)
}

impl AdminSession {
    /// `ListTrustedPublishers`.
    ///
    /// # Errors
    /// [`ClientError::SessionEnded`] (token wiped) or another error.
    pub async fn list_trusted_publishers(
        &mut self,
        include_removed: bool,
    ) -> Result<Vec<TrustedPublisherInfo>, ClientError> {
        let r = async {
            self.require_session()?;
            let timeout = self.config().rpc_timeout;
            let mut admin = self.admin().await.map_err(ClientError::Connect)?;
            list(&mut admin, timeout, include_removed)
                .await
                .map_err(|s| authenticated_error(&s))
        }
        .await;
        self.finish(r)
    }

    /// `AddTrustedPublisher` with a fresh `proof` (a TOTP code or a key's
    /// assertion); a lock during the key prompt sends nothing.
    ///
    /// # Errors
    /// [`ClientError::Rejected`] for a wrong proof (nothing changed), or as
    /// [`AdminSession::step_up`].
    pub async fn add_trusted_publisher(
        &mut self,
        mut req: AddTrustedPublisherRequest,
        proof: Factor,
    ) -> Result<Option<TrustedPublisherInfo>, ClientError> {
        let epoch = self.require_session()?;
        let r = async {
            req.proof = Some(self.proof(epoch, proof).await?);
            self.still(epoch)?;
            let timeout = self.config().rpc_timeout;
            let mut admin = self.admin().await.map_err(ClientError::Connect)?;
            add(&mut admin, timeout, req)
                .await
                .map_err(|s| ClientError::from_credential_status(&s))
        }
        .await;
        self.finish(r)
    }

    /// `RemoveTrustedPublisher`. A `step_up_required` answer
    /// ([`ClientError::needs_step_up`]) leaves the caller to step up and
    /// send the same `req` once more.
    ///
    /// # Errors
    /// [`ClientError::SessionEnded`] (token wiped) or another error.
    pub async fn remove_trusted_publisher(
        &mut self,
        req: RemoveTrustedPublisherRequest,
    ) -> Result<Option<TrustedPublisherInfo>, ClientError> {
        let r = async {
            self.require_session()?;
            let timeout = self.config().rpc_timeout;
            let mut admin = self.admin().await.map_err(ClientError::Connect)?;
            remove(&mut admin, timeout, req)
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
    use crate::secret::Secret;
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

    #[tokio::test]
    async fn without_a_session_nothing_is_sent() {
        let mut s = session();
        assert_eq!(
            s.list_trusted_publishers(false).await,
            Err(ClientError::SessionEnded)
        );
        let req = draft::remove_request("p-1", "k".into()).unwrap();
        assert_eq!(
            s.remove_trusted_publisher(req).await,
            Err(ClientError::SessionEnded)
        );
        let add = AddTrustedPublisherRequest::default();
        let mut secret = Secret::new();
        secret.push_str("123456");
        let code = Factor::Totp(secret);
        assert_eq!(
            s.add_trusted_publisher(add, code).await,
            Err(ClientError::SessionEnded)
        );
    }
}
