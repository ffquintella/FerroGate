//! Host-authenticated CMIS calls of feature F19 (§7.1): `SubmitAppRequest`,
//! `GetAppRequestStatus` and `SyncAllowlist`, plus the legacy, unauthenticated
//! `GetAllowlist` the allowlist sync falls back to on an older CMIS.
//!
//! Every host call carries a canonical-CBOR document from
//! `ferro_svid::app_docs` and a [`HostCallAuth`]: the host SVID, the machine
//! key's public half (CMIS checks it against the SVID's `cnf.jkt`) and the
//! machine-key signature over `context ‖ doc`, made by
//! [`crate::audit_client::host_call_auth`] exactly as audit forwarding signs.
//!
//! - [`HostCredentials`] / [`CredentialSlot`] — what signs, swapped when a
//!   re-attestation replaces the SVID.
//! - [`HostApi`] — the four RPCs behind a trait, so the sync loop and the
//!   registration outbox run against CMIS ([`ResolverApi`], with endpoint
//!   fail-over), an already-connected channel ([`ChannelApi`]) or a test
//!   double.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_proto::v1::{
    GetAllowlistRequest, GetAppRequestStatusRequest, GetAppRequestStatusResponse, HostCallAuth,
    SubmitAppRequestRequest, SubmitAppRequestResponse, SyncAllowlistRequest, SyncAllowlistResponse,
};
use futures::future::BoxFuture;
use tonic::transport::Channel;
use tonic::Status;

use crate::audit_client::{host_call_auth, HostProofSigner};

/// Deadline of one host RPC, connection included.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// The credentials that sign host calls: the machine key, the SVID bound to it
/// through `cnf.jkt`, and the identity that SVID names.
pub struct HostCredentials {
    /// The machine key the SVID binds.
    pub key: Arc<dyn ferro_sep::MachineKey + Send + Sync>,
    /// The host's compact-JWS SVID.
    pub svid_jws: String,
    /// The host UUID (last segment of `spiffe://<td>/host/<uuid>`).
    pub host_uuid: String,
    /// The SVID's trust domain.
    pub trust_domain: String,
    /// The SVID's expiry, Unix seconds.
    pub svid_expires_at: i64,
}

impl std::fmt::Debug for HostCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the SVID: it is a bearer credential for these calls.
        f.debug_struct("HostCredentials")
            .field("host_uuid", &self.host_uuid)
            .field("trust_domain", &self.trust_domain)
            .field("svid_expires_at", &self.svid_expires_at)
            .finish_non_exhaustive()
    }
}

/// Split a host SPIFFE id `spiffe://<trust-domain>/host/<uuid>` into its
/// trust domain and host UUID.
#[must_use]
pub fn split_host_spiffe_id(spiffe_id: &str) -> Option<(&str, &str)> {
    let rest = spiffe_id.strip_prefix("spiffe://")?;
    let (td, uuid) = rest.split_once("/host/")?;
    (!td.is_empty() && !uuid.is_empty() && !uuid.contains('/')).then_some((td, uuid))
}

impl HostCredentials {
    /// Credentials for the SVID `svid_jws` naming `spiffe_id`, signed by
    /// `key`; `None` when `spiffe_id` is not a host SPIFFE id.
    #[must_use]
    pub fn new(
        key: Arc<dyn ferro_sep::MachineKey + Send + Sync>,
        svid_jws: String,
        spiffe_id: &str,
        svid_expires_at: i64,
    ) -> Option<Self> {
        let (trust_domain, host_uuid) = split_host_spiffe_id(spiffe_id)?;
        Some(Self {
            key,
            svid_jws,
            host_uuid: host_uuid.to_string(),
            trust_domain: trust_domain.to_string(),
            svid_expires_at,
        })
    }

    /// Whether the SVID is still valid at `now`.
    #[must_use]
    pub fn valid_at(&self, now: i64) -> bool {
        now < self.svid_expires_at
    }

    /// The proof over `doc` under `context`.
    pub fn auth(&self, context: &[u8], doc: &[u8]) -> Result<HostCallAuth, ferro_sep::SepError> {
        host_call_auth(
            &HostProofSigner {
                key: &*self.key,
                svid_jws: &self.svid_jws,
                host_uuid: &self.host_uuid,
            },
            context,
            doc,
        )
    }
}

/// The current host credentials, shared by the sync loop and the registration
/// service and replaced when a (re-)attestation yields a new SVID. Empty
/// until the host holds an SVID whose key can sign host calls.
#[derive(Debug, Clone, Default)]
pub struct CredentialSlot(Arc<RwLock<Option<Arc<HostCredentials>>>>);

impl CredentialSlot {
    /// An empty slot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the credentials.
    pub fn set(&self, creds: Option<HostCredentials>) {
        *self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = creds.map(Arc::new);
    }

    /// The current credentials, if any.
    #[must_use]
    pub fn get(&self) -> Option<Arc<HostCredentials>> {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The current credentials when their SVID is valid at `now`.
    #[must_use]
    pub fn valid_at(&self, now: i64) -> Option<Arc<HostCredentials>> {
        self.get().filter(|c| c.valid_at(now))
    }
}

/// 16 bytes from the OS RNG.
#[must_use]
pub fn random_bytes() -> [u8; 16] {
    use rand_core::{Rng as _, UnwrapErr};
    let mut out = [0u8; 16];
    UnwrapErr(getrandom::SysRng).fill_bytes(&mut out);
    out
}

/// A fresh UUIDv4 (request ids, local ids).
#[must_use]
pub fn random_uuid() -> [u8; 16] {
    mia_helper_proto::uuid_v4(random_bytes())
}

/// The `retry-after` metadata of a `RESOURCE_EXHAUSTED` answer, in seconds.
#[must_use]
pub fn retry_after(status: &Status) -> Option<u64> {
    status
        .metadata()
        .get("retry-after")?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// The CMIS host RPCs MIA calls, boxed so the trait stays object-safe.
pub trait HostApi: Send + Sync {
    /// `SubmitAppRequest`.
    fn submit_app_request(
        &self,
        req: SubmitAppRequestRequest,
    ) -> BoxFuture<'_, Result<SubmitAppRequestResponse, Status>>;

    /// `GetAppRequestStatus`.
    fn app_request_status(
        &self,
        req: GetAppRequestStatusRequest,
    ) -> BoxFuture<'_, Result<GetAppRequestStatusResponse, Status>>;

    /// `SyncAllowlist`.
    fn sync_allowlist(
        &self,
        req: SyncAllowlistRequest,
    ) -> BoxFuture<'_, Result<SyncAllowlistResponse, Status>>;

    /// The legacy `GetAllowlist`: the signed v1 envelope, `None` when CMIS
    /// holds none for the host.
    fn get_allowlist(&self, host_uuid: String) -> BoxFuture<'_, Result<Option<Vec<u8>>, Status>>;
}

/// Run one call on `client` under [`CALL_TIMEOUT`].
async fn timed<T>(
    fut: impl std::future::Future<Output = Result<tonic::Response<T>, Status>>,
) -> Result<T, Status> {
    match tokio::time::timeout(CALL_TIMEOUT, fut).await {
        Ok(r) => r.map(tonic::Response::into_inner),
        Err(_) => Err(Status::deadline_exceeded("host call timed out")),
    }
}

/// Calls over an already-connected channel (one-shot commands, tests).
#[derive(Clone)]
pub struct ChannelApi {
    client: MachineIdentityClient<Channel>,
}

impl ChannelApi {
    /// Calls over `client`.
    #[must_use]
    pub fn new(client: MachineIdentityClient<Channel>) -> Self {
        Self { client }
    }
}

impl HostApi for ChannelApi {
    fn submit_app_request(
        &self,
        req: SubmitAppRequestRequest,
    ) -> BoxFuture<'_, Result<SubmitAppRequestResponse, Status>> {
        let mut c = self.client.clone();
        Box::pin(async move { timed(c.submit_app_request(req)).await })
    }

    fn app_request_status(
        &self,
        req: GetAppRequestStatusRequest,
    ) -> BoxFuture<'_, Result<GetAppRequestStatusResponse, Status>> {
        let mut c = self.client.clone();
        Box::pin(async move { timed(c.get_app_request_status(req)).await })
    }

    fn sync_allowlist(
        &self,
        req: SyncAllowlistRequest,
    ) -> BoxFuture<'_, Result<SyncAllowlistResponse, Status>> {
        let mut c = self.client.clone();
        Box::pin(async move { timed(c.sync_allowlist(req)).await })
    }

    fn get_allowlist(&self, host_uuid: String) -> BoxFuture<'_, Result<Option<Vec<u8>>, Status>> {
        let mut c = self.client.clone();
        Box::pin(async move {
            let resp = timed(c.get_allowlist(GetAllowlistRequest {
                host_uuid,
                accept_formats: Vec::new(),
            }))
            .await?;
            Ok((!resp.signed_allowlist.is_empty()).then_some(resp.signed_allowlist))
        })
    }
}

/// Calls through the configured CMIS endpoint(s): each call resolves and dials
/// a live node (SRV fail-over included) over the pinned hybrid-PQC channel.
#[derive(Clone)]
pub struct ResolverApi {
    resolver: crate::endpoint::CmisResolver,
}

impl ResolverApi {
    /// Calls through `resolver`.
    #[must_use]
    pub fn new(resolver: crate::endpoint::CmisResolver) -> Self {
        Self { resolver }
    }

    async fn channel(&self) -> Result<ChannelApi, Status> {
        match tokio::time::timeout(CALL_TIMEOUT, self.resolver.connect()).await {
            Ok(Ok((_, client))) => Ok(ChannelApi::new(client)),
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "could not reach CMIS for a host call");
                Err(Status::unavailable("cmis_unreachable"))
            }
            Err(_) => Err(Status::unavailable("cmis_unreachable")),
        }
    }
}

impl HostApi for ResolverApi {
    fn submit_app_request(
        &self,
        req: SubmitAppRequestRequest,
    ) -> BoxFuture<'_, Result<SubmitAppRequestResponse, Status>> {
        Box::pin(async move {
            let api = self.channel().await?;
            api.submit_app_request(req).await
        })
    }

    fn app_request_status(
        &self,
        req: GetAppRequestStatusRequest,
    ) -> BoxFuture<'_, Result<GetAppRequestStatusResponse, Status>> {
        Box::pin(async move {
            let api = self.channel().await?;
            api.app_request_status(req).await
        })
    }

    fn sync_allowlist(
        &self,
        req: SyncAllowlistRequest,
    ) -> BoxFuture<'_, Result<SyncAllowlistResponse, Status>> {
        Box::pin(async move {
            let api = self.channel().await?;
            api.sync_allowlist(req).await
        })
    }

    fn get_allowlist(&self, host_uuid: String) -> BoxFuture<'_, Result<Option<Vec<u8>>, Status>> {
        Box::pin(async move {
            let api = self.channel().await?;
            api.get_allowlist(host_uuid).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_spiffe_ids_split_into_trust_domain_and_uuid() {
        assert_eq!(
            split_host_spiffe_id("spiffe://ferrogate.test/host/1b4e28ba"),
            Some(("ferrogate.test", "1b4e28ba"))
        );
        for bad in [
            "spiffe://ferrogate.test/host/",
            "spiffe:///host/x",
            "https://ferrogate.test/host/x",
            "spiffe://ferrogate.test/workload/x",
            "spiffe://ferrogate.test/host/a/b",
        ] {
            assert_eq!(split_host_spiffe_id(bad), None, "{bad}");
        }
    }

    #[test]
    fn retry_after_is_read_from_metadata() {
        let mut s = Status::resource_exhausted("rate_limited");
        assert_eq!(retry_after(&s), None);
        s.metadata_mut()
            .insert("retry-after", "42".parse().unwrap());
        assert_eq!(retry_after(&s), Some(42));
    }

    #[test]
    fn credentials_sign_a_verifiable_proof() {
        let key: Arc<dyn ferro_sep::MachineKey + Send + Sync> =
            Arc::new(ferro_sep::SoftwareMachineKey::generate().unwrap());
        let creds = HostCredentials::new(
            Arc::clone(&key),
            "h.c.s".into(),
            "spiffe://ferrogate.test/host/abc",
            100,
        )
        .unwrap();
        assert_eq!(creds.host_uuid, "abc");
        assert_eq!(creds.trust_domain, "ferrogate.test");
        assert!(creds.valid_at(99) && !creds.valid_at(100));
        let auth = creds.auth(b"ctx", b"doc").unwrap();
        assert_eq!(auth.sep_pub, ferro_sep::MachineKey::public_spki_der(&*key));
        ferro_sep::verify_p256(
            &auth.sep_pub,
            &ferro_svid::host_call::signing_input(b"ctx", b"doc"),
            &auth.sig,
        )
        .unwrap();
        // The debug form never prints the SVID.
        assert!(!format!("{creds:?}").contains("h.c.s"));
        let slot = CredentialSlot::new();
        assert!(slot.get().is_none());
        slot.set(Some(creds));
        assert!(slot.valid_at(50).is_some());
        assert!(slot.valid_at(150).is_none());
    }
}
