//! The host SVID in force and the swap that replaces it (T294): host-call
//! credentials, the child-token minter and the SVID the allowlist proposal
//! presents, always replaced together and in a fixed order.

use std::sync::{Arc, RwLock};

use ferro_crypto::composite::CompositeSecretKey;
use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_proto::v1::SvidBundle;
use futures::future::BoxFuture;
use sha2::{Digest, Sha384};
use tonic::transport::Channel;
use tonic::Status;

use super::SvidInfo;
use crate::audit_client::HostProofSigner;
use crate::client::RotateClientError;
use crate::helper::token::{ChildTokenMinter, MinterConfig};
use crate::host_api::{split_host_spiffe_id, CredentialSlot, HostCredentials, CALL_TIMEOUT};

/// A host SVID in force, with the minter that parents child tokens on it
/// and, on the host-key tier, the machine key its `cnf.jkt` binds.
#[derive(Clone)]
pub struct HostSvid {
    /// The SVID's SPIFFE id.
    pub spiffe_id: String,
    /// The compact-JWS SVID.
    pub jws: String,
    /// Issue time, Unix seconds.
    pub issued_at: i64,
    /// Expiry, Unix seconds.
    pub expires_at: i64,
    /// The composite key the SVID certifies, shared with [`Self::minter`].
    pub svid_secret: Arc<CompositeSecretKey>,
    /// Mints child tokens naming this SVID as parent.
    pub minter: ChildTokenMinter,
    /// The machine key that signs host calls; `None` on the TPM tier, whose
    /// SVID binds the AIK (such a host never calls `Rotate`, D2).
    pub host_call_key: Option<Arc<dyn ferro_sep::MachineKey + Send + Sync>>,
    /// The X.509-SVID leaf issued with it (DER), empty when none.
    pub x509_svid: Vec<u8>,
    /// The X.509 trust bundle (DER), empty when none.
    pub x509_bundle: Vec<u8>,
}

impl std::fmt::Debug for HostSvid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the JWS (a bearer credential for host calls) or any key.
        f.debug_struct("HostSvid")
            .field("spiffe_id", &self.spiffe_id)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("host_call_key", &self.host_call_key.is_some())
            .finish_non_exhaustive()
    }
}

/// `SHA-384` of a compact JWS: the parent digest child tokens carry.
fn jws_sha384(jws: &str) -> [u8; 48] {
    let mut out = [0u8; 48];
    out.copy_from_slice(&Sha384::digest(jws.as_bytes()));
    out
}

impl HostSvid {
    /// The SVID in `bundle`, certifying `svid_secret` (published under
    /// `kid`), signing host calls with `host_call_key` when it binds one.
    #[must_use]
    pub fn new(
        bundle: SvidBundle,
        svid_secret: Arc<CompositeSecretKey>,
        kid: String,
        host_call_key: Option<Arc<dyn ferro_sep::MachineKey + Send + Sync>>,
    ) -> Self {
        let minter = ChildTokenMinter::from_shared(
            Arc::clone(&svid_secret),
            MinterConfig {
                host_spiffe_id: bundle.spiffe_id.clone(),
                parent_svid_sha384: jws_sha384(&bundle.jws),
                kid,
            },
        );
        Self {
            spiffe_id: bundle.spiffe_id,
            jws: bundle.jws,
            issued_at: bundle.issued_at,
            expires_at: bundle.expires_at,
            svid_secret,
            minter,
            host_call_key,
            x509_svid: bundle.x509_svid,
            x509_bundle: bundle.x509_bundle,
        }
    }

    /// The SVID a `Rotate` returned: same composite and machine key, new
    /// JWS, so the minter only changes its parent digest. The identity is
    /// checked by the caller ([`super::Renewal`] refuses another SPIFFE id).
    #[must_use]
    pub fn rotated(&self, bundle: SvidBundle) -> Self {
        Self {
            minter: self.minter.with_parent(jws_sha384(&bundle.jws)),
            spiffe_id: bundle.spiffe_id,
            jws: bundle.jws,
            issued_at: bundle.issued_at,
            expires_at: bundle.expires_at,
            svid_secret: Arc::clone(&self.svid_secret),
            host_call_key: self.host_call_key.clone(),
            x509_svid: bundle.x509_svid,
            x509_bundle: bundle.x509_bundle,
        }
    }

    /// What the renewal schedule needs. Only an SVID binding a host-call key
    /// may renew with `Rotate` (D2).
    #[must_use]
    pub fn info(&self) -> SvidInfo {
        SvidInfo {
            spiffe_id: self.spiffe_id.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            rotatable: self.host_call_key.is_some(),
        }
    }

    /// The host-call credentials it signs with, when it binds a host-call key.
    #[must_use]
    pub fn credentials(&self) -> Option<HostCredentials> {
        HostCredentials::new(
            self.host_call_key.clone()?,
            self.jws.clone(),
            &self.spiffe_id,
            self.expires_at,
        )
    }
}

/// Renew `current` with one host-signed `Rotate` (T293) on `client`,
/// reporting `state_digest` (host-key tier: the fingerprint `H`), under
/// [`CALL_TIMEOUT`].
///
/// # Errors
///
/// The refusal; a proof that cannot be built locally is `FAILED_PRECONDITION`.
pub async fn rotate_host_svid(
    client: &mut MachineIdentityClient<Channel>,
    current: &HostSvid,
    state_digest: &[u8; 48],
) -> Result<HostSvid, Status> {
    let Some(key) = current.host_call_key.as_deref() else {
        return Err(Status::failed_precondition("no_host_call_key"));
    };
    let key: &(dyn ferro_sep::MachineKey + Sync) = key;
    let Some((_, host_uuid)) = split_host_spiffe_id(&current.spiffe_id) else {
        return Err(Status::failed_precondition("not_a_host_svid"));
    };
    let signer = HostProofSigner {
        key,
        svid_jws: &current.jws,
        host_uuid,
    };
    match tokio::time::timeout(
        CALL_TIMEOUT,
        crate::client::rotate(client, &signer, state_digest),
    )
    .await
    {
        Ok(Ok(bundle)) => Ok(current.rotated(bundle)),
        Ok(Err(RotateClientError::Transport(status))) => Err(status),
        Ok(Err(e @ (RotateClientError::Doc(_) | RotateClientError::Sign(_)))) => {
            tracing::warn!(error = %e, "could not build the Rotate proof");
            Err(Status::failed_precondition("local_proof_failed"))
        }
        Err(_) => Err(Status::deadline_exceeded("rotate timed out")),
    }
}

/// Where the child-token minter is swapped: the helper API's
/// [`crate::helper::MinterReloader`], or a test double.
pub trait MinterSink: Send + Sync {
    /// Put `minter` in force (`None` refuses every mint, `no_host_svid`).
    fn set(&self, minter: Option<ChildTokenMinter>) -> BoxFuture<'_, ()>;
}

#[cfg(any(unix, windows))]
impl<A: crate::helper::auth::CallerAuth> MinterSink for crate::helper::MinterReloader<A> {
    fn set(&self, minter: Option<ChildTokenMinter>) -> BoxFuture<'_, ()> {
        Box::pin(crate::helper::MinterReloader::set(self, minter))
    }
}

/// The SVID the allowlist-propose task presents, read on every attempt so a
/// renewal reaches it without a restart.
#[derive(Clone, Default)]
pub struct SvidCell(Arc<RwLock<Option<(String, i64)>>>);

impl std::fmt::Debug for SvidCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let expires_at = self.read().as_ref().map(|(_, exp)| *exp);
        f.debug_struct("SvidCell")
            .field("expires_at", &expires_at)
            .finish_non_exhaustive()
    }
}

impl SvidCell {
    /// An empty cell.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Option<(String, i64)>> {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Hold `svid` (or nothing).
    pub fn set(&self, svid: Option<&HostSvid>) {
        *self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            svid.map(|s| (s.jws.clone(), s.expires_at));
    }

    /// The JWS held, when it is still valid at `now`.
    #[must_use]
    pub fn jws_valid_at(&self, now: i64) -> Option<String> {
        self.read()
            .as_ref()
            .filter(|(_, exp)| now < *exp)
            .map(|(jws, _)| jws.clone())
    }
}

/// Puts a host SVID in force, or takes it out (fail closed).
#[derive(Clone)]
pub struct Swap {
    creds: CredentialSlot,
    minter: Arc<dyn MinterSink>,
    svid: SvidCell,
}

impl Swap {
    /// A swap over the credential slot, the minter sink and the propose cell.
    #[must_use]
    pub fn new(creds: CredentialSlot, minter: Arc<dyn MinterSink>, svid: SvidCell) -> Self {
        Self {
            creds,
            minter,
            svid,
        }
    }

    /// Put `svid` in force: credentials, then the minter (its write lock
    /// waits out mints in flight, so once this returns no token names the
    /// old parent), then the propose cell.
    pub async fn install(&self, svid: &HostSvid) {
        self.creds.set(svid.credentials());
        self.minter.set(Some(svid.minter.clone())).await;
        self.svid.set(Some(svid));
    }

    /// Fail closed: minting off first, then host calls and proposals.
    pub async fn disable(&self) {
        self.minter.set(None).await;
        self.creds.set(None);
        self.svid.set(None);
    }
}
