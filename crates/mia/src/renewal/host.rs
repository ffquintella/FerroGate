//! The daemon's [`Renewer`] (T294): `Rotate` and full attestation against
//! CMIS, the X.509-SVID sealed only once a new SVID is accepted, and the
//! swap. The platform-specific parts (attestation backends, the CMIS dial,
//! the credential store, the allowlist refresh) come in through small traits.

use std::path::PathBuf;

use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use futures::future::BoxFuture;
use tonic::transport::Channel;
use tonic::Status;

use super::{rotate_host_svid, HostSvid, Issued, RenewalPath, Renewer, Swap};
use crate::host_api::CALL_TIMEOUT;
use crate::status::{AttestFailure, StatusHandle};

/// What an attestation may do with the host's machine key and SVID seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPolicy {
    /// Before this run attested: open what exists, create only what exists
    /// nowhere ([`crate::machine_key`]).
    OpenOrCreate,
    /// A renewal: reopen the key CMIS pinned and never create a key or seed;
    /// with `seed_required` a missing seed fails closed as well.
    OpenOnly {
        /// The SVID in force was derived from the persistent seed.
        seed_required: bool,
    },
}

/// A full attestation's result.
#[derive(Debug, Clone)]
pub struct Attested {
    /// The SVID and what uses it.
    pub svid: HostSvid,
    /// Its composite key was derived from the persistent SVID seed (stable
    /// child-signing `kid`).
    pub seeded: bool,
}

/// Runs one full attestation with the configured backend.
pub trait HostAttestor: Send + Sync {
    /// Attest under `policy`; the cause of a failure is logged by the backend.
    fn attest(&self, policy: KeyPolicy) -> BoxFuture<'_, Result<Attested, AttestFailure>>;
}

/// A connected CMIS client, and the endpoint it reached (for the status).
pub struct DialedCmis {
    /// The endpoint dialed, when known.
    pub endpoint: Option<String>,
    /// The client.
    pub client: MachineIdentityClient<Channel>,
}

/// Connects to CMIS for a `Rotate`.
pub trait CmisDial: Send + Sync {
    /// A client, or `UNAVAILABLE cmis_unreachable`.
    fn dial(&self) -> BoxFuture<'_, Result<DialedCmis, Status>>;
}

impl CmisDial for crate::endpoint::CmisResolver {
    fn dial(&self) -> BoxFuture<'_, Result<DialedCmis, Status>> {
        Box::pin(async move {
            match tokio::time::timeout(CALL_TIMEOUT, self.connect()).await {
                Ok(Ok((endpoint, client))) => Ok(DialedCmis {
                    endpoint: Some(endpoint),
                    client,
                }),
                Ok(Err(e)) => {
                    tracing::debug!(error = %e, "could not reach CMIS to renew the host SVID");
                    Err(Status::unavailable("cmis_unreachable"))
                }
                Err(_) => Err(Status::unavailable("cmis_unreachable")),
            }
        })
    }
}

impl CmisDial for MachineIdentityClient<Channel> {
    fn dial(&self) -> BoxFuture<'_, Result<DialedCmis, Status>> {
        let client = self.clone();
        Box::pin(async move {
            Ok(DialedCmis {
                endpoint: None,
                client,
            })
        })
    }
}

/// Seals a new SVID's X.509 half to disk.
pub trait X509Sealer: Send + Sync {
    /// Seal it (best-effort, failures logged); the backend name when stored.
    fn seal(&self, svid: &HostSvid) -> Option<&'static str>;
}

/// No store: nothing is sealed.
impl X509Sealer for () {
    fn seal(&self, _svid: &HostSvid) -> Option<&'static str> {
        None
    }
}

/// The machine-bound X.509-SVID store ([`crate::credstore`]) at `path`,
/// sealed with the strongest backend the host offers.
pub struct X509Store {
    path: PathBuf,
    fingerprint: Option<Vec<u8>>,
}

impl X509Store {
    /// The store at `path`, with the hardware `fingerprint` for the
    /// machine-key tier.
    #[must_use]
    pub fn new(path: PathBuf, fingerprint: Option<Vec<u8>>) -> Self {
        Self { path, fingerprint }
    }
}

impl X509Sealer for X509Store {
    fn seal(&self, svid: &HostSvid) -> Option<&'static str> {
        if svid.x509_svid.is_empty() || svid.x509_bundle.is_empty() {
            tracing::debug!("CMIS issued no X.509-SVID with this SVID; nothing to seal");
            return None;
        }
        let credential = crate::credstore::X509Credential {
            leaf_der: svid.x509_svid.clone(),
            bundle_der: svid.x509_bundle.clone(),
            key_pkcs8: svid.svid_secret.to_ed25519_pkcs8_der(),
        };
        let path = &self.path;
        let outcome = crate::credstore::with_sealer(self.fingerprint.as_deref(), |sealer| {
            (
                sealer.name(),
                crate::credstore::store(path, &credential, sealer),
            )
        });
        match outcome {
            Some((backend, Ok(()))) => {
                tracing::info!(
                    path = %path.display(),
                    backend,
                    "sealed the X.509-SVID to disk (opens only on this machine)"
                );
                Some(backend)
            }
            Some((backend, Err(e))) => {
                tracing::warn!(
                    error = %e, backend, path = %path.display(),
                    "could not seal the X.509-SVID; it stays in memory for this session only"
                );
                None
            }
            None => {
                tracing::warn!(
                    "no TPM and no hardware fingerprint on this host: the X.509-SVID will not be \
                     stored, since writing its private key unsealed is not an option"
                );
                None
            }
        }
    }
}

/// Refreshes what depends on the host SVID once a new one is in force.
pub trait RenewalHooks: Send {
    /// Called after the swap and the status update.
    fn after_install<'a>(&'a mut self, svid: &'a HostSvid) -> BoxFuture<'a, ()>;
}

impl RenewalHooks for () {
    fn after_install<'a>(&'a mut self, _svid: &'a HostSvid) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

/// The daemon's renewer.
pub struct HostRenewer<T, D, S, H> {
    attestor: T,
    dial: D,
    sealer: S,
    hooks: H,
    swap: Swap,
    status: StatusHandle,
    /// The host-key tier's signed state digest (the fingerprint `H`).
    state_digest: Option<[u8; 48]>,
    /// The SVID in force; `None` before the first attestation, after expiry.
    current: Option<HostSvid>,
    /// Set once this run attested: whether that SVID's key came from the seed.
    seeded: Option<bool>,
    /// The child-signing `kid` in force.
    kid: Option<String>,
}

impl<T, D, S, H> HostRenewer<T, D, S, H>
where
    T: HostAttestor,
    D: CmisDial,
    S: X509Sealer,
    H: RenewalHooks,
{
    /// A renewer over these parts; `state_digest` is `None` off the host-key
    /// tier (no `Rotate` is then possible).
    #[must_use]
    pub fn new(
        attestor: T,
        dial: D,
        sealer: S,
        hooks: H,
        swap: Swap,
        status: StatusHandle,
        state_digest: Option<[u8; 48]>,
    ) -> Self {
        Self {
            attestor,
            dial,
            sealer,
            hooks,
            swap,
            status,
            state_digest,
            current: None,
            seeded: None,
            kid: None,
        }
    }

    /// Hold the start-up attestation `attested` (already in force).
    #[must_use]
    pub fn with_current(mut self, attested: &Attested) -> Self {
        self.remember(attested);
        self
    }

    fn remember(&mut self, attested: &Attested) {
        self.current = Some(attested.svid.clone());
        self.seeded = Some(attested.seeded);
        self.kid = Some(attested.svid.minter.kid().to_string());
    }

    /// The policy for the next full attestation.
    fn key_policy(&self) -> KeyPolicy {
        match self.seeded {
            None => KeyPolicy::OpenOrCreate,
            Some(seed_required) => KeyPolicy::OpenOnly { seed_required },
        }
    }

    /// Refuse a seeded host's renewal under another key: the seed changed.
    fn check_key(&self, attested: &Attested) -> Result<(), AttestFailure> {
        if self.seeded != Some(true) {
            return Ok(());
        }
        let kid = attested.svid.minter.kid();
        if attested.seeded && self.kid.as_deref() == Some(kid) {
            return Ok(());
        }
        tracing::error!(
            kid_in_force = self.kid.as_deref().unwrap_or_default(),
            kid_issued = kid,
            seeded = attested.seeded,
            "the re-attestation produced another child-signing key although this run uses the \
             persistent SVID seed (was svid-seed.bin replaced?); it is not put in force"
        );
        Err(AttestFailure::MachineKey)
    }
}

impl<T, D, S, H> Renewer for HostRenewer<T, D, S, H>
where
    T: HostAttestor,
    D: CmisDial,
    S: X509Sealer,
    H: RenewalHooks,
{
    type Credential = Attested;

    fn rotate(&mut self) -> BoxFuture<'_, Result<Issued<Attested>, Status>> {
        Box::pin(async move {
            let Some(current) = self.current.clone() else {
                return Err(Status::failed_precondition("no_host_svid"));
            };
            let Some(digest) = self.state_digest else {
                return Err(Status::failed_precondition("no_fingerprint"));
            };
            let DialedCmis {
                endpoint,
                mut client,
            } = self.dial.dial().await?;
            if let Some(endpoint) = endpoint {
                self.status.set_cmis_node(&endpoint);
            }
            let svid = rotate_host_svid(&mut client, &current, &digest).await?;
            Ok(Issued {
                info: svid.info(),
                credential: Attested {
                    svid,
                    seeded: self.seeded.unwrap_or(false),
                },
            })
        })
    }

    fn full_attest(&mut self) -> BoxFuture<'_, Result<Issued<Attested>, AttestFailure>> {
        Box::pin(async move {
            let attested = self.attestor.attest(self.key_policy()).await?;
            self.check_key(&attested)?;
            Ok(Issued {
                info: attested.svid.info(),
                credential: attested,
            })
        })
    }

    fn install(&mut self, attested: Attested, _path: RenewalPath) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.swap.install(&attested.svid).await;
            // Sealed only now: an SVID the renewal refused never reaches disk.
            if let Some(backend) = self.sealer.seal(&attested.svid) {
                self.status.set_x509_store(backend);
            }
            self.remember(&attested);
        })
    }

    fn after_install(&mut self, _path: RenewalPath) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if let Some(svid) = self.current.as_ref() {
                self.hooks.after_install(svid).await;
            }
        })
    }

    fn disable(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.swap.disable().await;
            self.current = None;
        })
    }
}
