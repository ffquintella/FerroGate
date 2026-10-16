//! The TPM-less **host-key** attestation backend (feature F15) as a
//! [`HostAttestor`]: opens the machine key and SVID seed under the
//! [`KeyPolicy`], and refuses a key or seed a renewal must not use before
//! CMIS is contacted.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_sep::MachineKey as _;
use futures::future::BoxFuture;
use sha2::{Digest, Sha256};
use tonic::transport::Channel;

use super::{Attested, DialedCmis, HostAttestor, HostSvid, KeyPolicy};
use crate::machine_key::{KeyError, SeedError};
use crate::status::{AttestFailure, StatusHandle};

/// Set once this process created a machine key because none existed: if CMIS
/// then refuses the host, the likeliest cause is a key rebind, and the log
/// says so.
static MACHINE_KEY_CREATED: AtomicBool = AtomicBool::new(false);

/// Connects to CMIS for an attestation; the error keeps its cause so a pin
/// mismatch is told apart from an unreachable CMIS.
pub trait AttestDial: Send + Sync {
    /// A client, or why none could be had.
    fn connect(&self) -> BoxFuture<'_, anyhow::Result<DialedCmis>>;
}

impl AttestDial for crate::endpoint::CmisResolver {
    fn connect(&self) -> BoxFuture<'_, anyhow::Result<DialedCmis>> {
        Box::pin(async move {
            let (endpoint, client) = crate::endpoint::CmisResolver::connect(self).await?;
            Ok(DialedCmis {
                endpoint: Some(endpoint),
                client,
            })
        })
    }
}

impl AttestDial for MachineIdentityClient<Channel> {
    fn connect(&self) -> BoxFuture<'_, anyhow::Result<DialedCmis>> {
        let client = self.clone();
        Box::pin(async move {
            Ok(DialedCmis {
                endpoint: None,
                client,
            })
        })
    }
}

/// The host-key backend: the machine key at `key_path`, sealed to the
/// fingerprint of `facts`, and the SVID seed at `seed_path`.
pub struct HostKeyAttestor<D> {
    dial: D,
    facts: ferro_machineid::MachineFacts,
    key_path: PathBuf,
    seed_path: PathBuf,
    status: StatusHandle,
}

impl<D: AttestDial> HostKeyAttestor<D> {
    /// The backend over these files, dialing CMIS through `dial`.
    #[must_use]
    pub fn new(
        dial: D,
        facts: ferro_machineid::MachineFacts,
        key_path: PathBuf,
        seed_path: PathBuf,
        status: StatusHandle,
    ) -> Self {
        Self {
            dial,
            facts,
            key_path,
            seed_path,
            status,
        }
    }

    /// The dialer (for tests).
    #[must_use]
    pub fn dial(&self) -> &D {
        &self.dial
    }

    /// Open the machine key under `policy`: created only when none exists
    /// anywhere, and never on a renewal.
    fn open_key(&self, policy: &KeyPolicy) -> Result<ferro_sep::SoftwareMachineKey, AttestFailure> {
        let path = &self.key_path;
        let fingerprint = self.facts.fingerprint();
        let seal = Some(fingerprint.as_bytes().as_slice());
        let opened = match policy {
            KeyPolicy::OpenOrCreate => crate::machine_key::open_or_create_machine_key(path, seal),
            KeyPolicy::OpenOnly { .. } => {
                crate::machine_key::open_machine_key(path, seal).map(|key| {
                    crate::machine_key::MachineKey {
                        key,
                        created: false,
                    }
                })
            }
        };
        match opened {
            Ok(opened) => {
                if opened.created {
                    MACHINE_KEY_CREATED.store(true, Ordering::Relaxed);
                    tracing::warn!(
                        path = %path.display(),
                        fingerprint = %self.facts.fingerprint().to_hex(),
                        "no machine signing key existed; created a new one. This is a new host \
                         identity: if CMIS enrolled this machine before, it will refuse this key \
                         as a key rebind — restore the original host-key.bin instead"
                    );
                }
                Ok(opened.key)
            }
            Err(KeyError::Refused(refusal)) => {
                tracing::error!(path = %path.display(), "{refusal}");
                Err(AttestFailure::MachineKey)
            }
            Err(e @ KeyError::CreateFailed(_)) => {
                tracing::error!(error = %e, path = %path.display(), "cannot create the machine signing key");
                Err(AttestFailure::Other)
            }
        }
    }

    /// The SVID seed under `policy`: on a renewal only reopened, and refused
    /// when it no longer derives the `kid` in force. `None` ⇒ ephemeral key.
    fn open_seed(&self, policy: &KeyPolicy) -> Result<Option<[u8; 32]>, AttestFailure> {
        let path = &self.seed_path;
        let seed = match policy {
            KeyPolicy::OpenOrCreate => crate::machine_key::load_or_create_seed(path).map(|s| {
                if matches!(s, crate::machine_key::Seed::Created(_)) {
                    tracing::info!(path = %path.display(), "created the persistent SVID seed");
                }
                Some(*s.bytes())
            }),
            KeyPolicy::OpenOnly { seed_required, kid } => {
                crate::machine_key::reopen_seed(path, *seed_required, kid.as_deref())
            }
        };
        match seed {
            Ok(s) => Ok(s),
            Err(SeedError::Refused(refusal)) => {
                tracing::error!(path = %path.display(), "{refusal}");
                Err(AttestFailure::MachineKey)
            }
            Err(e @ SeedError::CreateFailed(_)) => {
                tracing::warn!(
                    error = %e,
                    path = %path.display(),
                    "cannot persist the SVID seed; using an ephemeral key (the child-signing kid \
                     will rotate on restart)"
                );
                Ok(None)
            }
        }
    }
}

impl<D: AttestDial> HostAttestor for HostKeyAttestor<D> {
    #[allow(clippy::large_futures)] // holds a composite key (~4 KB ML-DSA) across awaits
    fn attest(&self, policy: KeyPolicy) -> BoxFuture<'_, Result<Attested, AttestFailure>> {
        Box::pin(async move {
            // Key and seed first: a refused one never reaches CMIS.
            let key = self.open_key(&policy)?;
            let seed = self.open_seed(&policy)?;
            // A host-bound stand-in for the host DPoP key (F09); CMIS
            // records it as the SVID's `cnf.jkt`.
            let dpop_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(key.public_spki_der()));
            let DialedCmis {
                endpoint,
                mut client,
            } = match self.dial.connect().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = %e, "could not connect to CMIS for attestation");
                    return Err(AttestFailure::from_connect_error(&e));
                }
            };
            if let Some(endpoint) = &endpoint {
                self.status.set_cmis_node(endpoint);
            }
            let attested = match crate::client::run_attest_host_key(
                &mut client,
                &self.facts,
                &key,
                dpop_jkt,
                seed.as_ref(),
            )
            .await
            {
                Ok(a) => a,
                Err(e) => {
                    tracing::error!(error = %e, "host-key attestation failed");
                    let failure = AttestFailure::from_attest_error(&e, false);
                    if failure == AttestFailure::NotEnrolled
                        && MACHINE_KEY_CREATED.load(Ordering::Relaxed)
                    {
                        tracing::error!(
                            path = %self.key_path.display(),
                            fingerprint = %self.facts.fingerprint().to_hex(),
                            "CMIS refused this host, and this agent created its machine key at \
                             this start. If the machine was enrolled before, CMIS has pinned the \
                             earlier key for this fingerprint and refuses the new one as a key \
                             rebind: restore the original host-key.bin (and svid-seed.bin) from \
                             a backup, or have the CMIS operator clear this host's key pin"
                        );
                    }
                    return Err(failure);
                }
            };
            tracing::info!(
                spiffe_id = %attested.bundle.spiffe_id,
                fingerprint = %self.facts.fingerprint().to_hex(),
                cmis = endpoint.as_deref().unwrap_or_default(),
                "host SVID obtained via host-key attestation; token minting enabled"
            );
            let kid = ferro_svid::child_signing_kid(&attested.svid_public);
            let host_call_key: Arc<dyn ferro_sep::MachineKey + Send + Sync> = Arc::new(key);
            Ok(Attested {
                // The SVID's `cnf.jkt` binds the machine key: it signs host calls.
                svid: HostSvid::new(
                    attested.bundle,
                    Arc::new(attested.svid_secret),
                    kid,
                    Some(host_call_key),
                ),
                seeded: seed.is_some(),
            })
        })
    }
}
