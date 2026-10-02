//! Machine-bound storage for the host's X.509-SVID (features F04/F17).
//!
//! CMIS issues an X.509-SVID beside the JWS one. The certificate is public, but
//! the private key that makes it usable is not, and a credential lying in a file
//! is a credential that walks off on a cloned disk. This module keeps the whole
//! credential — leaf, trust bundle, and key — in one AEAD-sealed file whose
//! data-protection key **cannot be recovered on another machine**.
//!
//! ## Two ways to bind a file to a machine
//!
//! A usable TPM always wins — see [`with_sealer`] — even on a host that attests
//! through the software tier, because there is no reason to protect the
//! credential more weakly than the hardware allows:
//!
//! | Backend | Data-protection key | Opens only |
//! |---|---|---|
//! | `Sealer::Tpm` | random, sealed by the TPM to PCRs `{0,4,7,8}` (see [`crate::seal`]) | on this TPM, in this boot state |
//! | `Sealer::SecureEnclave` | random, ECIES-wrapped to a non-exportable macOS Secure Enclave key | on this Mac's Enclave |
//! | [`Sealer::MachineKey`] | derived from the hardware fingerprint `H` | on a host with this fingerprint |
//!
//! The first two are hardware roots of trust. The TPM releases the key only
//! under its PCR policy, so any change to firmware, the boot chain, secure-boot
//! policy, or the IMA aggregate makes it refuse — a firmware update therefore
//! invalidates the stored credential, deliberately and identically to how the
//! SVID cache behaves (`docs/features/F04-svid-lifecycle.md`). The Secure
//! Enclave holds a P-256 key that cannot be exported by anyone, root included;
//! the store's key is encrypted to its public half and only the Enclave can
//! decrypt it. The machine-key backend is the last resort (feature F16): clone
//! resistance bound to machine identity, not to hardware. All three share one
//! AEAD envelope ([`ferro_sep::seal_bytes`]) under distinct purposes; they
//! differ only in where the envelope's secret comes from.
//!
//! ## Fail-closed, always
//!
//! A stored credential is only returned if it unseals **and** re-verifies:
//! the certificate must still chain to its bundle under both signature halves,
//! must not have expired, and the stored private key must be the one the
//! certificate names. Anything else is a load failure, and the caller
//! re-attests. Nothing here decides *whether* to attest; it only preserves a
//! credential across restarts and makes it available to inspect.

use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use ferro_crypto::composite::ed25519_public_from_pkcs8;

/// Purpose tag separating this file from every other sealed file on the host.
const SEAL_PURPOSE: &[u8] = b"ferrogate-x509-svid-store-v1";

/// Store format version.
const FORMAT_VERSION: u8 = 1;

/// Clock skew allowed when re-checking a stored certificate's validity window.
/// Matches the `nbf` lookback CMIS stamps at issuance.
const LOAD_LEEWAY_SECS: i64 = 60;

const BACKEND_TPM: u8 = 1;
const BACKEND_MACHINE_KEY: u8 = 2;
const BACKEND_SECURE_ENCLAVE: u8 = 3;

/// Failure modes for the credential store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Reading or writing the file failed.
    #[error("credential store io: {0}")]
    Io(String),
    /// The file is not a credential store, or is a version this build cannot read.
    #[error("credential store is malformed: {0}")]
    Malformed(String),
    /// The file was sealed by a different backend than the one offered.
    #[error("credential store was sealed by the {stored} backend, but {offered} was offered")]
    BackendMismatch {
        /// Backend named in the file.
        stored: &'static str,
        /// Backend the caller supplied.
        offered: &'static str,
    },
    /// The data-protection key could not be recovered — on the TPM backend this
    /// is the expected outcome after a boot-state change or on another machine.
    #[error("credential store did not unseal on this machine: {0}")]
    Unseal(String),
    /// The credential unsealed but did not survive re-verification.
    #[error("stored credential is no longer usable: {0}")]
    Unusable(String),
}

/// The credential as held in memory.
#[derive(Clone)]
pub struct X509Credential {
    /// The X.509-SVID leaf, DER.
    pub leaf_der: Vec<u8>,
    /// The trust bundle it chains to, DER.
    pub bundle_der: Vec<u8>,
    /// The leaf's private key as PKCS#8 v1 Ed25519 — the form a TLS stack
    /// loads. Zeroed on drop.
    pub key_pkcs8: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for X509Credential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("X509Credential")
            .field("leaf_der", &format_args!("{} bytes", self.leaf_der.len()))
            .field(
                "bundle_der",
                &format_args!("{} bytes", self.bundle_der.len()),
            )
            .field("key_pkcs8", &"<redacted>")
            .finish()
    }
}

/// A credential recovered from the store, with what re-verification established.
#[derive(Debug, Clone)]
pub struct LoadedCredential {
    /// The credential itself.
    pub credential: X509Credential,
    /// The SPIFFE ID in the leaf's URI SAN.
    pub spiffe_id: String,
    /// `notAfter`, Unix seconds.
    pub not_after: i64,
    /// Which backend the file was sealed under.
    pub backend: &'static str,
}

/// How the store's data-protection key is bound to this machine.
///
/// Callers normally let [`with_sealer`] pick the strongest tier the host offers
/// rather than constructing a variant directly; naming one explicitly is for
/// tests and for a caller that already holds an open hardware handle.
pub enum Sealer<'a> {
    /// Derive the key from the hardware fingerprint `H` (feature F16). The
    /// last-resort tier, used where there is no hardware root available.
    MachineKey(&'a [u8]),
    /// Have the TPM release the key, bound to the sealing PCR state.
    #[cfg(target_os = "linux")]
    Tpm(&'a mut crate::tpm::TpmEngine),
    /// Have the macOS Secure Enclave unwrap the key. The Enclave-resident
    /// private half never leaves the hardware, so the file is inert on any
    /// other Mac.
    #[cfg(all(target_os = "macos", feature = "secure-enclave"))]
    SecureEnclave(&'a ferro_sep::enclave::SecureEnclaveSealKey),
}

impl Sealer<'_> {
    /// The backend tag written into the file.
    fn tag(&self) -> u8 {
        match self {
            Self::MachineKey(_) => BACKEND_MACHINE_KEY,
            #[cfg(target_os = "linux")]
            Self::Tpm(_) => BACKEND_TPM,
            #[cfg(all(target_os = "macos", feature = "secure-enclave"))]
            Self::SecureEnclave(_) => BACKEND_SECURE_ENCLAVE,
        }
    }

    /// Human-readable backend name, for logs and errors.
    #[must_use]
    pub fn name(&self) -> &'static str {
        backend_name(self.tag())
    }
}

fn backend_name(tag: u8) -> &'static str {
    match tag {
        BACKEND_TPM => "tpm",
        BACKEND_MACHINE_KEY => "machine-key",
        BACKEND_SECURE_ENCLAVE => "secure-enclave",
        _ => "unknown",
    }
}

/// The directory the daemon keeps its state in — the machine key, the SVID
/// seed, and this store.
#[must_use]
pub fn state_dir() -> std::path::PathBuf {
    #[cfg(target_os = "linux")]
    {
        std::path::PathBuf::from("/var/lib/ferrogate")
    }
    #[cfg(not(target_os = "linux"))]
    {
        crate::config::system_config_path().parent().map_or_else(
            || std::path::PathBuf::from("."),
            std::path::Path::to_path_buf,
        )
    }
}

/// Where the sealed X.509-SVID lives (e.g. `/var/lib/ferrogate/x509-svid.sealed`).
#[must_use]
pub fn store_path() -> std::path::PathBuf {
    state_dir().join("x509-svid.sealed")
}

/// Open the strongest machine-binding sealer this host offers and run `f` with it.
///
/// The order is a hardware root first, the fingerprint last:
///
/// 1. **TPM** (Linux) — even on a host that attests through the software tier,
///    because a key the chip releases beats one derived from a fingerprint and
///    there is no reason to protect the credential more weakly than the
///    hardware allows.
/// 2. **Secure Enclave** (macOS, `secure-enclave` feature) — the same argument
///    on Apple hardware. Skipped when the Enclave key cannot be *persisted*: a
///    key that dies with the process would leave the next start unable to open
///    its own store, so a build that macOS refuses the keychain to (an unsigned
///    binary, `-34018`) falls through rather than writing a file nothing can
///    reopen.
/// 3. **Machine key** — the fingerprint-derived last resort.
///
/// Returns `None` when the host offers none of them, in which case the caller
/// has nowhere safe to put the credential and must not write it in the clear.
pub fn with_sealer<T>(
    fingerprint: Option<&[u8]>,
    f: impl FnOnce(&mut Sealer<'_>) -> T,
) -> Option<T> {
    #[cfg(target_os = "linux")]
    {
        match crate::tpm::TpmEngine::open_device() {
            Ok(mut engine) => return Some(f(&mut Sealer::Tpm(&mut engine))),
            Err(e) => {
                tracing::debug!(error = %e, "no usable TPM for credential sealing; trying the next tier");
            }
        }
    }
    #[cfg(all(target_os = "macos", feature = "secure-enclave"))]
    {
        match ferro_sep::enclave::SecureEnclaveSealKey::open_or_create(ENCLAVE_KEY_LABEL) {
            Ok(key) => return Some(f(&mut Sealer::SecureEnclave(&key))),
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    "no persistent Secure Enclave key available (a build without a keychain \
                     entitlement cannot keep one); falling back to the machine key"
                );
            }
        }
    }
    let fingerprint = fingerprint?;
    Some(f(&mut Sealer::MachineKey(fingerprint)))
}

/// Keychain label of the Enclave key that wraps this host's store.
#[cfg(all(target_os = "macos", feature = "secure-enclave"))]
pub const ENCLAVE_KEY_LABEL: &str = "FerroGate X.509-SVID store key";

/// The on-disk file: a backend tag, whatever that backend needs to recover the
/// data-protection key, and the sealed payload.
#[derive(Serialize, Deserialize)]
struct SealedFile {
    v: u8,
    backend: u8,
    /// Marshaled `TPM2B_PUBLIC` of the sealed data-protection key (TPM backend).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tpm_public: Option<Vec<u8>>,
    /// Marshaled `TPM2B_PRIVATE` of the same object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tpm_private: Option<Vec<u8>>,
    /// The data-protection key ECIES-wrapped to the Secure Enclave key
    /// (Secure Enclave backend).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sep_wrapped: Option<Vec<u8>>,
    /// [`ferro_sep::seal_bytes`] output over the CBOR [`Record`].
    envelope: Vec<u8>,
}

/// The sealed payload.
#[derive(Serialize, Deserialize)]
struct Record {
    leaf_der: Vec<u8>,
    bundle_der: Vec<u8>,
    key_pkcs8: Vec<u8>,
}

/// Write `bytes` to `path` as an owner-only (`0600`) file, creating or
/// truncating it.
///
/// On Unix the mode is applied by `open(2)` at creation, so the bytes are never
/// briefly world-readable *and* no separate `chmod` is needed — the hardened
/// seccomp profile deliberately forbids `chmod` (see `ferro-harden`), so a
/// post-write `set_permissions` would be killed with `SIGSYS` once the daemon
/// has dropped privileges.
pub fn write_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

/// Seal `credential` to `path`, bound to this machine by `sealer`.
///
/// The write is not atomic: a torn file simply fails to load next start and the
/// daemon re-attests, which is the same path every other load failure takes.
pub fn store(
    path: &Path,
    credential: &X509Credential,
    sealer: &mut Sealer<'_>,
) -> Result<(), StoreError> {
    let record = Record {
        leaf_der: credential.leaf_der.clone(),
        bundle_der: credential.bundle_der.clone(),
        key_pkcs8: credential.key_pkcs8.to_vec(),
    };
    let mut plaintext = Zeroizing::new(Vec::new());
    ciborium::into_writer(&record, &mut *plaintext)
        .map_err(|e| StoreError::Malformed(format!("encode record: {e}")))?;

    let protection = protect(sealer)?;
    let envelope = ferro_sep::seal_bytes(&plaintext, &protection.secret, SEAL_PURPOSE)
        .map_err(|e| StoreError::Unseal(e.to_string()))?;

    let file = SealedFile {
        v: FORMAT_VERSION,
        backend: sealer.tag(),
        tpm_public: protection.tpm_public,
        tpm_private: protection.tpm_private,
        sep_wrapped: protection.sep_wrapped,
        envelope,
    };
    let mut bytes = Vec::new();
    ciborium::into_writer(&file, &mut bytes)
        .map_err(|e| StoreError::Malformed(format!("encode store: {e}")))?;

    write_secret_file(path, &bytes)
        .map_err(|e| StoreError::Io(format!("write {}: {e}", path.display())))
}

/// Recover the credential at `path`, or `Ok(None)` if no store exists yet.
///
/// Every other outcome is an error: the credential is returned only when it
/// unseals on this machine, still verifies as an X.509-SVID at `now`, and its
/// stored key matches the certificate.
pub fn load(
    path: &Path,
    sealer: &mut Sealer<'_>,
    now: i64,
) -> Result<Option<LoadedCredential>, StoreError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(StoreError::Io(format!("read {}: {e}", path.display()))),
    };

    let file: SealedFile = ciborium::from_reader(bytes.as_slice())
        .map_err(|e| StoreError::Malformed(format!("decode store: {e}")))?;
    if file.v != FORMAT_VERSION {
        return Err(StoreError::Malformed(format!(
            "unsupported store version {}",
            file.v
        )));
    }
    if file.backend != sealer.tag() {
        return Err(StoreError::BackendMismatch {
            stored: backend_name(file.backend),
            offered: sealer.name(),
        });
    }

    let secret = recover(sealer, &file)?;
    let plaintext = ferro_sep::unseal_bytes(&file.envelope, &secret, SEAL_PURPOSE)
        .map_err(|e| StoreError::Unseal(e.to_string()))?;
    let record: Record = ciborium::from_reader(plaintext.as_slice())
        .map_err(|e| StoreError::Malformed(format!("decode record: {e}")))?;

    // Re-verify rather than trust the file: a credential that no longer stands
    // up is worse than none, because a caller would act on it.
    let verified = ferro_svid_verify::x509::verify_x509(
        &record.leaf_der,
        &record.bundle_der,
        now,
        LOAD_LEEWAY_SECS,
    )
    .map_err(|e| StoreError::Unusable(e.to_string()))?;

    let stored_pub = ed25519_public_from_pkcs8(&record.key_pkcs8)
        .map_err(|e| StoreError::Unusable(format!("stored private key: {e}")))?;
    if stored_pub != verified.subject_pub.ed25519().to_bytes() {
        return Err(StoreError::Unusable(
            "stored private key does not match the certificate's subject key".to_string(),
        ));
    }

    Ok(Some(LoadedCredential {
        credential: X509Credential {
            leaf_der: record.leaf_der,
            bundle_der: record.bundle_der,
            key_pkcs8: Zeroizing::new(record.key_pkcs8),
        },
        spiffe_id: verified.spiffe_id,
        not_after: verified.not_after,
        backend: backend_name(file.backend),
    }))
}

/// Remove a store that failed to load, so the next start does not retry a file
/// that can never open again (a TPM seal after a firmware change, say).
/// Best-effort: a failure here is not worth failing the daemon over.
pub fn discard(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// What a backend contributes to a fresh write: the data-protection secret, and
/// whatever the file must carry to recover it later.
#[derive(Default)]
struct Protection {
    /// The secret the AEAD envelope is keyed from.
    secret: Zeroizing<Vec<u8>>,
    /// Marshaled `TPM2B_PUBLIC` / `TPM2B_PRIVATE` (TPM backend).
    tpm_public: Option<Vec<u8>>,
    tpm_private: Option<Vec<u8>>,
    /// The ECIES-wrapped secret (Secure Enclave backend).
    sep_wrapped: Option<Vec<u8>>,
}

/// A fresh 32-byte data-protection key, to be handed to a hardware root for
/// protection. Only the wrapped form reaches the disk.
#[cfg(any(
    target_os = "linux",
    all(target_os = "macos", feature = "secure-enclave")
))]
fn fresh_dpk() -> Zeroizing<Vec<u8>> {
    use getrandom::SysRng;
    use rand_core::{Rng as _, UnwrapErr};
    let mut dpk = Zeroizing::new(vec![0u8; 32]);
    UnwrapErr(SysRng).fill_bytes(&mut dpk);
    dpk
}

/// Mint the data-protection secret for a fresh write.
fn protect(sealer: &mut Sealer<'_>) -> Result<Protection, StoreError> {
    match sealer {
        Sealer::MachineKey(fingerprint) => {
            // The fingerprint is the secret; nothing extra goes in the file.
            Ok(Protection {
                secret: Zeroizing::new(fingerprint.to_vec()),
                ..Protection::default()
            })
        }
        #[cfg(target_os = "linux")]
        Sealer::Tpm(engine) => {
            let dpk = fresh_dpk();
            let sealed = crate::seal::seal_secret(engine, &dpk)
                .map_err(|e| StoreError::Unseal(format!("TPM seal: {e}")))?;
            Ok(Protection {
                secret: dpk,
                tpm_public: Some(sealed.public),
                tpm_private: Some(sealed.private),
                sep_wrapped: None,
            })
        }
        #[cfg(all(target_os = "macos", feature = "secure-enclave"))]
        Sealer::SecureEnclave(key) => {
            let dpk = fresh_dpk();
            let wrapped = key
                .wrap(&dpk)
                .map_err(|e| StoreError::Unseal(format!("Secure Enclave wrap: {e}")))?;
            Ok(Protection {
                secret: dpk,
                sep_wrapped: Some(wrapped),
                ..Protection::default()
            })
        }
    }
}

/// Recover the data-protection secret for an existing file.
// `file` carries the TPM-sealed key, which only the TPM branch reads.
#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
fn recover(sealer: &mut Sealer<'_>, file: &SealedFile) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    match sealer {
        Sealer::MachineKey(fingerprint) => Ok(Zeroizing::new(fingerprint.to_vec())),
        #[cfg(all(target_os = "macos", feature = "secure-enclave"))]
        Sealer::SecureEnclave(key) => {
            let wrapped = file.sep_wrapped.as_ref().ok_or_else(|| {
                StoreError::Malformed("Enclave-sealed store carries no wrapped key".to_string())
            })?;
            // The expected failure on another Mac: that Enclave holds a
            // different key, so the blob does not decrypt.
            key.unwrap_secret(wrapped)
                .map(|s| Zeroizing::new(s.to_vec()))
                .map_err(|e| StoreError::Unseal(format!("Secure Enclave unwrap: {e}")))
        }
        #[cfg(target_os = "linux")]
        Sealer::Tpm(engine) => {
            let (public, private) = match (&file.tpm_public, &file.tpm_private) {
                (Some(p), Some(q)) => (p.clone(), q.clone()),
                _ => {
                    return Err(StoreError::Malformed(
                        "TPM-sealed store carries no sealed key".to_string(),
                    ))
                }
            };
            let sealed = crate::seal::SealedKey { public, private };
            crate::seal::unseal_secret(engine, &sealed)
                .map(Zeroizing::new)
                // The expected failure after a boot-state change: the TPM
                // refuses the policy, so the credential stays unreadable.
                .map_err(|e| StoreError::Unseal(format!("TPM unseal: {e}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferro_crypto::composite::CompositeSecretKey;
    use ferro_svid::{IssueParams, Issuer};

    const NOW: i64 = 1_700_000_000;
    const FINGERPRINT: &[u8] = b"host-A-fingerprint-H";

    fn scratch(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "ferrogate-credstore-{}-{tag}.bin",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// A real issued credential: CMIS mints the certificate, the host holds the
    /// composite key whose Ed25519 half the certificate names.
    fn credential() -> X509Credential {
        let issuer = Issuer::generate("kid-test", "ferrogate.test").unwrap();
        let (host_secret, host_public) = CompositeSecretKey::from_seed(&[0x5a; 32]);
        let minted = issuer
            .issue(
                &IssueParams {
                    ek_cert_sha384: [0x11; 48],
                    pcr_digest: [0x22; 48],
                    policy_id: "rim-gen-5".to_string(),
                    dpop_jkt: "dpop".to_string(),
                    ttl_secs: 3600,
                    tee_evidence_id: None,
                    subject_pub: Some(host_public.to_concat_bytes()),
                },
                NOW,
            )
            .unwrap();
        X509Credential {
            leaf_der: minted.x509.unwrap().leaf_der,
            bundle_der: issuer.x509_ca().unwrap().to_vec(),
            key_pkcs8: host_secret.to_ed25519_pkcs8_der(),
        }
    }

    #[test]
    fn roundtrips_on_the_same_machine() {
        let path = scratch("roundtrip");
        let cred = credential();
        let mut sealer = Sealer::MachineKey(FINGERPRINT);

        store(&path, &cred, &mut sealer).unwrap();
        let loaded = load(&path, &mut sealer, NOW + 60).unwrap().expect("stored");

        assert_eq!(loaded.credential.leaf_der, cred.leaf_der);
        assert_eq!(loaded.credential.bundle_der, cred.bundle_der);
        assert_eq!(loaded.credential.key_pkcs8, cred.key_pkcs8);
        assert!(loaded
            .spiffe_id
            .starts_with("spiffe://ferrogate.test/host/"));
        assert_eq!(loaded.not_after, NOW + 3600);
        assert_eq!(loaded.backend, "machine-key");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn does_not_open_on_another_machine() {
        // The property the whole module exists for: the file is worthless on a
        // host whose fingerprint differs, so a cloned disk carries no usable
        // credential.
        let path = scratch("clone");
        store(&path, &credential(), &mut Sealer::MachineKey(FINGERPRINT)).unwrap();

        let err = load(
            &path,
            &mut Sealer::MachineKey(b"host-B-fingerprint"),
            NOW + 60,
        )
        .unwrap_err();
        assert!(matches!(err, StoreError::Unseal(_)), "got {err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn absent_store_is_not_an_error() {
        let path = scratch("absent");
        assert!(load(&path, &mut Sealer::MachineKey(FINGERPRINT), NOW)
            .unwrap()
            .is_none());
    }

    #[test]
    fn tampering_with_the_sealed_file_is_caught() {
        let path = scratch("tamper");
        store(&path, &credential(), &mut Sealer::MachineKey(FINGERPRINT)).unwrap();

        let mut bytes = std::fs::read(&path).unwrap();
        let n = bytes.len();
        bytes[n - 1] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();

        assert!(load(&path, &mut Sealer::MachineKey(FINGERPRINT), NOW + 60).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_expired_credential_is_refused() {
        let path = scratch("expired");
        store(&path, &credential(), &mut Sealer::MachineKey(FINGERPRINT)).unwrap();

        let err = load(&path, &mut Sealer::MachineKey(FINGERPRINT), NOW + 7200).unwrap_err();
        assert!(matches!(err, StoreError::Unusable(_)), "got {err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_key_that_does_not_match_the_certificate_is_refused() {
        // Guards against a store assembled from mismatched halves — the caller
        // would otherwise hand a workload a certificate it cannot sign for.
        let path = scratch("mismatch");
        let mut cred = credential();
        cred.key_pkcs8 = CompositeSecretKey::from_seed(&[0x99; 32])
            .0
            .to_ed25519_pkcs8_der();

        store(&path, &cred, &mut Sealer::MachineKey(FINGERPRINT)).unwrap();
        let err = load(&path, &mut Sealer::MachineKey(FINGERPRINT), NOW + 60).unwrap_err();
        assert!(
            matches!(&err, StoreError::Unusable(m) if m.contains("does not match")),
            "got {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_credential_from_another_trust_domain_is_refused() {
        // The bundle must actually be the one that signed the leaf; a swapped
        // bundle fails the same way a forged certificate would.
        let path = scratch("wrong-bundle");
        let mut cred = credential();
        cred.bundle_der = Issuer::generate("kid-other", "ferrogate.other")
            .unwrap()
            .x509_ca()
            .unwrap()
            .to_vec();

        store(&path, &cred, &mut Sealer::MachineKey(FINGERPRINT)).unwrap();
        assert!(matches!(
            load(&path, &mut Sealer::MachineKey(FINGERPRINT), NOW + 60).unwrap_err(),
            StoreError::Unusable(_)
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_file_never_holds_the_key_in_the_clear() {
        let path = scratch("opaque");
        let cred = credential();
        store(&path, &cred, &mut Sealer::MachineKey(FINGERPRINT)).unwrap();

        let bytes = std::fs::read(&path).unwrap();
        for needle in [cred.key_pkcs8.as_slice(), cred.leaf_der.as_slice()] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "sealed file must not contain the plaintext credential"
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_daemon_entry_point_round_trips_on_whatever_this_host_offers() {
        // `with_sealer` is what the daemon actually calls. Whichever tier it
        // lands on — TPM, Secure Enclave, or the machine key — a credential
        // written through it must read back through it. This is also the
        // fallback path: on a host where a hardware root is unavailable (an
        // unsigned macOS build cannot keep an Enclave key), it must degrade to
        // the machine key rather than fail.
        let path = scratch("with-sealer");
        let cred = credential();

        let backend = with_sealer(Some(FINGERPRINT), |sealer| {
            store(&path, &cred, sealer).expect("store through the daemon entry point");
            sealer.name()
        })
        .expect("this host offers at least the machine-key tier");

        let loaded = with_sealer(Some(FINGERPRINT), |sealer| load(&path, sealer, NOW + 60))
            .expect("sealer available")
            .expect("load")
            .expect("a credential is stored");

        assert_eq!(loaded.backend, backend);
        assert_eq!(loaded.credential.leaf_der, cred.leaf_der);
        eprintln!("with_sealer chose the {backend} tier on this host");
        let _ = std::fs::remove_file(&path);
    }

    // --- Secure Enclave backend (live hardware) ---------------------------
    //
    // These use an *ephemeral* Enclave key, which macOS lets an unsigned binary
    // generate. The key really is in the Enclave and every operation below is
    // real hardware; only keychain persistence needs an entitlement, and that is
    // covered by `ferro_sep::enclave`'s own ignored test.

    #[cfg(all(target_os = "macos", feature = "secure-enclave"))]
    mod secure_enclave {
        use super::*;
        use ferro_sep::enclave::SecureEnclaveSealKey;

        fn enclave_key(tag: &str) -> Option<SecureEnclaveSealKey> {
            SecureEnclaveSealKey::ephemeral(&format!("FerroGate credstore test {tag}"))
                .map_err(|e| eprintln!("no usable Secure Enclave ({e}); skipping"))
                .ok()
        }

        #[test]
        fn roundtrips_through_the_secure_enclave() {
            let Some(key) = enclave_key("roundtrip") else {
                return;
            };
            let path = scratch("sep-roundtrip");
            let cred = credential();

            store(&path, &cred, &mut Sealer::SecureEnclave(&key)).unwrap();
            let loaded = load(&path, &mut Sealer::SecureEnclave(&key), NOW + 60)
                .unwrap()
                .expect("stored");

            assert_eq!(loaded.credential.leaf_der, cred.leaf_der);
            assert_eq!(loaded.credential.key_pkcs8, cred.key_pkcs8);
            assert_eq!(loaded.backend, "secure-enclave");
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn does_not_open_under_a_different_enclave_key() {
            // Two Enclave keys stand in for two Macs: the wrapped
            // data-protection key is bound to the key that wrapped it, and
            // neither private half can leave the hardware.
            let (Some(mine), Some(theirs)) = (enclave_key("mine"), enclave_key("theirs")) else {
                return;
            };
            let path = scratch("sep-other-mac");
            store(&path, &credential(), &mut Sealer::SecureEnclave(&mine)).unwrap();

            let err = load(&path, &mut Sealer::SecureEnclave(&theirs), NOW + 60).unwrap_err();
            assert!(matches!(err, StoreError::Unseal(_)), "got {err}");
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn an_enclave_sealed_store_does_not_open_with_the_machine_key() {
            // The file names its backend, so an attempt to open it with a
            // weaker one is refused outright rather than silently downgraded.
            let Some(key) = enclave_key("mismatch") else {
                return;
            };
            let path = scratch("sep-mismatch");
            store(&path, &credential(), &mut Sealer::SecureEnclave(&key)).unwrap();

            let err = load(&path, &mut Sealer::MachineKey(FINGERPRINT), NOW + 60).unwrap_err();
            assert!(
                matches!(
                    err,
                    StoreError::BackendMismatch {
                        stored: "secure-enclave",
                        ..
                    }
                ),
                "got {err}"
            );
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn the_enclave_sealed_file_holds_nothing_in_the_clear() {
            let Some(key) = enclave_key("opaque") else {
                return;
            };
            let path = scratch("sep-opaque");
            let cred = credential();
            store(&path, &cred, &mut Sealer::SecureEnclave(&key)).unwrap();

            let bytes = std::fs::read(&path).unwrap();
            for needle in [cred.key_pkcs8.as_slice(), cred.leaf_der.as_slice()] {
                assert!(!bytes.windows(needle.len()).any(|w| w == needle));
            }
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn tampering_with_the_wrapped_key_is_caught() {
            let Some(key) = enclave_key("tamper") else {
                return;
            };
            let path = scratch("sep-tamper");
            store(&path, &credential(), &mut Sealer::SecureEnclave(&key)).unwrap();

            let mut bytes = std::fs::read(&path).unwrap();
            let n = bytes.len();
            bytes[n / 2] ^= 0x01;
            std::fs::write(&path, &bytes).unwrap();

            assert!(load(&path, &mut Sealer::SecureEnclave(&key), NOW + 60).is_err());
            let _ = std::fs::remove_file(&path);
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let path = scratch("perms");
        store(&path, &credential(), &mut Sealer::MachineKey(FINGERPRINT)).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got {mode:o}");
        let _ = std::fs::remove_file(&path);
    }
}
