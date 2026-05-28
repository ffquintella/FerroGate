//! ML-KEM-768 + attestation handshake for share transport.
//!
//! Two peers — initiator `I` and responder `R` — need to agree on a 32-byte
//! PSK over which they will exchange a Shamir share. The agreement must:
//!
//! 1. Be post-quantum secure (so a passive future attacker can't decrypt
//!    the recorded transcript and recover the share).
//! 2. Mutually authenticate via TEE attestation (the only artefact tying a
//!    peer to a CMIS image is its enclave report).
//! 3. Bind the report to the KEM ephemeral so an attacker can't replay a
//!    valid report on top of a substituted ML-KEM ciphertext.
//!
//! Protocol (over a separately-authenticated transport, e.g. CMIS peer
//! mTLS):
//!
//! ```text
//! I -> R: nonce_I, ek_I  (ML-KEM-768 encapsulation key)         (msg1)
//!         report_I bound to SHA3-384("psk-bind" || nonce_R||ek_I)
//!         where nonce_R was offered by R out-of-band.
//! R -> I: nonce_R, ct    (ML-KEM-768 ciphertext for ek_I)        (msg2)
//!         report_R bound to SHA3-384("psk-bind" || nonce_I||ek_I||ct)
//! Both:   ss = ML-KEM-Decaps(dk_I, ct)
//!         psk = HKDF-SHA3-384(salt=transcript, ikm=ss,
//!                             info="ferro-tee-psk-v1").expand(32)
//! ```
//!
//! Both sides verify each other's reports against the cluster's peer-roots
//! and the approved-CMIS-image allowlist before deriving the PSK; the
//! caller surfaces the verified peer measurement so callers can refuse to
//! send a share to an attested-but-not-approved peer.

use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768};
use rand_core::OsRng;
use sha3::{Digest, Sha3_384};

type EkSize = <<MlKem768 as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize;

use crate::attest::{verify_report, Attestor, PeerRoots, Report};
use crate::error::TeeError;
use crate::measurement::{Allowlist, Measurement};

/// Size of the derived session PSK.
pub const PSK_LEN: usize = 32;

/// `msg1`: initiator → responder.
#[derive(Debug, Clone)]
pub struct Msg1 {
    /// Initiator's nonce.
    pub nonce_i: [u8; 32],
    /// Initiator's ML-KEM-768 encapsulation key.
    pub ek_bytes: Vec<u8>,
    /// Initiator's attestation report binding `nonce_r || ek_bytes`.
    pub report_i: Report,
}

/// `msg2`: responder → initiator.
#[derive(Debug, Clone)]
pub struct Msg2 {
    /// Responder's nonce.
    pub nonce_r: [u8; 32],
    /// ML-KEM-768 ciphertext encapsulating the shared secret to `ek_i`.
    pub ct_bytes: Vec<u8>,
    /// Responder's attestation report binding `nonce_i || ek_bytes || ct`.
    pub report_r: Report,
}

/// Result of a completed handshake on either side.
#[derive(Debug)]
pub struct Session {
    /// 32-byte derived PSK; callers use this to key a fresh AEAD for share
    /// transport. Treated as a high-entropy secret.
    pub psk: [u8; PSK_LEN],
    /// Peer's verified launch measurement. Caller MUST cross-check this
    /// against the allowlist before doing anything with the share.
    pub peer_measurement: Measurement,
}

fn psk_bind(label: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha3_384::new();
    h.update(b"ferro-tee-psk-bind-v1");
    h.update(label);
    for p in parts {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p);
    }
    h.finalize().to_vec()
}

fn derive_psk(ss: &[u8], transcript: &[u8]) -> [u8; PSK_LEN] {
    let hk = Hkdf::<Sha3_384>::new(Some(transcript), ss);
    let mut out = [0u8; PSK_LEN];
    hk.expand(b"ferro-tee-psk-v1", &mut out)
        .expect("HKDF-Expand of 32 bytes from SHA3-384 always succeeds");
    out
}

/// Per-handshake state held by the initiator between `start` and `finish`.
pub struct Initiator {
    dk: <MlKem768 as KemCore>::DecapsulationKey,
    ek_bytes: Vec<u8>,
    nonce_i: [u8; 32],
    nonce_r_offered: [u8; 32],
}

impl Initiator {
    /// Begin a handshake. `nonce_r_offered` is the responder's nonce that
    /// the caller obtained out-of-band on the authenticated transport
    /// (typically the responder's "hello" frame). Returns `msg1`.
    pub fn start(
        attestor: &dyn Attestor,
        nonce_i: [u8; 32],
        nonce_r_offered: [u8; 32],
    ) -> (Self, Msg1) {
        let (dk, ek) = MlKem768::generate(&mut OsRng);
        let ek_bytes = ek.as_bytes().to_vec();
        let bound = psk_bind(b"initiator", &[&nonce_r_offered, &ek_bytes]);
        let report_i = attestor.produce(nonce_r_offered, &bound);
        let msg = Msg1 {
            nonce_i,
            ek_bytes: ek_bytes.clone(),
            report_i,
        };
        (
            Self {
                dk,
                ek_bytes,
                nonce_i,
                nonce_r_offered,
            },
            msg,
        )
    }

    /// Process `msg2` and derive the session PSK.
    pub fn finish(
        self,
        msg2: &Msg2,
        roots: &PeerRoots,
        allowlist: &Allowlist,
    ) -> Result<Session, TeeError> {
        // Sanity: the responder must echo back the nonce we expected on
        // the report we offered.
        if msg2.nonce_r != self.nonce_r_offered {
            return Err(TeeError::PskTranscript);
        }
        let bound = psk_bind(
            b"responder",
            &[&self.nonce_i, &self.ek_bytes, &msg2.ct_bytes],
        );
        let peer_measurement = verify_report(&msg2.report_r, &self.nonce_i, &bound, roots)?;
        if !allowlist.contains(&peer_measurement) {
            return Err(TeeError::MeasurementNotAllowed);
        }
        let ct = Ciphertext::<MlKem768>::try_from(msg2.ct_bytes.as_slice())
            .map_err(|_| TeeError::MlKem)?;
        let ss = self.dk.decapsulate(&ct).map_err(|()| TeeError::MlKem)?;
        let transcript = {
            let mut h = Sha3_384::new();
            h.update(b"ferro-tee-psk-transcript-v1");
            h.update(self.nonce_i);
            h.update(msg2.nonce_r);
            h.update(&self.ek_bytes);
            h.update(&msg2.ct_bytes);
            h.finalize().to_vec()
        };
        let psk = derive_psk(ss.as_slice(), &transcript);
        Ok(Session {
            psk,
            peer_measurement,
        })
    }
}

/// Responder API: a single function that processes `msg1` and returns
/// `(msg2, Session)`.
pub fn respond(
    attestor: &dyn Attestor,
    msg1: &Msg1,
    nonce_r: [u8; 32],
    roots: &PeerRoots,
    allowlist: &Allowlist,
) -> Result<(Msg2, Session), TeeError> {
    // The initiator's report must bind the nonce we previously offered
    // (delivered to it as `nonce_r_offered`) and its own ek.
    let bound = psk_bind(b"initiator", &[&nonce_r, &msg1.ek_bytes]);
    let peer_measurement = verify_report(&msg1.report_i, &nonce_r, &bound, roots)?;
    if !allowlist.contains(&peer_measurement) {
        return Err(TeeError::MeasurementNotAllowed);
    }
    let ek_array: ml_kem::array::Array<u8, EkSize> =
        ml_kem::array::Array::try_from(msg1.ek_bytes.as_slice()).map_err(|_| TeeError::MlKem)?;
    let ek = <<MlKem768 as KemCore>::EncapsulationKey as EncodedSizeUser>::from_bytes(&ek_array);
    let (ct, ss) = ek.encapsulate(&mut OsRng).map_err(|()| TeeError::MlKem)?;
    let ct_bytes = ct.as_slice().to_vec();
    let bound_r = psk_bind(b"responder", &[&msg1.nonce_i, &msg1.ek_bytes, &ct_bytes]);
    let report_r = attestor.produce(msg1.nonce_i, &bound_r);

    let transcript = {
        let mut h = Sha3_384::new();
        h.update(b"ferro-tee-psk-transcript-v1");
        h.update(msg1.nonce_i);
        h.update(nonce_r);
        h.update(&msg1.ek_bytes);
        h.update(&ct_bytes);
        h.finalize().to_vec()
    };
    let psk = derive_psk(ss.as_slice(), &transcript);

    Ok((
        Msg2 {
            nonce_r,
            ct_bytes,
            report_r,
        },
        Session {
            psk,
            peer_measurement,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::SoftwareAttestor;
    use crate::measurement::{Allowlist, Measurement};

    fn pair() -> (SoftwareAttestor, SoftwareAttestor, PeerRoots, Allowlist) {
        let i_m = Measurement([10u8; 48]);
        let r_m = Measurement([11u8; 48]);
        let i = SoftwareAttestor::generate(i_m);
        let r = SoftwareAttestor::generate(r_m);
        let roots = PeerRoots::new([i.signer_pk(), r.signer_pk()]);
        let allow = Allowlist::new([i_m, r_m]);
        (i, r, roots, allow)
    }

    #[test]
    fn happy_path_both_sides_derive_same_psk() {
        let (i_att, r_att, roots, allow) = pair();
        let nonce_i = [1u8; 32];
        let nonce_r = [2u8; 32];
        let (init, m1) = Initiator::start(&i_att, nonce_i, nonce_r);
        let (m2, r_sess) = respond(&r_att, &m1, nonce_r, &roots, &allow).unwrap();
        let i_sess = init.finish(&m2, &roots, &allow).unwrap();
        assert_eq!(i_sess.psk, r_sess.psk);
        assert_eq!(i_sess.peer_measurement, r_att.measurement());
        assert_eq!(r_sess.peer_measurement, i_att.measurement());
    }

    #[test]
    fn initiator_not_on_allowlist_is_refused() {
        let (i_att, r_att, roots, _allow) = pair();
        let nonce_i = [1u8; 32];
        let nonce_r = [2u8; 32];
        let (_, m1) = Initiator::start(&i_att, nonce_i, nonce_r);
        // Allowlist excludes the initiator.
        let restricted = Allowlist::new([r_att.measurement()]);
        let err = respond(&r_att, &m1, nonce_r, &roots, &restricted).unwrap_err();
        assert!(matches!(err, TeeError::MeasurementNotAllowed));
    }

    #[test]
    fn responder_with_swapped_root_is_refused() {
        let (i_att, r_att, _roots, allow) = pair();
        let nonce_i = [1u8; 32];
        let nonce_r = [2u8; 32];
        let only_initiator = PeerRoots::new([i_att.signer_pk()]);
        let (init, m1) = Initiator::start(&i_att, nonce_i, nonce_r);
        // The responder's response is unattested for the initiator's view
        // because the responder's signing key isn't in the root set.
        let (m2, _) = respond(
            &r_att,
            &m1,
            nonce_r,
            &PeerRoots::new([i_att.signer_pk(), r_att.signer_pk()]),
            &allow,
        )
        .unwrap();
        let err = init.finish(&m2, &only_initiator, &allow).unwrap_err();
        assert!(matches!(err, TeeError::BadReportSignature));
    }

    #[test]
    fn tampered_ciphertext_breaks_transcript() {
        let (i_att, r_att, roots, allow) = pair();
        let nonce_i = [1u8; 32];
        let nonce_r = [2u8; 32];
        let (init, m1) = Initiator::start(&i_att, nonce_i, nonce_r);
        let (mut m2, _) = respond(&r_att, &m1, nonce_r, &roots, &allow).unwrap();
        // Flip a byte: signature over the responder's report covers the
        // ct via bound_data → verify_report rejects.
        m2.ct_bytes[0] ^= 0x01;
        let err = init.finish(&m2, &roots, &allow).unwrap_err();
        assert!(matches!(err, TeeError::BadReport(_)));
    }
}
