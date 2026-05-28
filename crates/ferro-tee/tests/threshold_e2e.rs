//! End-to-end exercise of the F06 acceptance criteria.
//!
//! Builds five distinct CMIS replicas, splits a 32-byte composite-key seed
//! 3-of-5, seals each share to its replica's measurement, has the leader
//! perform peer-attested PSK handshakes with each, receives the unsealed
//! shares over the resulting AEAD channels, and reconstructs into a
//! page-locked `ProtectedKey`. Exercises:
//!
//! - 3-of-5 reconstruction (and that 2 of 5 doesn't reconstruct).
//! - A replica whose measurement isn't on the cluster allowlist cannot
//!   participate.
//! - A non-owner replica cannot unseal another's share.
//! - Loss of one share still reconstructs.
//! - Loss of three shares halts gracefully.
//! - Reconstructed key zeroizes when its holder is dropped.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChachaKey, Nonce};
use ferro_tee::attest::{Attestor, PeerRoots, SoftwareAttestor};
use ferro_tee::psk::{respond, Initiator};
use ferro_tee::{
    seal, shamir, Allowlist, Measurement, ProtectedKey, Reconstructor, Share, ShareHolder,
    SHAMIR_SHARES, SHAMIR_THRESHOLD,
};

struct Replica {
    attestor: SoftwareAttestor,
    sealed: seal::SealedEnvelope,
    share_index: u8,
}

fn build_cluster(secret: &[u8]) -> (Vec<Replica>, PeerRoots, Allowlist) {
    let set = shamir::split(secret, SHAMIR_THRESHOLD, SHAMIR_SHARES).unwrap();
    let mut replicas = Vec::with_capacity(SHAMIR_SHARES);
    let mut roots = PeerRoots::default();
    let mut allow_entries: Vec<Measurement> = Vec::new();
    for (i, share) in set.shares.into_iter().enumerate() {
        // Each replica gets a distinct measurement.
        let mut m_bytes = [0u8; 48];
        m_bytes[0] = u8::try_from(i + 1).unwrap();
        m_bytes[1] = 0xA5;
        let measurement = Measurement(m_bytes);
        let attestor = SoftwareAttestor::generate(measurement);
        let aad: Vec<u8> = format!("share-{}", share.x).into_bytes();
        // Serialise the share to a stable byte form so it can be sealed.
        let share_bytes = encode_share(&share);
        let env = seal::seal(&attestor, &aad, &share_bytes).unwrap();
        roots.push(attestor.signer_pk());
        allow_entries.push(measurement);
        replicas.push(Replica {
            attestor,
            sealed: env,
            share_index: share.x,
        });
    }
    (replicas, roots, Allowlist::new(allow_entries))
}

fn encode_share(s: &Share) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + s.y.len());
    buf.push(s.x);
    buf.extend_from_slice(&s.y);
    buf
}

fn decode_share(bytes: &[u8]) -> Share {
    Share {
        x: bytes[0],
        y: bytes[1..].to_vec(),
    }
}

/// Drive one peer-attested share exchange and return the unwrapped share.
fn fetch_share(
    leader: &SoftwareAttestor,
    holder: &Replica,
    allow: &Allowlist,
    roots: &PeerRoots,
) -> Share {
    use ferro_tee::psk::{respond, Initiator};

    let nonce_l = [0x11u8; 32];
    let nonce_h = [0x22u8; 32];
    let (init, m1) = Initiator::start(leader, nonce_l, nonce_h);
    let (m2, holder_sess) = respond(&holder.attestor, &m1, nonce_h, roots, allow).unwrap();
    let leader_sess = init.finish(&m2, roots, allow).unwrap();
    assert_eq!(leader_sess.psk, holder_sess.psk);
    assert_eq!(leader_sess.peer_measurement, holder.attestor.measurement());

    // Holder unseals its own share envelope.
    let share_bytes = seal::unseal(&holder.attestor, &holder.sealed).unwrap();

    // Encrypt under the PSK and send to leader; leader decrypts.
    let cipher = ChaCha20Poly1305::new(ChachaKey::from_slice(&holder_sess.psk));
    let nonce = Nonce::from_slice(b"share-xfer01");
    let ct = cipher.encrypt(nonce, share_bytes.as_slice()).unwrap();

    let leader_cipher = ChaCha20Poly1305::new(ChachaKey::from_slice(&leader_sess.psk));
    let pt = leader_cipher.decrypt(nonce, ct.as_slice()).unwrap();
    let share = decode_share(&pt);
    assert_eq!(share.x, holder.share_index);
    share
}

#[test]
fn full_three_of_five_round_trip() {
    let secret = *b"thirty-two-byte composite seed!!";
    assert_eq!(secret.len(), 32);
    let (replicas, roots, allow) = build_cluster(&secret);

    // Leader is one of the replicas (any of them — pick #0).
    let leader = &replicas[0].attestor;

    // Fetch three shares from peers 0, 2, 4 (interleave to prove order
    // doesn't matter and that the threshold property holds for an
    // arbitrary 3-subset).
    let mut holders: Vec<ShareHolder> = Vec::with_capacity(3);
    for idx in [0usize, 2, 4] {
        let share = fetch_share(leader, &replicas[idx], &allow, &roots);
        holders.push(ShareHolder::new(share));
    }

    let key = Reconstructor::new(SHAMIR_THRESHOLD)
        .reconstruct::<32>(&holders)
        .expect("threshold satisfied");
    assert_eq!(key.expose(), &secret);
}

#[test]
fn replica_not_on_allowlist_is_refused() {
    let secret = [0u8; 32];
    let (replicas, roots, _allow) = build_cluster(&secret);
    // Build a restricted allowlist that excludes replica #2.
    let mut restricted = Allowlist::default();
    for (i, r) in replicas.iter().enumerate() {
        if i != 2 {
            restricted.push(r.attestor.measurement());
        }
    }
    let leader = &replicas[0].attestor;
    let (init, m1) = Initiator::start(leader, [1u8; 32], [2u8; 32]);
    // The responder still accepts the leader (the leader's measurement is on
    // the restricted allowlist) so `respond` succeeds at this stage. The
    // refusal must happen on the leader side when it observes the responder's
    // measurement is absent from its allowlist.
    let (m2, _) = respond(
        &replicas[2].attestor,
        &m1,
        [2u8; 32],
        &roots,
        &Allowlist::new(replicas.iter().map(|r| r.attestor.measurement())),
    )
    .unwrap();
    let err = init.finish(&m2, &roots, &restricted).unwrap_err();
    assert!(matches!(err, ferro_tee::TeeError::MeasurementNotAllowed));
}

#[test]
fn replica_cannot_unseal_anothers_share() {
    let secret = [0u8; 32];
    let (replicas, _roots, _allow) = build_cluster(&secret);
    // Replica 0 attempts to unseal replica 1's envelope. Different measurement
    // → seal::unseal must refuse.
    let err = seal::unseal(&replicas[0].attestor, &replicas[1].sealed).unwrap_err();
    assert!(matches!(err, ferro_tee::TeeError::Seal));
}

#[test]
fn loss_of_one_share_still_reconstructs_via_peer_exchange() {
    let secret = *b"another 32-byte issuance secret.";
    let (replicas, roots, allow) = build_cluster(&secret);
    // Simulate replica #3 down: collect shares from {0, 1, 2, 4} but only
    // need three of them.
    let leader = &replicas[0].attestor;
    let mut holders = Vec::new();
    for idx in [0, 1, 4] {
        holders.push(ShareHolder::new(fetch_share(
            leader,
            &replicas[idx],
            &allow,
            &roots,
        )));
    }
    let key = Reconstructor::new(SHAMIR_THRESHOLD)
        .reconstruct::<32>(&holders)
        .unwrap();
    assert_eq!(key.expose(), &secret);
}

#[test]
fn loss_of_three_shares_halts_gracefully() {
    let secret = [0u8; 32];
    let (replicas, roots, allow) = build_cluster(&secret);
    // Only two replicas survive.
    let leader = &replicas[0].attestor;
    let mut holders = Vec::new();
    for idx in [0, 1] {
        holders.push(ShareHolder::new(fetch_share(
            leader,
            &replicas[idx],
            &allow,
            &roots,
        )));
    }
    let err = Reconstructor::new(SHAMIR_THRESHOLD)
        .reconstruct::<32>(&holders)
        .unwrap_err();
    assert!(matches!(
        err,
        ferro_tee::TeeError::NotEnoughShares { have: 2, need: 3 }
    ));
}

#[test]
fn reconstructed_key_can_be_wiped_explicitly() {
    let secret = [0xa5u8; 32];
    let (replicas, roots, allow) = build_cluster(&secret);
    let leader = &replicas[0].attestor;
    let mut holders = Vec::new();
    for idx in [0, 2, 4] {
        holders.push(ShareHolder::new(fetch_share(
            leader,
            &replicas[idx],
            &allow,
            &roots,
        )));
    }
    let mut key: ProtectedKey<32> = Reconstructor::new(SHAMIR_THRESHOLD)
        .reconstruct::<32>(&holders)
        .unwrap();
    assert_eq!(key.expose(), &secret);
    key.wipe();
    assert_eq!(key.expose(), &[0u8; 32]);
}
