//! Sync-loop tests against a scripted CMIS.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferro_audit::AuditEvent;
use ferro_crypto::composite::{CompositePublicKey, CompositeSecretKey};
use ferro_proto::v1::sync_allowlist_response::Result as SyncResult;
use ferro_proto::v1::{
    GetAppRequestStatusRequest, GetAppRequestStatusResponse, NotModified, SubmitAppRequestRequest,
    SubmitAppRequestResponse, SyncAllowlistRequest, SyncAllowlistResponse,
};
use ferro_svid::allowlist_v2::{sign_v2, AllowEntryV2, AllowlistDocV2};
use ferro_svid::app_docs::{decode_allowlist_sync, AllowlistSyncDoc};
use futures::future::BoxFuture;
use tokio::sync::mpsc;
use tonic::Status;

use super::*;
use crate::helper::allowlist::{encode, AllowEntry, AllowlistDoc};
use crate::host_api::HostApi;

const HOST: &str = "1b4e28ba-2fa1-4d2a-883f-0016d3cca427";
const NOW: i64 = 1_800_000_000;

/// A scripted CMIS: `SyncAllowlist` answers pop from a queue; every request
/// document is recorded.
#[derive(Default)]
struct FakeCmis {
    answers: Mutex<VecDeque<Result<SyncAllowlistResponse, Status>>>,
    legacy: Mutex<Option<Vec<u8>>>,
    seen: Mutex<Vec<AllowlistSyncDoc>>,
}

impl FakeCmis {
    fn answer(&self, a: Result<SyncAllowlistResponse, Status>) {
        self.answers.lock().unwrap().push_back(a);
    }

    fn last_doc(&self) -> AllowlistSyncDoc {
        self.seen
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("a request")
    }
}

impl HostApi for FakeCmis {
    fn submit_app_request(
        &self,
        _req: SubmitAppRequestRequest,
    ) -> BoxFuture<'_, Result<SubmitAppRequestResponse, Status>> {
        Box::pin(async { Err(Status::unimplemented("")) })
    }

    fn app_request_status(
        &self,
        _req: GetAppRequestStatusRequest,
    ) -> BoxFuture<'_, Result<GetAppRequestStatusResponse, Status>> {
        Box::pin(async { Err(Status::unimplemented("")) })
    }

    fn sync_allowlist(
        &self,
        req: SyncAllowlistRequest,
    ) -> BoxFuture<'_, Result<SyncAllowlistResponse, Status>> {
        self.seen
            .lock()
            .unwrap()
            .push(decode_allowlist_sync(&req.doc).unwrap());
        let a = self
            .answers
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(Status::unavailable("no answer scripted")));
        Box::pin(async move { a })
    }

    fn get_allowlist(&self, host_uuid: String) -> BoxFuture<'_, Result<Option<Vec<u8>>, Status>> {
        assert_eq!(host_uuid, HOST);
        let body = self.legacy.lock().unwrap().clone();
        Box::pin(async move { Ok(body) })
    }
}

#[derive(Default)]
struct Sink(Mutex<Vec<Allowlist>>);

impl AllowlistSink for Sink {
    fn apply(&self, allowlist: Allowlist) -> BoxFuture<'_, ()> {
        self.0.lock().unwrap().push(allowlist);
        Box::pin(async {})
    }
}

impl Sink {
    fn generations(&self) -> Vec<Option<u64>> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(Allowlist::generation)
            .collect()
    }
}

struct Rig {
    dir: std::path::PathBuf,
    sk: CompositeSecretKey,
    cmis: Arc<FakeCmis>,
    sink: Arc<Sink>,
    audit: mpsc::Receiver<AuditEvent>,
    sync: AllowlistSync,
}

fn rig(tag: &str, held: Option<SyncState>) -> Rig {
    let dir = std::env::temp_dir().join(format!("mia-sync-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (sk, pk) = CompositeSecretKey::generate().unwrap();
    std::fs::write(dir.join("allowlist.pub"), pk.to_concat_bytes()).unwrap();
    let state_path = dir.join("allowlist.state");
    let cfg = SyncConfig {
        interval: Duration::from_secs(300),
        jitter_pct: 10,
        body_path: synced_body_path(&state_path),
        state_path,
        key_path: Some(dir.join("allowlist.pub")),
        max_age_secs: 86_400,
    };
    let key: Arc<dyn ferro_sep::MachineKey + Send + Sync> =
        Arc::new(ferro_sep::SoftwareMachineKey::generate().unwrap());
    let creds = CredentialSlot::new();
    creds.set(HostCredentials::new(
        key,
        "h.c.s".into(),
        &format!("spiffe://ferrogate.test/host/{HOST}"),
        NOW + 100_000,
    ));
    let cmis = Arc::new(FakeCmis::default());
    let sink = Arc::new(Sink::default());
    let (tx, audit) = mpsc::channel(16);
    let sync = AllowlistSync::new(
        cfg,
        Arc::clone(&cmis) as Arc<dyn HostApi>,
        creds,
        Arc::clone(&sink) as Arc<dyn AllowlistSink>,
        held,
    )
    .with_audit(tx);
    Rig {
        dir,
        sk,
        cmis,
        sink,
        audit,
        sync,
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn entry(b: u8) -> AllowEntryV2 {
    AllowEntryV2 {
        approval_id: [b; 16],
        bin_sha: hex::encode([b; 48]),
        uid: Some(1000),
        user_sid_hash: None,
        path_hash: None,
        expires_at: None,
    }
}

fn body(
    sk: &CompositeSecretKey,
    host: &str,
    generation: u64,
    entries: Vec<AllowEntryV2>,
) -> Vec<u8> {
    let doc = AllowlistDocV2 {
        format: 2,
        trust_domain: "ferrogate.test".into(),
        host_uuid: host.into(),
        generation,
        issued_at: NOW,
        not_after: NOW + 86_400,
        entries,
    };
    encode(&sign_v2(&doc, sk).unwrap()).unwrap()
}

fn served(envelope: Vec<u8>, generation: u64) -> Result<SyncAllowlistResponse, Status> {
    Ok(SyncAllowlistResponse {
        result: Some(SyncResult::SignedAllowlistV2(envelope)),
        generation,
        next_poll_hint_secs: 300,
    })
}

fn held(generation: u64, entries: &[AllowEntryV2]) -> SyncState {
    SyncState {
        v: 1,
        host_uuid: HOST.into(),
        generation,
        entries_digest: hex::encode(ferro_svid::allowlist_v2::entries_digest(entries).unwrap()),
        issued_at: NOW,
        not_after: NOW + 86_400,
    }
}

fn rejected(rig: &mut Rig) -> (String, u64) {
    match rig.audit.try_recv().expect("an audit event") {
        AuditEvent::AllowlistSyncRejected {
            host_uuid,
            generation,
            reason,
        } => {
            assert_eq!(host_uuid, HOST, "the event names this host");
            (reason, generation)
        }
        other => panic!("unexpected event {other:?}"),
    }
}

#[tokio::test]
async fn a_newer_body_is_applied_persisted_and_audited() {
    let mut r = rig("apply", None);
    r.cmis
        .answer(served(body(&r.sk, HOST, 10, vec![entry(1)]), 10));
    let out = r.sync.tick(NOW).await;
    assert_eq!(
        out,
        TickOutcome::Applied {
            generation: 10,
            entries: 1
        }
    );
    assert_eq!(r.cmis.last_doc().have_generation, 0);
    assert_eq!(r.cmis.last_doc().accept_formats, vec![2]);
    assert_eq!(r.sink.generations(), vec![Some(10)]);
    assert!(matches!(
        r.audit.try_recv().unwrap(),
        AuditEvent::AllowlistSyncApplied { ref host_uuid, generation: 10 } if host_uuid == HOST
    ));
    let state = SyncState::load(&r.dir.join("allowlist.state"))
        .unwrap()
        .unwrap();
    assert_eq!(state.generation, 10);
    assert!(r.dir.join("allowlist.synced.cbor").exists());
    assert_eq!(r.sync.trigger().held_generation(), 10);

    // The next sync holds generation 10, and `not_modified` changes nothing.
    r.cmis.answer(Ok(SyncAllowlistResponse {
        result: Some(SyncResult::NotModified(NotModified {
            not_after: NOW + 86_400,
        })),
        generation: 10,
        next_poll_hint_secs: 300,
    }));
    assert_eq!(r.sync.tick(NOW + 300).await, TickOutcome::NotModified);
    assert_eq!(r.cmis.last_doc().have_generation, 10);
    assert_eq!(r.sink.generations(), vec![Some(10)]);
}

#[tokio::test]
async fn rollback_wrong_host_bad_signature_and_conflicts_are_refused() {
    let entries = vec![entry(1)];
    let mut r = rig("reject", Some(held(10, &entries)));

    // A lower generation.
    r.cmis
        .answer(served(body(&r.sk, HOST, 9, entries.clone()), 9));
    assert!(matches!(
        r.sync.tick(NOW).await,
        TickOutcome::Rejected(Rejection {
            reason: RejectReason::Rollback,
            generation: 9
        })
    ));
    assert_eq!(rejected(&mut r), ("rollback".into(), 9));

    // Another host's body.
    r.cmis
        .answer(served(body(&r.sk, "another-host", 11, entries.clone()), 11));
    assert!(matches!(
        r.sync.tick(NOW).await,
        TickOutcome::Rejected(Rejection {
            reason: RejectReason::WrongHost,
            ..
        })
    ));
    assert_eq!(rejected(&mut r).0, "wrong_host");

    // Signed by another key.
    let (other, _) = CompositeSecretKey::generate().unwrap();
    r.cmis
        .answer(served(body(&other, HOST, 11, entries.clone()), 11));
    assert!(matches!(
        r.sync.tick(NOW).await,
        TickOutcome::Rejected(Rejection {
            reason: RejectReason::BadSignature,
            generation: 0
        })
    ));
    assert_eq!(rejected(&mut r).0, "bad_signature");

    // The same generation with different entries.
    r.cmis
        .answer(served(body(&r.sk, HOST, 10, vec![entry(2)]), 10));
    assert!(matches!(
        r.sync.tick(NOW).await,
        TickOutcome::Rejected(Rejection {
            reason: RejectReason::GenerationConflict,
            ..
        })
    ));
    assert_eq!(rejected(&mut r).0, "generation_conflict");

    // A body whose generation is not the one the response names.
    r.cmis
        .answer(served(body(&r.sk, HOST, 12, entries.clone()), 13));
    assert!(matches!(
        r.sync.tick(NOW).await,
        TickOutcome::Rejected(Rejection {
            reason: RejectReason::Malformed,
            ..
        })
    ));

    // Nothing was ever applied; the held state is unchanged.
    assert_eq!(r.sink.generations().len(), 0);
    assert_eq!(r.sync.held().unwrap().generation, 10);
    assert!(!r.dir.join("allowlist.state").exists());
}

#[tokio::test]
async fn a_refresh_past_half_life_reapplies_the_same_generation() {
    let entries = vec![entry(1)];
    let mut r = rig("refresh", Some(held(10, &entries)));
    let later = NOW + 50_000; // past half of the 86 400 s window
    r.cmis.answer(served(body(&r.sk, HOST, 10, entries), 10));
    // The body is issued at NOW, so it is 50 000 s old: inside max_age.
    let out = r.sync.tick(later).await;
    assert_eq!(
        r.cmis.last_doc().have_generation,
        0,
        "asks for a fresh body"
    );
    assert_eq!(
        out,
        TickOutcome::Applied {
            generation: 10,
            entries: 1
        }
    );
}

#[tokio::test]
async fn failures_keep_the_current_allowlist_and_back_off() {
    let mut r = rig("fail", None);
    r.cmis.answer(Err(Status::unavailable("down")));
    let out = r.sync.tick(NOW).await;
    assert!(matches!(
        out,
        TickOutcome::Failed {
            retry_after: None,
            reason: "cmis_unreachable"
        }
    ));
    assert_eq!(r.sync.next_delay(&out, 0.5), Duration::from_secs(5));
    assert_eq!(r.sync.next_delay(&out, 0.5), Duration::from_secs(10));
    let mut limited = Status::resource_exhausted("rate_limited");
    limited
        .metadata_mut()
        .insert("retry-after", "17".parse().unwrap());
    r.cmis.answer(Err(limited));
    let out = r.sync.tick(NOW).await;
    assert_eq!(r.sync.next_delay(&out, 0.5), Duration::from_secs(17));
    // Success resets the back-off to the jittered interval.
    r.cmis.answer(served(body(&r.sk, HOST, 1, vec![]), 1));
    let out = r.sync.tick(NOW).await;
    let d = r.sync.next_delay(&out, 0.0);
    assert_eq!(d, Duration::from_secs(270));
    assert!(r.sync.next_delay(&out, 0.999) <= Duration::from_secs(330));
    assert_eq!(r.sink.generations(), vec![Some(1)]);
}

#[tokio::test]
async fn no_svid_means_no_call() {
    let mut r = rig("nosvid", None);
    r.sync.creds.set(None);
    assert_eq!(r.sync.tick(NOW).await, TickOutcome::NoCredentials);
    assert_eq!(r.cmis.seen.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn an_older_cmis_falls_back_to_get_allowlist_v1() {
    let mut r = rig("legacy", None);
    let (sk, pk) = (
        &r.sk,
        CompositePublicKey::from_concat_bytes(&std::fs::read(r.dir.join("allowlist.pub")).unwrap())
            .unwrap(),
    );
    let v1 = encode(
        &crate::helper::allowlist::sign(
            &AllowlistDoc {
                trust_domain: "ferrogate.test".into(),
                issued_at: NOW,
                not_after: NOW + 3600,
                entries: vec![AllowEntry {
                    uid: Some(5),
                    bin_sha: hex::encode([9u8; 48]),
                }],
            },
            sk,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(Allowlist::load_v1(&v1, &pk, NOW, 60).is_ok());
    *r.cmis.legacy.lock().unwrap() = Some(v1);
    r.cmis.answer(Err(Status::unimplemented("SyncAllowlist")));
    assert_eq!(
        r.sync.tick(NOW).await,
        TickOutcome::LegacyApplied { entries: 1 }
    );
    r.cmis.answer(Err(Status::unimplemented("SyncAllowlist")));
    assert_eq!(r.sync.tick(NOW).await, TickOutcome::LegacyUnchanged);
    assert_eq!(r.sink.generations(), vec![None]);
}

#[tokio::test]
async fn a_held_v2_generation_is_never_downgraded_to_v1() {
    let mut r = rig("downgrade", Some(held(10, &[entry(1)])));
    *r.cmis.legacy.lock().unwrap() = Some(vec![1, 2, 3]);
    r.cmis.answer(Err(Status::unimplemented("SyncAllowlist")));
    assert!(matches!(
        r.sync.tick(NOW).await,
        TickOutcome::Failed {
            reason: "sync_unimplemented",
            ..
        }
    ));
    assert_eq!(r.sink.generations().len(), 0);
}

#[test]
fn the_trigger_fires_only_for_newer_generations() {
    let t = SyncTrigger::new();
    t.publish(10);
    assert!(!t.sync_if_newer(10));
    assert!(!t.sync_if_newer(3));
    assert!(t.sync_if_newer(11));
}

#[test]
fn a_start_prefers_the_synced_body_and_refuses_a_v1_downgrade() {
    let r = rig("inforce", None);
    let cfg = r.sync.cfg.clone();
    let pk =
        CompositePublicKey::from_concat_bytes(&std::fs::read(r.dir.join("allowlist.pub")).unwrap())
            .unwrap();
    let v1 = || {
        let bytes = encode(
            &crate::helper::allowlist::sign(
                &AllowlistDoc {
                    trust_domain: "ferrogate.test".into(),
                    issued_at: NOW,
                    not_after: NOW + 3600,
                    entries: vec![],
                },
                &r.sk,
            )
            .unwrap(),
        )
        .unwrap();
        let al = Allowlist::load(&bytes, &pk, NOW, 86_400).unwrap();
        let load = AllowlistLoad::of(&al);
        (Some(al), load)
    };
    let host = Some((HOST, "ferrogate.test"));

    // Nothing synced yet: the operator's v1 body is in force.
    let f = load_in_force(&cfg, v1(), host, NOW);
    assert_eq!(f.allowlist.unwrap().format(), 1);
    assert!(f.held.is_none());

    // A synced v2 body and its state: the synced body wins.
    let entries = vec![entry(4)];
    std::fs::write(&cfg.body_path, body(&r.sk, HOST, 20, entries.clone())).unwrap();
    held(20, &entries).store(&cfg.state_path).unwrap();
    let f = load_in_force(&cfg, v1(), host, NOW);
    assert_eq!(f.allowlist.unwrap().generation(), Some(20));
    // Bound to the host from the state when not attested yet.
    let f = load_in_force(&cfg, v1(), None, NOW);
    assert_eq!(f.allowlist.unwrap().generation(), Some(20));
    // On another host identity it is refused, and the v1 fallback is not a
    // downgrade path while a v2 generation is held.
    let f = load_in_force(&cfg, v1(), Some(("other", "ferrogate.test")), NOW);
    assert!(f.allowlist.is_none());
    assert_eq!(f.outcome, AllowlistLoad::Invalid);
    // A synced body below the held generation is a rollback.
    held(21, &entries).store(&cfg.state_path).unwrap();
    let f = load_in_force(&cfg, v1(), host, NOW);
    assert!(f.allowlist.is_none());
}
