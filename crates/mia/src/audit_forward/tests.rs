use std::collections::HashSet;
use std::path::PathBuf;

use ferro_audit::Hash384;
use ferro_svid::host_call::{self, AUDIT_FORWARD_CONTEXT};

use super::*;

type Answer = Box<dyn FnMut(u32, &[u8]) -> Result<u64, Status> + Send>;

/// A fake CMIS: checks every proof as CMIS would (signature over
/// `context ‖ doc`, document binding these event bytes), records each
/// attempt, and answers through `answer(pid, sep_pub)`.
struct FakeCmis {
    answer: Mutex<Answer>,
    attempts: Mutex<Vec<u32>>,
    accepted: Mutex<Vec<u32>>,
    nonces: Mutex<HashSet<[u8; 16]>>,
    hang: bool,
}

impl FakeCmis {
    fn new(answer: impl FnMut(u32, &[u8]) -> Result<u64, Status> + Send + 'static) -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(Box::new(answer)),
            attempts: Mutex::new(Vec::new()),
            accepted: Mutex::new(Vec::new()),
            nonces: Mutex::new(HashSet::new()),
            hang: false,
        })
    }

    fn accepting() -> Arc<Self> {
        Self::new(|_, _| Ok(0))
    }

    fn hanging() -> Arc<Self> {
        Arc::new(Self {
            hang: true,
            ..Arc::into_inner(Self::accepting()).unwrap()
        })
    }

    fn accepted(&self) -> Vec<u32> {
        self.accepted.lock().unwrap().clone()
    }

    fn attempts(&self) -> Vec<u32> {
        self.attempts.lock().unwrap().clone()
    }
}

impl AuditApi for FakeCmis {
    fn append_audit_event(&self, req: AppendAuditRequest) -> BoxFuture<'_, Result<u64, Status>> {
        if self.hang {
            return Box::pin(std::future::pending());
        }
        let auth = req.auth.expect("every forward carries a host proof");
        ferro_sep::verify_p256(
            &auth.sep_pub,
            &host_call::signing_input(AUDIT_FORWARD_CONTEXT, &req.doc),
            &auth.sig,
        )
        .expect("signature over context ‖ doc");
        let doc = host_call::decode_audit_forward(&req.doc).unwrap();
        assert!(doc.binds_event(&req.event_cbor));
        assert_eq!(doc.host_uuid, "host-1");
        assert!(
            self.nonces.lock().unwrap().insert(doc.nonce),
            "a retry is a new call, never a replay"
        );
        let AuditEvent::LocalDenied { pid, .. } =
            ferro_audit::event::decode(&req.event_cbor).unwrap()
        else {
            panic!("unexpected event");
        };
        self.attempts.lock().unwrap().push(pid);
        let answer = (self.answer.lock().unwrap())(pid, &auth.sep_pub);
        if answer.is_ok() {
            self.accepted.lock().unwrap().push(pid);
        }
        Box::pin(async move { answer })
    }
}

/// A scratch directory, removed when dropped (a failed test included).
pub(super) struct TempDir(PathBuf);

impl TempDir {
    pub(super) fn new(prefix: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            hex::encode(crate::host_api::random_bytes())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    pub(super) fn path(&self) -> &Path {
        &self.0
    }

    pub(super) fn join(&self, part: impl AsRef<Path>) -> PathBuf {
        self.0.join(part)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_spool(tag: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new(&format!("mia-audit-fwd-{tag}"));
    let path = dir.join("audit-spool.jsonl");
    (dir, path)
}

fn creds_with(
    key: Arc<dyn ferro_sep::MachineKey + Send + Sync>,
    expires_at: i64,
) -> HostCredentials {
    HostCredentials::new(
        key,
        "header.claims.sig".into(),
        "spiffe://ferrogate.test/host/host-1",
        expires_at,
    )
    .unwrap()
}

fn new_key() -> Arc<dyn ferro_sep::MachineKey + Send + Sync> {
    Arc::new(ferro_sep::SoftwareMachineKey::generate().unwrap())
}

fn valid_creds() -> CredentialSlot {
    let slot = CredentialSlot::new();
    slot.set(Some(creds_with(new_key(), i64::MAX)));
    slot
}

fn fast() -> ForwarderConfig {
    ForwarderConfig {
        limits: SpoolLimits::default(),
        backoff_min: Duration::from_millis(5),
        backoff_max: Duration::from_millis(40),
        creds_poll: Duration::from_millis(5),
    }
}

fn denied(pid: u32) -> AuditEvent {
    AuditEvent::LocalDenied {
        pid,
        uid: 1000,
        bin_sha: Hash384([3; 48]),
        reason: "not_allowlisted".into(),
    }
}

/// A forwarder aborted when dropped, so a failed test stops writing into
/// its scratch directory before that is removed.
struct Running(AuditForwarder);

impl std::ops::Deref for Running {
    type Target = AuditForwarder;
    fn deref(&self) -> &AuditForwarder {
        &self.0
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn start(
    api: &Arc<FakeCmis>,
    creds: &CredentialSlot,
    path: &Path,
    cfg: ForwarderConfig,
) -> (mpsc::Sender<AuditEvent>, Running) {
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    let api: Arc<FakeCmis> = Arc::clone(api);
    let fwd = spawn(
        rx,
        Some(Forwarding {
            api,
            creds: creds.clone(),
        }),
        path,
        cfg,
    );
    (tx, Running(fwd))
}

/// Wait (up to 10 s) until `cond` holds.
async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn events_are_forwarded_in_order() {
    let (_dir, path) = temp_spool("order");
    let cmis = FakeCmis::accepting();
    let (tx, fwd) = start(&cmis, &valid_creds(), &path, fast());
    for pid in 1..=20 {
        tx.send(denied(pid)).await.unwrap();
    }
    until("all forwarded", || cmis.accepted().len() == 20).await;
    assert_eq!(cmis.accepted(), (1..=20).collect::<Vec<_>>());
    until("spool drained", || fwd.stats().pending == 0).await;
    let stats = fwd.stats();
    assert_eq!(
        (stats.spooled, stats.forwarded, stats.rejected),
        (20, 20, 0)
    );
    fwd.abort();
}

#[tokio::test]
async fn a_transient_failure_is_retried_not_lost() {
    let (_dir, path) = temp_spool("transient");
    let mut calls = 0;
    let cmis = FakeCmis::new(move |_, _| {
        calls += 1;
        match calls {
            1 => Err(Status::unavailable("cmis_unreachable")),
            2 => Err(Status::deadline_exceeded("host call timed out")),
            3 => {
                let mut s = Status::resource_exhausted("rate_limited");
                s.metadata_mut().insert("retry-after", "0".parse().unwrap());
                Err(s)
            }
            4 => Err(Status::internal("boom")),
            _ => Ok(7),
        }
    });
    let (tx, fwd) = start(&cmis, &valid_creds(), &path, fast());
    for pid in 1..=3 {
        tx.send(denied(pid)).await.unwrap();
    }
    until("all forwarded", || cmis.accepted().len() == 3).await;
    assert_eq!(cmis.accepted(), vec![1, 2, 3]);
    // The first event was attempted five times, in order, before the others.
    assert_eq!(cmis.attempts(), vec![1, 1, 1, 1, 1, 2, 3]);
    assert_eq!(fwd.stats().rejected, 0);
    fwd.abort();
}

#[tokio::test]
async fn a_permanent_rejection_drops_that_event_and_the_next_is_sent() {
    let (_dir, path) = temp_spool("reject");
    // The answers `AppendAuditEvent` gives about the event itself.
    let cmis = FakeCmis::new(|pid, _| match pid {
        2 => Err(Status::invalid_argument("malformed audit event")),
        3 => Err(Status::permission_denied("event_not_forwardable")),
        4 => Err(Status::invalid_argument("field_too_long")),
        _ => Ok(1),
    });
    let (tx, fwd) = start(&cmis, &valid_creds(), &path, fast());
    for pid in 1..=5 {
        tx.send(denied(pid)).await.unwrap();
    }
    until("queue moved on", || cmis.accepted().len() == 2).await;
    assert_eq!(cmis.accepted(), vec![1, 5]);
    assert_eq!(
        cmis.attempts(),
        vec![1, 2, 3, 4, 5],
        "each refusal tried once"
    );
    until("spool drained", || fwd.stats().pending == 0).await;
    assert_eq!(fwd.stats().rejected, 3);
    fwd.abort();
}

#[tokio::test]
async fn auth_refusals_hold_the_queue_until_new_credentials() {
    let (_dir, path) = temp_spool("auth");
    let old_key = new_key();
    let old_pub = ferro_sep::MachineKey::public_spki_der(&*old_key);
    let mut calls = 0;
    let cmis = FakeCmis::new(move |_, sep_pub| {
        calls += 1;
        if sep_pub == old_pub.as_slice() {
            // A revoked SVID, then a CMIS-side policy refusal.
            Err(if calls % 2 == 0 {
                Status::unauthenticated("host_auth_failed")
            } else {
                Status::permission_denied("not_a_host")
            })
        } else {
            Ok(1)
        }
    });
    let creds = CredentialSlot::new();
    creds.set(Some(creds_with(old_key, i64::MAX)));
    let (tx, fwd) = start(&cmis, &creds, &path, fast());
    for pid in 1..=3 {
        tx.send(denied(pid)).await.unwrap();
    }
    until("refused a few times", || cmis.attempts().len() >= 3).await;
    assert_eq!(cmis.accepted(), Vec::<u32>::new());
    assert!(cmis.attempts().iter().all(|&p| p == 1), "the head is held");
    assert_eq!(fwd.stats().pending, 3, "nothing dropped");
    assert_eq!(fwd.stats().rejected, 0);

    // A re-attestation brings new credentials: the backlog flows.
    creds.set(Some(creds_with(new_key(), i64::MAX)));
    until("all forwarded", || cmis.accepted().len() == 3).await;
    assert_eq!(cmis.accepted(), vec![1, 2, 3]);
    fwd.abort();
}

#[tokio::test]
async fn proof_document_and_host_mismatch_refusals_hold_the_queue() {
    let (_dir, path) = temp_spool("hold");
    let mut calls = 0;
    let cmis = FakeCmis::new(move |_, _| {
        calls += 1;
        match calls {
            // Version skew: CMIS cannot decode the signed proof document.
            1 | 2 => Err(Status::invalid_argument("malformed_doc")),
            3 => Err(Status::invalid_argument("some_future_reason")),
            // The proof check's (or the per-event) host mismatch.
            4 | 5 => Err(Status::permission_denied("host_mismatch")),
            _ => Ok(1),
        }
    });
    let (tx, fwd) = start(&cmis, &valid_creds(), &path, fast());
    for pid in 1..=3 {
        tx.send(denied(pid)).await.unwrap();
    }
    until("all forwarded", || cmis.accepted().len() == 3).await;
    assert_eq!(cmis.accepted(), vec![1, 2, 3]);
    assert_eq!(
        cmis.attempts(),
        vec![1, 1, 1, 1, 1, 1, 2, 3],
        "the head is held"
    );
    assert_eq!(fwd.stats().rejected, 0, "nothing dropped");
    fwd.abort();
}

#[test]
fn an_expired_svid_is_told_apart_and_logged_once() {
    let slot = CredentialSlot::new();
    assert_eq!(usable_creds(&slot, 100).err(), Some(CredsWait::Missing));
    slot.set(Some(creds_with(new_key(), 100)));
    assert_eq!(usable_creds(&slot, 100).err(), Some(CredsWait::Expired));
    assert!(usable_creds(&slot, 99).is_ok());

    // One log per change of reason, never one per poll.
    let mut state = None;
    assert!(wait_changed(&mut state, CredsWait::Missing));
    assert!(!wait_changed(&mut state, CredsWait::Missing));
    assert!(wait_changed(&mut state, CredsWait::Expired));
    assert!(!wait_changed(&mut state, CredsWait::Expired));
    // Valid credentials reset it: the next expiry is logged again.
    state = None;
    assert!(wait_changed(&mut state, CredsWait::Expired));
}

#[tokio::test]
async fn missing_or_expired_credentials_hold_events_until_valid_ones_appear() {
    let (_dir, path) = temp_spool("nocreds");
    let cmis = FakeCmis::accepting();
    let creds = CredentialSlot::new();
    let (tx, fwd) = start(&cmis, &creds, &path, fast());
    for pid in 1..=2 {
        tx.send(denied(pid)).await.unwrap();
    }
    until("spooled", || fwd.stats().spooled == 2).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    // An expired SVID is as good as none.
    creds.set(Some(creds_with(new_key(), 1)));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        cmis.attempts(),
        Vec::<u32>::new(),
        "nothing sent without a valid SVID"
    );
    assert_eq!(fwd.stats().pending, 2);

    creds.set(Some(creds_with(new_key(), i64::MAX)));
    until("all forwarded", || cmis.accepted().len() == 2).await;
    assert_eq!(cmis.accepted(), vec![1, 2]);
    fwd.abort();
}

#[tokio::test]
async fn the_spool_survives_a_restart() {
    let (_dir, path) = temp_spool("restart");
    let down = FakeCmis::new(|_, _| Err(Status::unavailable("cmis_unreachable")));
    let creds = valid_creds();
    let (tx, fwd) = start(&down, &creds, &path, fast());
    for pid in 1..=3 {
        tx.send(denied(pid)).await.unwrap();
    }
    until("spooled", || fwd.stats().spooled == 3).await;
    until("attempted", || !down.attempts().is_empty()).await;
    fwd.abort();
    drop(tx);
    tokio::time::sleep(Duration::from_millis(20)).await;

    // The next run replays the backlog first, then carries on.
    let up = FakeCmis::accepting();
    let (tx, fwd) = start(&up, &creds, &path, fast());
    until("backlog replayed", || up.accepted().len() == 3).await;
    tx.send(denied(4)).await.unwrap();
    until("new event forwarded", || up.accepted().len() == 4).await;
    assert_eq!(up.accepted(), vec![1, 2, 3, 4]);
    until("spool drained", || fwd.stats().pending == 0).await;
    fwd.abort();
}

#[tokio::test]
async fn helper_pushes_never_wait_on_cmis_and_the_cap_drops_oldest() {
    let (_dir, path) = temp_spool("noblock");
    // CMIS accepts the connection and never answers.
    let cmis = FakeCmis::hanging();
    let cfg = ForwarderConfig {
        limits: SpoolLimits {
            max_entries: 100,
            max_bytes: spool::DEFAULT_MAX_BYTES,
        },
        ..fast()
    };
    let (tx, fwd) = start(&cmis, &valid_creds(), &path, cfg);
    let total = 20 * CHANNEL_CAPACITY;
    tokio::time::timeout(Duration::from_secs(10), async {
        for pid in 0..total {
            tx.send(denied(u32::try_from(pid).unwrap())).await.unwrap();
        }
    })
    .await
    .expect("the helper API's sends complete although CMIS hangs");
    until("all spooled", || fwd.stats().spooled == total as u64).await;
    let stats = fwd.stats();
    assert_eq!(stats.pending, 100);
    assert_eq!(stats.dropped_over_cap, total as u64 - 100);
    // What is kept is the newest events.
    let (spool, _) = Spool::open(&path, cfg.limits);
    let oldest_kept = ferro_audit::event::decode(&spool.front().unwrap().cbor).unwrap();
    assert_eq!(oldest_kept, denied(u32::try_from(total - 100).unwrap()));
    fwd.abort();
}

#[tokio::test]
async fn without_cmis_events_are_logged_and_never_spooled() {
    let (_dir, path) = temp_spool("nocmis");
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    let fwd = spawn(rx, None, &path, fast());
    tokio::time::timeout(Duration::from_secs(10), async {
        for pid in 0..(4 * CHANNEL_CAPACITY) {
            tx.send(denied(u32::try_from(pid).unwrap())).await.unwrap();
        }
    })
    .await
    .expect("the channel drains");
    assert!(!path.exists(), "no spool that nothing could drain");
    assert_eq!(fwd.stats(), ForwardStats::default());
    fwd.abort();
}

#[test]
fn answers_are_classified_by_what_they_say_about_the_event() {
    assert_eq!(classify(Ok(9)), Outcome::Forwarded(9));
    // Only CMIS's answers about the event itself drop it.
    assert_eq!(
        classify(Err(Status::invalid_argument("field_too_long"))),
        Outcome::Rejected("field_too_long")
    );
    assert_eq!(
        classify(Err(Status::invalid_argument("malformed audit event"))),
        Outcome::Rejected("malformed_event")
    );
    assert_eq!(
        classify(Err(Status::permission_denied("event_not_forwardable"))),
        Outcome::Rejected("event_not_forwardable")
    );
    // Proof-level answers hold it.
    assert_eq!(
        classify(Err(Status::invalid_argument("malformed_doc"))),
        Outcome::AuthRefused("malformed_doc")
    );
    assert_eq!(
        classify(Err(Status::invalid_argument("anything else"))),
        Outcome::AuthRefused("invalid_argument")
    );
    assert_eq!(
        classify(Err(Status::permission_denied("host_mismatch"))),
        Outcome::AuthRefused("host_mismatch")
    );
    assert_eq!(
        classify(Err(Status::permission_denied("something else"))),
        Outcome::AuthRefused("permission_denied")
    );
    assert_eq!(
        classify(Err(Status::unauthenticated("host_auth_failed"))),
        Outcome::AuthRefused("host_auth_failed")
    );
    let mut limited = Status::resource_exhausted("rate_limited");
    assert_eq!(classify(Err(limited.clone())), Outcome::RateLimited(None));
    limited
        .metadata_mut()
        .insert("retry-after", "12".parse().unwrap());
    assert_eq!(
        classify(Err(limited)),
        Outcome::RateLimited(Some(Duration::from_secs(12)))
    );
    for transient in [
        Status::unavailable("x"),
        Status::deadline_exceeded("x"),
        Status::unimplemented("x"),
        Status::internal("x"),
        Status::unknown("x"),
        Status::failed_precondition("x"),
    ] {
        assert!(
            matches!(classify(Err(transient)), Outcome::Transient(_)),
            "never dropped on an unrecognised answer"
        );
    }
}

#[test]
fn backoff_doubles_to_its_cap_with_jitter() {
    let min = Duration::from_secs(1);
    let max = Duration::from_secs(300);
    let mut b = Backoff::new(min, max);
    let mut ceiling = min;
    for _ in 0..20 {
        let d = b.next_delay();
        assert!(
            d >= ceiling / 2 && d <= ceiling,
            "{d:?} outside [{:?}, {ceiling:?}]",
            ceiling / 2
        );
        ceiling = (ceiling * 2).min(max);
    }
    b.reset();
    assert!(b.next_delay() <= min);
}

#[test]
fn only_the_variant_name_of_an_event_is_logged() {
    assert_eq!(event_type(&denied(1)), "LocalDenied");
    let cbor = ferro_audit::event::encode(&denied(1)).unwrap();
    assert_eq!(event_type_of(&cbor), "LocalDenied");
    assert_eq!(event_type_of(b"junk"), "unknown");
}
