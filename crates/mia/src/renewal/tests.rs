//! `renewal::tests` — the renewal state machine against a fake [`Renewer`]
//! and a fixed clock (no sleeps), the pure schedule, and the credential swap.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ferro_crypto::composite::CompositeSecretKey;
use ferro_proto::v1::SvidBundle;
use futures::future::BoxFuture;
use sha2::{Digest, Sha384};
use tonic::{Code, Status};

use super::schedule::{
    self, classify, next_wait, Next, EXPIRY_MARGIN_SECS, REATTEST_INTERVAL, RETRY_CAP,
    ROTATE_WINDOW_MARGIN_SECS,
};
use super::{
    next_fatal, spawn, Attested, CmisDial, DialedCmis, Exit, Fatal, HostAttestor, HostRenewer,
    HostSvid, Issued, KeyPolicy, MinterSink, Renewal, RenewalHooks, RenewalPath, Renewer, SvidCell,
    SvidInfo, Swap, Timeouts, X509Sealer,
};
use crate::helper::auth::CallerIdentity;
use crate::helper::token::{ChildClaims, ChildTokenMinter};
use crate::host_api::CredentialSlot;
use crate::status::{AttestFailure, AttestPhase, StatusHandle};

const ID: &str = "spiffe://ferrogate.test/host/1b4e28ba-2fa1-4d2a-883f-0016d3cca427";
const OTHER_ID: &str = "spiffe://ferrogate.test/host/99999999-2fa1-4d2a-883f-0016d3cca427";
/// The test SVID's lifetime: `0..TTL`, renewal point at 60 % = 600 with the
/// centred jitter the tests use.
const TTL: i64 = 1000;

fn info(spiffe_id: &str, iat: i64, exp: i64, rotatable: bool) -> SvidInfo {
    SvidInfo {
        spiffe_id: spiffe_id.to_string(),
        issued_at: iat,
        expires_at: exp,
        rotatable,
    }
}

/// What the fake renewer was asked to do, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Rotate,
    FullAttest,
    Install(u32, RenewalPath),
    AfterInstall(RenewalPath),
    Disable,
}

/// Which call of the fake never completes (a CMIS that stalls mid-stream).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stall {
    Rotate,
    FullAttest,
    AfterInstall,
}

/// A scripted [`Renewer`]: each call pops the next prepared answer. A
/// credential is a plain number, so the tests can see which one went in.
#[derive(Default)]
struct Fake {
    rotations: VecDeque<Result<Issued<u32>, Status>>,
    attestations: VecDeque<Result<Issued<u32>, AttestFailure>>,
    calls: Arc<Mutex<Vec<Call>>>,
    stall: Option<Stall>,
    panic_on_rotate: bool,
}

impl Fake {
    fn rotates(mut self, r: Result<Issued<u32>, Status>) -> Self {
        self.rotations.push_back(r);
        self
    }

    fn attests(mut self, r: Result<Issued<u32>, AttestFailure>) -> Self {
        self.attestations.push_back(r);
        self
    }

    fn stalls(mut self, stage: Stall) -> Self {
        self.stall = Some(stage);
        self
    }

    fn log(&self, c: Call) {
        self.calls.lock().unwrap().push(c);
    }
}

impl Renewer for Fake {
    type Credential = u32;

    fn rotate(&mut self) -> BoxFuture<'_, Result<Issued<u32>, Status>> {
        self.log(Call::Rotate);
        assert!(!self.panic_on_rotate, "the renewer panicked");
        if self.stall == Some(Stall::Rotate) {
            return Box::pin(futures::future::pending());
        }
        let r = self
            .rotations
            .pop_front()
            .expect("an unexpected Rotate call");
        Box::pin(async move { r })
    }

    fn full_attest(&mut self) -> BoxFuture<'_, Result<Issued<u32>, AttestFailure>> {
        self.log(Call::FullAttest);
        if self.stall == Some(Stall::FullAttest) {
            return Box::pin(futures::future::pending());
        }
        let r = self
            .attestations
            .pop_front()
            .expect("an unexpected full attestation");
        Box::pin(async move { r })
    }

    fn install(&mut self, credential: u32, path: RenewalPath) -> BoxFuture<'_, ()> {
        self.log(Call::Install(credential, path));
        Box::pin(async {})
    }

    fn after_install(&mut self, path: RenewalPath) -> BoxFuture<'_, ()> {
        self.log(Call::AfterInstall(path));
        if self.stall == Some(Stall::AfterInstall) {
            return Box::pin(futures::future::pending());
        }
        Box::pin(async {})
    }

    fn disable(&mut self) -> BoxFuture<'_, ()> {
        self.log(Call::Disable);
        Box::pin(async {})
    }
}

fn issued(n: u32, svid: SvidInfo) -> Issued<u32> {
    Issued {
        info: svid,
        credential: n,
    }
}

/// A renewal holding the host-key SVID `0..TTL` attested at 0, with the
/// centred jitter (renewal point 600); returns the call log too.
fn holding(fake: Fake, rotatable: bool) -> (Renewal<Fake>, Arc<Mutex<Vec<Call>>>, StatusHandle) {
    let calls = Arc::clone(&fake.calls);
    let status = StatusHandle::new("default", 0);
    status.attest_succeeded(ID, 0, TTL);
    let r = Renewal::new(fake, status.clone())
        .with_jitter(|| 0.5)
        .with_current(info(ID, 0, TTL, rotatable), 0);
    (r, calls, status)
}

fn calls(log: &Arc<Mutex<Vec<Call>>>) -> Vec<Call> {
    log.lock().unwrap().clone()
}

fn installed(n: u32, path: RenewalPath) -> [Call; 2] {
    [Call::Install(n, path), Call::AfterInstall(path)]
}

// --- the state machine ------------------------------------------------------

#[tokio::test]
async fn renews_at_rotation_point() {
    let fake = Fake::default().rotates(Ok(issued(2, info(ID, 600, 1600, true))));
    let (mut r, log, status) = holding(fake, true);

    // Before the renewal point nothing happens: wait the rest.
    assert_eq!(r.step(599).await.unwrap(), Duration::from_secs(1));
    assert_eq!(calls(&log), Vec::<Call>::new());

    // At 60 % of the TTL a host-key host renews with Rotate, then waits for
    // the renewed SVID's own renewal point (600 + 600).
    assert_eq!(r.step(600).await.unwrap(), Duration::from_secs(600));
    let mut want = vec![Call::Rotate];
    want.extend(installed(2, RenewalPath::Rotate));
    assert_eq!(calls(&log), want);
    let svid = status.observe().await.svid.unwrap();
    assert_eq!((svid.not_after, svid.renew_at), (1600, 1200));
}

#[test]
fn jitter_stays_in_band() {
    // 60 % of the TTL ± 10 %, for any jitter sample.
    for unit in [0.0, 0.1, 0.25, 0.5, 0.75, 0.999_999] {
        let d = next_wait(0, 0, TTL, 0, unit).as_secs();
        assert!((500..=700).contains(&d), "{unit}: {d}");
    }
    assert_eq!(next_wait(0, 0, TTL, 0, 0.0), Duration::from_secs(500));
    assert_eq!(next_wait(0, 0, TTL, 0, 0.5), Duration::from_secs(600));
    // A retry is jittered within [base/2, base]: 30 s after one failure.
    let exp = 100_000;
    for unit in [0.0, 0.5, 0.999_999] {
        let d = next_wait(0, 0, exp, 1, unit);
        assert!(
            (Duration::from_secs(15)..=Duration::from_secs(30)).contains(&d),
            "{d:?}"
        );
    }
    // A fleet scheduled from one issuance spreads its renewals.
    assert_ne!(next_wait(0, 0, TTL, 0, 0.1), next_wait(0, 0, TTL, 0, 0.9));
}

#[tokio::test]
async fn falls_back_to_full_attestation_on_precondition() {
    // CMIS answers FAILED_PRECONDITION (re-attestation required: tier,
    // superseded SVID, drift, epoch bump or window): attest in the same step.
    let fake = Fake::default()
        .rotates(Err(Status::failed_precondition("re-attestation required")))
        .attests(Ok(issued(3, info(ID, 600, 1600, true))));
    let (mut r, log, status) = holding(fake, true);
    assert_eq!(r.step(600).await.unwrap(), Duration::from_secs(600));
    let mut want = vec![Call::Rotate, Call::FullAttest];
    want.extend(installed(3, RenewalPath::FullAttest));
    assert_eq!(calls(&log), want);
    assert_eq!(status.observe().await.phase, AttestPhase::Attested);
}

#[tokio::test]
async fn falls_back_on_not_found_and_unauthenticated() {
    for refusal in [
        Status::not_found("unknown subject; full attestation required"),
        // The proof refused, e.g. after the CMIS issuer key rotated.
        Status::unauthenticated("host proof refused"),
        // Anything CMIS does not document as transient.
        Status::unimplemented("no Rotate on this CMIS"),
    ] {
        let fake = Fake::default()
            .rotates(Err(refusal.clone()))
            .attests(Ok(issued(4, info(ID, 600, 1600, true))));
        let (mut r, log, _) = holding(fake, true);
        r.step(600).await.unwrap();
        assert_eq!(
            calls(&log)[..2],
            [Call::Rotate, Call::FullAttest],
            "{refusal:?}"
        );
        assert_eq!(calls(&log)[2], Call::Install(4, RenewalPath::FullAttest));
    }
}

#[tokio::test]
async fn retries_transient_errors_before_expiry() {
    let fake = Fake::default()
        .rotates(Err(Status::unavailable("store_unavailable")))
        .rotates(Err(Status::deadline_exceeded("rotate timed out")))
        .rotates(Ok(issued(5, info(ID, 700, 1700, true))));
    let (mut r, log, status) = holding(fake, true);

    // A transient error retries Rotate after a short, growing back-off — no
    // full attestation, and the host stays Attested on its valid SVID.
    let first = r.step(600).await.unwrap();
    assert!(first <= Duration::from_secs(30), "{first:?}");
    let obs = status.observe().await;
    assert_eq!(obs.phase, AttestPhase::Attested);
    assert_eq!(
        obs.renewal,
        Some(crate::status::RenewalPhase::Failed(
            AttestFailure::CmisUnreachable
        ))
    );
    let now = 600 + i64::try_from(first.as_secs()).unwrap();
    let second = r.step(now).await.unwrap();
    assert!(
        (Duration::from_secs(30)..=Duration::from_secs(60)).contains(&second),
        "{second:?}"
    );
    let now = now + i64::try_from(second.as_secs()).unwrap();
    r.step(now).await.unwrap();
    let mut want = vec![Call::Rotate, Call::Rotate, Call::Rotate];
    want.extend(installed(5, RenewalPath::Rotate));
    assert_eq!(calls(&log), want);
    assert!(
        status.observe().await.renewal.is_none(),
        "cleared on success"
    );
}

#[tokio::test]
async fn honours_retry_after() {
    let mut limited = Status::resource_exhausted("rate_limited");
    limited
        .metadata_mut()
        .insert("retry-after", "120".parse().unwrap());
    assert_eq!(
        classify(&limited),
        Next::RetryAfter(Duration::from_secs(120))
    );
    // Without the header it is an ordinary transient failure.
    assert_eq!(
        classify(&Status::resource_exhausted("rate_limited")),
        Next::Retry
    );

    let fake = Fake::default().rotates(Err(limited.clone()));
    let (mut r, log, _) = holding(fake, true);
    assert_eq!(r.step(600).await.unwrap(), Duration::from_secs(120));
    assert_eq!(calls(&log), [Call::Rotate]);

    // Even CMIS's retry-after never keeps the daemon asleep past expiry
    // (it must switch minting off then): SVID 0..400, 100 s left.
    let fake = Fake::default().rotates(Err(limited));
    let mut r = Renewal::new(fake, StatusHandle::new("default", 0))
        .with_jitter(|| 0.5)
        .with_current(info(ID, 0, 400, true), 0);
    assert_eq!(r.step(300).await.unwrap(), Duration::from_secs(100));
}

#[test]
fn never_sleeps_past_expiry() {
    let exp = 345_600; // 96 h, the TTL floor.
    for failures in 1..40 {
        for now in [
            0,
            exp / 2,
            exp - 3600,
            exp - 600,
            exp - 121,
            exp - 61,
            exp - 60,
            exp - 1,
        ] {
            for unit in [0.0, 0.5, 0.999_999] {
                let d = i64::try_from(next_wait(now, 0, exp, failures, unit).as_secs()).unwrap();
                assert!(d >= 1, "a retry never spins: {failures} {now}");
                assert!(now + d <= exp, "past expiry: {failures} {now} {d}");
                if exp - now > EXPIRY_MARGIN_SECS {
                    assert!(
                        now + d <= exp - EXPIRY_MARGIN_SECS,
                        "past exp - 60 s: {failures} {now} {d}"
                    );
                }
                assert!(d <= i64::try_from(RETRY_CAP.as_secs()).unwrap());
                assert!(d <= ((exp - now) / 4).max(1));
            }
        }
    }
    // Healthy schedules land before expiry too; after it, retry every
    // REATTEST_INTERVAL (jittered ±10 %).
    assert!(next_wait(0, 0, exp, 0, 0.999_999).as_secs() < 345_600);
    assert_eq!(next_wait(exp, 0, exp, 3, 0.5), REATTEST_INTERVAL);
    for unit in [0.0, 0.5, 0.999_999] {
        let d = next_wait(exp, 0, exp, 3, unit).as_secs();
        assert!((270..=330).contains(&d), "{d}");
        assert_eq!(schedule::reattest_wait(unit).as_secs(), d);
    }
    // A rate limit's retry-after never sleeps past expiry either.
    for after in [0, 1, 30, 120, 900, 86_400] {
        for now in [0, exp - 600, exp - 61, exp - 1] {
            let d = schedule::retry_after_wait(now, exp, Duration::from_secs(after));
            let d = i64::try_from(d.as_secs()).unwrap();
            assert!(d >= 1 && now + d <= exp, "{after} {now} {d}");
        }
    }
    // The capped back-off is jittered too, so a fleet near expiry spreads.
    assert_ne!(
        next_wait(exp - 400, 0, exp, 10, 0.0),
        next_wait(exp - 400, 0, exp, 10, 0.999_999)
    );
}

#[tokio::test]
async fn rotate_only_inside_reattest_window() {
    // D1: Rotate only while the last full attestation is inside CMIS's 24 h
    // window, with a margin; otherwise go straight to a full attestation.
    let window = ferro_svid::REATTEST_WINDOW_SECS;
    let ttl = 4 * 24 * 3600; // 96 h: the renewal point is past the window.
    let due = 2 * window; // well past 60 % … and past the window
    let fake = Fake::default().attests(Ok(issued(6, info(ID, due, due + ttl, true))));
    let calls_log = Arc::clone(&fake.calls);
    let status = StatusHandle::new("default", 0);
    let mut r = Renewal::new(fake, status)
        .with_jitter(|| 0.5)
        .with_current(info(ID, 0, ttl, true), 0);
    r.step(ttl * 6 / 10).await.unwrap();
    assert_eq!(calls(&calls_log)[0], Call::FullAttest, "no Rotate");

    // The edge of the window: one second inside the margin still rotates,
    // the margin itself does not.
    let edge = window - ROTATE_WINDOW_MARGIN_SECS;
    assert!(schedule::rotate_allowed(edge - 1, 0));
    assert!(!schedule::rotate_allowed(edge, 0));
    // A Rotate does not move the window: it is anchored on the last *full*
    // attestation, as on CMIS.
    let fake = Fake::default()
        .rotates(Ok(issued(7, info(ID, 600, 1600, true))))
        .attests(Ok(issued(8, info(ID, 1200, 2200, true))));
    let log = Arc::clone(&fake.calls);
    let mut r = Renewal::new(fake, StatusHandle::new("default", 0))
        .with_jitter(|| 0.5)
        .with_current(
            info(ID, 0, TTL, true),
            1000 - window + ROTATE_WINDOW_MARGIN_SECS,
        );
    r.step(600).await.unwrap(); // inside: Rotate
    r.step(1200).await.unwrap(); // window passed: full attestation
    assert_eq!(calls(&log)[0], Call::Rotate);
    assert_eq!(calls(&log)[3], Call::FullAttest);
}

#[tokio::test]
async fn expired_svid_disables_minting_then_full_attests() {
    let fake = Fake::default()
        .attests(Err(AttestFailure::CmisUnreachable))
        .attests(Ok(issued(9, info(ID, 1400, 2400, true))));
    let (mut r, log, status) = holding(fake, true);

    // The SVID ran out without a renewal (e.g. a suspended host): minting
    // and host calls go off first, then a full attestation is tried (a
    // Rotate cannot renew an expired SVID).
    assert_eq!(r.step(TTL).await.unwrap(), REATTEST_INTERVAL);
    assert_eq!(calls(&log), [Call::Disable, Call::FullAttest]);
    // Expired and the attestation failed: the failure names the state.
    assert_eq!(
        status.observe().await.phase,
        AttestPhase::Failed(AttestFailure::CmisUnreachable)
    );

    // An early wake waits out the interval; the next attempt does not
    // disable twice.
    assert_eq!(r.step(TTL + 60).await.unwrap(), Duration::from_secs(240));
    assert_eq!(calls(&log), [Call::Disable, Call::FullAttest]);
    r.step(TTL + 300).await.unwrap();
    let mut want = vec![Call::Disable, Call::FullAttest, Call::FullAttest];
    want.extend(installed(9, RenewalPath::FullAttest));
    assert_eq!(calls(&log), want);
    assert_eq!(status.observe().await.phase, AttestPhase::Attested);
}

#[tokio::test]
async fn startup_failure_attests_immediately_then_every_interval() {
    let fake = Fake::default()
        .attests(Err(AttestFailure::CmisUnreachable))
        .attests(Err(AttestFailure::NotEnrolled))
        .attests(Ok(issued(10, info(ID, 650, 1650, true))));
    let log = Arc::clone(&fake.calls);
    let status = StatusHandle::new("default", 0);
    // No SVID: the first step attests at once …
    let mut r = Renewal::new(fake, status.clone()).with_jitter(|| 0.5);
    assert_eq!(r.step(50).await.unwrap(), REATTEST_INTERVAL);
    assert_eq!(
        status.observe().await.phase,
        AttestPhase::Failed(AttestFailure::CmisUnreachable)
    );
    // The daemon counts its inline start-up attempt as the first one.
    let fake = Fake::default().attests(Ok(issued(16, info(ID, 400, 1400, true))));
    let late = Arc::clone(&fake.calls);
    let mut d = Renewal::new(fake, StatusHandle::new("default", 0)).with_first_attempt_at(400);
    assert_eq!(d.step(100).await.unwrap(), Duration::from_secs(300));
    assert_eq!(calls(&late), Vec::<Call>::new());
    d.step(400).await.unwrap();
    assert_eq!(calls(&late)[0], Call::FullAttest);
    assert_eq!(
        status.observe().await.phase,
        AttestPhase::Failed(AttestFailure::CmisUnreachable)
    );
    // … then every REATTEST_INTERVAL, no back-off and no Rotate. The run
    // loop wakes every minute to re-read the clock; an early wake waits on.
    assert_eq!(r.step(110).await.unwrap(), Duration::from_secs(240));
    assert_eq!(calls(&log), [Call::FullAttest]);
    assert_eq!(r.step(350).await.unwrap(), REATTEST_INTERVAL);
    assert_eq!(r.step(650).await.unwrap(), Duration::from_secs(600));
    let mut want = vec![Call::FullAttest, Call::FullAttest, Call::FullAttest];
    want.extend(installed(10, RenewalPath::FullAttest));
    assert_eq!(calls(&log), want);
    assert_eq!(status.observe().await.phase, AttestPhase::Attested);
}

#[tokio::test]
async fn tpm_tier_skips_rotate() {
    // D2: a TPM SVID binds no host-call key, so it never calls Rotate.
    let fake = Fake::default().attests(Ok(issued(11, info(ID, 600, 1600, false))));
    let (mut r, log, _) = holding(fake, false);
    r.step(600).await.unwrap();
    let mut want = vec![Call::FullAttest];
    want.extend(installed(11, RenewalPath::FullAttest));
    assert_eq!(calls(&log), want);
}

#[tokio::test]
async fn identity_change_is_not_swapped() {
    // A full re-attestation that comes back under another SPIFFE id (the
    // host was re-enrolled) is never put in force: the allowlist binding and
    // the held state belong to the old identity. Minting goes off and the
    // loop stops so `serve` exits and the supervisor restarts the daemon.
    let fake = Fake::default().attests(Ok(issued(12, info(OTHER_ID, 600, 1600, false))));
    let (mut r, log, _) = holding(fake, false);
    let Err(Fatal::IdentityChanged {
        held,
        issued: other,
    }) = r.step(600).await
    else {
        panic!("an identity change must stop the loop");
    };
    assert_eq!((held.as_str(), other.as_str()), (ID, OTHER_ID));
    assert_eq!(calls(&log), [Call::FullAttest, Call::Disable]);

    // The same through `run`: it returns the fatal exit.
    let fake = Fake::default().attests(Ok(issued(13, info(OTHER_ID, 600, 1600, false))));
    let (r, _, _) = holding(fake, false);
    let exit = r
        .run(|| 600, Duration::ZERO, std::future::pending::<()>())
        .await;
    assert!(matches!(exit, Exit::Fatal(Fatal::IdentityChanged { .. })));
}

#[tokio::test]
async fn an_svid_already_expired_on_arrival_is_not_installed() {
    let fake = Fake::default().rotates(Ok(issued(14, info(ID, 0, 500, true))));
    let (mut r, log, status) = holding(fake, true);
    // A clock problem, not a transient error: back off a full interval.
    assert_eq!(r.step(600).await.unwrap(), REATTEST_INTERVAL);
    assert_eq!(calls(&log), [Call::Rotate]);
    assert_eq!(status.observe().await.svid.unwrap().not_after, TTL);
}

#[tokio::test]
async fn a_fresh_svid_that_is_almost_expired_counts_as_clock_skew() {
    // 20 s of life left on arrival (a host clock ahead of CMIS): it is not
    // put in force, and the host does not hammer CMIS for new ones.
    let fake = Fake::default()
        .rotates(Ok(issued(17, info(ID, 600, 620, true))))
        .attests(Ok(issued(18, info(ID, 900, 1900, true))));
    let (mut r, log, status) = holding(fake, true);
    assert_eq!(r.step(600).await.unwrap(), REATTEST_INTERVAL);
    assert_eq!(calls(&log), [Call::Rotate]);
    assert_eq!(
        status.observe().await.renewal,
        Some(crate::status::RenewalPhase::Failed(AttestFailure::Other))
    );
    // An early wake does not retry; the next attempt waits the interval.
    assert_eq!(r.step(700).await.unwrap(), Duration::from_secs(200));
    // By then only the last quarter of the lifetime is left: re-attest.
    r.step(900).await.unwrap();
    assert_eq!(
        calls(&log)[1..3],
        [Call::FullAttest, Call::Install(18, RenewalPath::FullAttest)]
    );
}

#[tokio::test]
async fn a_stalled_full_attestation_past_expiry_disables_minting() {
    // A CMIS that stalls mid-stream must not keep the step from switching
    // minting off at expiry (1 s left here).
    let fake = Fake::default().stalls(Stall::FullAttest);
    let (mut r, log, status) = holding(fake, false);
    let wait = r.step(TTL - 1).await.unwrap();
    assert_eq!(calls(&log), [Call::FullAttest, Call::Disable]);
    assert!(wait >= Duration::from_secs(270), "{wait:?}");
    assert_eq!(
        status.observe().await.phase,
        AttestPhase::Failed(AttestFailure::CmisUnreachable)
    );
}

#[tokio::test]
async fn a_stalled_rotate_past_expiry_disables_minting() {
    // SVID 0..4: renewal point 2, one second left at 3 (still a quarter).
    let fake = Fake::default().stalls(Stall::Rotate);
    let log = Arc::clone(&fake.calls);
    let mut r = Renewal::new(fake, StatusHandle::new("default", 0))
        .with_jitter(|| 0.5)
        .with_current(info(ID, 0, 4, true), 0);
    r.step(3).await.unwrap();
    assert_eq!(calls(&log), [Call::Rotate, Call::Disable]);
}

#[tokio::test]
async fn every_renewer_call_has_a_deadline() {
    let short = Timeouts {
        rotate: Duration::from_millis(50),
        full_attest: Duration::from_millis(50),
        after_install: Duration::from_millis(50),
    };
    // A stalled Rotate is a transient failure: retried after the back-off.
    let fake = Fake::default().stalls(Stall::Rotate);
    let (r, log, _) = holding(fake, true);
    let mut r = r.with_timeouts(short);
    let wait = r.step(600).await.unwrap();
    assert!(wait <= Duration::from_secs(30), "{wait:?}");
    assert_eq!(calls(&log), [Call::Rotate]);
    // A stalled full attestation too, without disabling a valid SVID.
    let fake = Fake::default().stalls(Stall::FullAttest);
    let (r, log, status) = holding(fake, false);
    let mut r = r.with_timeouts(short);
    assert!(r.step(600).await.unwrap() <= Duration::from_secs(30));
    assert_eq!(calls(&log), [Call::FullAttest]);
    assert_eq!(status.observe().await.phase, AttestPhase::Attested);
    // A stalled refresh after the swap leaves the new SVID in force.
    let fake = Fake::default()
        .rotates(Ok(issued(19, info(ID, 600, 1600, true))))
        .stalls(Stall::AfterInstall);
    let (r, log, status) = holding(fake, true);
    let mut r = r.with_timeouts(short);
    assert_eq!(r.step(600).await.unwrap(), Duration::from_secs(600));
    assert_eq!(calls(&log)[1..3], installed(19, RenewalPath::Rotate));
    assert_eq!(status.observe().await.svid.unwrap().not_after, 1600);
}

#[tokio::test]
async fn status_reports_the_jittered_renewal_point() {
    // A healthy host is not "renewal due" before its own jittered point.
    let fake = Fake::default().rotates(Ok(issued(20, info(ID, 500, 1500, true))));
    let log = Arc::clone(&fake.calls);
    let status = StatusHandle::new("default", 0);
    status.attest_succeeded(ID, 0, TTL);
    let mut r = Renewal::new(fake, status.clone())
        .with_jitter(|| 0.999)
        .with_current(info(ID, 0, TTL, true), 0);
    let due = ferro_svid::rotation_at(0, TTL, 0.999);
    assert_eq!(status.observe().await.svid.unwrap().renew_at, due);
    assert_eq!(due, 700);
    r.step(due).await.unwrap();
    assert_eq!(calls(&log)[0], Call::Rotate);
    assert_eq!(
        status.observe().await.svid.unwrap().renew_at,
        ferro_svid::rotation_at(500, 1500, 0.999)
    );
}

#[tokio::test]
async fn repeated_transient_rotate_failures_fall_back_to_full_attestation() {
    let fake = Fake::default()
        .rotates(Err(Status::internal("x")))
        .rotates(Err(Status::unknown("x")))
        .rotates(Err(Status::aborted("x")))
        .attests(Ok(issued(21, info(ID, 700, 1700, true))));
    let (mut r, log, _) = holding(fake, true);
    let mut now = 600;
    for _ in 0..4 {
        now += i64::try_from(r.step(now).await.unwrap().as_secs()).unwrap();
    }
    let mut want = vec![Call::Rotate, Call::Rotate, Call::Rotate, Call::FullAttest];
    want.extend(installed(21, RenewalPath::FullAttest));
    assert_eq!(calls(&log), want);
}

#[tokio::test]
async fn rotate_is_skipped_in_the_last_quarter_of_the_lifetime() {
    let fake = Fake::default()
        .rotates(Err(Status::unavailable("x")))
        .attests(Ok(issued(22, info(ID, 760, 1760, true))));
    let (mut r, log, _) = holding(fake, true);
    let wait = r.step(600).await.unwrap(); // Rotate fails transiently
    let _ = wait;
    r.step(760).await.unwrap(); // 240 s left of 1000: re-attest
    assert_eq!(calls(&log)[..2], [Call::Rotate, Call::FullAttest]);
}

#[tokio::test]
async fn identity_change_on_rotate_is_not_swapped() {
    let fake = Fake::default().rotates(Ok(issued(23, info(OTHER_ID, 600, 1600, true))));
    let (mut r, log, status) = holding(fake, true);
    assert!(matches!(
        r.step(600).await,
        Err(Fatal::IdentityChanged { .. })
    ));
    assert_eq!(calls(&log), [Call::Rotate, Call::Disable]);
    assert_eq!(
        status.observe().await.phase,
        AttestPhase::Failed(AttestFailure::IdentityChanged)
    );
}

#[tokio::test]
async fn accept_never_waits_past_the_new_expiry() {
    for (iat, exp) in [
        (600, 1600),
        (0, 1100),
        (-500, 700),
        (600, 640),
        (600, 100_000),
    ] {
        let fake = Fake::default().rotates(Ok(issued(24, info(ID, iat, exp, true))));
        let (mut r, _, _) = holding(fake, true);
        let wait = i64::try_from(r.step(600).await.unwrap().as_secs()).unwrap();
        assert!(600 + wait <= exp.max(TTL), "{iat}..{exp}: {wait}");
        assert!(wait >= 1);
    }
}

#[tokio::test]
async fn a_panicking_renewal_task_disables_minting_and_is_fatal() {
    // If the task dies, `serve` must not wait forever with minting on.
    let fake = Fake {
        panic_on_rotate: true,
        ..Fake::default()
    };
    let (r, _, _) = holding(fake, true);
    let creds = CredentialSlot::new();
    let sink = Arc::new(CheckingSink {
        slot: creds.clone(),
        current: Mutex::new(None),
        history: Mutex::new(Vec::new()),
    });
    let swap = Swap::new(
        creds,
        Arc::clone(&sink) as Arc<dyn MinterSink>,
        SvidCell::new(),
    );
    let rx = spawn(r, swap, || 600, std::future::pending::<()>());
    let fatal = tokio::time::timeout(Duration::from_secs(10), next_fatal(Some(rx)))
        .await
        .expect("the supervisor reports the dead task");
    assert_eq!(fatal, Fatal::TaskEnded);
    assert_eq!(*sink.history.lock().unwrap(), [None]);
}

#[tokio::test]
async fn next_fatal_waits_only_for_a_fatal_exit() {
    // No task, or one that shut down cleanly: never resolves.
    let pending = tokio::time::timeout(Duration::from_millis(50), next_fatal(None)).await;
    assert!(pending.is_err());
    let (tx, rx) = tokio::sync::watch::channel(None);
    drop(tx);
    let pending = tokio::time::timeout(Duration::from_millis(50), next_fatal(Some(rx))).await;
    assert!(pending.is_err());
    let (tx, rx) = tokio::sync::watch::channel(None);
    tx.send(Some(Fatal::TaskEnded)).unwrap();
    assert_eq!(next_fatal(Some(rx)).await, Fatal::TaskEnded);
}

#[tokio::test]
async fn a_renewed_svid_is_not_renewed_again_at_once() {
    // A host clock ahead of CMIS can see the new SVID's own renewal point as
    // already passed: wait at least RETRY_BASE instead of looping on CMIS.
    let fake = Fake::default().rotates(Ok(issued(15, info(ID, 0, 1100, true))));
    let (mut r, log, _) = holding(fake, true);
    assert_eq!(r.step(700).await.unwrap(), schedule::RETRY_BASE);
    assert_eq!(r.step(701).await.unwrap(), Duration::from_secs(29));
    assert_eq!(calls(&log).len(), 3, "one renewal only: {:?}", calls(&log));
}

#[tokio::test]
async fn run_stops_on_shutdown() {
    let (r, log, _) = holding(Fake::default(), true);
    let exit = r.run(|| 0, Duration::from_secs(3600), async {}).await;
    assert!(matches!(exit, Exit::Shutdown));
    assert_eq!(calls(&log), Vec::<Call>::new());
}

#[test]
fn transient_and_refusal_codes_are_classified() {
    for code in [
        Code::Unavailable,
        Code::DeadlineExceeded,
        Code::Cancelled,
        Code::Aborted,
        Code::Unknown,
        Code::Internal,
        Code::ResourceExhausted,
    ] {
        assert_eq!(classify(&Status::new(code, "x")), Next::Retry, "{code:?}");
    }
    for code in [
        Code::FailedPrecondition,
        Code::NotFound,
        Code::Unauthenticated,
        Code::PermissionDenied,
        Code::InvalidArgument,
        Code::Unimplemented,
    ] {
        assert_eq!(
            classify(&Status::new(code, "x")),
            Next::FullAttest,
            "{code:?}"
        );
    }
}

// --- the credential swap ----------------------------------------------------

/// A host-key SVID over `secret` naming `jws` (a stand-in; the swap never
/// parses it).
fn host_svid(secret: &Arc<CompositeSecretKey>, jws: &str, iat: i64, exp: i64) -> HostSvid {
    let key: Arc<dyn ferro_sep::MachineKey + Send + Sync> =
        Arc::new(ferro_sep::SoftwareMachineKey::generate().unwrap());
    HostSvid::new(
        SvidBundle {
            jws: jws.to_string(),
            issued_at: iat,
            expires_at: exp,
            spiffe_id: ID.to_string(),
            x509_svid: Vec::new(),
            x509_bundle: Vec::new(),
        },
        Arc::clone(secret),
        "host-kid".to_string(),
        Some(key),
    )
}

fn sha(jws: &str) -> [u8; 48] {
    let mut out = [0u8; 48];
    out.copy_from_slice(&Sha384::digest(jws.as_bytes()));
    out
}

/// A minter sink that checks, at every swap, that the credentials already in
/// the slot name the SVID the new minter is parented on.
struct CheckingSink {
    slot: CredentialSlot,
    current: Mutex<Option<ChildTokenMinter>>,
    history: Mutex<Vec<Option<[u8; 48]>>>,
}

impl MinterSink for CheckingSink {
    fn set(&self, minter: Option<ChildTokenMinter>) -> BoxFuture<'_, ()> {
        if let Some(m) = &minter {
            let creds = self
                .slot
                .get()
                .expect("credentials go in before the minter");
            assert_eq!(sha(&creds.svid_jws), m.parent_svid_sha384());
        }
        self.history
            .lock()
            .unwrap()
            .push(minter.as_ref().map(ChildTokenMinter::parent_svid_sha384));
        *self.current.lock().unwrap() = minter;
        Box::pin(async {})
    }
}

fn parent_of_minted(m: &ChildTokenMinter) -> String {
    let actor = CallerIdentity::new(1, 1000, 1000, [0xAB; 48]);
    let t = m.mint("aud", "jkt", 60, &actor, 0).unwrap();
    let claims = t.jws.split('.').nth(1).unwrap();
    let claims: ChildClaims =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims).unwrap()).unwrap();
    claims.ferrogate.parent_svid
}

#[tokio::test]
async fn swap_installs_credentials_before_the_minter() {
    let (secret, _) = CompositeSecretKey::generate().unwrap();
    let secret = Arc::new(secret);
    let creds = CredentialSlot::new();
    let sink = Arc::new(CheckingSink {
        slot: creds.clone(),
        current: Mutex::new(None),
        history: Mutex::new(Vec::new()),
    });
    let cell = SvidCell::new();
    let swap = Swap::new(
        creds.clone(),
        Arc::clone(&sink) as Arc<dyn MinterSink>,
        cell,
    );

    let old = host_svid(&secret, "old.svid.jws", 0, TTL);
    swap.install(&old).await;
    // A Rotate renews the same key under a new JWS.
    let renewed = old.rotated(SvidBundle {
        jws: "new.svid.jws".into(),
        issued_at: 600,
        expires_at: 1600,
        spiffe_id: ID.into(),
        x509_svid: Vec::new(),
        x509_bundle: Vec::new(),
    });
    assert_eq!(renewed.minter.parent_svid_sha384(), sha("new.svid.jws"));
    assert_eq!(old.minter.parent_svid_sha384(), sha("old.svid.jws"));
    swap.install(&renewed).await;

    // After the swap: the slot signs with the new SVID and every token names
    // it as parent; the old digest is never minted again.
    let c = creds.get().unwrap();
    assert_eq!(c.svid_jws, "new.svid.jws");
    assert_eq!(c.svid_expires_at, 1600);
    let live = sink.current.lock().unwrap().clone().unwrap();
    assert_eq!(parent_of_minted(&live), hex::encode(sha("new.svid.jws")));
    assert_eq!(
        *sink.history.lock().unwrap(),
        [Some(sha("old.svid.jws")), Some(sha("new.svid.jws"))]
    );

    // Fail closed: minting off first, then the credentials.
    swap.disable().await;
    assert!(sink.current.lock().unwrap().is_none());
    assert!(creds.get().is_none());
}

#[tokio::test]
async fn propose_uses_renewed_svid() {
    // The allowlist-propose task reads the SVID it presents from the cell on
    // every attempt, so a renewal reaches it without a restart.
    let (secret, _) = CompositeSecretKey::generate().unwrap();
    let secret = Arc::new(secret);
    let cell = SvidCell::new();
    let sink = Arc::new(CheckingSink {
        slot: CredentialSlot::new(),
        current: Mutex::new(None),
        history: Mutex::new(Vec::new()),
    });
    let swap = Swap::new(
        sink.slot.clone(),
        Arc::clone(&sink) as Arc<dyn MinterSink>,
        cell.clone(),
    );
    assert!(cell.jws_valid_at(0).is_none());
    let old = host_svid(&secret, "old.svid.jws", 0, TTL);
    swap.install(&old).await;
    assert_eq!(cell.jws_valid_at(10).as_deref(), Some("old.svid.jws"));
    swap.install(&old.rotated(SvidBundle {
        jws: "new.svid.jws".into(),
        issued_at: 600,
        expires_at: 1600,
        spiffe_id: ID.into(),
        ..SvidBundle::default()
    }))
    .await;
    assert_eq!(cell.jws_valid_at(1200).as_deref(), Some("new.svid.jws"));
    // Never an expired one, and none once the swap fails closed.
    assert!(cell.jws_valid_at(1600).is_none());
    swap.disable().await;
    assert!(cell.jws_valid_at(700).is_none());
    // The cell's Debug output never shows the JWS.
    swap.install(&old).await;
    assert!(!format!("{cell:?}").contains("svid.jws"));
}

// --- the daemon's renewer (HostRenewer) ---------------------------------------

/// A scripted [`HostAttestor`] that records the key policy of every call.
#[derive(Default)]
struct FakeAttestor {
    results: Mutex<VecDeque<Result<Attested, AttestFailure>>>,
    policies: Arc<Mutex<Vec<KeyPolicy>>>,
}

impl HostAttestor for FakeAttestor {
    fn attest(&self, policy: KeyPolicy) -> BoxFuture<'_, Result<Attested, AttestFailure>> {
        self.policies.lock().unwrap().push(policy);
        let r = self
            .results
            .lock()
            .unwrap()
            .pop_front()
            .expect("an unexpected attestation");
        Box::pin(async move { r })
    }
}

/// A dialer for tests that never Rotate.
struct NoDial;

impl CmisDial for NoDial {
    fn dial(&self) -> BoxFuture<'_, Result<DialedCmis, Status>> {
        Box::pin(async { Err(Status::unavailable("cmis_unreachable")) })
    }
}

/// Records which SVIDs were sealed.
#[derive(Default, Clone)]
struct FakeSealer(Arc<Mutex<Vec<String>>>);

impl X509Sealer for FakeSealer {
    fn seal(&self, svid: &HostSvid) -> Option<&'static str> {
        self.0.lock().unwrap().push(svid.jws.clone());
        Some("machine-key")
    }
}

/// Records the SVIDs `after_install` saw.
#[derive(Default, Clone)]
struct FakeHooks(Arc<Mutex<Vec<String>>>);

impl RenewalHooks for FakeHooks {
    fn after_install<'a>(&'a mut self, svid: &'a HostSvid) -> BoxFuture<'a, ()> {
        self.0.lock().unwrap().push(svid.jws.clone());
        Box::pin(async {})
    }
}

/// A host SVID for `spiffe_id` under `kid`, `iat..exp`.
fn svid_for(spiffe_id: &str, jws: &str, kid: &str, iat: i64, exp: i64) -> HostSvid {
    let (secret, _) = CompositeSecretKey::generate().unwrap();
    let key: Arc<dyn ferro_sep::MachineKey + Send + Sync> =
        Arc::new(ferro_sep::SoftwareMachineKey::generate().unwrap());
    HostSvid::new(
        SvidBundle {
            jws: jws.to_string(),
            issued_at: iat,
            expires_at: exp,
            spiffe_id: spiffe_id.to_string(),
            x509_svid: vec![1],
            x509_bundle: vec![2],
        },
        Arc::new(secret),
        kid.to_string(),
        Some(key),
    )
}

struct Rig {
    renewal: Renewal<HostRenewer<FakeAttestor, NoDial, FakeSealer, FakeHooks>>,
    policies: Arc<Mutex<Vec<KeyPolicy>>>,
    sealed: FakeSealer,
    hooks: FakeHooks,
    creds: CredentialSlot,
    status: StatusHandle,
}

/// A renewal over a [`HostRenewer`] answering `results`, holding `current`
/// (a seeded start-up attestation) when given.
fn rig(results: Vec<Result<Attested, AttestFailure>>, current: Option<Attested>) -> Rig {
    let attestor = FakeAttestor {
        results: Mutex::new(results.into()),
        policies: Arc::default(),
    };
    let policies = Arc::clone(&attestor.policies);
    let (sealed, hooks) = (FakeSealer::default(), FakeHooks::default());
    let creds = CredentialSlot::new();
    let sink = Arc::new(CheckingSink {
        slot: creds.clone(),
        current: Mutex::new(None),
        history: Mutex::new(Vec::new()),
    });
    let swap = Swap::new(creds.clone(), sink as Arc<dyn MinterSink>, SvidCell::new());
    let status = StatusHandle::new("default", 0);
    let mut renewer = HostRenewer::new(
        attestor,
        NoDial,
        sealed.clone(),
        hooks.clone(),
        swap,
        status.clone(),
        None,
    );
    let mut renewal_info = None;
    if let Some(a) = current {
        status.attest_succeeded(&a.svid.spiffe_id, a.svid.issued_at, a.svid.expires_at);
        renewal_info = Some(a.svid.info());
        renewer = renewer.with_current(&a);
    }
    let mut renewal = Renewal::new(renewer, status.clone()).with_jitter(|| 0.5);
    if let Some(info) = renewal_info {
        renewal = renewal.with_current(info, 0);
    }
    Rig {
        renewal,
        policies,
        sealed,
        hooks,
        creds,
        status,
    }
}

fn seeded(svid: HostSvid) -> Attested {
    Attested { svid, seeded: true }
}

#[tokio::test]
async fn renewals_reopen_the_key_and_seed_they_started_with() {
    // Before this run attested anything, the key and seed may be created;
    // after, a renewal only reopens them (and needs the seed it used).
    let first = svid_for(ID, "a.b.c", "kid-1", 0, TTL);
    let second = svid_for(ID, "d.e.f", "kid-1", 600, 1600);
    let mut rig = rig(vec![Ok(seeded(first)), Ok(seeded(second))], None);
    rig.renewal.step(0).await.unwrap();
    rig.renewal.step(600).await.unwrap();
    assert_eq!(
        *rig.policies.lock().unwrap(),
        [
            KeyPolicy::OpenOrCreate,
            KeyPolicy::OpenOnly {
                seed_required: true
            }
        ]
    );
    // The hooks ran with each new SVID, after the swap.
    assert_eq!(*rig.hooks.0.lock().unwrap(), ["a.b.c", "d.e.f"]);
    assert_eq!(rig.creds.get().unwrap().svid_jws, "d.e.f");
}

#[tokio::test]
async fn a_seeded_host_refuses_a_renewal_under_another_kid() {
    // A seed swapped behind the agent's back (or lost and re-created) would
    // rotate the child-signing key and break tokens verifiers trust.
    let start = seeded(svid_for(ID, "a.b.c", "kid-1", 0, TTL));
    let other_kid = seeded(svid_for(ID, "d.e.f", "kid-2", 600, 1600));
    let ephemeral = Attested {
        svid: svid_for(ID, "g.h.i", "kid-1", 600, 1600),
        seeded: false,
    };
    let mut rig = rig(vec![Ok(other_kid), Ok(ephemeral)], Some(start));
    rig.renewal.step(600).await.unwrap();
    assert_eq!(
        rig.status.observe().await.renewal,
        Some(crate::status::RenewalPhase::Failed(
            AttestFailure::MachineKey
        ))
    );
    let mut now = 600;
    now += i64::try_from(rig.renewal.step(now).await.unwrap().as_secs()).unwrap();
    let _ = now;
    assert!(rig.sealed.0.lock().unwrap().is_empty(), "nothing sealed");
    assert!(rig.hooks.0.lock().unwrap().is_empty(), "nothing installed");
}

#[tokio::test]
async fn x509_is_sealed_only_after_acceptance() {
    // Another identity, or an SVID with no life left, must not overwrite the
    // sealed X.509 store.
    let start = seeded(svid_for(ID, "a.b.c", "kid-1", 0, TTL));
    let skewed = seeded(svid_for(ID, "d.e.f", "kid-1", 0, 610));
    let good = seeded(svid_for(ID, "g.h.i", "kid-1", 900, 1900));
    let mut r = rig(vec![Ok(skewed), Ok(good)], Some(start));
    r.renewal.step(600).await.unwrap();
    assert!(r.sealed.0.lock().unwrap().is_empty());
    r.renewal.step(900).await.unwrap();
    assert_eq!(*r.sealed.0.lock().unwrap(), ["g.h.i"]);

    let start = seeded(svid_for(ID, "a.b.c", "kid-1", 0, TTL));
    let foreign = seeded(svid_for(OTHER_ID, "x.y.z", "kid-1", 600, 1600));
    let mut r = rig(vec![Ok(foreign)], Some(start));
    assert!(r.renewal.step(600).await.is_err());
    assert!(r.sealed.0.lock().unwrap().is_empty());
    assert!(r.creds.get().is_none(), "minting and host calls off");
}
