//! The F20 admin tables: database-enforced immutability, single-use token
//! redemption and the TOTP replay guard, on a real single-node cluster.

use ferro_raft::admin::{
    AdminAccountRow, AdminSessionRow, EnrollmentCompletion, EnrollmentTokenRow, MfaVerification,
    PasswordUpdate, WebAuthnCredentialRow, ACCOUNT_ACTIVE, ACCOUNT_PENDING,
    MAX_WEBAUTHN_CREDENTIALS, TOKEN_BOOTSTRAP, TOKEN_ENROLL,
};
use ferro_raft::Cluster;

struct Dir(std::path::PathBuf);
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn cluster(tag: &str) -> (Cluster, Dir) {
    let dir =
        std::env::temp_dir().join(format!("ferrogate-raft-admin-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let c = Cluster::start_single_node(dir.to_string_lossy().into_owned())
        .await
        .unwrap();
    (c, Dir(dir))
}

fn pending(admin_id: &str, username: &str) -> AdminAccountRow {
    AdminAccountRow {
        admin_id: admin_id.into(),
        username: username.into(),
        display_name: Some("Name".into()),
        state: ACCOUNT_PENDING,
        created_at: 100,
        created_by_admin_id: Some("creator".into()),
        password_phc: None,
        pepper_id: None,
        password_changed_at: None,
        password_expires_at: None,
        totp_secret_enc: None,
        totp_last_step: None,
        last_login_at: None,
        disabled_at: None,
        disabled_by_admin_id: None,
        row_version: 1,
    }
}

fn token(hash: u8, admin_id: Option<&str>, purpose: i64) -> EnrollmentTokenRow {
    EnrollmentTokenRow {
        token_hash: vec![hash; 32],
        admin_id: admin_id.map(str::to_string),
        purpose,
        created_by_admin_id: None,
        created_at: 100,
        expires_at: 10_000,
        used_at: None,
        pending_secret_enc: None,
    }
}

fn completion(hash: u8, admin_id: &str, at: i64) -> EnrollmentCompletion {
    EnrollmentCompletion {
        token_hash: vec![hash; 32],
        admin_id: admin_id.into(),
        password: Some(PasswordUpdate {
            password_phc: format!("$argon2id$fake${at}"),
            pepper_id: None,
            changed_at: at,
            expires_at: at + 1000,
        }),
        totp: Some((vec![1, 2, 3], 7)),
        webauthn: None,
        now: at,
    }
}

fn credential(admin_id: &str, id: u8) -> WebAuthnCredentialRow {
    WebAuthnCredentialRow {
        credential_id: vec![id; 20],
        admin_id: admin_id.into(),
        cose_public_key: vec![0xa5, id],
        sign_count: 0,
        aaguid: Some(vec![0; 16]),
        label: Some(format!("key {id}")),
        created_at: 300 + i64::from(id),
        last_used_at: None,
    }
}

/// An active account `a1` holding a TOTP secret.
async fn active_with_totp(c: &Cluster, hash: u8) {
    c.admin_create_account(
        &pending("a1", "alice"),
        &["ferrogate-viewers".into()],
        &token(hash, Some("a1"), TOKEN_ENROLL),
    )
    .await
    .unwrap();
    c.admin_complete_enrollment(&completion(hash, "a1", 200))
        .await
        .unwrap();
}

#[tokio::test]
async fn builtin_groups_carry_the_f20_permission_table() {
    let (c, _d) = cluster("groups").await;
    let groups = c.admin_groups().await.unwrap();
    let names: Vec<_> = groups.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "ferrogate-account-admins",
            "ferrogate-approvers",
            "ferrogate-platform-operators",
            "ferrogate-viewers"
        ]
    );
    let ops = groups
        .iter()
        .find(|g| g.name == "ferrogate-platform-operators")
        .unwrap();
    assert!(ops.builtin);
    assert!(ops
        .permissions
        .contains(&"legacy.allowlist.write".to_string()));
    let viewers = groups
        .iter()
        .find(|g| g.name == "ferrogate-viewers")
        .unwrap();
    assert!(!viewers
        .permissions
        .contains(&"legacy.allowlist.write".to_string()));
    c.shutdown().await.unwrap();
}

#[tokio::test]
async fn accounts_cannot_be_deleted_and_history_is_insert_only() {
    let (c, _d) = cluster("immutable").await;
    c.admin_create_account(
        &pending("a1", "alice"),
        &["ferrogate-viewers".into()],
        &token(1, Some("a1"), TOKEN_ENROLL),
    )
    .await
    .unwrap();
    c.admin_complete_enrollment(&completion(1, "a1", 200))
        .await
        .unwrap();

    let del = c
        .client()
        .execute(
            "DELETE FROM admin_accounts WHERE admin_id = $1",
            vec![hiqlite_param("a1")],
        )
        .await;
    assert!(
        del.is_err(),
        "deleting an account must be refused by the DB"
    );

    let upd = c
        .client()
        .execute(
            "UPDATE admin_password_history SET password_phc = 'x' WHERE admin_id = $1",
            vec![hiqlite_param("a1")],
        )
        .await;
    assert!(upd.is_err(), "history rows are immutable");
    let del = c
        .client()
        .execute(
            "DELETE FROM admin_password_history WHERE admin_id = $1",
            vec![hiqlite_param("a1")],
        )
        .await;
    assert!(del.is_err(), "history rows cannot be deleted");

    let redeemed = c
        .client()
        .execute(
            "UPDATE admin_enrollment_tokens SET used_at = NULL WHERE admin_id = $1",
            vec![hiqlite_param("a1")],
        )
        .await;
    assert!(redeemed.is_err(), "a redeemed token cannot be re-armed");

    c.admin_security_log(1, "login.failed", None, None, Some("10.0.0.1"), None)
        .await
        .unwrap();
    let wipe = c
        .client()
        .execute("DELETE FROM admin_security_log", Vec::new())
        .await;
    assert!(wipe.is_err(), "the security log is insert-only");
    c.shutdown().await.unwrap();
}

#[tokio::test]
async fn an_enrollment_token_redeems_exactly_once() {
    let (c, _d) = cluster("once").await;
    c.admin_create_account(
        &pending("a1", "alice"),
        &["ferrogate-viewers".into()],
        &token(2, Some("a1"), TOKEN_ENROLL),
    )
    .await
    .unwrap();
    c.admin_complete_enrollment(&completion(2, "a1", 200))
        .await
        .unwrap();
    let acct = c.admin_account("a1").await.unwrap().unwrap();
    assert_eq!(acct.state, ACCOUNT_ACTIVE);
    assert_eq!(acct.totp_last_step, Some(7));

    let again = c.admin_complete_enrollment(&completion(2, "a1", 300)).await;
    assert!(again.is_err(), "second redemption must fail");
    c.shutdown().await.unwrap();
}

#[tokio::test]
async fn bootstrap_creates_an_active_account_and_burns_the_token() {
    let (c, _d) = cluster("bootstrap").await;
    c.admin_insert_enrollment_token(&token(3, None, TOKEN_BOOTSTRAP))
        .await
        .unwrap();
    assert!(c
        .admin_live_token_exists(TOKEN_BOOTSTRAP, 200)
        .await
        .unwrap());

    let mut acct = pending("b1", "root-admin");
    acct.created_by_admin_id = None;
    c.admin_bootstrap_account(
        &acct,
        &[
            "ferrogate-account-admins".into(),
            "ferrogate-platform-operators".into(),
        ],
        &completion(3, "b1", 200),
        &[("admin_bootstrapped", "1")],
    )
    .await
    .unwrap();
    assert_eq!(
        c.setting("admin_bootstrapped").await.unwrap().as_deref(),
        Some("1")
    );
    assert_eq!(
        c.admin_groups_of("b1").await.unwrap(),
        ["ferrogate-account-admins", "ferrogate-platform-operators"]
    );
    assert!(c
        .admin_permissions_of("b1")
        .await
        .unwrap()
        .contains(&"legacy.allowlist.write".to_string()));
    assert!(!c
        .admin_live_token_exists(TOKEN_BOOTSTRAP, 200)
        .await
        .unwrap());

    let mut second = pending("b2", "other");
    second.created_by_admin_id = None;
    assert!(
        c.admin_bootstrap_account(&second, &[], &completion(3, "b2", 201), &[])
            .await
            .is_err(),
        "a bootstrap token cannot create a second account"
    );
    assert!(c.admin_account("b2").await.unwrap().is_none());
    c.shutdown().await.unwrap();
}

#[tokio::test]
async fn totp_steps_only_move_forward() {
    let (c, _d) = cluster("totp").await;
    c.admin_create_account(
        &pending("a1", "alice"),
        &[],
        &token(4, Some("a1"), TOKEN_ENROLL),
    )
    .await
    .unwrap();
    c.admin_complete_enrollment(&completion(4, "a1", 200))
        .await
        .unwrap();
    assert!(
        !c.admin_advance_totp_step("a1", 7).await.unwrap(),
        "same step"
    );
    assert!(
        !c.admin_advance_totp_step("a1", 6).await.unwrap(),
        "older step"
    );
    assert!(
        c.admin_advance_totp_step("a1", 8).await.unwrap(),
        "newer step"
    );
    c.shutdown().await.unwrap();
}

#[tokio::test]
async fn sessions_rotate_and_revoke() {
    let (c, _d) = cluster("sessions").await;
    let row = AdminSessionRow {
        session_hash: vec![9; 32],
        admin_id: "a1".into(),
        created_at: 100,
        last_seen_at: 100,
        absolute_expires_at: 1000,
        idle_timeout_secs: 900,
        aal: 2,
        mfa_at: 100,
        mfa_method: 1,
        source_ip: "127.0.0.1".into(),
        client_cert_sha256: None,
        client_kind: 3,
        client_version: None,
        restricted: 0,
        revoked_at: None,
        revoked_reason: None,
        stepup_failures: 0,
    };
    c.admin_insert_session(&row).await.unwrap();
    assert_eq!(
        c.admin_session_stepup_failed(&row.session_hash)
            .await
            .unwrap(),
        1
    );
    assert!(c
        .admin_rotate_session(
            &row.session_hash,
            &[8; 32],
            Some(MfaVerification {
                at: 150,
                method: 2,
                aal: 3,
            }),
            0,
        )
        .await
        .unwrap());
    assert!(c.admin_session(&row.session_hash).await.unwrap().is_none());
    let rotated = c.admin_session(&[8; 32]).await.unwrap().unwrap();
    assert_eq!(rotated.mfa_at, 150);
    assert_eq!((rotated.mfa_method, rotated.aal), (2, 3));
    assert_eq!(rotated.stepup_failures, 0);

    assert!(c.admin_revoke_session(&[8; 32], 200, 1).await.unwrap());
    assert!(!c.admin_revoke_session(&[8; 32], 201, 1).await.unwrap());
    assert_eq!(c.admin_live_sessions("a1").await.unwrap(), Vec::new());
    c.shutdown().await.unwrap();
}

fn hiqlite_param(v: &str) -> hiqlite::Param {
    hiqlite::Param::from(v.to_string())
}

#[tokio::test]
async fn a_stale_row_version_writes_nothing() {
    let (c, _d) = cluster("rowver").await;
    c.admin_create_account(
        &pending("a1", "alice"),
        &["ferrogate-viewers".into()],
        &token(5, Some("a1"), TOKEN_ENROLL),
    )
    .await
    .unwrap();
    let v = c.admin_account("a1").await.unwrap().unwrap().row_version;
    let stale = c
        .admin_update_account(
            "a1",
            Some(Some("New".into())),
            Some(&["ferrogate-approvers".to_string()]),
            "admin",
            300,
            v + 7,
            false,
        )
        .await
        .unwrap();
    assert_eq!(stale, None, "a stale version is refused");
    let acct = c.admin_account("a1").await.unwrap().unwrap();
    assert_eq!(acct.display_name.as_deref(), Some("Name"));
    assert_eq!(
        c.admin_groups_of("a1").await.unwrap(),
        ["ferrogate-viewers"]
    );

    let fresh = c
        .admin_update_account(
            "a1",
            None,
            Some(&["ferrogate-approvers".to_string()]),
            "admin",
            300,
            v,
            false,
        )
        .await
        .unwrap();
    assert_eq!(fresh, Some(v + 1));
    assert_eq!(
        c.admin_groups_of("a1").await.unwrap(),
        ["ferrogate-approvers"]
    );

    assert!(
        c.admin_create_account(
            &pending("a2", "alice"),
            &[],
            &token(6, Some("a2"), TOKEN_ENROLL),
        )
        .await
        .is_err(),
        "a taken username is refused"
    );
    assert!(
        c.admin_enrollment_token(&[6; 32]).await.unwrap().is_none(),
        "and writes nothing"
    );
    c.shutdown().await.unwrap();
}

#[tokio::test]
async fn concurrent_throttle_failures_are_all_counted() {
    let (c, _d) = cluster("throttle-atomic").await;
    let c = std::sync::Arc::new(c);
    let tasks: Vec<_> = (0..20)
        .map(|_| {
            let c = std::sync::Arc::clone(&c);
            tokio::spawn(async move {
                c.admin_throttle_increment(&[7; 32], 1, 1_000, 86_400)
                    .await
                    .unwrap()
            })
        })
        .collect();
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(
        c.admin_throttle(&[7; 32]).await.unwrap().unwrap().failures,
        20
    );
    // A quiet day starts the count over and drops the old lock.
    c.admin_throttle_lock(&[7; 32], 5_000).await.unwrap();
    let row = c
        .admin_throttle_increment(&[7; 32], 1, 1_000 + 86_400, 86_400)
        .await
        .unwrap();
    assert_eq!((row.failures, row.locked_until), (1, 0));
}

/// F20 §7 rule 4, inside the write: once one of two account administrators is
/// disabled, a guarded write that would remove the other applies nothing.
#[tokio::test]
async fn the_last_account_admin_guard_is_part_of_the_write() {
    let (c, _d) = cluster("rule4").await;
    for (i, id) in ["a1", "a2"].iter().enumerate() {
        let hash = u8::try_from(10 + i).unwrap();
        c.admin_create_account(
            &pending(id, &format!("user-{id}")),
            &["ferrogate-account-admins".into()],
            &token(hash, Some(id), TOKEN_ENROLL),
        )
        .await
        .unwrap();
        c.admin_complete_enrollment(&completion(hash, id, 200 + i64::try_from(i).unwrap()))
            .await
            .unwrap();
    }
    assert!(c
        .admin_set_account_state("a1", 3, "a2", 300, None, true)
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        c.admin_set_account_state("a2", 3, "a1", 301, None, true)
            .await
            .unwrap(),
        None,
        "the last active account admin cannot be disabled"
    );
    assert_eq!(
        c.admin_account("a2").await.unwrap().unwrap().state,
        ACCOUNT_ACTIVE
    );
    let v = c.admin_account("a2").await.unwrap().unwrap().row_version;
    assert_eq!(
        c.admin_update_account(
            "a2",
            None,
            Some(&["ferrogate-viewers".to_string()]),
            "x",
            302,
            v,
            true
        )
        .await
        .unwrap(),
        None,
        "nor demoted"
    );
    assert_eq!(
        c.admin_groups_of("a2").await.unwrap(),
        ["ferrogate-account-admins"]
    );
    // Disabling supersedes the account's unredeemed tokens.
    c.admin_insert_enrollment_token(&token(30, Some("a1"), TOKEN_ENROLL))
        .await
        .unwrap();
    c.admin_set_account_state("a1", 3, "a2", 303, None, false)
        .await
        .unwrap();
    assert!(c
        .admin_enrollment_token(&[30; 32])
        .await
        .unwrap()
        .unwrap()
        .used_at
        .is_some());
    c.shutdown().await.unwrap();
}

/// F20 §5: at most eight FIDO2 credentials per account, and a credential id
/// belongs to one account only.
#[tokio::test]
async fn webauthn_credentials_are_capped_and_unique() {
    let (c, _d) = cluster("wa-cap").await;
    active_with_totp(&c, 40).await;
    let cap = u8::try_from(MAX_WEBAUTHN_CREDENTIALS).unwrap();
    for id in 1..=cap {
        assert!(c
            .admin_add_webauthn_credential(&credential("a1", id))
            .await
            .unwrap());
    }
    assert!(
        !c.admin_add_webauthn_credential(&credential("a1", 99))
            .await
            .unwrap(),
        "a ninth key is refused"
    );
    let listed = c.admin_webauthn_credentials("a1").await.unwrap();
    assert_eq!(listed.len(), 8);
    assert_eq!(listed[0], credential("a1", 1));

    let mut stolen = credential("someone-else", 1);
    stolen.admin_id = "a2".into();
    assert!(
        matches!(
            c.admin_add_webauthn_credential(&stolen).await,
            Err(ferro_raft::ClusterError::Conflict(_))
        ),
        "a registered credential id cannot be claimed by another account"
    );
    assert!(c
        .admin_webauthn_credential("a2", &[1; 20])
        .await
        .unwrap()
        .is_none());
    assert!(c
        .admin_webauthn_credential("a1", &[1; 20])
        .await
        .unwrap()
        .is_some());
    c.shutdown().await.unwrap();
}

/// WebAuthn §7.2 step 21: a signature counter only moves forward; an
/// authenticator that always reports zero is accepted every time.
#[tokio::test]
async fn sign_counts_only_move_forward() {
    let (c, _d) = cluster("wa-count").await;
    active_with_totp(&c, 41).await;
    c.admin_add_webauthn_credential(&credential("a1", 1))
        .await
        .unwrap();
    c.admin_add_webauthn_credential(&credential("a1", 2))
        .await
        .unwrap();
    assert!(c.admin_webauthn_used("a1", &[1; 20], 5, 400).await.unwrap());
    assert!(!c.admin_webauthn_used("a1", &[1; 20], 5, 401).await.unwrap());
    assert!(!c.admin_webauthn_used("a1", &[1; 20], 4, 402).await.unwrap());
    assert!(
        !c.admin_webauthn_used("a1", &[1; 20], 0, 403).await.unwrap(),
        "a counter that drops to zero is a regression"
    );
    assert!(c.admin_webauthn_used("a1", &[1; 20], 6, 404).await.unwrap());
    let row = c
        .admin_webauthn_credential("a1", &[1; 20])
        .await
        .unwrap()
        .unwrap();
    assert_eq!((row.sign_count, row.last_used_at), (6, Some(404)));

    for t in 0..3 {
        assert!(c
            .admin_webauthn_used("a1", &[2; 20], 0, 500 + t)
            .await
            .unwrap());
    }
    assert!(
        !c.admin_webauthn_used("a2", &[2; 20], 9, 600).await.unwrap(),
        "only the owner's credential is updated"
    );
    c.shutdown().await.unwrap();
}

/// F20 §5: removing a factor never leaves an account without one, even
/// under concurrent removals; TOTP is added only when absent.
#[tokio::test]
async fn the_last_factor_cannot_be_removed() {
    let (c, _d) = cluster("wa-last").await;
    active_with_totp(&c, 42).await;
    assert!(
        !c.admin_remove_totp("a1").await.unwrap(),
        "TOTP is the only factor"
    );
    assert!(
        !c.admin_add_totp("a1", &[9, 9], 50).await.unwrap(),
        "a second TOTP secret is refused"
    );
    c.admin_add_webauthn_credential(&credential("a1", 1))
        .await
        .unwrap();
    c.admin_add_webauthn_credential(&credential("a1", 2))
        .await
        .unwrap();
    assert!(c.admin_remove_totp("a1").await.unwrap());
    assert!(c
        .admin_account("a1")
        .await
        .unwrap()
        .unwrap()
        .totp_secret_enc
        .is_none());
    assert!(c
        .admin_remove_webauthn_credential("a1", &[1; 20])
        .await
        .unwrap());
    assert!(
        !c.admin_remove_webauthn_credential("a1", &[2; 20])
            .await
            .unwrap(),
        "the last key is the last factor"
    );
    assert!(c.admin_add_totp("a1", &[9, 9], 50).await.unwrap());
    let a = c.admin_account("a1").await.unwrap().unwrap();
    assert_eq!(
        (a.totp_secret_enc.as_deref(), a.totp_last_step),
        (Some(&[9u8, 9][..]), Some(50))
    );
    assert!(c
        .admin_remove_webauthn_credential("a1", &[2; 20])
        .await
        .unwrap());
    assert_eq!(c.admin_webauthn_credentials("a1").await.unwrap().len(), 0);
    c.shutdown().await.unwrap();
}

/// A credential enrolled with a token is stored in the same transaction that
/// redeems the token, and only then.
#[tokio::test]
async fn enrollment_stores_a_webauthn_credential_atomically() {
    let (c, _d) = cluster("wa-enroll").await;
    c.admin_create_account(
        &pending("a1", "alice"),
        &["ferrogate-viewers".into()],
        &token(43, Some("a1"), TOKEN_ENROLL),
    )
    .await
    .unwrap();
    let mut done = completion(43, "a1", 200);
    done.totp = None;
    done.webauthn = Some(credential("a1", 7));
    c.admin_complete_enrollment(&done).await.unwrap();
    assert_eq!(
        c.admin_webauthn_credentials("a1").await.unwrap(),
        [credential("a1", 7)]
    );
    let mut replay = done.clone();
    replay.webauthn = Some(credential("a1", 8));
    assert!(c.admin_complete_enrollment(&replay).await.is_err());
    assert_eq!(c.admin_webauthn_credentials("a1").await.unwrap().len(), 1);
    c.shutdown().await.unwrap();
}
