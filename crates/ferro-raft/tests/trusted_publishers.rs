//! Trusted publisher records (ADR-0006): add, duplicate refusal, removal
//! once and final, the in-force view, and the database guards.

use ferro_raft::publishers::{NewPublisher, PUBLISHER_ACTIVE, PUBLISHER_REMOVED};
use ferro_raft::{Cluster, LedgerError};
use hiqlite::Param;

const NOW: i64 = 1_800_000_000;

struct Dir(std::path::PathBuf);
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn cluster(tag: &str) -> (Cluster, Dir) {
    let dir = std::env::temp_dir().join(format!("ferrogate-raft-pub-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let c = Cluster::start_single_node(dir.to_string_lossy().into_owned())
        .await
        .unwrap();
    (c, Dir(dir))
}

fn publisher(id: &str, pin: u8) -> NewPublisher {
    NewPublisher {
        publisher_id: id.into(),
        kind: 1,
        anchor_sha256: [0xa0; 32],
        pin_kind: 2,
        pin: [pin; 32],
        require_timestamp: true,
        label: "ACME".into(),
        subject: "CN=ACME Corp".into(),
        issuer: "CN=ACME CA".into(),
        leaf_cert_sha256: Some([0x11; 32]),
        created_at: NOW,
        created_by_admin_id: "admin-1".into(),
        expires_at: None,
    }
}

#[tokio::test]
async fn add_list_remove_and_the_in_force_view() {
    let (c, _dir) = cluster("crud").await;
    let a = c.publisher_add(&publisher("p-1", 1)).await.unwrap();
    assert_eq!(a.state, PUBLISHER_ACTIVE);
    assert_eq!(a.record, publisher("p-1", 1));

    let mut expiring = publisher("p-2", 2);
    expiring.expires_at = Some(NOW + 10);
    c.publisher_add(&expiring).await.unwrap();
    assert_eq!(c.publishers(false).await.unwrap().len(), 2);
    assert_eq!(c.publishers_in_force(NOW).await.unwrap().len(), 2);
    assert_eq!(c.publishers_in_force(NOW + 10).await.unwrap().len(), 1);

    let r = c.publisher_remove("p-1", "admin-2", NOW + 1).await.unwrap();
    assert_eq!(r.state, PUBLISHER_REMOVED);
    assert_eq!(r.removed_by_admin_id.as_deref(), Some("admin-2"));
    assert_eq!(c.publishers(false).await.unwrap().len(), 1);
    assert_eq!(
        c.publishers(true).await.unwrap().len(),
        2,
        "removal keeps the record"
    );

    assert!(matches!(
        c.publisher_remove("p-1", "admin-2", NOW + 2).await,
        Err(LedgerError::InvalidState)
    ));
    assert!(matches!(
        c.publisher_remove("nope", "admin-2", NOW + 2).await,
        Err(LedgerError::NotFound)
    ));
}

#[tokio::test]
async fn the_same_pin_is_refused_while_active_and_allowed_after_removal() {
    let (c, _dir) = cluster("dup").await;
    c.publisher_add(&publisher("p-1", 7)).await.unwrap();
    assert!(matches!(
        c.publisher_add(&publisher("p-2", 7)).await,
        Err(LedgerError::Invalid("publisher_exists"))
    ));
    c.publisher_remove("p-1", "admin-1", NOW).await.unwrap();
    c.publisher_add(&publisher("p-3", 7)).await.unwrap();
}

#[tokio::test]
async fn bad_input_is_refused_before_writing() {
    let (c, _dir) = cluster("bad").await;
    let mut p = publisher("p-1", 1);
    p.kind = 3;
    assert!(matches!(
        c.publisher_add(&p).await,
        Err(LedgerError::Invalid("kind"))
    ));
    let mut p = publisher("p-1", 1);
    p.label = "x".repeat(129);
    assert!(matches!(
        c.publisher_add(&p).await,
        Err(LedgerError::Invalid("label"))
    ));
    assert_eq!(c.publishers(true).await.unwrap().len(), 0);
}

/// The triggers hold even for writes that bypass the typed API.
#[tokio::test]
async fn records_are_never_deleted_or_rewritten() {
    let (c, _dir) = cluster("guards").await;
    c.publisher_add(&publisher("p-1", 1)).await.unwrap();
    let id = || vec![Param::from("p-1".to_string())];
    assert!(c
        .client()
        .execute(
            "DELETE FROM trusted_publishers WHERE publisher_id = ?1",
            id()
        )
        .await
        .is_err());
    assert!(c
        .client()
        .execute(
            "UPDATE trusted_publishers SET pin = zeroblob(32) WHERE publisher_id = ?1",
            id()
        )
        .await
        .is_err());
    c.publisher_remove("p-1", "admin-1", NOW).await.unwrap();
    assert!(c
        .client()
        .execute(
            "UPDATE trusted_publishers SET state = 1, removed_at = NULL, \
             removed_by_admin_id = NULL WHERE publisher_id = ?1",
            id()
        )
        .await
        .is_err());
    assert_eq!(c.publishers(true).await.unwrap().len(), 1);
}
