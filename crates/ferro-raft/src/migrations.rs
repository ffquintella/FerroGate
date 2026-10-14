//! Ordered, versioned schema migrations (feature F19 §2).
//!
//! The tables that predate F19 are still created by idempotent `CREATE ...
//! IF NOT EXISTS` statements at start (`Cluster::init_schema`). Everything
//! from F19 on goes through this runner instead: each migration has a version
//! number, its statements run in **one** Raft transaction together with the
//! `schema_migrations` row that records it, and a node applies only the
//! versions it has not seen.
//!
//! Migrations are additive only (new tables, indexes and triggers; no
//! destructive `ALTER`). Their statements are written with `IF NOT EXISTS`
//! as well, so two nodes that start at the same moment and both try to apply
//! the same version cannot fail on the DDL: the loser's transaction aborts on
//! the `schema_migrations` primary key and rolls back, and the version is
//! then simply present.

use hiqlite::Param;

use crate::cluster::{Cluster, ClusterError};

/// One schema migration: a version and the statements it applies.
pub(crate) struct Migration {
    /// Strictly increasing version number.
    pub(crate) version: i64,
    /// Short name, for logs.
    pub(crate) name: &'static str,
    /// DDL statements, applied in order inside one transaction.
    pub(crate) statements: &'static [&'static str],
}

/// Every migration this build knows, in version order.
pub(crate) const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "app approval ledger (F19)",
    statements: crate::apps::schema::LEDGER_SCHEMA,
}];

#[derive(Debug)]
struct VersionRow(i64);
impl<'r> From<&'r mut hiqlite::Row<'_>> for VersionRow {
    fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
        Self(row.get("version"))
    }
}

impl Cluster {
    /// Apply every migration in [`MIGRATIONS`] that this database has not
    /// recorded yet, in order.
    pub(crate) async fn run_migrations(&self, now_unix: i64) -> Result<(), ClusterError> {
        self.client()
            .execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ( \
                    version INTEGER PRIMARY KEY, \
                    applied_at INTEGER NOT NULL \
                )",
                Vec::<Param>::new(),
            )
            .await?;
        for migration in MIGRATIONS {
            if self
                .applied_migrations()
                .await?
                .contains(&migration.version)
            {
                continue;
            }
            let mut stmts: Vec<(&'static str, Vec<Param>)> = migration
                .statements
                .iter()
                .map(|ddl| (*ddl, Vec::new()))
                .collect();
            stmts.push((
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                vec![Param::from(migration.version), Param::from(now_unix)],
            ));
            match self.client().txn(stmts).await {
                Ok(results) => {
                    for r in results {
                        r?;
                    }
                    tracing::info!(
                        version = migration.version,
                        name = migration.name,
                        "schema migration applied"
                    );
                }
                // Another node applied the same version first: the primary
                // key aborted our copy, and the schema is already in place.
                Err(e)
                    if self
                        .applied_migrations()
                        .await?
                        .contains(&migration.version) =>
                {
                    tracing::debug!(
                        version = migration.version,
                        error = %e,
                        "schema migration already applied by a peer"
                    );
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// Versions recorded in `schema_migrations`, ascending.
    pub async fn applied_migrations(&self) -> Result<Vec<i64>, ClusterError> {
        let rows: Vec<VersionRow> = self
            .client()
            .query_consistent_map(
                "SELECT version FROM schema_migrations ORDER BY version",
                Vec::new(),
            )
            .await?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }
}
