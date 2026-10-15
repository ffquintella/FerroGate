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
//! destructive `ALTER`). The one exception is a guard trigger being
//! replaced: `DROP TRIGGER IF EXISTS` followed by its new `CREATE` in the
//! same migration, hence the same transaction, so the table is never
//! unguarded and a database created by an earlier version ends with the same
//! triggers as a new one. An applied migration is never edited. Statements
//! are written with `IF NOT EXISTS` as well, so two nodes that start at the
//! same moment and both try to apply the same version cannot fail on the
//! DDL: the loser's transaction aborts on the `schema_migrations` primary key
//! and rolls back, and the version is then simply present.

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
pub(crate) const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "app approval ledger (F19)",
        statements: crate::apps::schema::LEDGER_SCHEMA,
    },
    Migration {
        version: 2,
        name: "app approval user guards (F19 security review)",
        statements: crate::apps::schema::APPROVAL_USER_GUARDS,
    },
    Migration {
        version: 3,
        name: "legacy import terms (F19 §11, M38)",
        statements: crate::apps::schema::LEGACY_IMPORT_GUARDS,
    },
];

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::schema::{APPROVAL_USER_GUARDS, LEDGER_SCHEMA};

    /// The triggers migration 2 replaces.
    const REPLACED: [&str; 3] = [
        "app_approvals_user_changes_on_narrowing",
        "app_approvals_revoked_final",
        "app_approvals_changes_are_versioned",
    ];

    struct SqlRow(String);
    impl<'r> From<&'r mut hiqlite::Row<'_>> for SqlRow {
        fn from(row: &'r mut hiqlite::Row<'_>) -> Self {
            Self(row.get("sql"))
        }
    }

    async fn trigger_sql(c: &Cluster, name: &str) -> String {
        let rows: Vec<SqlRow> = c
            .client()
            .query_consistent_map(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                vec![Param::from(name.to_string())],
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "{name}");
        rows.into_iter().next().unwrap().0
    }

    /// A database created by migration 1 alone (this branch before the F19
    /// security review) gets the migration 2 guards on its next start.
    #[tokio::test]
    async fn migration_2_replaces_the_guards_of_a_migration_1_database() {
        let dir = std::env::temp_dir().join(format!("ferrogate-raft-migr2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let c = Cluster::start_single_node(dir.to_string_lossy().into_owned())
            .await
            .unwrap();
        assert_eq!(c.applied_migrations().await.unwrap(), vec![1, 2, 3]);

        // Roll the database back to what migration 1 alone left.
        for drop in APPROVAL_USER_GUARDS
            .iter()
            .filter(|s| s.starts_with("DROP"))
        {
            c.client().execute(*drop, Vec::new()).await.unwrap();
        }
        for create in LEDGER_SCHEMA
            .iter()
            .filter(|s| REPLACED.iter().any(|n| s.contains(&format!("EXISTS {n} "))))
        {
            c.client().execute(*create, Vec::new()).await.unwrap();
        }
        c.client()
            .execute(
                "DELETE FROM schema_migrations WHERE version = 2",
                Vec::new(),
            )
            .await
            .unwrap();
        assert_eq!(c.applied_migrations().await.unwrap(), vec![1, 3]);
        for name in REPLACED {
            assert!(!trigger_sql(&c, name).await.contains("pseudonym:v1:"));
        }

        c.run_migrations(1).await.unwrap();
        assert_eq!(c.applied_migrations().await.unwrap(), vec![1, 2, 3]);
        for name in REPLACED {
            let sql = trigger_sql(&c, name).await;
            assert!(sql.contains("pseudonym:v1:"), "{name}: {sql}");
        }
        c.shutdown().await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
