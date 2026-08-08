use std::{future::Future, time::Duration};

use sqlx::{Acquire, PgPool, Postgres, Transaction, pool::PoolConnection};
use tokio::time::{Instant, timeout, timeout_at};

use crate::{
    MaintenanceError,
    protocol::{
        CLEANUP_SQL, SET_LOCAL_TIMEOUTS_SQL, is_server_timeout, remaining_server_timeout_settings,
    },
};

#[derive(Debug)]
pub(crate) enum MaintenanceRunError {
    Public(MaintenanceError),
    ClientTimedOutBeforeCommit { operation: &'static str },
    ClientCommitTimedOut,
}

impl MaintenanceRunError {
    pub(crate) const fn client_timeout_won(&self) -> bool {
        matches!(
            self,
            Self::ClientTimedOutBeforeCommit { .. } | Self::ClientCommitTimedOut
        )
    }

    pub(crate) fn into_public(self) -> MaintenanceError {
        match self {
            Self::Public(error) => error,
            Self::ClientTimedOutBeforeCommit { operation } => {
                MaintenanceError::TimedOutBeforeCommit { operation }
            }
            Self::ClientCommitTimedOut => MaintenanceError::CommitTimedOut,
        }
    }
}

pub(crate) async fn acquire_maintenance_connection(
    pool: &PgPool,
    acquire_timeout: Duration,
) -> Result<PoolConnection<Postgres>, MaintenanceError> {
    timeout(acquire_timeout, pool.acquire())
        .await
        .map_err(|_| MaintenanceError::TimedOutBeforeCommit {
            operation: "acquiring database connection",
        })?
        .map_err(MaintenanceError::Database)
}

pub(crate) async fn run_cleanup_transaction(
    connection: &mut PoolConnection<Postgres>,
    maximum_rows: u32,
    deadline: Instant,
) -> Result<u64, MaintenanceRunError> {
    let mut transaction = maintenance_before_commit(
        deadline,
        "beginning cleanup transaction",
        connection.begin(),
    )
    .await?;
    set_maintenance_server_timeouts(
        &mut transaction,
        deadline,
        "configuring cleanup transaction timeouts",
    )
    .await?;
    let result = maintenance_before_commit(
        deadline,
        "deleting expired windows",
        sqlx::query(CLEANUP_SQL)
            .bind(i64::from(maximum_rows))
            .execute(&mut *transaction),
    )
    .await?;
    let rows_affected = result.rows_affected();

    commit_maintenance(deadline, transaction).await?;
    Ok(rows_affected)
}

async fn maintenance_before_commit<T, F>(
    deadline: Instant,
    operation: &'static str,
    future: F,
) -> Result<T, MaintenanceRunError>
where
    F: Future<Output = Result<T, sqlx::Error>>,
{
    timeout_at(deadline, future)
        .await
        .map_err(|_| MaintenanceRunError::ClientTimedOutBeforeCommit { operation })?
        .map_err(|error| {
            let public = if is_server_timeout(&error) {
                MaintenanceError::TimedOutBeforeCommit { operation }
            } else {
                MaintenanceError::Database(error)
            };
            MaintenanceRunError::Public(public)
        })
}

async fn set_maintenance_server_timeouts(
    transaction: &mut Transaction<'_, Postgres>,
    deadline: Instant,
    operation: &'static str,
) -> Result<(), MaintenanceRunError> {
    let (statement_timeout, lock_timeout) = remaining_server_timeout_settings(deadline).ok_or(
        MaintenanceRunError::Public(MaintenanceError::TimedOutBeforeCommit { operation }),
    )?;
    maintenance_before_commit(
        deadline,
        operation,
        sqlx::query(SET_LOCAL_TIMEOUTS_SQL)
            .bind(statement_timeout)
            .bind(lock_timeout)
            .execute(&mut **transaction),
    )
    .await
    .map(|_| ())
}

async fn commit_maintenance(
    deadline: Instant,
    transaction: Transaction<'_, Postgres>,
) -> Result<(), MaintenanceRunError> {
    if Instant::now() >= deadline {
        return Err(MaintenanceRunError::Public(
            MaintenanceError::TimedOutBeforeCommit {
                operation: "starting expired-window cleanup commit",
            },
        ));
    }

    timeout_at(deadline, transaction.commit())
        .await
        .map_err(|_| MaintenanceRunError::ClientCommitTimedOut)?
        .map_err(|error| MaintenanceRunError::Public(MaintenanceError::CommitOutcomeUnknown(error)))
}
