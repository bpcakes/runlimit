use std::{future::Future, time::Duration};

use sqlx::{Acquire, PgPool, Postgres, Transaction, pool::PoolConnection};
use tokio::time::{Instant, timeout, timeout_at};

use crate::{
    ConnectionOutcome, MaintenanceError,
    protocol::{
        CLEANUP_SQL, SET_LOCAL_TIMEOUTS_SQL, is_server_timeout, remaining_server_timeout_settings,
    },
};

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
) -> ConnectionOutcome<Result<u64, MaintenanceError>> {
    match run_cleanup_transaction_inner(connection, maximum_rows, deadline).await {
        Ok(rows) => ConnectionOutcome::Reusable(Ok(rows)),
        Err(outcome) => outcome.map(Err),
    }
}

async fn run_cleanup_transaction_inner(
    connection: &mut PoolConnection<Postgres>,
    maximum_rows: u32,
    deadline: Instant,
) -> Result<u64, ConnectionOutcome<MaintenanceError>> {
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
) -> Result<T, ConnectionOutcome<MaintenanceError>>
where
    F: Future<Output = Result<T, sqlx::Error>>,
{
    timeout_at(deadline, future)
        .await
        .map_err(|_| {
            ConnectionOutcome::MustClose(MaintenanceError::TimedOutBeforeCommit { operation })
        })?
        .map_err(|error| {
            let public = if is_server_timeout(&error) {
                MaintenanceError::TimedOutBeforeCommit { operation }
            } else {
                MaintenanceError::Database(error)
            };
            ConnectionOutcome::Reusable(public)
        })
}

async fn set_maintenance_server_timeouts(
    transaction: &mut Transaction<'_, Postgres>,
    deadline: Instant,
    operation: &'static str,
) -> Result<(), ConnectionOutcome<MaintenanceError>> {
    let (statement_timeout, lock_timeout) = remaining_server_timeout_settings(deadline).ok_or(
        ConnectionOutcome::Reusable(MaintenanceError::TimedOutBeforeCommit { operation }),
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
) -> Result<(), ConnectionOutcome<MaintenanceError>> {
    if Instant::now() >= deadline {
        return Err(ConnectionOutcome::Reusable(
            MaintenanceError::TimedOutBeforeCommit {
                operation: "starting expired-window cleanup commit",
            },
        ));
    }

    timeout_at(deadline, transaction.commit())
        .await
        .map_err(|_| ConnectionOutcome::MustClose(MaintenanceError::CommitTimedOut))?
        .map_err(|error| ConnectionOutcome::Reusable(MaintenanceError::CommitOutcomeUnknown(error)))
}
