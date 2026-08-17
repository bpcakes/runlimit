use std::{future::Future, time::Duration};

use runlimit_core::{BatchDecision, Check, Decision, Denial, QuotaMode};
use sqlx::{
    Acquire, PgPool, Postgres, Row, Transaction,
    pool::PoolConnection,
    postgres::{PgRow, types::PgInterval},
    types::chrono::{DateTime, Utc},
};
use tokio::time::{Instant, timeout, timeout_at};

use crate::{
    CheckError, ConnectionOutcome,
    protocol::{
        BATCH_ADVISORY_LOCK_SQL, BATCH_CAPACITY_LOCK_SQL, BATCH_PREFLIGHT_SQL, BATCH_ROW_LOCK_SQL,
        BATCH_UPSERT_SQL, CAPACITY_SHARD_COUNT, SET_LOCAL_TIMEOUTS_SQL, advisory_lock_id,
        capacity_shard, is_server_timeout, remaining_server_timeout_settings,
    },
};

pub(crate) fn single_decision_from_batch(batch: BatchDecision) -> Result<Decision, CheckError> {
    batch
        .try_into_single_decision()
        .map_err(|invalid| match invalid {
            BatchDecision::Denied { .. } | BatchDecision::ShadowDenied { .. } => {
                CheckError::ResponseInvariant
            }
            // A future outcome may describe already-committed quota, so keep
            // the public error's consumption classification conservative.
            _ => CheckError::CommittedResponseInvariant,
        })
}

#[derive(Debug)]
enum PendingBatchOutcome {
    Allowed(Vec<PendingAllowance>),
    Denied { index: usize, denial: PendingDenial },
}

#[derive(Debug)]
pub(crate) struct BatchSqlInput {
    policy_ids: Vec<String>,
    scope_ids: Vec<String>,
    fingerprints: Vec<Vec<u8>>,
    subjects: Vec<Vec<u8>>,
    capacity_shards: Vec<i16>,
    pub(crate) lock_input_positions: Vec<i64>,
    advisory_lock_ids: Vec<i64>,
    windows: Vec<PgInterval>,
    costs: Vec<i64>,
    limits: Vec<i64>,
}

impl BatchSqlInput {
    pub(crate) fn from_checks(checks: &[Check<'_>]) -> Self {
        let counter_keys = checks.iter().map(Check::counter_key).collect::<Vec<_>>();
        let mut ordered_indices = (0..checks.len()).collect::<Vec<_>>();
        ordered_indices.sort_unstable_by_key(|index| counter_keys[*index]);

        let mut input = Self {
            policy_ids: Vec::with_capacity(checks.len()),
            scope_ids: Vec::with_capacity(checks.len()),
            fingerprints: Vec::with_capacity(checks.len()),
            subjects: Vec::with_capacity(checks.len()),
            capacity_shards: Vec::with_capacity(checks.len()),
            lock_input_positions: ordered_indices
                .into_iter()
                .map(|index| {
                    i64::try_from(index + 1)
                        .expect("bounded batch input positions fit PostgreSQL BIGINT")
                })
                .collect(),
            advisory_lock_ids: counter_keys.iter().copied().map(advisory_lock_id).collect(),
            windows: Vec::with_capacity(checks.len()),
            costs: Vec::with_capacity(checks.len()),
            limits: Vec::with_capacity(checks.len()),
        };
        input.advisory_lock_ids.sort_unstable();
        input.advisory_lock_ids.dedup();

        for (check, counter_key) in checks.iter().zip(counter_keys) {
            let policy = check.policy();
            input.policy_ids.push(policy.id().as_str().to_owned());
            input.scope_ids.push(policy.scope().as_str().to_owned());
            input
                .fingerprints
                .push(counter_key.fingerprint().as_bytes().to_vec());
            input
                .subjects
                .push(counter_key.subject().as_bytes().to_vec());
            input.capacity_shards.push(capacity_shard(counter_key));
            input.windows.push(
                PgInterval::try_from(policy.window())
                    .expect("core policy windows fit PostgreSQL INTERVAL exactly"),
            );
            input.costs.push(database_integer(check.cost()));
            input.limits.push(database_integer(policy.limit()));
        }
        input
    }
}

#[derive(Debug)]
struct BatchPreflight {
    database_now: DateTime<Utc>,
    response_now: DateTime<Utc>,
    denial: Option<(usize, PendingDenial)>,
}

#[derive(Debug)]
pub(crate) struct PendingAllowance {
    pub(crate) limit: u64,
    pub(crate) remaining: u64,
    pub(crate) reset_from_sample: Duration,
}

impl PendingAllowance {
    pub(crate) fn finish(self, authoritative_elapsed: Duration) -> Decision {
        Decision::allowed(
            self.limit,
            self.remaining,
            self.reset_from_sample.saturating_sub(authoritative_elapsed),
        )
    }
}

#[derive(Debug)]
pub(crate) struct PendingQuotaDenial {
    pub(crate) limit: u64,
    pub(crate) retry_from_sample: Duration,
}

#[derive(Debug)]
pub(crate) enum PendingDenial {
    Quota(PendingQuotaDenial),
    StorageCapacity,
}

impl PendingDenial {
    pub(crate) fn finish(self, authoritative_elapsed: Duration) -> Denial {
        match self {
            Self::Quota(PendingQuotaDenial {
                limit,
                retry_from_sample,
            }) => Denial::QuotaExceeded {
                capacity: limit,
                retry_after: retry_from_sample.saturating_sub(authoritative_elapsed),
            },
            Self::StorageCapacity => Denial::StorageCapacity { retry_after: None },
        }
    }
}

#[derive(Debug)]
pub(crate) enum PendingBatchDenial {
    Enforced {
        index: usize,
        denial: PendingDenial,
    },
    Shadow {
        index: usize,
        denial: PendingQuotaDenial,
    },
}

pub(crate) async fn acquire_check_connection(
    pool: &PgPool,
    acquire_timeout: Duration,
) -> Result<PoolConnection<Postgres>, CheckError> {
    timeout(acquire_timeout, pool.acquire())
        .await
        .map_err(|_| CheckError::TimedOutBeforeCommit {
            operation: "acquiring database connection",
        })?
        .map_err(CheckError::DefinitelyNotConsumed)
}

pub(crate) async fn run_check_transaction(
    connection: &mut PoolConnection<Postgres>,
    input: &BatchSqlInput,
    checks: &[Check<'_>],
    maximum_rows_per_shard: u32,
    deadline: Instant,
) -> ConnectionOutcome<Result<BatchDecision, CheckError>> {
    match run_check_transaction_inner(connection, input, checks, maximum_rows_per_shard, deadline)
        .await
    {
        Ok(outcome) => outcome.map(Ok),
        Err(outcome) => outcome.map(Err),
    }
}

async fn run_check_transaction_inner(
    connection: &mut PoolConnection<Postgres>,
    input: &BatchSqlInput,
    checks: &[Check<'_>],
    maximum_rows_per_shard: u32,
    deadline: Instant,
) -> Result<ConnectionOutcome<BatchDecision>, ConnectionOutcome<CheckError>> {
    let mut transaction =
        check_before_commit(deadline, "beginning transaction", connection.begin()).await?;
    set_check_server_timeouts(
        &mut transaction,
        deadline,
        "configuring transaction timeouts",
    )
    .await?;

    // Advisory locks cover logical keys that do not have rows yet. Their
    // stable numeric IDs are sorted independently from exact storage keys so
    // deliberately colliding batches cannot acquire them in opposite orders.
    // Singles deliberately use this separate statement too: a statement
    // snapshot taken before an advisory-lock wait cannot safely decide whether
    // a capacity slot is needed.
    acquire_advisory_locks(&mut transaction, &input.advisory_lock_ids, deadline).await?;

    // Existing rows may be held by cleanup or a transaction predating the
    // advisory-lock protocol. Wait for all row locks before sampling database
    // time or deciding which keys need capacity.
    acquire_existing_row_locks(&mut transaction, input, deadline).await?;

    let (pending, authoritative_elapsed) = execute_batch(
        &mut transaction,
        input,
        checks,
        maximum_rows_per_shard,
        deadline,
    )
    .await?;

    match pending {
        PendingBatchOutcome::Denied { index, denial } => {
            let denial = match (denial, checks[0].policy().quota_mode()) {
                (PendingDenial::Quota(denial), QuotaMode::Shadow) => {
                    PendingBatchDenial::Shadow { index, denial }
                }
                (denial, _) => PendingBatchDenial::Enforced { index, denial },
            };
            Ok(finish_denied_transaction(
                deadline,
                denial,
                authoritative_elapsed,
                transaction.rollback(),
            )
            .await)
        }
        PendingBatchOutcome::Allowed(allowances) => {
            commit_check(deadline, transaction).await?;
            Ok(ConnectionOutcome::Reusable(BatchDecision::Allowed(
                allowances
                    .into_iter()
                    .map(|allowance| allowance.finish(authoritative_elapsed))
                    .collect(),
            )))
        }
    }
}

pub(crate) async fn finish_denied_transaction<F>(
    deadline: Instant,
    pending: PendingBatchDenial,
    authoritative_elapsed: Duration,
    rollback: F,
) -> ConnectionOutcome<BatchDecision>
where
    F: Future<Output = Result<(), sqlx::Error>>,
{
    let decision = match pending {
        PendingBatchDenial::Enforced { index, denial } => BatchDecision::Denied {
            index,
            denial: denial.finish(authoritative_elapsed),
        },
        PendingBatchDenial::Shadow { index, denial } => BatchDecision::ShadowDenied {
            index,
            denial: Denial::QuotaExceeded {
                capacity: denial.limit,
                retry_after: denial
                    .retry_from_sample
                    .saturating_sub(authoritative_elapsed),
            },
        },
    };
    if denied_rollback_succeeded(deadline, rollback).await {
        ConnectionOutcome::Reusable(decision)
    } else {
        ConnectionOutcome::MustClose(decision)
    }
}

async fn denied_rollback_succeeded<F>(deadline: Instant, rollback: F) -> bool
where
    F: Future<Output = Result<(), sqlx::Error>>,
{
    matches!(timeout_at(deadline, rollback).await, Ok(Ok(())))
}

async fn check_before_commit<T, F>(
    deadline: Instant,
    operation: &'static str,
    future: F,
) -> Result<T, ConnectionOutcome<CheckError>>
where
    F: Future<Output = Result<T, sqlx::Error>>,
{
    timeout_at(deadline, future)
        .await
        .map_err(|_| ConnectionOutcome::MustClose(CheckError::TimedOutBeforeCommit { operation }))?
        .map_err(|error| ConnectionOutcome::Reusable(map_check_database_error(error, operation)))
}

async fn commit_check(
    deadline: Instant,
    transaction: Transaction<'_, Postgres>,
) -> Result<(), ConnectionOutcome<CheckError>> {
    if Instant::now() >= deadline {
        return Err(ConnectionOutcome::Reusable(
            CheckError::TimedOutBeforeCommit {
                operation: "starting commit",
            },
        ));
    }

    timeout_at(deadline, transaction.commit())
        .await
        .map_err(|_| ConnectionOutcome::MustClose(CheckError::CommitTimedOut))?
        .map_err(|error| ConnectionOutcome::Reusable(CheckError::CommitOutcomeUnknown(error)))
}

fn map_check_database_error(error: sqlx::Error, operation: &'static str) -> CheckError {
    if is_server_timeout(&error) {
        CheckError::TimedOutBeforeCommit { operation }
    } else {
        CheckError::DefinitelyNotConsumed(error)
    }
}

const fn reusable_check_error(error: CheckError) -> ConnectionOutcome<CheckError> {
    ConnectionOutcome::Reusable(error)
}

async fn set_check_server_timeouts(
    transaction: &mut Transaction<'_, Postgres>,
    deadline: Instant,
    operation: &'static str,
) -> Result<(), ConnectionOutcome<CheckError>> {
    let (statement_timeout, lock_timeout) = remaining_server_timeout_settings(deadline).ok_or(
        ConnectionOutcome::Reusable(CheckError::TimedOutBeforeCommit { operation }),
    )?;
    check_before_commit(
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

async fn acquire_advisory_locks(
    transaction: &mut Transaction<'_, Postgres>,
    advisory_lock_ids: &[i64],
    deadline: Instant,
) -> Result<(), ConnectionOutcome<CheckError>> {
    check_before_commit(deadline, "acquiring logical key lock", async {
        sqlx::query(BATCH_ADVISORY_LOCK_SQL)
            .bind(advisory_lock_ids)
            .execute(&mut **transaction)
            .await
            .map(|_| ())
    })
    .await
}

async fn acquire_existing_row_locks(
    transaction: &mut Transaction<'_, Postgres>,
    input: &BatchSqlInput,
    deadline: Instant,
) -> Result<(), ConnectionOutcome<CheckError>> {
    check_before_commit(deadline, "acquiring counter row lock", async {
        sqlx::query(BATCH_ROW_LOCK_SQL)
            .bind(input.fingerprints.as_slice())
            .bind(input.subjects.as_slice())
            .bind(input.lock_input_positions.as_slice())
            .execute(&mut **transaction)
            .await
            .map(|_| ())
    })
    .await
}

async fn first_capacity_denial(
    transaction: &mut Transaction<'_, Postgres>,
    input: &BatchSqlInput,
    maximum_rows_per_shard: u32,
    deadline: Instant,
) -> Result<Option<(usize, PendingDenial)>, ConnectionOutcome<CheckError>> {
    let rows = check_before_commit(
        deadline,
        "acquiring capacity shard lock",
        sqlx::query(BATCH_CAPACITY_LOCK_SQL)
            .bind(input.fingerprints.as_slice())
            .bind(input.subjects.as_slice())
            .bind(input.capacity_shards.as_slice())
            .fetch_all(&mut **transaction),
    )
    .await?;

    let mut pending_insertions = [0_u32; CAPACITY_SHARD_COUNT];
    for row in rows {
        let input_index: i64 = row
            .try_get("input_index")
            .map_err(CheckError::DefinitelyNotConsumed)
            .map_err(reusable_check_error)?;
        let input_index = usize::try_from(input_index)
            .map_err(|_| {
                CheckError::StorageInvariant("capacity preflight returned an invalid input index")
            })
            .map_err(reusable_check_error)?;
        let expected_shard = input
            .capacity_shards
            .get(input_index)
            .ok_or(CheckError::StorageInvariant(
                "capacity preflight returned an out-of-range input index",
            ))
            .map_err(reusable_check_error)?;
        let returned_shard: i16 = row
            .try_get("capacity_shard")
            .map_err(CheckError::DefinitelyNotConsumed)
            .map_err(reusable_check_error)?;
        if &returned_shard != expected_shard {
            return Err(reusable_check_error(CheckError::StorageInvariant(
                "capacity preflight returned a mismatched shard",
            )));
        }
        let shard_index = usize::try_from(returned_shard)
            .map_err(|_| {
                CheckError::StorageInvariant("capacity preflight returned a negative shard")
            })
            .map_err(reusable_check_error)?;
        let pending = pending_insertions
            .get_mut(shard_index)
            .ok_or(CheckError::StorageInvariant(
                "capacity preflight returned an out-of-range shard",
            ))
            .map_err(reusable_check_error)?;
        let stored_rows: Option<i64> = row
            .try_get("row_count")
            .map_err(CheckError::DefinitelyNotConsumed)
            .map_err(reusable_check_error)?;
        let stored_rows = stored_rows
            .ok_or(CheckError::StorageInvariant(
                "capacity shard ledger row is missing",
            ))
            .map_err(reusable_check_error)?;
        let stored_rows = u64::try_from(stored_rows)
            .map_err(|_| CheckError::StorageInvariant("capacity shard ledger count is negative"))
            .map_err(reusable_check_error)?;
        let projected_rows = stored_rows
            .checked_add(u64::from(*pending))
            .and_then(|rows| rows.checked_add(1))
            .ok_or(CheckError::StorageInvariant(
                "capacity shard ledger count overflowed",
            ))
            .map_err(reusable_check_error)?;
        if projected_rows > u64::from(maximum_rows_per_shard) {
            return Ok(Some((input_index, PendingDenial::StorageCapacity)));
        }
        *pending += 1;
    }

    Ok(None)
}
fn authoritative_elapsed(start: DateTime<Utc>, end: DateTime<Utc>) -> Duration {
    end.signed_duration_since(start)
        .to_std()
        .unwrap_or(Duration::ZERO)
}

async fn execute_batch(
    transaction: &mut Transaction<'_, Postgres>,
    input: &BatchSqlInput,
    checks: &[Check<'_>],
    maximum_rows_per_shard: u32,
    deadline: Instant,
) -> Result<(PendingBatchOutcome, Duration), ConnectionOutcome<CheckError>> {
    let capacity_denial =
        first_capacity_denial(transaction, input, maximum_rows_per_shard, deadline).await?;
    let preflight = preflight_batch(transaction, input, checks, deadline).await?;
    let first_denial = match (capacity_denial, preflight.denial) {
        (Some(capacity), Some(quota)) => Some(if capacity.0 < quota.0 {
            capacity
        } else {
            quota
        }),
        (Some(capacity), None) => Some(capacity),
        (None, Some(quota)) => Some(quota),
        (None, None) => None,
    };
    if let Some((index, denial)) = first_denial {
        return Ok((
            PendingBatchOutcome::Denied { index, denial },
            authoritative_elapsed(preflight.database_now, preflight.response_now),
        ));
    }
    let (allowances, response_now) =
        upsert_batch(transaction, input, checks, preflight.database_now, deadline).await?;
    Ok((
        PendingBatchOutcome::Allowed(allowances),
        authoritative_elapsed(preflight.database_now, response_now),
    ))
}

async fn preflight_batch(
    transaction: &mut Transaction<'_, Postgres>,
    input: &BatchSqlInput,
    checks: &[Check<'_>],
    deadline: Instant,
) -> Result<BatchPreflight, ConnectionOutcome<CheckError>> {
    let preflight_row = check_before_commit(
        deadline,
        "preflighting counter batch",
        sqlx::query(BATCH_PREFLIGHT_SQL)
            .bind(input.fingerprints.as_slice())
            .bind(input.subjects.as_slice())
            .bind(input.costs.as_slice())
            .bind(input.limits.as_slice())
            .fetch_one(&mut **transaction),
    )
    .await?;

    let database_now: DateTime<Utc> = preflight_row
        .try_get("database_now")
        .map_err(CheckError::DefinitelyNotConsumed)
        .map_err(reusable_check_error)?;
    let preflight_response_now: DateTime<Utc> = preflight_row
        .try_get("response_now")
        .map_err(CheckError::DefinitelyNotConsumed)
        .map_err(reusable_check_error)?;
    let denied_index: Option<i64> = preflight_row
        .try_get("input_index")
        .map_err(CheckError::DefinitelyNotConsumed)
        .map_err(reusable_check_error)?;
    let denied_expiry: Option<DateTime<Utc>> = preflight_row
        .try_get("window_expires_at")
        .map_err(CheckError::DefinitelyNotConsumed)
        .map_err(reusable_check_error)?;

    let denial = match (denied_index, denied_expiry) {
        (Some(input_index), Some(expires_at)) => {
            let input_index = usize::try_from(input_index)
                .map_err(|_| {
                    CheckError::StorageInvariant("batch preflight returned an invalid input index")
                })
                .map_err(reusable_check_error)?;
            let check = checks
                .get(input_index)
                .ok_or(CheckError::StorageInvariant(
                    "batch preflight returned an out-of-range input index",
                ))
                .map_err(reusable_check_error)?;
            Some((
                input_index,
                PendingDenial::Quota(PendingQuotaDenial {
                    limit: check.policy().limit(),
                    retry_from_sample: duration_until(expires_at, database_now)
                        .map_err(reusable_check_error)?,
                }),
            ))
        }
        (None, None) => None,
        _ => {
            return Err(reusable_check_error(CheckError::StorageInvariant(
                "batch preflight returned an incomplete denial",
            )));
        }
    };

    Ok(BatchPreflight {
        database_now,
        response_now: preflight_response_now,
        denial,
    })
}

async fn upsert_batch(
    transaction: &mut Transaction<'_, Postgres>,
    input: &BatchSqlInput,
    checks: &[Check<'_>],
    database_now: DateTime<Utc>,
    deadline: Instant,
) -> Result<(Vec<PendingAllowance>, DateTime<Utc>), ConnectionOutcome<CheckError>> {
    let rows = check_before_commit(
        deadline,
        "updating counter batch",
        sqlx::query(BATCH_UPSERT_SQL)
            .bind(input.policy_ids.as_slice())
            .bind(input.scope_ids.as_slice())
            .bind(input.fingerprints.as_slice())
            .bind(input.subjects.as_slice())
            .bind(input.windows.as_slice())
            .bind(input.costs.as_slice())
            .bind(input.limits.as_slice())
            .bind(database_now)
            .fetch_all(&mut **transaction),
    )
    .await?;

    if rows.is_empty() {
        return Err(reusable_check_error(CheckError::StorageInvariant(
            "allowed batch update returned no decisions",
        )));
    }
    let response_now: DateTime<Utc> = rows[0]
        .try_get("response_now")
        .map_err(CheckError::DefinitelyNotConsumed)
        .map_err(reusable_check_error)?;

    let mut allowances = Vec::with_capacity(checks.len());
    for (output_position, row) in rows.iter().enumerate() {
        let input_index: i64 = row
            .try_get("input_index")
            .map_err(CheckError::DefinitelyNotConsumed)
            .map_err(reusable_check_error)?;
        let input_index = usize::try_from(input_index)
            .map_err(|_| {
                CheckError::StorageInvariant("batch evaluation returned an invalid input index")
            })
            .map_err(reusable_check_error)?;
        let Some(check) = checks.get(input_index) else {
            return Err(reusable_check_error(CheckError::StorageInvariant(
                "batch evaluation returned an out-of-range input index",
            )));
        };
        let expires_at = read_expiry(row).map_err(reusable_check_error)?;
        let remaining_from_sample =
            duration_until(expires_at, database_now).map_err(reusable_check_error)?;

        if input_index != output_position {
            return Err(reusable_check_error(CheckError::StorageInvariant(
                "allowed batch decisions were not returned in caller order",
            )));
        }
        let used = read_used(row).map_err(reusable_check_error)?;
        let remaining = check
            .policy()
            .limit()
            .checked_sub(used)
            .ok_or(CheckError::StorageInvariant(
                "stored usage exceeds its policy limit",
            ))
            .map_err(reusable_check_error)?;
        allowances.push(PendingAllowance {
            limit: check.policy().limit(),
            remaining,
            reset_from_sample: remaining_from_sample,
        });
    }

    if allowances.len() != checks.len() {
        return Err(reusable_check_error(CheckError::StorageInvariant(
            "allowed batch returned an incomplete decision set",
        )));
    }
    Ok((allowances, response_now))
}

pub(crate) fn database_integer(value: u64) -> i64 {
    i64::try_from(value)
        .expect("core policy and check validation keep database integers within i64")
}

fn read_used(row: &PgRow) -> Result<u64, CheckError> {
    let used: i64 = row
        .try_get("used")
        .map_err(CheckError::DefinitelyNotConsumed)?;
    u64::try_from(used).map_err(|_| CheckError::StorageInvariant("stored usage is negative"))
}

fn read_expiry(row: &PgRow) -> Result<DateTime<Utc>, CheckError> {
    row.try_get("window_expires_at")
        .map_err(CheckError::DefinitelyNotConsumed)
}

fn duration_until(
    expires_at: DateTime<Utc>,
    database_now: DateTime<Utc>,
) -> Result<Duration, CheckError> {
    expires_at
        .signed_duration_since(database_now)
        .to_std()
        .map_err(|_| CheckError::StorageInvariant("stored window is already expired"))
}
