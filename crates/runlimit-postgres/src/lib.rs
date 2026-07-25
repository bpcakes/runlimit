//! Replica-safe `PostgreSQL` storage for Runlimit fixed-window policies.
//!
//! [`PostgresLimiter`] implements the same anchored fixed-window model as the
//! in-memory backend: the first admitted check starts a window, and subsequent
//! checks share that window until it expires. `PostgreSQL`'s clock is the sole
//! time authority, so callers on different hosts do not need synchronized
//! clocks. Atomic batches use set-based lock, preflight, and update phases, so
//! their number of SQL phases does not grow with the batch size. Single checks
//! combine lock acquisition, time sampling, evaluation, and mutation into one
//! admission statement inside the transaction.
//!
//! # Installation
//!
//! Call [`PostgresLimiter::migrate`] before serving traffic. It can share
//! `SQLx`'s `_sqlx_migrations` table with application migrations only when every
//! participating [`Migrator`] configures
//! [`Migrator::set_ignore_missing`] to `true`.
//! A strict application migrator will reject Runlimit's migration versions as
//! unknown. The first migration creates `runlimit_fixed_windows` in the
//! connection's default schema.
//!
//! [`MIGRATOR`] is the raw bundled migrator with `SQLx`'s strict defaults. It is
//! intended for an exclusively managed migration history and connection. It
//! does not add [`PostgresLimiter::migrate`]'s protection against returning a
//! possibly session-locked connection to a pool after an error or cancellation.
//! Applications that retain a strict host migrator should vendor the bundled
//! Runlimit SQL as an application-owned migration instead of invoking either
//! Runlimit migrator against the shared history.
//!
//! # Failure semantics
//!
//! Pre-commit database failures and pre-commit timeouts mean the transaction
//! did not commit. A
//! [`CheckError::CommitOutcomeUnknown`] or [`CheckError::CommitTimedOut`] error
//! means `PostgreSQL` may have committed even though the client did not receive
//! confirmation. [`CheckError::CommittedResponseInvariant`] means the commit
//! was confirmed but its response was unusable. Fail closed in all three cases,
//! and do not blindly retry a check that may already have consumed quota.
//! Once the database has produced a denial, an explicit rollback failure or
//! deadline cannot replace that valid decision; the connection is discarded so
//! closing it rolls back the non-mutating denied transaction.
//! Dropping a check or cleanup future prevents the backend from reporting its
//! outcome; if cancellation races with commit, callers must likewise treat the
//! outcome as unknown. Prefer this backend's configured deadline to a shorter
//! outer timeout.
//!
//! The advisory-lock `v1` domain and derivation are a cross-replica protocol.
//! They must not be changed in place: replicas from a rolling deployment must
//! calculate identical lock IDs for the same persistent counter. `PostgreSQL`'s
//! advisory-lock namespace is shared by every application in the same database.
//! An unrelated or deliberately held matching `bigint` lock therefore blocks
//! the affected Runlimit key until the operation deadline; use a trusted
//! database boundary and restrict advisory-lock privileges for unrelated roles.
//!
//! # Integration tests
//!
//! The database tests are opt-in:
//!
//! ```text
//! RUNLIMIT_POSTGRES_TEST_DATABASE_URL=postgresql:///runlimit_test \
//! cargo test -p runlimit-postgres --test postgres -- --ignored
//! ```

use std::{future::Future, time::Duration};

use runlimit_core::{
    BatchDecision, BatchError, Check, CounterKey, Decision, Denial, validate_batch,
};
use sha2::{Digest, Sha256};
use sqlx::{
    Acquire, PgPool, Postgres, Row, Transaction,
    migrate::{MigrateError, Migrator},
    pool::PoolConnection,
    postgres::{PgRow, types::PgInterval},
    types::chrono::{DateTime, Utc},
};
use thiserror::Error;
use tokio::time::{Instant, timeout_at};

/// Raw bundled migrations required by [`PostgresLimiter`].
///
/// This value retains `SQLx`'s strict missing-version behavior and is suitable
/// only for an exclusively managed migration history and connection. For a
/// pooled application that shares `_sqlx_migrations`, prefer
/// [`PostgresLimiter::migrate`] and configure every other participating
/// [`Migrator`] to set [`Migrator::set_ignore_missing`] to `true`.
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

const ADVISORY_LOCK_DOMAIN: &[u8] = b"runlimit/postgres-advisory-lock/v1\0";
const SERVER_TIMEOUT_GRACE: Duration = Duration::from_millis(25);

const SET_LOCAL_TIMEOUTS_SQL: &str = r"
SELECT
    set_config('statement_timeout', $1, true),
    set_config('lock_timeout', $2, true)
";

const BATCH_ADVISORY_LOCK_SQL: &str = r"
WITH RECURSIVE acquired(position, locked) AS (
    SELECT 1, pg_advisory_xact_lock($1[1])
    WHERE cardinality($1::BIGINT[]) > 0

    UNION ALL

    SELECT
        acquired.position + 1,
        pg_advisory_xact_lock($1[acquired.position + 1])
    FROM acquired
    WHERE acquired.position < cardinality($1::BIGINT[])
)
SELECT count(*)
FROM acquired
";

const BATCH_ROW_LOCK_SQL: &str = r"
WITH input_keys AS (
    SELECT *
    FROM unnest(
        $1::BYTEA[],
        $2::BYTEA[]
    ) WITH ORDINALITY AS keys(
        config_fingerprint,
        subject_key,
        input_position
    )
),
lock_order AS (
    SELECT *
    FROM unnest($3::BIGINT[])
        WITH ORDINALITY AS positions(input_position, lock_position)
),
ordered_keys AS (
    SELECT
        input_keys.config_fingerprint,
        input_keys.subject_key,
        lock_order.lock_position
    FROM input_keys
    INNER JOIN lock_order
        ON lock_order.input_position = input_keys.input_position
    ORDER BY lock_order.lock_position
)
SELECT 1
FROM ordered_keys
INNER JOIN runlimit_fixed_windows AS windows
    ON windows.config_fingerprint = ordered_keys.config_fingerprint
    AND windows.subject_key = ordered_keys.subject_key
ORDER BY ordered_keys.lock_position
FOR UPDATE OF windows
";

const BATCH_PREFLIGHT_SQL: &str = r"
WITH input AS (
    SELECT *
    FROM unnest(
        $1::BYTEA[],
        $2::BYTEA[],
        $3::BIGINT[],
        $4::BIGINT[]
    ) WITH ORDINALITY AS checks(
        config_fingerprint,
        subject_key,
        cost,
        quota_limit,
        input_position
    )
),
sample AS (
    SELECT clock_timestamp() AS database_now
),
first_denial AS (
    SELECT
        input.input_position - 1 AS input_index,
        windows.window_expires_at
    FROM input
    CROSS JOIN sample
    INNER JOIN runlimit_fixed_windows AS windows
        ON windows.config_fingerprint = input.config_fingerprint
        AND windows.subject_key = input.subject_key
    WHERE
        windows.window_expires_at > sample.database_now
        AND windows.used > input.quota_limit - input.cost
    ORDER BY input.input_position
    LIMIT 1
)
SELECT
    sample.database_now,
    clock_timestamp() AS response_now,
    first_denial.input_index,
    first_denial.window_expires_at
FROM sample
LEFT JOIN first_denial ON TRUE
";

const BATCH_UPSERT_SQL: &str = r"
WITH input AS (
    SELECT *
    FROM unnest(
        $1::TEXT[],
        $2::TEXT[],
        $3::BYTEA[],
        $4::BYTEA[],
        $5::INTERVAL[],
        $6::BIGINT[],
        $7::BIGINT[]
    ) WITH ORDINALITY AS checks(
        policy_id,
        scope_id,
        config_fingerprint,
        subject_key,
        window_size,
        cost,
        quota_limit,
        input_position
    )
),
upserted AS (
    INSERT INTO runlimit_fixed_windows (
        policy_id,
        scope_id,
        config_fingerprint,
        subject_key,
        window_started_at,
        window_expires_at,
        used
    )
    SELECT
        policy_id,
        scope_id,
        config_fingerprint,
        subject_key,
        $8,
        $8 + window_size,
        cost
    FROM input
    ON CONFLICT (config_fingerprint, subject_key)
    DO UPDATE SET
        policy_id = EXCLUDED.policy_id,
        scope_id = EXCLUDED.scope_id,
        window_started_at = CASE
            WHEN runlimit_fixed_windows.window_expires_at <= $8 THEN $8
            ELSE runlimit_fixed_windows.window_started_at
        END,
        window_expires_at = CASE
            WHEN runlimit_fixed_windows.window_expires_at <= $8
                THEN $8 + (EXCLUDED.window_expires_at - EXCLUDED.window_started_at)
            ELSE runlimit_fixed_windows.window_expires_at
        END,
        used = CASE
            WHEN runlimit_fixed_windows.window_expires_at <= $8 THEN EXCLUDED.used
            ELSE runlimit_fixed_windows.used + EXCLUDED.used
        END
    WHERE
        runlimit_fixed_windows.window_expires_at <= $8
        OR runlimit_fixed_windows.used
            <= (
                SELECT quota_limit - cost
                FROM input
                WHERE
                    input.config_fingerprint = EXCLUDED.config_fingerprint
                    AND input.subject_key = EXCLUDED.subject_key
            )
    RETURNING
        config_fingerprint,
        subject_key,
        used,
        window_expires_at
),
response AS (
    SELECT clock_timestamp() AS response_now
    FROM upserted
    HAVING count(*) >= 0
)
SELECT
    input.input_position - 1 AS input_index,
    upserted.used,
    upserted.window_expires_at,
    response.response_now
FROM input
INNER JOIN upserted
    ON upserted.config_fingerprint = input.config_fingerprint
    AND upserted.subject_key = input.subject_key
CROSS JOIN response
ORDER BY input.input_position
";

// These materialized CTEs form execution barriers, not just an optimizer hint:
// `count(acquired)` consumes the volatile advisory-lock result, the correlated
// lateral row lookup cannot run before that count exists, and the second count
// exhausts the locking lookup before `clock_timestamp()` can be evaluated.
// Consequently the authoritative sample is taken only after both lock phases.
const SINGLE_CHECK_SQL: &str = r"
WITH advisory_lock AS MATERIALIZED (
    SELECT
        $1::BIGINT AS lock_id,
        pg_advisory_xact_lock($1) AS acquired
),
advisory_lock_barrier AS MATERIALIZED (
    SELECT
        lock_id,
        count(acquired) AS acquired_count
    FROM advisory_lock
    GROUP BY lock_id
),
locked_window AS MATERIALIZED (
    SELECT
        windows.window_expires_at,
        windows.used
    FROM advisory_lock_barrier
    CROSS JOIN LATERAL (
        SELECT
            candidate.window_expires_at,
            candidate.used
        FROM runlimit_fixed_windows AS candidate
        WHERE
            candidate.config_fingerprint = $4
            AND candidate.subject_key = $5
            AND advisory_lock_barrier.acquired_count = 1
        FOR UPDATE OF candidate
    ) AS windows
),
row_lock_barrier AS MATERIALIZED (
    SELECT count(*) AS locked_count
    FROM locked_window
),
sample AS MATERIALIZED (
    SELECT clock_timestamp() AS database_now
    FROM row_lock_barrier
),
evaluation AS MATERIALIZED (
    SELECT
        sample.database_now,
        locked_window.window_expires_at,
        COALESCE(
            locked_window.window_expires_at > sample.database_now
                AND locked_window.used > $8 - $7,
            FALSE
        ) AS denied
    FROM sample
    LEFT JOIN locked_window ON TRUE
),
upserted AS (
    INSERT INTO runlimit_fixed_windows (
        policy_id,
        scope_id,
        config_fingerprint,
        subject_key,
        window_started_at,
        window_expires_at,
        used
    )
    SELECT
        $2,
        $3,
        $4,
        $5,
        evaluation.database_now,
        evaluation.database_now + $6,
        $7
    FROM evaluation
    WHERE NOT evaluation.denied
    ON CONFLICT (config_fingerprint, subject_key)
    DO UPDATE SET
        policy_id = EXCLUDED.policy_id,
        scope_id = EXCLUDED.scope_id,
        window_started_at = CASE
            WHEN runlimit_fixed_windows.window_expires_at <= EXCLUDED.window_started_at
                THEN EXCLUDED.window_started_at
            ELSE runlimit_fixed_windows.window_started_at
        END,
        window_expires_at = CASE
            WHEN runlimit_fixed_windows.window_expires_at <= EXCLUDED.window_started_at
                THEN EXCLUDED.window_expires_at
            ELSE runlimit_fixed_windows.window_expires_at
        END,
        used = CASE
            WHEN runlimit_fixed_windows.window_expires_at <= EXCLUDED.window_started_at
                THEN EXCLUDED.used
            ELSE runlimit_fixed_windows.used + EXCLUDED.used
        END
    WHERE
        runlimit_fixed_windows.window_expires_at <= EXCLUDED.window_started_at
        OR runlimit_fixed_windows.used <= $8 - $7
    RETURNING
        used,
        window_expires_at
)
SELECT
    evaluation.database_now,
    clock_timestamp() AS response_now,
    evaluation.denied,
    COALESCE(
        upserted.window_expires_at,
        evaluation.window_expires_at
    ) AS window_expires_at,
    upserted.used
FROM evaluation
LEFT JOIN upserted ON TRUE
";

const CLEANUP_SQL: &str = include_str!("cleanup_expired.sql");

/// Runtime bounds for `PostgreSQL` admission work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgresConfig {
    max_batch_size: usize,
    operation_timeout: Duration,
}

impl PostgresConfig {
    /// Default maximum number of checks in one atomic batch.
    pub const DEFAULT_MAX_BATCH_SIZE: usize = 32;

    /// Default total deadline for one check or cleanup operation.
    pub const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(3);

    /// Largest accepted online-operation deadline.
    pub const MAXIMUM_OPERATION_TIMEOUT: Duration = Duration::from_secs(60);

    /// Returns the conservative defaults suitable for an online admission
    /// path.
    pub const fn new() -> Self {
        Self {
            max_batch_size: Self::DEFAULT_MAX_BATCH_SIZE,
            operation_timeout: Self::DEFAULT_OPERATION_TIMEOUT,
        }
    }

    /// Sets the maximum number of checks that may retain locks in one batch.
    ///
    /// # Errors
    ///
    /// Returns an error if `maximum` is zero.
    pub fn with_max_batch_size(mut self, maximum: usize) -> Result<Self, PostgresConfigError> {
        if maximum == 0 {
            return Err(PostgresConfigError::ZeroBatchSize);
        }
        self.max_batch_size = maximum;
        Ok(self)
    }

    /// Sets the total deadline for a check, batch, or cleanup statement.
    ///
    /// The deadline covers pool acquisition, lock waits, statements, rollback,
    /// and commit. It is intentionally not applied to schema migrations.
    ///
    /// # Errors
    ///
    /// Returns an error if `timeout` is zero or exceeds 60 seconds.
    pub fn with_operation_timeout(
        mut self,
        timeout: Duration,
    ) -> Result<Self, PostgresConfigError> {
        if timeout.is_zero() {
            return Err(PostgresConfigError::ZeroOperationTimeout);
        }
        if timeout > Self::MAXIMUM_OPERATION_TIMEOUT {
            return Err(PostgresConfigError::OperationTimeoutTooLong {
                actual: timeout,
                maximum: Self::MAXIMUM_OPERATION_TIMEOUT,
            });
        }
        self.operation_timeout = timeout;
        Ok(self)
    }

    /// Returns the maximum accepted batch length.
    pub const fn max_batch_size(&self) -> usize {
        self.max_batch_size
    }

    /// Returns the total deadline applied to an operation.
    pub const fn operation_timeout(self) -> Duration {
        self.operation_timeout
    }
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Invalid `PostgreSQL` backend configuration.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PostgresConfigError {
    /// A zero maximum batch size would reject every nonempty batch.
    #[error("max_batch_size must be greater than zero")]
    ZeroBatchSize,
    /// A zero deadline cannot permit database work.
    #[error("PostgreSQL rate-limit operation timeout must be greater than zero")]
    ZeroOperationTimeout,
    /// An admission deadline longer than one minute is not operationally
    /// bounded enough for this backend.
    #[error("PostgreSQL rate-limit operation timeout {actual:?} exceeds maximum {maximum:?}")]
    OperationTimeoutTooLong {
        /// Supplied timeout.
        actual: Duration,
        /// Largest accepted timeout.
        maximum: Duration,
    },
}

/// A replica-safe rate limiter backed by a `PostgreSQL` pool.
///
/// Cloning this value is cheap because [`PgPool`] is internally reference
/// counted.
#[derive(Clone, Debug)]
pub struct PostgresLimiter {
    pool: PgPool,
    config: PostgresConfig,
}

impl PostgresLimiter {
    /// Creates a limiter using `pool`.
    ///
    /// Call [`Self::migrate`] during application startup before admitting
    /// requests.
    pub const fn new(pool: PgPool) -> Self {
        Self {
            pool,
            config: PostgresConfig::new(),
        }
    }

    /// Creates a limiter using an explicit runtime configuration.
    pub const fn with_config(pool: PgPool, config: PostgresConfig) -> Self {
        Self { pool, config }
    }

    /// Returns the underlying connection pool.
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Returns the backend runtime configuration.
    pub const fn config(&self) -> PostgresConfig {
        self.config
    }

    /// Applies the bundled Runlimit database migrations.
    ///
    /// Unrelated successful versions in `_sqlx_migrations` are ignored, which
    /// permits a shared migration history only when every other participating
    /// `SQLx` migrator also sets [`Migrator::set_ignore_missing`] to `true`.
    /// Known Runlimit versions still receive `SQLx`'s checksum validation.
    /// Applications that keep a strict host migrator should instead vendor the
    /// bundled SQL into their application-owned migration stream.
    ///
    /// Migration locking is session scoped. An acquired connection is returned
    /// to the pool only after a successful run and unlock; an error or
    /// cancellation closes it instead.
    ///
    /// # Errors
    ///
    /// Returns an error if migration metadata cannot be read or `PostgreSQL`
    /// rejects a migration.
    pub async fn migrate(&self) -> Result<(), MigrateError> {
        let connection = self.pool.acquire().await?;
        let mut guarded_connection = ConnectionCancellationGuard::new(connection);
        let mut migrator = sqlx::migrate!("./migrations");
        migrator.set_ignore_missing(true);

        let result = migrator
            .run_direct(&mut **guarded_connection.connection())
            .await;
        if result.is_ok() {
            guarded_connection.disarm();
        }
        result
    }

    /// Checks and, when allowed, consumes one fixed-window quota.
    ///
    /// A denied decision does not change the stored counter.
    ///
    /// # Errors
    ///
    /// Returns [`CheckError::DefinitelyNotConsumed`] for failures before a
    /// successful commit and [`CheckError::CommitOutcomeUnknown`] when commit
    /// confirmation is unavailable. An internal single-response invariant
    /// failure reports whether the batch was rolled back or committed.
    pub async fn check(&self, check: &Check<'_>) -> Result<Decision, CheckError> {
        single_decision_from_batch(self.check_all(std::slice::from_ref(check)).await?)
    }

    /// Atomically checks and consumes every quota in `checks`.
    ///
    /// Rows are acquired in a deterministic storage-key order to avoid
    /// deadlocks between overlapping batches. Returned allowed decisions retain
    /// the caller's input order. Repeated occurrences of the same storage key
    /// are rejected before a connection is acquired because their independent
    /// decision metadata would be ambiguous.
    ///
    /// If any check is denied, the backend attempts an explicit rollback and
    /// the returned denial index is the earliest denied item in caller order.
    /// A rollback error or deadline does not replace the denial because no
    /// counter was changed; instead, the connection is discarded so socket
    /// closure rolls the transaction back. Passing an empty slice succeeds
    /// without acquiring a database connection.
    ///
    /// # Errors
    ///
    /// Database failures before commit are
    /// [`CheckError::DefinitelyNotConsumed`]. Any commit error is
    /// conservatively classified as [`CheckError::CommitOutcomeUnknown`].
    pub async fn check_all(&self, checks: &[Check<'_>]) -> Result<BatchDecision, CheckError> {
        validate_batch(checks, self.config.max_batch_size())?;
        if checks.is_empty() {
            return Ok(BatchDecision::Allowed(Vec::new()));
        }

        // Materialize every SQL array and both lock orders before reserving a
        // pool slot. Every database phase then consumes the exact same key
        // arrays, preventing identity drift between locking and mutation.
        let input = BatchSqlInput::from_checks(checks);
        let deadline = Instant::now() + self.config.operation_timeout();
        let connection = acquire_check_connection(&self.pool, deadline).await?;
        let mut guarded_connection = ConnectionCancellationGuard::new(connection);
        let result =
            run_check_transaction(guarded_connection.connection(), &input, checks, deadline).await;
        match result {
            Ok(outcome) => {
                if outcome.connection_reusable {
                    guarded_connection.disarm();
                }
                Ok(outcome.decision)
            }
            Err(error) => {
                if !error.client_timeout_won() {
                    guarded_connection.disarm();
                }
                Err(error.into_public())
            }
        }
    }

    /// Deletes at most `maximum_rows` expired windows.
    ///
    /// Cleanup uses `FOR UPDATE SKIP LOCKED`, so it does not wait behind active
    /// checks and cannot remove a row concurrently being renewed. A zero limit
    /// performs no database work.
    ///
    /// # Errors
    ///
    /// Returns an error if `PostgreSQL` rejects the maintenance transaction or
    /// it exceeds [`PostgresConfig::operation_timeout`]. A commit error or
    /// commit timeout means rows may have been removed; inspect
    /// [`MaintenanceError::may_have_removed_rows`]. Cleanup only targets
    /// already-expired rows and never consumes quota.
    pub async fn cleanup_expired(&self, maximum_rows: u32) -> Result<u64, MaintenanceError> {
        if maximum_rows == 0 {
            return Ok(0);
        }

        let deadline = Instant::now() + self.config.operation_timeout();
        let connection = acquire_maintenance_connection(&self.pool, deadline).await?;
        let mut guarded_connection = ConnectionCancellationGuard::new(connection);
        let result =
            run_cleanup_transaction(guarded_connection.connection(), maximum_rows, deadline).await;
        if !result
            .as_ref()
            .is_err_and(MaintenanceRunError::client_timeout_won)
        {
            guarded_connection.disarm();
        }
        result.map_err(MaintenanceRunError::into_public)
    }
}

/// Failure from a quota check.
#[derive(Debug, Error)]
pub enum CheckError {
    /// The atomic batch violated a backend-independent structural requirement.
    #[error(transparent)]
    InvalidBatch(#[from] BatchError),

    /// `PostgreSQL` did not commit the transaction, so no quota was consumed.
    #[error("PostgreSQL rate-limit check failed before commit; quota was not consumed")]
    DefinitelyNotConsumed(#[source] sqlx::Error),

    /// Commit confirmation was lost, so quota may or may not have been consumed.
    #[error("PostgreSQL rate-limit commit outcome is unknown; quota may have been consumed")]
    CommitOutcomeUnknown(#[source] sqlx::Error),

    /// The total deadline elapsed before commit started.
    #[error("PostgreSQL rate-limit check timed out while {operation}; quota was not consumed")]
    TimedOutBeforeCommit {
        /// Database phase that exhausted the deadline.
        operation: &'static str,
    },

    /// The total deadline elapsed after commit started.
    #[error("PostgreSQL rate-limit commit timed out; quota may have been consumed")]
    CommitTimedOut,

    /// Persisted state violated an invariant guaranteed by the migration.
    #[error("PostgreSQL rate-limit storage invariant failed: {0}")]
    StorageInvariant(&'static str),

    /// A rolled-back single check produced malformed response metadata.
    #[error(
        "PostgreSQL rate-limit single-check response invariant failed after rollback; quota was not consumed"
    )]
    ResponseInvariant,

    /// A committed single check produced malformed response metadata.
    #[error(
        "PostgreSQL rate-limit single-check response invariant failed after commit; quota was consumed"
    )]
    CommittedResponseInvariant,
}

impl CheckError {
    /// Reports whether the failed operation may have consumed quota.
    pub const fn may_have_consumed_quota(&self) -> bool {
        matches!(
            self,
            Self::CommitOutcomeUnknown(_) | Self::CommitTimedOut | Self::CommittedResponseInvariant
        )
    }
}

/// Failure from bounded expired-window cleanup.
#[derive(Debug, Error)]
pub enum MaintenanceError {
    /// `PostgreSQL` did not commit the cleanup transaction, so no rows were
    /// removed.
    #[error("PostgreSQL expired-window cleanup failed before commit; no rows were removed")]
    Database(#[source] sqlx::Error),
    /// The total deadline elapsed before cleanup commit started.
    #[error("PostgreSQL expired-window cleanup timed out while {operation}; no rows were removed")]
    TimedOutBeforeCommit {
        /// Database phase that exhausted the deadline.
        operation: &'static str,
    },
    /// Commit confirmation was lost, so rows may or may not have been removed.
    #[error(
        "PostgreSQL expired-window cleanup commit outcome is unknown; rows may have been removed"
    )]
    CommitOutcomeUnknown(#[source] sqlx::Error),
    /// The total deadline elapsed after cleanup commit started.
    #[error("PostgreSQL expired-window cleanup commit timed out; rows may have been removed")]
    CommitTimedOut,
}

impl MaintenanceError {
    /// Reports whether the failed cleanup may have committed row removals.
    pub const fn may_have_removed_rows(&self) -> bool {
        matches!(self, Self::CommitOutcomeUnknown(_) | Self::CommitTimedOut)
    }
}

fn single_decision_from_batch(batch: BatchDecision) -> Result<Decision, CheckError> {
    batch
        .try_into_single_decision()
        .map_err(|invalid| match invalid {
            BatchDecision::Allowed(_) => CheckError::CommittedResponseInvariant,
            BatchDecision::Denied { .. } => CheckError::ResponseInvariant,
        })
}

struct ConnectionCancellationGuard {
    connection: PoolConnection<Postgres>,
    armed: bool,
}

impl ConnectionCancellationGuard {
    const fn new(connection: PoolConnection<Postgres>) -> Self {
        Self {
            connection,
            armed: true,
        }
    }

    const fn connection(&mut self) -> &mut PoolConnection<Postgres> {
        &mut self.connection
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ConnectionCancellationGuard {
    fn drop(&mut self) {
        if self.armed {
            // Dropping an SQLx query future does not send a PostgreSQL cancel
            // request. Close the socket instead of returning a potentially
            // busy connection to the pool when either Runlimit's deadline or
            // cancellation of the outer limiter future wins the race.
            self.connection.close_on_drop();
        }
    }
}

#[derive(Debug)]
enum CheckRunError {
    Public(CheckError),
    ClientTimedOutBeforeCommit { operation: &'static str },
    ClientCommitTimedOut,
}

#[derive(Debug)]
struct CheckRunOutcome {
    decision: BatchDecision,
    connection_reusable: bool,
}

impl CheckRunError {
    const fn client_timeout_won(&self) -> bool {
        matches!(
            self,
            Self::ClientTimedOutBeforeCommit { .. } | Self::ClientCommitTimedOut
        )
    }

    fn into_public(self) -> CheckError {
        match self {
            Self::Public(error) => error,
            Self::ClientTimedOutBeforeCommit { operation } => {
                CheckError::TimedOutBeforeCommit { operation }
            }
            Self::ClientCommitTimedOut => CheckError::CommitTimedOut,
        }
    }
}

impl From<CheckError> for CheckRunError {
    fn from(error: CheckError) -> Self {
        Self::Public(error)
    }
}

#[derive(Debug)]
enum MaintenanceRunError {
    Public(MaintenanceError),
    ClientTimedOutBeforeCommit { operation: &'static str },
    ClientCommitTimedOut,
}

impl MaintenanceRunError {
    const fn client_timeout_won(&self) -> bool {
        matches!(
            self,
            Self::ClientTimedOutBeforeCommit { .. } | Self::ClientCommitTimedOut
        )
    }

    fn into_public(self) -> MaintenanceError {
        match self {
            Self::Public(error) => error,
            Self::ClientTimedOutBeforeCommit { operation } => {
                MaintenanceError::TimedOutBeforeCommit { operation }
            }
            Self::ClientCommitTimedOut => MaintenanceError::CommitTimedOut,
        }
    }
}

#[derive(Debug)]
enum PendingBatchOutcome {
    Allowed(Vec<PendingAllowance>),
    Denied { index: usize, denial: PendingDenial },
}

#[derive(Debug)]
struct BatchSqlInput {
    policy_ids: Vec<String>,
    scope_ids: Vec<String>,
    fingerprints: Vec<Vec<u8>>,
    subjects: Vec<Vec<u8>>,
    lock_input_positions: Vec<i64>,
    advisory_lock_ids: Vec<i64>,
    windows: Vec<PgInterval>,
    costs: Vec<i64>,
    limits: Vec<i64>,
}

impl BatchSqlInput {
    fn from_checks(checks: &[Check<'_>]) -> Self {
        let counter_keys = checks.iter().map(Check::counter_key).collect::<Vec<_>>();
        let mut ordered_indices = (0..checks.len()).collect::<Vec<_>>();
        ordered_indices.sort_unstable_by_key(|index| counter_keys[*index]);

        let mut input = Self {
            policy_ids: Vec::with_capacity(checks.len()),
            scope_ids: Vec::with_capacity(checks.len()),
            fingerprints: Vec::with_capacity(checks.len()),
            subjects: Vec::with_capacity(checks.len()),
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
struct PendingAllowance {
    limit: u64,
    remaining: u64,
    reset_from_sample: Duration,
}

impl PendingAllowance {
    fn finish(self, authoritative_elapsed: Duration) -> Decision {
        Decision::allowed(
            self.limit,
            self.remaining,
            self.reset_from_sample.saturating_sub(authoritative_elapsed),
        )
    }
}

#[derive(Debug)]
struct PendingDenial {
    limit: u64,
    retry_from_sample: Duration,
}

impl PendingDenial {
    fn finish(self, authoritative_elapsed: Duration) -> Denial {
        Denial::QuotaExceeded {
            limit: self.limit,
            retry_after: self.retry_from_sample.saturating_sub(authoritative_elapsed),
        }
    }
}

async fn acquire_check_connection(
    pool: &PgPool,
    deadline: Instant,
) -> Result<PoolConnection<Postgres>, CheckError> {
    timeout_at(deadline, pool.acquire())
        .await
        .map_err(|_| CheckError::TimedOutBeforeCommit {
            operation: "acquiring database connection",
        })?
        .map_err(CheckError::DefinitelyNotConsumed)
}

async fn run_check_transaction(
    connection: &mut PoolConnection<Postgres>,
    input: &BatchSqlInput,
    checks: &[Check<'_>],
    deadline: Instant,
) -> Result<CheckRunOutcome, CheckRunError> {
    let mut transaction =
        check_before_commit(deadline, "beginning transaction", connection.begin()).await?;
    set_check_server_timeouts(
        &mut transaction,
        deadline,
        "configuring transaction timeouts",
    )
    .await?;

    let (pending, authoritative_elapsed) = if checks.len() == 1 {
        execute_single(&mut transaction, input, &checks[0], deadline).await?
    } else {
        // Advisory locks cover logical keys that do not have rows yet. Their
        // stable numeric IDs are sorted independently from exact storage keys
        // so deliberately colliding batches cannot acquire them in opposite
        // orders.
        acquire_advisory_locks(&mut transaction, &input.advisory_lock_ids, deadline).await?;

        // Existing rows may be held by cleanup or a transaction predating the
        // advisory-lock protocol. Wait for all row locks before sampling
        // database time, otherwise a contended request could evaluate against
        // stale time.
        acquire_existing_row_locks(&mut transaction, input, deadline).await?;

        execute_batch(&mut transaction, input, checks, deadline).await?
    };

    match pending {
        PendingBatchOutcome::Denied { index, denial } => Ok(finish_denied_transaction(
            deadline,
            index,
            denial,
            authoritative_elapsed,
            transaction.rollback(),
        )
        .await),
        PendingBatchOutcome::Allowed(allowances) => {
            commit_check(deadline, transaction).await?;
            Ok(CheckRunOutcome {
                decision: BatchDecision::Allowed(
                    allowances
                        .into_iter()
                        .map(|allowance| allowance.finish(authoritative_elapsed))
                        .collect(),
                ),
                connection_reusable: true,
            })
        }
    }
}

async fn finish_denied_transaction<F>(
    deadline: Instant,
    index: usize,
    denial: PendingDenial,
    authoritative_elapsed: Duration,
    rollback: F,
) -> CheckRunOutcome
where
    F: Future<Output = Result<(), sqlx::Error>>,
{
    let decision = BatchDecision::Denied {
        index,
        denial: denial.finish(authoritative_elapsed),
    };
    let connection_reusable = denied_rollback_succeeded(deadline, rollback).await;
    CheckRunOutcome {
        decision,
        connection_reusable,
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
) -> Result<T, CheckRunError>
where
    F: Future<Output = Result<T, sqlx::Error>>,
{
    timeout_at(deadline, future)
        .await
        .map_err(|_| CheckRunError::ClientTimedOutBeforeCommit { operation })?
        .map_err(|error| CheckRunError::Public(map_check_database_error(error, operation)))
}

async fn commit_check(
    deadline: Instant,
    transaction: Transaction<'_, Postgres>,
) -> Result<(), CheckRunError> {
    if Instant::now() >= deadline {
        return Err(CheckRunError::Public(CheckError::TimedOutBeforeCommit {
            operation: "starting commit",
        }));
    }

    timeout_at(deadline, transaction.commit())
        .await
        .map_err(|_| CheckRunError::ClientCommitTimedOut)?
        .map_err(|error| CheckRunError::Public(CheckError::CommitOutcomeUnknown(error)))
}

fn map_check_database_error(error: sqlx::Error, operation: &'static str) -> CheckError {
    if is_server_timeout(&error) {
        CheckError::TimedOutBeforeCommit { operation }
    } else {
        CheckError::DefinitelyNotConsumed(error)
    }
}

fn is_server_timeout(error: &sqlx::Error) -> bool {
    let sqlx::Error::Database(database_error) = error else {
        return false;
    };
    matches!(database_error.code().as_deref(), Some("57014" | "55P03"))
}

fn remaining_server_timeout_settings(deadline: Instant) -> Option<(String, String)> {
    let remaining = deadline.checked_duration_since(Instant::now())?;
    let remaining_millis = remaining.as_millis();
    let statement_millis = remaining_millis
        .saturating_sub(SERVER_TIMEOUT_GRACE.as_millis())
        .max(1);
    let lock_millis = statement_millis.saturating_sub(1).max(1);
    Some((format!("{statement_millis}ms"), format!("{lock_millis}ms")))
}

async fn set_check_server_timeouts(
    transaction: &mut Transaction<'_, Postgres>,
    deadline: Instant,
    operation: &'static str,
) -> Result<(), CheckRunError> {
    let (statement_timeout, lock_timeout) = remaining_server_timeout_settings(deadline).ok_or(
        CheckRunError::Public(CheckError::TimedOutBeforeCommit { operation }),
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
) -> Result<(), CheckRunError> {
    check_before_commit(deadline, "acquiring logical key lock", async {
        sqlx::query(BATCH_ADVISORY_LOCK_SQL)
            .bind(advisory_lock_ids)
            .execute(&mut **transaction)
            .await
            .map(|_| ())
    })
    .await
}

fn advisory_lock_id(counter_key: CounterKey) -> i64 {
    let mut digest = Sha256::new();
    digest.update(ADVISORY_LOCK_DOMAIN);
    digest.update(counter_key.to_bytes());
    let digest = digest.finalize();
    let mut id_bytes = [0_u8; 8];
    let id_length = id_bytes.len();
    id_bytes.copy_from_slice(&digest[..id_length]);
    i64::from_be_bytes(id_bytes)
}

async fn acquire_existing_row_locks(
    transaction: &mut Transaction<'_, Postgres>,
    input: &BatchSqlInput,
    deadline: Instant,
) -> Result<(), CheckRunError> {
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

async fn acquire_maintenance_connection(
    pool: &PgPool,
    deadline: Instant,
) -> Result<PoolConnection<Postgres>, MaintenanceError> {
    timeout_at(deadline, pool.acquire())
        .await
        .map_err(|_| MaintenanceError::TimedOutBeforeCommit {
            operation: "acquiring database connection",
        })?
        .map_err(MaintenanceError::Database)
}

async fn run_cleanup_transaction(
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

fn authoritative_elapsed(start: DateTime<Utc>, end: DateTime<Utc>) -> Duration {
    end.signed_duration_since(start)
        .to_std()
        .unwrap_or(Duration::ZERO)
}

async fn execute_batch(
    transaction: &mut Transaction<'_, Postgres>,
    input: &BatchSqlInput,
    checks: &[Check<'_>],
    deadline: Instant,
) -> Result<(PendingBatchOutcome, Duration), CheckRunError> {
    let preflight = preflight_batch(transaction, input, checks, deadline).await?;
    if let Some((index, denial)) = preflight.denial {
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

async fn execute_single(
    transaction: &mut Transaction<'_, Postgres>,
    input: &BatchSqlInput,
    check: &Check<'_>,
    deadline: Instant,
) -> Result<(PendingBatchOutcome, Duration), CheckRunError> {
    let row = check_before_commit(
        deadline,
        "evaluating counter",
        sqlx::query(SINGLE_CHECK_SQL)
            .bind(input.advisory_lock_ids[0])
            .bind(&input.policy_ids[0])
            .bind(&input.scope_ids[0])
            .bind(input.fingerprints[0].as_slice())
            .bind(input.subjects[0].as_slice())
            .bind(input.windows[0])
            .bind(input.costs[0])
            .bind(input.limits[0])
            .fetch_one(&mut **transaction),
    )
    .await?;

    let database_now: DateTime<Utc> = row
        .try_get("database_now")
        .map_err(CheckError::DefinitelyNotConsumed)?;
    let response_now: DateTime<Utc> = row
        .try_get("response_now")
        .map_err(CheckError::DefinitelyNotConsumed)?;
    let denied: bool = row
        .try_get("denied")
        .map_err(CheckError::DefinitelyNotConsumed)?;
    let expires_at: Option<DateTime<Utc>> = row
        .try_get("window_expires_at")
        .map_err(CheckError::DefinitelyNotConsumed)?;
    let used: Option<i64> = row
        .try_get("used")
        .map_err(CheckError::DefinitelyNotConsumed)?;
    let authoritative_elapsed = authoritative_elapsed(database_now, response_now);

    if denied {
        if used.is_some() {
            return Err(
                CheckError::StorageInvariant("denied single check returned stored usage").into(),
            );
        }
        let expires_at = expires_at.ok_or(CheckError::StorageInvariant(
            "denied single check returned no window expiry",
        ))?;
        return Ok((
            PendingBatchOutcome::Denied {
                index: 0,
                denial: PendingDenial {
                    limit: check.policy().limit(),
                    retry_from_sample: duration_until(expires_at, database_now)?,
                },
            },
            authoritative_elapsed,
        ));
    }

    if expires_at.is_none() && used.is_none() {
        // A statement takes its READ COMMITTED snapshot before it can wait for
        // the advisory lock. If another transaction inserts this fresh key
        // while this statement waits, the row-lock CTE cannot see that row,
        // while INSERT ... ON CONFLICT can see and lock the now-current row.
        // A rejected conflict update therefore advances us to a fresh
        // statement snapshot. The advisory lock remains held, and the regular
        // batch phases reacquire the exact row lock before sampling time.
        acquire_existing_row_locks(transaction, input, deadline).await?;
        return execute_batch(transaction, input, std::slice::from_ref(check), deadline).await;
    }

    let expires_at = expires_at.ok_or(CheckError::StorageInvariant(
        "allowed single check returned no window expiry",
    ))?;
    let used = used.ok_or(CheckError::StorageInvariant(
        "allowed single check returned no stored usage",
    ))?;
    let used = u64::try_from(used)
        .map_err(|_| CheckError::StorageInvariant("stored usage is negative"))?;
    let remaining =
        check
            .policy()
            .limit()
            .checked_sub(used)
            .ok_or(CheckError::StorageInvariant(
                "stored usage exceeds its policy limit",
            ))?;

    Ok((
        PendingBatchOutcome::Allowed(vec![PendingAllowance {
            limit: check.policy().limit(),
            remaining,
            reset_from_sample: duration_until(expires_at, database_now)?,
        }]),
        authoritative_elapsed,
    ))
}

async fn preflight_batch(
    transaction: &mut Transaction<'_, Postgres>,
    input: &BatchSqlInput,
    checks: &[Check<'_>],
    deadline: Instant,
) -> Result<BatchPreflight, CheckRunError> {
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
        .map_err(CheckError::DefinitelyNotConsumed)?;
    let preflight_response_now: DateTime<Utc> = preflight_row
        .try_get("response_now")
        .map_err(CheckError::DefinitelyNotConsumed)?;
    let denied_index: Option<i64> = preflight_row
        .try_get("input_index")
        .map_err(CheckError::DefinitelyNotConsumed)?;
    let denied_expiry: Option<DateTime<Utc>> = preflight_row
        .try_get("window_expires_at")
        .map_err(CheckError::DefinitelyNotConsumed)?;

    let denial = match (denied_index, denied_expiry) {
        (Some(input_index), Some(expires_at)) => {
            let input_index = usize::try_from(input_index).map_err(|_| {
                CheckError::StorageInvariant("batch preflight returned an invalid input index")
            })?;
            let check = checks.get(input_index).ok_or(CheckError::StorageInvariant(
                "batch preflight returned an out-of-range input index",
            ))?;
            Some((
                input_index,
                PendingDenial {
                    limit: check.policy().limit(),
                    retry_from_sample: duration_until(expires_at, database_now)?,
                },
            ))
        }
        (None, None) => None,
        _ => {
            return Err(CheckError::StorageInvariant(
                "batch preflight returned an incomplete denial",
            )
            .into());
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
) -> Result<(Vec<PendingAllowance>, DateTime<Utc>), CheckRunError> {
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
        return Err(
            CheckError::StorageInvariant("allowed batch update returned no decisions").into(),
        );
    }
    let response_now: DateTime<Utc> = rows[0]
        .try_get("response_now")
        .map_err(CheckError::DefinitelyNotConsumed)?;

    let mut allowances = Vec::with_capacity(checks.len());
    for (output_position, row) in rows.iter().enumerate() {
        let input_index: i64 = row
            .try_get("input_index")
            .map_err(CheckError::DefinitelyNotConsumed)?;
        let input_index = usize::try_from(input_index).map_err(|_| {
            CheckError::StorageInvariant("batch evaluation returned an invalid input index")
        })?;
        let Some(check) = checks.get(input_index) else {
            return Err(CheckError::StorageInvariant(
                "batch evaluation returned an out-of-range input index",
            )
            .into());
        };
        let expires_at = read_expiry(row)?;
        let remaining_from_sample = duration_until(expires_at, database_now)?;

        if input_index != output_position {
            return Err(CheckError::StorageInvariant(
                "allowed batch decisions were not returned in caller order",
            )
            .into());
        }
        let used = read_used(row)?;
        let remaining =
            check
                .policy()
                .limit()
                .checked_sub(used)
                .ok_or(CheckError::StorageInvariant(
                    "stored usage exceeds its policy limit",
                ))?;
        allowances.push(PendingAllowance {
            limit: check.policy().limit(),
            remaining,
            reset_from_sample: remaining_from_sample,
        });
    }

    if allowances.len() != checks.len() {
        return Err(CheckError::StorageInvariant(
            "allowed batch returned an incomplete decision set",
        )
        .into());
    }
    Ok((allowances, response_now))
}

fn database_integer(value: u64) -> i64 {
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use runlimit_core::{
        FixedWindowPolicy, MAX_LIMIT, MAX_WINDOW, MAX_WINDOW_MILLIS, PolicyId, ScopeId, SubjectKey,
    };

    fn policy(id: &str, scope: &str) -> FixedWindowPolicy {
        FixedWindowPolicy::new(
            PolicyId::new(id).expect("valid policy identifier"),
            ScopeId::new(scope).expect("valid scope identifier"),
            10,
            Duration::from_secs(60),
        )
        .expect("valid policy")
    }

    fn key(byte: u8) -> SubjectKey {
        SubjectKey::from_digest([byte; 32])
    }

    #[test]
    fn portable_core_boundaries_fit_database_values_exactly() {
        let policy = FixedWindowPolicy::new(
            PolicyId::new("portable.maximum").unwrap(),
            ScopeId::new("subject").unwrap(),
            MAX_LIMIT,
            MAX_WINDOW,
        )
        .unwrap();
        let check = Check::with_cost(&policy, key(1), MAX_LIMIT).unwrap();

        assert_eq!(database_integer(policy.limit()), i64::MAX);
        assert_eq!(database_integer(check.cost()), i64::MAX);
        let interval = PgInterval::try_from(policy.window()).unwrap();
        assert_eq!(interval.months, 0);
        assert_eq!(interval.days, 0);
        assert_eq!(
            interval.microseconds,
            i64::try_from(MAX_WINDOW_MILLIS * 1_000).unwrap()
        );
    }

    #[test]
    fn row_lock_permutation_orders_complete_counter_keys() {
        let alpha_client = policy("alpha", "client");
        let alpha_identity = policy("alpha", "identity");
        let beta_client = policy("beta", "client");
        let checks = [
            Check::new(&beta_client, key(0)),
            Check::new(&alpha_identity, key(0)),
            Check::new(&alpha_client, key(1)),
            Check::new(&alpha_client, key(0)),
        ];

        let input = BatchSqlInput::from_checks(&checks);
        let locked_keys = input
            .lock_input_positions
            .iter()
            .map(|position| checks[usize::try_from(*position - 1).unwrap()].counter_key())
            .collect::<Vec<_>>();

        assert!(locked_keys.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn advisory_lock_protocol_has_a_golden_vector() {
        let policy = policy("login", "client");
        let check = Check::new(&policy, key(7));

        assert_eq!(
            advisory_lock_id(check.counter_key()),
            4_549_358_434_381_602_087
        );
    }

    #[test]
    fn response_metadata_subtracts_only_authoritative_elapsed_time() {
        let allowed = PendingAllowance {
            limit: 10,
            remaining: 4,
            reset_from_sample: Duration::from_millis(250),
        }
        .finish(Duration::from_millis(80));
        let denied = PendingDenial {
            limit: 10,
            retry_from_sample: Duration::from_millis(150),
        }
        .finish(Duration::from_millis(80));

        assert_eq!(allowed.reset_after(), Some(Duration::from_millis(170)));
        assert_eq!(denied.retry_after(), Some(Duration::from_millis(70)));
        assert_eq!(denied.retry_after_seconds(), Some(1));
    }

    #[tokio::test]
    async fn denied_decision_survives_rollback_failure_and_discards_connection() {
        let outcome = finish_denied_transaction(
            Instant::now() + Duration::from_secs(1),
            2,
            PendingDenial {
                limit: 10,
                retry_from_sample: Duration::from_millis(150),
            },
            Duration::from_millis(20),
            std::future::ready(Err(sqlx::Error::Protocol(
                "injected rollback failure".to_owned(),
            ))),
        )
        .await;

        assert!(matches!(
            outcome.decision,
            BatchDecision::Denied {
                index: 2,
                denial: Denial::QuotaExceeded {
                    limit: 10,
                    retry_after
                }
            } if retry_after == Duration::from_millis(130)
        ));
        assert!(!outcome.connection_reusable);
    }

    #[tokio::test]
    async fn denied_decision_survives_rollback_deadline_and_discards_connection() {
        let outcome = finish_denied_transaction(
            Instant::now(),
            0,
            PendingDenial {
                limit: 1,
                retry_from_sample: Duration::from_millis(50),
            },
            Duration::ZERO,
            std::future::pending(),
        )
        .await;

        assert!(matches!(
            outcome.decision,
            BatchDecision::Denied {
                index: 0,
                denial: Denial::QuotaExceeded { limit: 1, .. }
            }
        ));
        assert!(!outcome.connection_reusable);
    }

    #[test]
    fn configuration_bounds_batches_and_deadlines() {
        let defaults = PostgresConfig::new();
        assert_eq!(defaults.max_batch_size(), 32);
        assert_eq!(defaults.operation_timeout(), Duration::from_secs(3));
        assert_eq!(
            defaults.with_max_batch_size(0),
            Err(PostgresConfigError::ZeroBatchSize)
        );
        assert_eq!(
            defaults.with_operation_timeout(Duration::ZERO),
            Err(PostgresConfigError::ZeroOperationTimeout)
        );
        assert_eq!(
            defaults.with_operation_timeout(Duration::from_secs(61)),
            Err(PostgresConfigError::OperationTimeoutTooLong {
                actual: Duration::from_secs(61),
                maximum: Duration::from_secs(60),
            })
        );
    }

    #[tokio::test]
    async fn duplicate_storage_keys_fail_before_connecting() {
        let alpha = policy("alpha", "client");
        let beta = policy("beta", "client");
        let checks = [
            Check::new(&beta, key(7)),
            Check::new(&beta, key(7)),
            Check::new(&alpha, key(8)),
            Check::new(&alpha, key(8)),
        ];
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://runlimit:runlimit@127.0.0.1:1/runlimit")
            .expect("syntactically valid database URL");
        let limiter = PostgresLimiter::new(pool);

        let error = limiter
            .check_all(&checks)
            .await
            .expect_err("duplicate keys must be rejected");

        assert!(matches!(
            error,
            CheckError::InvalidBatch(BatchError::DuplicateKey {
                first_index: 0,
                duplicate_index: 1,
            })
        ));
    }

    #[tokio::test]
    async fn oversized_batch_fails_before_connecting() {
        let first_policy = policy("login", "client");
        let second_policy = policy("signup", "client");
        let checks = [
            Check::new(&first_policy, key(1)),
            Check::new(&second_policy, key(2)),
        ];
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://runlimit:runlimit@127.0.0.1:1/runlimit")
            .expect("syntactically valid database URL");
        let config = PostgresConfig::new()
            .with_max_batch_size(1)
            .expect("one is a valid batch limit");
        let limiter = PostgresLimiter::with_config(pool, config);

        let error = limiter
            .check_all(&checks)
            .await
            .expect_err("oversized batch must be rejected");

        assert!(matches!(
            error,
            CheckError::InvalidBatch(BatchError::BatchTooLarge {
                actual: 2,
                maximum: 1,
            })
        ));
    }

    #[test]
    fn error_reports_consumption_uncertainty() {
        let definite = CheckError::DefinitelyNotConsumed(sqlx::Error::RowNotFound);
        let unknown = CheckError::CommitOutcomeUnknown(sqlx::Error::RowNotFound);
        let rolled_back_invariant = CheckError::ResponseInvariant;
        let committed_invariant = CheckError::CommittedResponseInvariant;
        let cleanup_definite = MaintenanceError::Database(sqlx::Error::RowNotFound);
        let cleanup_unknown = MaintenanceError::CommitOutcomeUnknown(sqlx::Error::RowNotFound);

        assert!(!definite.may_have_consumed_quota());
        assert!(unknown.may_have_consumed_quota());
        assert!(CheckError::CommitTimedOut.may_have_consumed_quota());
        assert!(!rolled_back_invariant.may_have_consumed_quota());
        assert!(committed_invariant.may_have_consumed_quota());
        assert!(!cleanup_definite.may_have_removed_rows());
        assert!(cleanup_unknown.may_have_removed_rows());
        assert!(MaintenanceError::CommitTimedOut.may_have_removed_rows());
    }

    #[test]
    fn malformed_single_responses_preserve_consumption_status() {
        let denial = Denial::QuotaExceeded {
            limit: 1,
            retry_after: Duration::from_secs(1),
        };

        let committed = single_decision_from_batch(BatchDecision::Allowed(Vec::new()))
            .expect_err("malformed allowed response follows a confirmed commit");
        let rolled_back = single_decision_from_batch(BatchDecision::Denied { index: 1, denial })
            .expect_err("malformed denied response follows a rollback");

        assert!(matches!(committed, CheckError::CommittedResponseInvariant));
        assert!(committed.may_have_consumed_quota());
        assert!(matches!(rolled_back, CheckError::ResponseInvariant));
        assert!(!rolled_back.may_have_consumed_quota());
    }

    #[test]
    fn cleanup_query_is_bounded_and_nonblocking() {
        assert_eq!(CLEANUP_SQL.matches("clock_timestamp()").count(), 1);
        assert!(CLEANUP_SQL.contains("AS MATERIALIZED"));
        assert!(CLEANUP_SQL.contains("SELECT sampled_at\n        FROM authoritative_time"));
        assert!(!CLEANUP_SQL.contains("window_expires_at <= clock_timestamp()"));
        assert!(CLEANUP_SQL.contains("LIMIT $1"));
        assert!(CLEANUP_SQL.contains("FOR UPDATE SKIP LOCKED"));
    }
}
