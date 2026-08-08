//! Replica-safe `PostgreSQL` storage for Runlimit fixed-window policies.
//!
//! [`PostgresLimiter`] implements the same anchored fixed-window model as the
//! in-memory backend: the first admitted check starts a window, and subsequent
//! checks share that window until it expires. `PostgreSQL`'s clock is the sole
//! time authority, so callers on different hosts do not need synchronized
//! clocks. Atomic batches use set-based lock, preflight, and update phases, so
//! their number of SQL phases does not grow with the batch size. Single checks
//! use the same separate logical-key, counter-row, and capacity-shard lock
//! phases so every statement that tests row absence starts after the logical
//! key lock has been acquired.
//! [`PostgresLimiter`] implements [`runlimit_core::Limiter`] for async generic
//! adapters.
//! The optional `serde` feature enables validated [`PostgresConfig`] loading
//! and the corresponding `runlimit-core` policy and response metadata.
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
//! Runlimit SQL as application-owned migrations, in order, using
//! [`CREATE_RUNLIMIT_FIXED_WINDOWS_SQL`] and
//! [`SET_RUNLIMIT_FIXED_WINDOWS_FILLFACTOR_SQL`] followed by
//! [`BOUND_RUNLIMIT_FIXED_WINDOW_CARDINALITY_SQL`] instead of invoking either
//! Runlimit migrator against the shared history.
//!
//! # Storage capacity
//!
//! Every counter belongs to one of [`CAPACITY_SHARD_COUNT`] persistent shards.
//! The migration-maintained ledger enforces
//! [`HARD_MAX_ROWS_PER_SHARD`] even for older replicas, while
//! [`PostgresConfig::maximum_rows_per_shard`] lets current replicas fail closed
//! at a lower operational bound. A full shard denies only new storage keys;
//! existing rows remain usable and active rows are never evicted. Expiry alone
//! does not release a row. Capacity becomes reusable only after
//! [`PostgresLimiter::cleanup_expired`] commits its deletion.
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
//! outcome as unknown. Prefer this backend's configured acquisition and
//! operation budgets to a shorter outer timeout.
//!
//! The advisory-lock `v1` domain and derivation are a cross-replica protocol.
//! They must not be changed in place: replicas from a rolling deployment must
//! calculate identical lock IDs for the same persistent counter. `PostgreSQL`'s
//! advisory-lock namespace is shared by every application in the same database.
//! An unrelated or deliberately held matching `bigint` lock therefore blocks
//! the affected Runlimit key until the operation deadline; use a trusted
//! database boundary and restrict advisory-lock privileges for unrelated roles.
//! The persisted capacity-shard derivation is likewise a cross-replica
//! protocol: it XORs the leading bytes of the policy fingerprint and opaque
//! subject key. Changing the derivation or shard count requires a new storage
//! protocol and migration.
//!
//! # Integration tests
//!
//! The database tests are opt-in:
//!
//! ```text
//! RUNLIMIT_POSTGRES_TEST_DATABASE_URL=postgresql:///runlimit_test \
//! cargo test -p runlimit-postgres --test postgres -- --ignored
//! ```

use std::{
    fmt,
    future::Future,
    sync::Arc,
    time::{Duration, Instant as WallClockInstant},
};

use runlimit_core::{
    AdmissionObservation, AdmissionOperation, AdmissionOutcome, BatchDecision, Check,
    CleanupObservation, ConsumptionStatus, Decision, FixedWindowPolicy, Limiter, Observation,
    Observer, observe_safely, validate_batch,
};
use sqlx::{
    PgPool, Postgres,
    migrate::{MigrateError, Migrator},
    pool::PoolConnection,
};
use tokio::time::Instant;

mod admission;
mod config;
mod errors;
mod maintenance;
mod protocol;

pub use config::{PostgresConfig, PostgresConfigError};
pub use errors::{CheckError, MaintenanceError};
pub use protocol::{CAPACITY_SHARD_COUNT, HARD_MAX_ROWS_PER_SHARD};

use admission::{
    BatchSqlInput, acquire_check_connection, run_check_transaction, single_decision_from_batch,
};
use errors::check_error_consumption;
use maintenance::{MaintenanceRunError, acquire_maintenance_connection, run_cleanup_transaction};

#[cfg(test)]
use admission::{PendingAllowance, PendingDenial, database_integer, finish_denied_transaction};
#[cfg(test)]
use protocol::{
    BATCH_PREFLIGHT_SQL, BATCH_UPSERT_SQL, CLEANUP_SQL, advisory_lock_id, capacity_shard,
};
#[cfg(test)]
use runlimit_core::{BatchError, Denial};
#[cfg(test)]
use sqlx::postgres::types::PgInterval;

/// SQL for the immutable `20260723000000_create_runlimit_fixed_windows`
/// migration.
///
/// Strict host migrators can copy this SQL into their application-owned
/// migration stream instead of running [`MIGRATOR`] against a shared
/// `_sqlx_migrations` history. Apply it before
/// [`SET_RUNLIMIT_FIXED_WINDOWS_FILLFACTOR_SQL`].
pub const CREATE_RUNLIMIT_FIXED_WINDOWS_SQL: &str =
    include_str!("../migrations/20260723000000_create_runlimit_fixed_windows.sql");

/// SQL for the additive
/// `20260725000000_set_runlimit_fixed_windows_fillfactor` migration.
///
/// Strict host migrators can copy this SQL into their application-owned
/// migration stream after [`CREATE_RUNLIMIT_FIXED_WINDOWS_SQL`]. The
/// application remains responsible for assigning versions that fit its own
/// migration history.
pub const SET_RUNLIMIT_FIXED_WINDOWS_FILLFACTOR_SQL: &str =
    include_str!("../migrations/20260725000000_set_runlimit_fixed_windows_fillfactor.sql");

/// SQL for the additive
/// `20260726000000_bound_runlimit_fixed_window_cardinality` migration.
///
/// This migration assigns every persisted counter to one of 256 stable
/// capacity shards and installs a trigger-maintained row-count ledger. Apply it
/// after [`SET_RUNLIMIT_FIXED_WINDOWS_FILLFACTOR_SQL`].
pub const BOUND_RUNLIMIT_FIXED_WINDOW_CARDINALITY_SQL: &str =
    include_str!("../migrations/20260726000000_bound_runlimit_fixed_window_cardinality.sql");

/// Raw bundled migrations required by [`PostgresLimiter`].
///
/// This value retains `SQLx`'s strict missing-version behavior and is suitable
/// only for an exclusively managed migration history and connection. For a
/// pooled application that shares `_sqlx_migrations`, prefer
/// [`PostgresLimiter::migrate`] and configure every other participating
/// [`Migrator`] to set [`Migrator::set_ignore_missing`] to `true`.
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// A replica-safe rate limiter backed by a `PostgreSQL` pool.
///
/// Cloning this value is cheap because [`PgPool`] is internally reference
/// counted.
#[derive(Clone)]
pub struct PostgresLimiter {
    pool: PgPool,
    config: PostgresConfig,
    observer: Option<Arc<dyn Observer>>,
}

impl fmt::Debug for PostgresLimiter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresLimiter")
            .field("pool", &self.pool)
            .field("config", &self.config)
            .field("has_observer", &self.observer.is_some())
            .finish_non_exhaustive()
    }
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
            observer: None,
        }
    }

    /// Creates a limiter using an explicit runtime configuration.
    pub const fn with_config(pool: PgPool, config: PostgresConfig) -> Self {
        Self {
            pool,
            config,
            observer: None,
        }
    }

    /// Returns this limiter with an operational observer.
    ///
    /// Observer callbacks run only after a database operation has released its
    /// connection. Callback panics are isolated and cannot change admission or
    /// cleanup results.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn Observer>) -> Self {
        self.observer = Some(observer);
        self
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
        let started = WallClockInstant::now();
        let result = self
            .check_all_unobserved(std::slice::from_ref(check))
            .await
            .and_then(single_decision_from_batch);
        self.observe_single_admission(check, &result, started.elapsed());
        result
    }

    /// Atomically checks and consumes every quota in `checks`.
    ///
    /// Rows are acquired in a deterministic storage-key order to avoid
    /// deadlocks between overlapping batches. Returned allowed decisions retain
    /// the caller's input order. Repeated occurrences of the same storage key
    /// are rejected before a connection is acquired because their independent
    /// decision metadata would be ambiguous.
    ///
    /// New keys lock their capacity-ledger rows in shard order. If the earliest
    /// caller-ordered failure is the configured shard bound, the batch returns
    /// [`runlimit_core::Denial::StorageCapacity`] with no retry duration and changes neither
    /// quota nor storage. Existing and expired target rows need no new slot.
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
    /// Pool-acquisition or operation timeout before commit is
    /// [`CheckError::TimedOutBeforeCommit`]. Other database failures before
    /// commit are [`CheckError::DefinitelyNotConsumed`]. Any commit error is
    /// conservatively classified as [`CheckError::CommitOutcomeUnknown`].
    pub async fn check_all(&self, checks: &[Check<'_>]) -> Result<BatchDecision, CheckError> {
        let started = WallClockInstant::now();
        let result = self.check_all_unobserved(checks).await;
        self.observe_batch_admission(checks, &result, started.elapsed());
        result
    }

    async fn check_all_unobserved(
        &self,
        checks: &[Check<'_>],
    ) -> Result<BatchDecision, CheckError> {
        validate_batch(checks, self.config.max_batch_size())?;
        if checks.is_empty() {
            return Ok(BatchDecision::Allowed(Vec::new()));
        }

        // Materialize every SQL array and both lock orders before reserving a
        // pool slot. Every database phase then consumes the exact same key
        // arrays, preventing identity drift between locking and mutation.
        let input = BatchSqlInput::from_checks(checks);
        let connection =
            acquire_check_connection(&self.pool, self.config.pool_acquire_timeout()).await?;
        // Pool contention does not consume the database-work budget. A
        // survivor receives a fresh deadline for begin, statements, locks,
        // rollback, and commit.
        let deadline = Instant::now() + self.config.operation_timeout();
        let mut guarded_connection = ConnectionCancellationGuard::new(connection);
        let result = run_check_transaction(
            guarded_connection.connection(),
            &input,
            checks,
            self.config.maximum_rows_per_shard(),
            deadline,
        )
        .await;
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

    /// Deletes at most `maximum_rows` expired windows and releases their
    /// capacity-ledger slots in the same transaction.
    ///
    /// Cleanup uses `FOR UPDATE SKIP LOCKED`, so it does not wait behind active
    /// checks and cannot remove a row concurrently being renewed. A zero limit
    /// performs no database work.
    ///
    /// # Errors
    ///
    /// Returns an error if `PostgreSQL` rejects the maintenance transaction or
    /// if either [`PostgresConfig::pool_acquire_timeout`] or the fresh
    /// [`PostgresConfig::operation_timeout`] budget is exceeded. A commit error
    /// or commit timeout means rows may have been removed; inspect
    /// [`MaintenanceError::may_have_removed_rows`]. Cleanup only targets
    /// already-expired rows and never consumes quota.
    pub async fn cleanup_expired(&self, maximum_rows: u32) -> Result<u64, MaintenanceError> {
        let started = WallClockInstant::now();
        let result = self.cleanup_expired_unobserved(maximum_rows).await;
        self.observe_cleanup(maximum_rows, &result, started.elapsed());
        result
    }

    async fn cleanup_expired_unobserved(&self, maximum_rows: u32) -> Result<u64, MaintenanceError> {
        if maximum_rows == 0 {
            return Ok(0);
        }

        let connection =
            acquire_maintenance_connection(&self.pool, self.config.pool_acquire_timeout()).await?;
        let deadline = Instant::now() + self.config.operation_timeout();
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

    fn observe_single_admission(
        &self,
        check: &Check<'_>,
        result: &Result<Decision, CheckError>,
        elapsed: Duration,
    ) {
        match result {
            Ok(decision) => self
                .observe_admission(|| AdmissionObservation::from_check(check, decision, elapsed)),
            Err(error) => self.observe_admission(|| {
                AdmissionObservation::new(
                    AdmissionOperation::Check,
                    1,
                    Some(check.policy().id()),
                    Some(check.policy().scope()),
                    AdmissionOutcome::Failed,
                    check_error_consumption(error),
                    elapsed,
                )
            }),
        }
    }

    fn observe_batch_admission(
        &self,
        checks: &[Check<'_>],
        result: &Result<BatchDecision, CheckError>,
        elapsed: Duration,
    ) {
        match result {
            Ok(decision) => self
                .observe_admission(|| AdmissionObservation::from_batch(checks, decision, elapsed)),
            Err(error) => {
                self.observe_admission(|| {
                    let relevant_check = if checks.len() == 1 {
                        checks.first()
                    } else {
                        None
                    };
                    let (policy_id, scope_id) = relevant_check.map_or((None, None), |check| {
                        (Some(check.policy().id()), Some(check.policy().scope()))
                    });
                    AdmissionObservation::new(
                        AdmissionOperation::Batch,
                        checks.len(),
                        policy_id,
                        scope_id,
                        AdmissionOutcome::Failed,
                        check_error_consumption(error),
                        elapsed,
                    )
                });
            }
        }
    }

    fn observe_admission<'a>(&self, build_observation: impl FnOnce() -> AdmissionObservation<'a>) {
        let Some(observer) = &self.observer else {
            return;
        };
        let admission = build_observation();
        observe_safely(observer.as_ref(), &Observation::Admission(admission));
    }

    fn observe_cleanup(
        &self,
        requested: u32,
        result: &Result<u64, MaintenanceError>,
        elapsed: Duration,
    ) {
        let Some(observer) = &self.observer else {
            return;
        };
        let (removed, consumption) = match result {
            Ok(removed) => (Some(*removed), ConsumptionStatus::Consumed),
            Err(error) if error.may_have_removed_rows() => {
                (None, ConsumptionStatus::PossiblyConsumed)
            }
            Err(_) => (Some(0), ConsumptionStatus::NotConsumed),
        };
        observe_safely(
            observer.as_ref(),
            &Observation::Cleanup(CleanupObservation::new(
                usize::try_from(requested).unwrap_or(usize::MAX),
                removed,
                elapsed,
                consumption,
            )),
        );
    }
}

impl Limiter for PostgresLimiter {
    type Policy = FixedWindowPolicy;
    type Error = CheckError;

    fn check(
        &self,
        check: &Check<'_>,
    ) -> impl Future<Output = Result<Decision, Self::Error>> + Send {
        PostgresLimiter::check(self, check)
    }

    fn check_all(
        &self,
        checks: &[Check<'_>],
    ) -> impl Future<Output = Result<BatchDecision, Self::Error>> + Send {
        PostgresLimiter::check_all(self, checks)
    }
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

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

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

    #[derive(Default)]
    struct RecordingObserver {
        events: Mutex<Vec<(AdmissionOperation, AdmissionOutcome, ConsumptionStatus)>>,
        cleanups: Mutex<Vec<(usize, Option<u64>, ConsumptionStatus)>>,
    }

    impl Observer for RecordingObserver {
        fn observe(&self, observation: &Observation<'_>) {
            match observation {
                Observation::Admission(admission) => self.events.lock().unwrap().push((
                    admission.operation(),
                    admission.outcome(),
                    admission.consumption(),
                )),
                Observation::Cleanup(cleanup) => self.cleanups.lock().unwrap().push((
                    cleanup.requested(),
                    cleanup.removed(),
                    cleanup.consumption(),
                )),
                _ => {}
            }
        }
    }

    struct PanickingObserver;

    impl Observer for PanickingObserver {
        fn observe(&self, _: &Observation<'_>) {
            panic!("injected observer panic");
        }
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
    fn capacity_shard_protocol_has_a_golden_vector() {
        let policy = policy("login", "client");
        let check = Check::new(&policy, key(7));

        assert_eq!(capacity_shard(check.counter_key()), 141);
    }

    #[tokio::test]
    async fn observer_reports_connection_free_operations_and_isolates_panics() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://runlimit:runlimit@127.0.0.1:1/runlimit")
            .expect("syntactically valid database URL");
        let observer = Arc::new(RecordingObserver::default());
        let limiter = PostgresLimiter::new(pool.clone()).with_observer(observer.clone());

        assert_eq!(
            limiter.check_all(&[]).await.unwrap(),
            BatchDecision::Allowed(Vec::new())
        );
        assert_eq!(limiter.cleanup_expired(0).await.unwrap(), 0);
        assert_eq!(
            observer.events.lock().unwrap().as_slice(),
            [(
                AdmissionOperation::Batch,
                AdmissionOutcome::Allowed,
                ConsumptionStatus::NotConsumed,
            )]
        );
        assert_eq!(
            observer.cleanups.lock().unwrap().as_slice(),
            [(0, Some(0), ConsumptionStatus::Consumed)]
        );

        let panicking = PostgresLimiter::new(pool).with_observer(Arc::new(PanickingObserver));
        assert_eq!(
            panicking.check_all(&[]).await.unwrap(),
            BatchDecision::Allowed(Vec::new())
        );
        assert_eq!(panicking.cleanup_expired(0).await.unwrap(), 0);
    }

    #[test]
    fn response_metadata_subtracts_only_authoritative_elapsed_time() {
        let allowed = PendingAllowance {
            limit: 10,
            remaining: 4,
            reset_from_sample: Duration::from_millis(250),
        }
        .finish(Duration::from_millis(80));
        let denied = PendingDenial::QuotaExceeded {
            limit: 10,
            retry_from_sample: Duration::from_millis(150),
        }
        .finish(Duration::from_millis(80));

        assert_eq!(
            allowed.replenishes_after(),
            Some(Duration::from_millis(170))
        );
        assert_eq!(denied.retry_after(), Some(Duration::from_millis(70)));
        assert_eq!(denied.retry_after_seconds(), Some(1));
    }

    #[tokio::test]
    async fn denied_decision_survives_rollback_failure_and_discards_connection() {
        let outcome = finish_denied_transaction(
            Instant::now() + Duration::from_secs(1),
            2,
            PendingDenial::QuotaExceeded {
                limit: 10,
                retry_from_sample: Duration::from_millis(150),
            },
            false,
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
                    capacity: 10,
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
            PendingDenial::QuotaExceeded {
                limit: 1,
                retry_from_sample: Duration::from_millis(50),
            },
            false,
            Duration::ZERO,
            std::future::pending(),
        )
        .await;

        assert!(matches!(
            outcome.decision,
            BatchDecision::Denied {
                index: 0,
                denial: Denial::QuotaExceeded { capacity: 1, .. }
            }
        ));
        assert!(!outcome.connection_reusable);
    }

    #[tokio::test]
    async fn shadow_quota_denial_is_reported_after_rollback() {
        let outcome = finish_denied_transaction(
            Instant::now() + Duration::from_secs(1),
            0,
            PendingDenial::QuotaExceeded {
                limit: 1,
                retry_from_sample: Duration::from_secs(1),
            },
            true,
            Duration::ZERO,
            std::future::ready(Ok(())),
        )
        .await;

        assert!(matches!(
            outcome.decision,
            BatchDecision::ShadowDenied {
                index: 0,
                denial: Denial::QuotaExceeded { capacity: 1, .. }
            }
        ));
        assert!(outcome.connection_reusable);
    }

    #[test]
    fn configuration_bounds_batches_and_deadlines() {
        let defaults = PostgresConfig::new();
        assert_eq!(defaults.maximum_rows_per_shard(), 4_096);
        assert_eq!(defaults.max_batch_size(), 32);
        assert_eq!(defaults.pool_acquire_timeout(), Duration::from_secs(3));
        assert_eq!(defaults.operation_timeout(), Duration::from_secs(3));
        assert_eq!(
            defaults.with_maximum_rows_per_shard(0),
            Err(PostgresConfigError::ZeroMaximumRowsPerShard)
        );
        assert_eq!(
            defaults.with_maximum_rows_per_shard(HARD_MAX_ROWS_PER_SHARD + 1),
            Err(PostgresConfigError::MaximumRowsPerShardTooLarge {
                actual: HARD_MAX_ROWS_PER_SHARD + 1,
                maximum: HARD_MAX_ROWS_PER_SHARD,
            })
        );
        assert_eq!(
            defaults.with_max_batch_size(0),
            Err(PostgresConfigError::ZeroBatchSize)
        );
        assert_eq!(
            defaults.with_pool_acquire_timeout(Duration::ZERO),
            Err(PostgresConfigError::ZeroPoolAcquireTimeout)
        );
        assert_eq!(
            defaults.with_pool_acquire_timeout(Duration::from_secs(61)),
            Err(PostgresConfigError::PoolAcquireTimeoutTooLong {
                actual: Duration::from_secs(61),
                maximum: Duration::from_secs(60),
            })
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
        assert_eq!(
            check_error_consumption(&definite),
            ConsumptionStatus::NotConsumed
        );
        assert_eq!(
            check_error_consumption(&unknown),
            ConsumptionStatus::PossiblyConsumed
        );
        assert_eq!(
            check_error_consumption(&CheckError::CommitTimedOut),
            ConsumptionStatus::PossiblyConsumed
        );
        assert_eq!(
            check_error_consumption(&rolled_back_invariant),
            ConsumptionStatus::NotConsumed
        );
        assert_eq!(
            check_error_consumption(&committed_invariant),
            ConsumptionStatus::Consumed
        );
        assert!(!cleanup_definite.may_have_removed_rows());
        assert!(cleanup_unknown.may_have_removed_rows());
        assert!(MaintenanceError::CommitTimedOut.may_have_removed_rows());
    }

    #[test]
    fn malformed_single_responses_preserve_consumption_status() {
        let denial = Denial::QuotaExceeded {
            capacity: 1,
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
        assert_eq!(
            CLEANUP_SQL.matches("pg_catalog.clock_timestamp()").count(),
            1
        );
        assert!(CLEANUP_SQL.contains("AS MATERIALIZED"));
        assert!(CLEANUP_SQL.contains("SELECT sampled_at\n        FROM authoritative_time"));
        assert!(!CLEANUP_SQL.contains("window_expires_at <= pg_catalog.clock_timestamp()"));
        assert!(CLEANUP_SQL.contains("LIMIT $1"));
        assert!(CLEANUP_SQL.contains("FOR UPDATE SKIP LOCKED"));
        assert!(CLEANUP_SQL.contains("ORDER BY capacity.capacity_shard"));
        assert!(CLEANUP_SQL.contains("FOR UPDATE OF capacity"));
    }

    #[test]
    fn every_production_clock_call_is_catalog_qualified() {
        for (name, sql) in [
            ("batch preflight", BATCH_PREFLIGHT_SQL),
            ("batch upsert", BATCH_UPSERT_SQL),
            ("cleanup", CLEANUP_SQL),
        ] {
            let without_qualified_calls = sql.replace("pg_catalog.clock_timestamp()", "");
            assert!(
                !without_qualified_calls.contains("clock_timestamp()"),
                "{name} contains a search_path-resolved clock_timestamp() call"
            );
        }
    }
}
