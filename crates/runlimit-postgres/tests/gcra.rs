//! Opt-in GCRA tests using disposable PostgreSQL schemas.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use runlimit_core::{
    AdmissionOutcome, BatchDecisionView, BatchError, Check, ConsumptionStatus, DecisionView,
    Denial, GcraPolicy, Limiter, MAX_LIMIT, Observation, Observer, PolicyId, QuotaMode, ScopeId,
    SubjectKey,
};
use runlimit_memory::{Clock, GcraStore, MemoryStoreConfig};
use runlimit_postgres::{
    BatchCheckError, CheckError, GCRA_MIGRATOR, MIGRATOR, PostgresConfig, PostgresGcraLimiter,
};
use sqlx::{AssertSqlSafe, PgPool, postgres::PgPoolOptions};
use tokio::sync::Barrier;

static NEXT_SCHEMA: AtomicU64 = AtomicU64::new(0);

struct Database {
    pool: PgPool,
    admin: PgPool,
    schema: String,
}

impl Database {
    async fn new() -> Self {
        let url = std::env::var("RUNLIMIT_POSTGRES_TEST_DATABASE_URL")
            .expect("disposable PostgreSQL URL required");
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!(
            "runlimit_gcra_{}_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed)
        );
        sqlx::query(AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        let target = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(40)
            .after_connect(move |connection, _| {
                let query = format!("SET search_path = {target}, pg_catalog");
                Box::pin(async move {
                    sqlx::query(AssertSqlSafe(query))
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        PostgresGcraLimiter::new(pool.clone())
            .migrate()
            .await
            .unwrap();
        Self {
            pool,
            admin,
            schema,
        }
    }

    fn limiter(&self) -> PostgresGcraLimiter {
        PostgresGcraLimiter::new(self.pool.clone())
    }

    async fn teardown(self) {
        self.pool.close().await;
        sqlx::query(AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin)
        .await
        .unwrap();
        self.admin.close().await;
    }

    async fn freeze_time(&self) -> u64 {
        let now: i64 = sqlx::query_scalar("WITH sample AS MATERIALIZED (SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT + 3600000 AS now_ms) UPDATE runlimit_gcra_shards SET observed_at_ms = (SELECT now_ms FROM sample) RETURNING observed_at_ms").fetch_one(&self.pool).await.unwrap();
        u64::try_from(now).unwrap()
    }

    async fn row_count(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM runlimit_gcra")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

fn policy(quota: u64, millis: u64, burst: u64) -> GcraPolicy {
    GcraPolicy::new(
        PolicyId::new("auth.peer").unwrap(),
        ScopeId::new("peer").unwrap(),
        quota,
        Duration::from_millis(millis),
        burst,
    )
    .unwrap()
}

fn subject(id: u8, shard: u8, policy: &GcraPolicy) -> SubjectKey {
    let mut bytes = [id; 32];
    bytes[0] = shard ^ policy.fingerprint().as_bytes()[0];
    SubjectKey::from_digest(bytes)
}

#[derive(Clone, Copy)]
struct FrozenClock(u64);
impl Clock for FrozenClock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.0)
    }
}

#[derive(Default)]
struct Recorder(Mutex<Vec<(AdmissionOutcome, ConsumptionStatus)>>);
impl Observer for Recorder {
    fn observe(&self, event: &Observation<'_>) {
        if let Observation::Admission(admission) = event {
            self.0
                .lock()
                .unwrap()
                .push((admission.outcome(), admission.consumption()));
        }
    }
}

#[test]
fn migration_streams_are_independent_and_trait_remains_generic() {
    fn accepts<L: Limiter<Policy = GcraPolicy>>() {}
    assert_eq!(GCRA_MIGRATOR.iter().count(), 1);
    assert!(
        MIGRATOR
            .iter()
            .all(|migration| !migration.sql.as_ref().contains("runlimit_gcra"))
    );
    accepts::<PostgresGcraLimiter>();
}

#[tokio::test]
async fn invalid_batches_and_unpolled_futures_do_not_access_the_database() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://invalid:invalid@127.0.0.1:1/invalid")
        .unwrap();
    let recorder = Arc::new(Recorder::default());
    let limiter = PostgresGcraLimiter::new(pool).with_observer(recorder.clone());
    let policy = policy(1, 1000, 1);
    let check = Check::new(subject(1, 1, &policy).bind(&policy));
    drop(Limiter::check(&limiter, &check));
    drop(Limiter::check_all(&limiter, &[check]));
    assert!(recorder.0.lock().unwrap().is_empty());
    assert!(matches!(
        limiter.check_all(&[]).await,
        Err(BatchCheckError::InvalidBatch(BatchError::EmptyBatch))
    ));
    assert!(matches!(
        limiter.check_all(&[check, check]).await,
        Err(BatchCheckError::InvalidBatch(_))
    ));
    assert_eq!(limiter.cleanup_expired(0).await.unwrap(), 0);
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn installation_is_opt_in_and_preserves_unrelated_migrations() {
    let db = Database::new().await;
    let absent: bool = sqlx::query_scalar("SELECT to_regclass('runlimit_fixed_windows') IS NULL")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(absent);
    db.limiter().migrate().await.unwrap();
    runlimit_postgres::PostgresLimiter::new(db.pool.clone())
        .migrate()
        .await
        .unwrap();
    db.limiter().migrate().await.unwrap();
    db.teardown().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn exact_memory_parity_covers_fractional_refill_weighted_costs_and_shadow_mode() {
    for mode in [QuotaMode::Enforce, QuotaMode::Shadow] {
        let db = Database::new().await;
        let now = db.freeze_time().await;
        let memory = GcraStore::builder(MemoryStoreConfig::new(8).unwrap())
            .with_clock(FrozenClock(now))
            .build();
        let policy = policy(3, 10, 7).with_quota_mode(mode);
        let limiter = db.limiter();
        for cost in [3, 2, 3, 1, 2, 1] {
            let check = Check::new(subject(1, 0, &policy).bind(&policy))
                .with_cost(cost)
                .unwrap();
            assert_eq!(
                limiter.check(&check).await.unwrap(),
                memory.check(&check).unwrap()
            );
        }
        let checks = [
            Check::new(subject(2, 0, &policy).bind(&policy))
                .with_cost(4)
                .unwrap(),
            Check::new(subject(3, 1, &policy).bind(&policy))
                .with_cost(5)
                .unwrap(),
        ];
        assert_eq!(
            limiter.check_all(&checks).await.unwrap(),
            memory.check_all(&checks).unwrap()
        );
        db.teardown().await;
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn denial_rolls_back_every_member_and_returns_first_input_failure() {
    let db = Database::new().await;
    db.freeze_time().await;
    let policy = policy(1, 1000, 1);
    let earlier = Check::new(subject(1, 0, &policy).bind(&policy));
    let exhausted = Check::new(subject(2, 1, &policy).bind(&policy));
    let limiter = db.limiter();
    assert!(limiter.check(&exhausted).await.unwrap().permits_request());
    let denial = limiter.check_all(&[earlier, exhausted]).await.unwrap();
    assert!(matches!(
        denial.view(),
        BatchDecisionView::Denied { index: 1, .. }
    ));
    assert!(limiter.check(&earlier).await.unwrap().permits_request());
    assert_eq!(db.row_count().await, 2);
    db.teardown().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn independent_replicas_and_opposite_batches_cannot_over_admit() {
    let db = Database::new().await;
    db.freeze_time().await;
    let policy = Arc::new(policy(1, 1000, 7));
    let barrier = Arc::new(Barrier::new(33));
    let mut tasks = Vec::new();
    for index in 0..32 {
        let limiter = db.limiter();
        let policy = policy.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            let a = Check::new(subject(1, 0, &policy).bind(policy.as_ref()));
            let b = Check::new(subject(2, 255, &policy).bind(policy.as_ref()));
            let checks = if index % 2 == 0 { [a, b] } else { [b, a] };
            barrier.wait().await;
            limiter.check_all(&checks).await.unwrap().permits_request()
        }));
    }
    barrier.wait().await;
    let mut allowed = 0;
    for task in tasks {
        allowed += usize::from(task.await.unwrap());
    }
    assert_eq!(allowed, 7);
    assert_eq!(db.row_count().await, 2);
    db.teardown().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn shard_capacity_is_atomic_enforced_in_shadow_and_existing_rows_remain_usable() {
    let db = Database::new().await;
    let policy = policy(1, 1000, 3).with_quota_mode(QuotaMode::Shadow);
    let limiter = db.limiter().with_config(
        PostgresConfig::new()
            .with_maximum_rows_per_shard(1)
            .unwrap(),
    );
    let existing = Check::new(subject(1, 0, &policy).bind(&policy));
    let fresh = Check::new(subject(2, 0, &policy).bind(&policy));
    assert!(limiter.check(&existing).await.unwrap().permits_request());
    let denied = limiter.check_all(&[existing, fresh]).await.unwrap();
    assert!(matches!(
        denied.view(),
        BatchDecisionView::Denied {
            index: 1,
            denial: Denial::StorageCapacity { .. },
            ..
        }
    ));
    let allowed = limiter.check(&existing).await.unwrap();
    assert!(
        matches!(allowed.view(), DecisionView::Allowed { allowance } if allowance.available() == 1)
    );
    assert_eq!(db.row_count().await, 1);
    db.teardown().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn concurrent_new_subjects_cannot_exceed_capacity() {
    let db = Database::new().await;
    let policy = Arc::new(policy(1, 1000, 3));
    let mut tasks = Vec::new();
    for id in 0..24 {
        let limiter = db.limiter().with_config(
            PostgresConfig::new()
                .with_maximum_rows_per_shard(2)
                .unwrap(),
        );
        let policy = policy.clone();
        tasks.push(tokio::spawn(async move {
            limiter
                .check(&Check::new(subject(id, 0, &policy).bind(&policy)))
                .await
                .unwrap()
                .permits_request()
        }));
    }
    let mut allowed = 0;
    for task in tasks {
        allowed += usize::from(task.await.unwrap());
    }
    assert_eq!(allowed, 2);
    assert_eq!(db.row_count().await, 2);
    let ledger: i64 = sqlx::query_scalar("SELECT sum(row_count)::BIGINT FROM runlimit_gcra_shards")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(ledger, 2);
    db.teardown().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn bounded_cleanup_releases_slots_and_skips_busy_shards() {
    let db = Database::new().await;
    let policy = policy(1, 1000, 1);
    let limiter = db.limiter();
    for id in 1..=3 {
        assert!(
            limiter
                .check(&Check::new(subject(id, 0, &policy).bind(&policy)))
                .await
                .unwrap()
                .permits_request()
        );
    }
    sqlx::query("UPDATE runlimit_gcra SET expires_at_ms = 0, tat_scaled = 0")
        .execute(&db.pool)
        .await
        .unwrap();
    let mut blocker = db.pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM runlimit_gcra_shards WHERE capacity_shard = 0 FOR UPDATE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    assert_eq!(limiter.cleanup_expired(2).await.unwrap(), 0);
    blocker.rollback().await.unwrap();
    assert_eq!(limiter.cleanup_expired(2).await.unwrap(), 2);
    assert_eq!(db.row_count().await, 1);
    let ledger: i64 =
        sqlx::query_scalar("SELECT row_count FROM runlimit_gcra_shards WHERE capacity_shard = 0")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(ledger, 1);
    assert_eq!(limiter.cleanup_expired(2).await.unwrap(), 1);
    db.teardown().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn database_time_replenishes_continuously_without_window_boundary_burst() {
    let db = Database::new().await;
    let policy = policy(2, 400, 2);
    let check = Check::new(subject(1, 0, &policy).bind(&policy));
    let limiter = db.limiter();
    assert!(
        limiter
            .check(&check.with_cost(2).unwrap())
            .await
            .unwrap()
            .permits_request()
    );
    tokio::time::sleep(Duration::from_millis(230)).await;
    assert!(limiter.check(&check).await.unwrap().permits_request());
    assert!(!limiter.check(&check).await.unwrap().permits_request());
    db.teardown().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn committed_database_clock_watermark_survives_clock_regression() {
    let db = Database::new().await;
    let now = db.freeze_time().await;
    let policy = policy(1, 1000, 1);
    let check = Check::new(subject(1, 0, &policy).bind(&policy));
    let limiter = db.limiter();
    assert!(limiter.check(&check).await.unwrap().permits_request());
    let decision = limiter.check(&check).await.unwrap();
    assert!(
        matches!(decision.view(), DecisionView::Denied { denial: Denial::QuotaExceeded(quota) } if quota.retry_after().duration() == Duration::from_secs(1))
    );
    let observed: i64 = sqlx::query_scalar(
        "SELECT observed_at_ms FROM runlimit_gcra_shards WHERE capacity_shard = 0",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(u64::try_from(observed).unwrap(), now);
    db.teardown().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn full_policy_integer_range_stays_exact_and_malformed_state_is_precommit() {
    let db = Database::new().await;
    db.freeze_time().await;
    let policy = policy(MAX_LIMIT, 1000, MAX_LIMIT);
    let check = Check::new(subject(1, 0, &policy).bind(&policy));
    let limiter = db.limiter();
    let allowed = limiter
        .check(&check.with_cost(MAX_LIMIT).unwrap())
        .await
        .unwrap();
    assert!(
        matches!(allowed.view(), DecisionView::Allowed { allowance } if allowance.available() == 0)
    );
    assert!(!limiter.check(&check).await.unwrap().permits_request());
    sqlx::query("UPDATE runlimit_gcra SET tat_scaled = 999999999999999999999999999999999999999")
        .execute(&db.pool)
        .await
        .unwrap();
    let error = limiter.check(&check).await.unwrap_err();
    assert!(matches!(error, CheckError::StorageInvariant(_)));
    assert_eq!(error.consumption(), ConsumptionStatus::NotConsumed);
    db.teardown().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn shard_lock_timeout_is_not_consumed_and_releases_connection() {
    let db = Database::new().await;
    let policy = policy(1, 1000, 1);
    let check = Check::new(subject(1, 0, &policy).bind(&policy));
    let limiter = db.limiter().with_config(
        PostgresConfig::new()
            .with_operation_timeout(Duration::from_millis(70))
            .unwrap(),
    );
    let mut blocker = db.pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM runlimit_gcra_shards WHERE capacity_shard = 0 FOR UPDATE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let error = limiter.check(&check).await.unwrap_err();
    assert!(matches!(error, CheckError::TimedOutBeforeCommit { .. }));
    assert_eq!(error.consumption(), ConsumptionStatus::NotConsumed);
    blocker.rollback().await.unwrap();
    assert_eq!(db.row_count().await, 0);
    assert!(limiter.check(&check).await.unwrap().permits_request());
    db.teardown().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn database_ceiling_enforces_bounds_even_for_direct_inserts() {
    let db = Database::new().await;
    let policy = policy(1, 1000, 1);
    let key = subject(1, 0, &policy);
    // Simulate a full ledger without spending time on 65,536 fixture rows.
    sqlx::query("UPDATE runlimit_gcra_shards SET row_count = 65536 WHERE capacity_shard = 0")
        .execute(&db.pool)
        .await
        .unwrap();
    let error = sqlx::query("INSERT INTO runlimit_gcra(config_fingerprint, subject_key, tat_scaled, expires_at_ms) VALUES ($1, $2, 1, 1)")
        .bind(policy.fingerprint().as_bytes().as_slice()).bind(key.as_bytes().as_slice())
        .execute(&db.pool).await.unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23514")
    );
    assert_eq!(db.row_count().await, 0);
    db.teardown().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn commit_timeout_is_explicitly_uncertain_and_never_replayed() {
    let db = Database::new().await;
    sqlx::raw_sql("CREATE FUNCTION slow_gcra_commit() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.3); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER slow_commit AFTER INSERT ON runlimit_gcra DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION slow_gcra_commit();")
        .execute(&db.pool).await.unwrap();
    let policy = policy(1, 1000, 1);
    let check = Check::new(subject(1, 0, &policy).bind(&policy));
    let observer = Arc::new(Recorder::default());
    let limiter = db
        .limiter()
        .with_config(
            PostgresConfig::new()
                .with_operation_timeout(Duration::from_millis(100))
                .unwrap(),
        )
        .with_observer(observer.clone());
    let error = limiter.check(&check).await.unwrap_err();
    assert!(matches!(
        error,
        CheckError::CommitOutcomeUnknown(_) | CheckError::CommitTimedOut
    ));
    assert_eq!(error.consumption(), ConsumptionStatus::PossiblyConsumed);
    assert_eq!(
        observer.0.lock().unwrap().as_slice(),
        &[(
            AdmissionOutcome::Failed,
            ConsumptionStatus::PossiblyConsumed
        )]
    );
    // The injected server timeout rolls back this particular commit. The API
    // conservatively reports uncertainty rather than generalizing this fact.
    assert_eq!(db.row_count().await, 0);
    db.teardown().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn cancellation_before_admission_cannot_late_commit() {
    let db = Database::new().await;
    let policy = policy(1, 1000, 1);
    let mut blocker = db.pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM runlimit_gcra_shards WHERE capacity_shard = 0 FOR UPDATE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let limiter = db.limiter();
    let pending = tokio::spawn(async move {
        limiter
            .check(&Check::new(subject(1, 0, &policy).bind(&policy)))
            .await
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let waiters: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE 'SELECT capacity_shard, row_count, observed_at_ms FROM runlimit_gcra_shards%'")
                .fetch_one(&db.admin).await.unwrap();
            if waiters > 0 { break; }
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    blocker.rollback().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(db.row_count().await, 0);
    db.teardown().await;
}
