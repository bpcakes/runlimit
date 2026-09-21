//! Live transaction, concurrency, capacity, and fencing tests for attempts.
use runlimit_core::{
    KeyHasher, PolicyId, QuotaPeriod, ScopeId,
    attempts::{
        AttemptAdmission, AttemptCompletionResult, AttemptDenial, AttemptOutcome, AttemptPolicy,
        StagedAttemptCompletion,
    },
};
use runlimit_postgres::{
    PostgresConfig,
    attempts::{PgAttemptClaimResult, PgAttemptReceipt, PostgresAttemptLimiter, low_level},
};
use sqlx::{AssertSqlSafe, PgPool, postgres::PgPoolOptions};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
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
            "runlimit_attempt_{}_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        sqlx::query(AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        let target = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .after_connect(move |connection, _| {
                let query = format!("SET search_path={target},pg_catalog");
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
        PostgresAttemptLimiter::new(pool.clone())
            .migrate()
            .await
            .unwrap();
        Self {
            pool,
            admin,
            schema,
        }
    }
    async fn close(self) {
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
}
fn period(ms: u64) -> QuotaPeriod {
    QuotaPeriod::new(Duration::from_millis(ms)).unwrap()
}
fn policy() -> AttemptPolicy {
    AttemptPolicy::new(
        PolicyId::new("auth").unwrap(),
        ScopeId::new("identifier").unwrap(),
        period(10),
        period(40),
        period(1000),
        period(30_000),
    )
    .unwrap()
}
fn receipt(value: AttemptAdmission<PgAttemptReceipt>) -> PgAttemptReceipt {
    match value {
        AttemptAdmission::Admitted(r) => r,
        AttemptAdmission::Denied(d) => panic!("denied {d:?}"),
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn failure_escalation_cap_and_success_reset() {
    let db = Database::new().await;
    let limiter = PostgresAttemptLimiter::new(db.pool.clone());
    let p = policy();
    let h = KeyHasher::new([7; 32]).unwrap();
    let s = h.hash_attempt_for(&p, b"user");
    for (failures, delay) in [(1, 10), (2, 20), (3, 40), (4, 40)] {
        let r = receipt(limiter.admit(s).await.unwrap());
        let AttemptCompletionResult::Applied(done) =
            limiter.complete(r, AttemptOutcome::Failure).await.unwrap()
        else {
            panic!()
        };
        assert_eq!(done.consecutive_failures(), failures);
        assert_eq!(done.retry_after().duration(), Duration::from_millis(delay));
        sqlx::query("UPDATE runlimit_attempts SET retry_at_ms=0")
            .execute(&db.pool)
            .await
            .unwrap();
    }
    let r = receipt(limiter.admit(s).await.unwrap());
    assert!(
        matches!(limiter.complete(r,AttemptOutcome::Success).await.unwrap(),AttemptCompletionResult::Applied(done) if done.consecutive_failures()==0)
    );
    let r = receipt(limiter.admit(s).await.unwrap());
    assert!(
        matches!(limiter.complete(r,AttemptOutcome::Abandoned).await.unwrap(),AttemptCompletionResult::Applied(done) if done.consecutive_failures()==1)
    );
    db.close().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn concurrent_replicas_admit_exactly_one_verification() {
    let db = Database::new().await;
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let pool = db.pool.clone();
        tasks.push(tokio::spawn(async move {
            let p = policy();
            let h = KeyHasher::new([7; 32]).unwrap();
            PostgresAttemptLimiter::new(pool)
                .admit(h.hash_attempt_for(&p, b"user"))
                .await
                .unwrap()
        }));
    }
    let mut admitted = 0;
    for task in tasks {
        match task.await.unwrap() {
            AttemptAdmission::Admitted(_) => admitted += 1,
            AttemptAdmission::Denied(AttemptDenial::Busy { .. }) => {}
            other @ AttemptAdmission::Denied(_) => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(admitted, 1);
    db.close().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn completion_and_application_writes_rollback_together() {
    let db = Database::new().await;
    sqlx::query("CREATE TABLE app_events (id INT)")
        .execute(&db.pool)
        .await
        .unwrap();
    let limiter = PostgresAttemptLimiter::new(db.pool.clone());
    let p = policy();
    let h = KeyHasher::new([7; 32]).unwrap();
    let s = h.hash_attempt_for(&p, b"user");
    let r = receipt(limiter.admit(s).await.unwrap());
    let mut tx = db.pool.begin().await.unwrap();
    let PgAttemptClaimResult::Claimed(claim) = low_level::claim_in(&mut *tx, r).await.unwrap()
    else {
        panic!()
    };
    sqlx::query("INSERT INTO app_events VALUES(1)")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(matches!(
        low_level::finish_in(&mut *tx, claim, AttemptOutcome::Failure)
            .await
            .unwrap(),
        StagedAttemptCompletion::Applied(_)
    ));
    tx.rollback().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM app_events")
            .fetch_one(&db.pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT failures FROM runlimit_attempts")
            .fetch_one(&db.pool)
            .await
            .unwrap(),
        0
    );
    assert!(matches!(
        limiter.admit(s).await.unwrap(),
        AttemptAdmission::Denied(AttemptDenial::Busy { .. })
    ));
    db.close().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn claim_is_transaction_fenced_and_survives_lease_elapsed_while_locked() {
    let db = Database::new().await;
    let limiter = PostgresAttemptLimiter::new(db.pool.clone());
    let p = policy();
    let h = KeyHasher::new([7; 32]).unwrap();
    let s = h.hash_attempt_for(&p, b"user");
    let r = receipt(limiter.admit(s).await.unwrap());
    let mut tx = db.pool.begin().await.unwrap();
    let PgAttemptClaimResult::Claimed(claim) = low_level::claim_in(&mut *tx, r).await.unwrap()
    else {
        panic!()
    };
    sqlx::query("UPDATE runlimit_attempts SET lease_until_ms=0")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(matches!(
        low_level::finish_in(&mut *tx, claim, AttemptOutcome::Success)
            .await
            .unwrap(),
        StagedAttemptCompletion::Applied(_)
    ));
    tx.commit().await.unwrap();
    let r = receipt(limiter.admit(s).await.unwrap());
    let mut tx = db.pool.begin().await.unwrap();
    let PgAttemptClaimResult::Claimed(claim) = low_level::claim_in(&mut *tx, r).await.unwrap()
    else {
        panic!()
    };
    tx.commit().await.unwrap();
    let mut other = db.pool.begin().await.unwrap();
    assert_eq!(
        low_level::finish_in(&mut *other, claim, AttemptOutcome::Success)
            .await
            .unwrap(),
        StagedAttemptCompletion::Stale
    );
    other.rollback().await.unwrap();
    assert!(matches!(
        limiter.admit(s).await.unwrap(),
        AttemptAdmission::Denied(AttemptDenial::Busy { .. })
    ));
    db.close().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn expired_receipt_cannot_clear_newer_failures() {
    let db = Database::new().await;
    let limiter = PostgresAttemptLimiter::new(db.pool.clone());
    let p = policy();
    let h = KeyHasher::new([7; 32]).unwrap();
    let s = h.hash_attempt_for(&p, b"user");
    let old = receipt(limiter.admit(s).await.unwrap());
    sqlx::query("UPDATE runlimit_attempts SET lease_until_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint-100").execute(&db.pool).await.unwrap();
    let new = receipt(limiter.admit(s).await.unwrap());
    assert_eq!(
        limiter
            .complete(old, AttemptOutcome::Success)
            .await
            .unwrap(),
        AttemptCompletionResult::Stale
    );
    assert!(
        matches!(limiter.complete(new,AttemptOutcome::Failure).await.unwrap(),AttemptCompletionResult::Applied(done) if done.consecutive_failures()==2)
    );
    db.close().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn capacity_is_bounded_and_quiet_expiry_reclaims_slots() {
    let db = Database::new().await;
    let limiter = PostgresAttemptLimiter::new(db.pool.clone()).with_config(
        PostgresConfig::new()
            .with_maximum_rows_per_shard(1)
            .unwrap(),
    );
    let p = policy();
    let h = KeyHasher::new([7; 32]).unwrap();
    let first = h.hash_attempt_for(&p, b"first");
    let shard = first.into_unbound_subject_key().as_bytes()[0];
    let other = (0..10000)
        .map(|value| value.to_string())
        .find(|value| {
            h.hash_attempt_for(&p, value)
                .into_unbound_subject_key()
                .as_bytes()[0]
                == shard
        })
        .unwrap();
    let second = h.hash_attempt_for(&p, &other);
    drop(receipt(limiter.admit(first).await.unwrap()));
    assert!(matches!(
        limiter.admit(second).await.unwrap(),
        AttemptAdmission::Denied(AttemptDenial::StorageCapacity)
    ));
    sqlx::query("UPDATE runlimit_attempts SET lease_until_ms=0")
        .execute(&db.pool)
        .await
        .unwrap();
    drop(receipt(limiter.admit(second).await.unwrap()));
    assert!(
        sqlx::query("UPDATE runlimit_attempts SET capacity_slot=65536")
            .execute(&db.pool)
            .await
            .is_err()
    );
    db.close().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn dropped_unpolled_admission_does_no_work() {
    let db = Database::new().await;
    let limiter = PostgresAttemptLimiter::new(db.pool.clone());
    let p = policy();
    let h = KeyHasher::new([7; 32]).unwrap();
    drop(limiter.admit(h.hash_attempt_for(&p, b"user")));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM runlimit_attempts")
            .fetch_one(&db.pool)
            .await
            .unwrap(),
        0
    );
    db.close().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn claim_checks_expiry_after_waiting_for_the_row_lock() {
    let db = Database::new().await;
    let limiter = PostgresAttemptLimiter::new(db.pool.clone());
    let p = policy();
    let h = KeyHasher::new([7; 32]).unwrap();
    let r = receipt(
        limiter
            .admit(h.hash_attempt_for(&p, b"user"))
            .await
            .unwrap(),
    );
    let mut blocker = db.pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM runlimit_attempts FOR UPDATE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let mut waiting = db.pool.acquire().await.unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *waiting)
        .await
        .unwrap();
    let task = tokio::spawn(async move {
        use sqlx::Acquire;
        let mut tx = waiting.begin().await.unwrap();
        let result = low_level::claim_in(&mut *tx, r).await.unwrap();
        tx.rollback().await.unwrap();
        result
    });
    let mut observed_wait = false;
    for _ in 0..200 {
        let waiting: bool = sqlx::query_scalar(
            "SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1",
        )
        .bind(pid)
        .fetch_one(&db.admin)
        .await
        .unwrap();
        if waiting {
            observed_wait = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(observed_wait, "claim never waited for row lock");
    sqlx::query("UPDATE runlimit_attempts SET lease_until_ms=0")
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    assert!(matches!(task.await.unwrap(), PgAttemptClaimResult::Stale));
    db.close().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn cancelled_host_transaction_does_not_reset_retry_state() {
    let db = Database::new().await;
    let limiter = PostgresAttemptLimiter::new(db.pool.clone());
    let p = policy();
    let h = KeyHasher::new([7; 32]).unwrap();
    let s = h.hash_attempt_for(&p, b"user");
    let r = receipt(limiter.admit(s).await.unwrap());
    let mut tx = db.pool.begin().await.unwrap();
    let PgAttemptClaimResult::Claimed(claim) = low_level::claim_in(&mut *tx, r).await.unwrap()
    else {
        panic!()
    };
    assert!(matches!(
        low_level::finish_in(&mut *tx, claim, AttemptOutcome::Success)
            .await
            .unwrap(),
        StagedAttemptCompletion::Applied(_)
    ));
    drop(tx); // SQLx queues rollback; no completion is published by the owner.
    assert!(matches!(
        limiter.admit(s).await.unwrap(),
        AttemptAdmission::Denied(AttemptDenial::Busy { .. })
    ));
    db.close().await;
}
