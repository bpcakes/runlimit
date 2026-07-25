//! Opt-in integration tests against a real `PostgreSQL` database.

use std::{
    process,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use runlimit_core::{
    BatchDecision, Check, Decision, Denial, FixedWindowPolicy, MAX_LIMIT, MAX_WINDOW,
    MAX_WINDOW_MILLIS, PolicyId, ScopeId, SubjectKey,
};
use runlimit_memory::{Clock, MemoryStore, MemoryStoreConfig};
use runlimit_postgres::{CheckError, MIGRATOR, MaintenanceError, PostgresConfig, PostgresLimiter};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, migrate::Migrate, postgres::PgPoolOptions};
use tokio::{sync::Barrier, time::sleep};

const TEST_DATABASE_URL: &str = "RUNLIMIT_POSTGRES_TEST_DATABASE_URL";
const CLEANUP_SQL: &str = include_str!("../src/cleanup_expired.sql");
const TEST_HOST_MIGRATION_VERSION: i64 = 20_260_722_000_000;
const PUBLISHED_CREATE_MIGRATION_VERSION: i64 = 20_260_723_000_000;
const FILLFACTOR_MIGRATION_VERSION: i64 = 20_260_725_000_000;
const ADVISORY_LOCK_DOMAIN: &[u8] = b"runlimit/postgres-advisory-lock/v1\0";
const PUBLISHED_CREATE_MIGRATION_SHA384: [u8; 48] = [
    0x31, 0xd9, 0x3f, 0xde, 0x98, 0xc2, 0x36, 0x4a, 0x33, 0x06, 0x2e, 0x37, 0x35, 0x08, 0xf5, 0x63,
    0xb4, 0x86, 0xdf, 0x28, 0x98, 0xf8, 0xe7, 0x73, 0x65, 0x91, 0x8e, 0x81, 0xda, 0x89, 0x80, 0xa8,
    0xe7, 0x4b, 0xf9, 0xc6, 0x30, 0x22, 0xd2, 0x51, 0xae, 0xb3, 0xd5, 0x80, 0x67, 0xe9, 0x80, 0xec,
];
static NEXT_POLICY: AtomicU64 = AtomicU64::new(0);

#[test]
fn published_create_migration_is_immutable_and_fillfactor_is_additive() {
    let migrations = MIGRATOR.iter().collect::<Vec<_>>();

    assert!(migrations.len() >= 2);
    assert_eq!(migrations[0].version, PUBLISHED_CREATE_MIGRATION_VERSION);
    assert_eq!(migrations[1].version, FILLFACTOR_MIGRATION_VERSION);
    assert_eq!(
        migrations[0].checksum.as_ref(),
        PUBLISHED_CREATE_MIGRATION_SHA384
    );
    assert!(!migrations[0].sql.contains("fillfactor"));
    assert!(migrations[1].sql.contains("SET (fillfactor = 80)"));
}

async fn test_pool(maximum_connections: u32) -> PgPool {
    let database_url = std::env::var(TEST_DATABASE_URL)
        .expect("RUNLIMIT_POSTGRES_TEST_DATABASE_URL is required for ignored integration tests");
    let pool = PgPoolOptions::new()
        .max_connections(maximum_connections)
        .connect(&database_url)
        .await
        .expect("connect to integration-test PostgreSQL");
    PostgresLimiter::new(pool.clone())
        .migrate()
        .await
        .expect("apply Runlimit migrations");
    pool
}

async fn isolated_migration_test_pools(maximum_connections: u32) -> (PgPool, PgPool, String) {
    let database_url = std::env::var(TEST_DATABASE_URL)
        .expect("RUNLIMIT_POSTGRES_TEST_DATABASE_URL is required for ignored integration tests");
    let setup_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("connect migration-test setup pool");
    let schema_suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos();
    let schema = format!("runlimit_migration_{}_{}", process::id(), schema_suffix);
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&setup_pool)
        .await
        .expect("create isolated migration-test schema");

    let connection_schema = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(maximum_connections)
        .after_connect(move |connection, _metadata| {
            let search_path_sql = format!("SET search_path = {connection_schema}, pg_catalog");
            Box::pin(async move {
                sqlx::query(&search_path_sql).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&database_url)
        .await
        .expect("connect isolated migration-test pool");

    (setup_pool, pool, schema)
}

async fn run_test_host_migrations(pool: &PgPool) {
    let mut migrator = sqlx::migrate!("./tests/host-migrations");
    migrator.set_ignore_missing(true);
    migrator
        .run(pool)
        .await
        .expect("apply host migrations configured to ignore unrelated versions");
}

async fn drop_migration_test_schema(setup_pool: PgPool, pool: PgPool, schema: &str) {
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&setup_pool)
        .await
        .expect("drop isolated migration-test schema");
    setup_pool.close().await;
}

async fn counter_table_options(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        r"
SELECT COALESCE(reloptions, ARRAY[]::TEXT[])
FROM pg_catalog.pg_class
WHERE oid = 'runlimit_fixed_windows'::regclass
",
    )
    .fetch_one(pool)
    .await
    .expect("read counter table storage options")
}

fn unique_policy(label: &str, limit: u64, window: Duration) -> FixedWindowPolicy {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos();
    let sequence = NEXT_POLICY.fetch_add(1, Ordering::Relaxed);
    FixedWindowPolicy::new(
        PolicyId::new(format!(
            "test.{label}.{}.{}.{}",
            process::id(),
            timestamp,
            sequence
        ))
        .expect("generated policy identifier is valid"),
        ScopeId::new("subject").expect("static scope identifier is valid"),
        limit,
        window,
    )
    .expect("generated fixed-window policy is valid")
}

fn key(value: u8) -> SubjectKey {
    SubjectKey::from_digest([value; 32])
}

fn advisory_lock_id(check: &Check<'_>) -> i64 {
    let mut digest = Sha256::new();
    digest.update(ADVISORY_LOCK_DOMAIN);
    digest.update(check.counter_key().to_bytes());
    let digest = digest.finalize();
    let mut id_bytes = [0_u8; 8];
    id_bytes.copy_from_slice(&digest[..8]);
    i64::from_be_bytes(id_bytes)
}

fn test_config() -> PostgresConfig {
    PostgresConfig::new()
        .with_operation_timeout(Duration::from_secs(10))
        .expect("test timeout is valid")
}

#[derive(Clone, Default)]
struct ConformanceClock {
    now_millis: Arc<AtomicU64>,
}

impl ConformanceClock {
    fn set(&self, now_millis: u64) {
        self.now_millis.store(now_millis, Ordering::Relaxed);
    }
}

impl Clock for ConformanceClock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.now_millis.load(Ordering::Relaxed))
    }
}

#[derive(Clone, Copy, Debug)]
struct TransitionStep {
    name: &'static str,
    at_millis: u64,
    cost: u64,
    expected: Decision,
}

const FIXED_WINDOW_TRANSITIONS: [TransitionStep; 6] = [
    TransitionStep {
        name: "new window",
        at_millis: 0,
        cost: 2,
        expected: Decision::allowed(5, 3, Duration::from_millis(10)),
    },
    TransitionStep {
        name: "live increment",
        at_millis: 3,
        cost: 2,
        expected: Decision::allowed(5, 1, Duration::from_millis(7)),
    },
    TransitionStep {
        name: "live denial",
        at_millis: 3,
        cost: 2,
        expected: Decision::denied(Denial::QuotaExceeded {
            limit: 5,
            retry_after: Duration::from_millis(7),
        }),
    },
    TransitionStep {
        name: "exact fill after denial",
        at_millis: 9,
        cost: 1,
        expected: Decision::allowed(5, 0, Duration::from_millis(1)),
    },
    TransitionStep {
        name: "full-window denial",
        at_millis: 9,
        cost: 1,
        expected: Decision::denied(Denial::QuotaExceeded {
            limit: 5,
            retry_after: Duration::from_millis(1),
        }),
    },
    TransitionStep {
        name: "exact-expiry renewal",
        at_millis: 10,
        cost: 3,
        expected: Decision::allowed(5, 2, Duration::from_millis(10)),
    },
];

async fn create_transition_clock(pool: &PgPool) -> String {
    let schema_suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos();
    let schema = format!("runlimit_transition_{}_{}", process::id(), schema_suffix);
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(pool)
        .await
        .expect("create transition-test schema");
    sqlx::query(&format!(
        r"
CREATE TABLE {schema}.authoritative_clock (
    sampled_at TIMESTAMPTZ NOT NULL
)
"
    ))
    .execute(pool)
    .await
    .expect("create transition-test clock table");
    sqlx::query(&format!(
        r"
INSERT INTO {schema}.authoritative_clock (sampled_at)
VALUES (TIMESTAMPTZ '2040-01-01 00:00:00+00')
"
    ))
    .execute(pool)
    .await
    .expect("initialize transition-test clock");
    sqlx::query(&format!(
        r"
CREATE FUNCTION {schema}.clock_timestamp()
RETURNS TIMESTAMPTZ
LANGUAGE sql
STABLE
AS $function$
    SELECT sampled_at
    FROM {schema}.authoritative_clock
$function$
"
    ))
    .execute(pool)
    .await
    .expect("create transition-test clock function");
    schema
}

async fn connect_with_transition_clock(schema: &str) -> PgPool {
    let database_url =
        std::env::var(TEST_DATABASE_URL).expect("test URL remains available during test");
    let connection_schema = schema.to_owned();
    PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |connection, _metadata| {
            let search_path_sql =
                format!("SET search_path = {connection_schema}, pg_catalog, public");
            Box::pin(async move {
                sqlx::query(&search_path_sql).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&database_url)
        .await
        .expect("connect pool with the transition-test clock")
}

async fn set_transition_clock(
    pool: &PgPool,
    schema: &str,
    now_millis: u64,
) -> Result<(), sqlx::Error> {
    sqlx::query(&format!(
        r"
UPDATE {schema}.authoritative_clock
SET sampled_at =
    TIMESTAMPTZ '2040-01-01 00:00:00+00'
    + $1::BIGINT * INTERVAL '1 millisecond'
"
    ))
    .bind(i64::try_from(now_millis).expect("test clock fits PostgreSQL BIGINT"))
    .execute(pool)
    .await
    .map(|_| ())
}

async fn drop_transition_clock(pool: &PgPool, schema: &str) {
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(pool)
        .await
        .expect("drop transition-test schema");
}

async fn delete_counter(pool: &PgPool, policy: &FixedWindowPolicy, subject: SubjectKey) -> u64 {
    sqlx::query(
        r"
DELETE FROM runlimit_fixed_windows
WHERE
    config_fingerprint = $1
    AND subject_key = $2
",
    )
    .bind(policy.fingerprint().as_bytes().as_slice())
    .bind(subject.as_bytes().as_slice())
    .execute(pool)
    .await
    .expect("delete test counter")
    .rows_affected()
}

async fn stored_counter_usage(
    pool: &PgPool,
    policy: &FixedWindowPolicy,
    subject: SubjectKey,
) -> i64 {
    sqlx::query_scalar(
        r"
SELECT used
FROM runlimit_fixed_windows
WHERE
    config_fingerprint = $1
    AND subject_key = $2
",
    )
    .bind(policy.fingerprint().as_bytes().as_slice())
    .bind(subject.as_bytes().as_slice())
    .fetch_one(pool)
    .await
    .expect("read test counter usage")
}

async fn wait_for_advisory_waiters(pool: &PgPool, query_fragment: &str, minimum: i64) {
    for _ in 0..200 {
        let waiting: i64 = sqlx::query_scalar(
            r"
SELECT count(*)
FROM pg_stat_activity
WHERE
    datname = current_database()
    AND state = 'active'
    AND wait_event_type = 'Lock'
    AND wait_event = 'advisory'
    AND position($1 IN query) > 0
",
        )
        .bind(query_fragment)
        .fetch_one(pool)
        .await
        .expect("inspect advisory-lock waiters");
        if waiting >= minimum {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("did not observe {minimum} advisory-lock waiter(s) running {query_fragment:?}");
}

async fn insert_counter_window(
    pool: &PgPool,
    policy: &FixedWindowPolicy,
    subject: SubjectKey,
    starts_after_seconds: i64,
    expires_after_seconds: i64,
) {
    sqlx::query(
        r"
INSERT INTO runlimit_fixed_windows (
    policy_id,
    scope_id,
    config_fingerprint,
    subject_key,
    window_started_at,
    window_expires_at,
    used
)
VALUES (
    $1,
    $2,
    $3,
    $4,
    clock_timestamp() + $5::BIGINT * INTERVAL '1 second',
    clock_timestamp() + $6::BIGINT * INTERVAL '1 second',
    1
)
",
    )
    .bind(policy.id().as_str())
    .bind(policy.scope().as_str())
    .bind(policy.fingerprint().as_bytes().as_slice())
    .bind(subject.as_bytes().as_slice())
    .bind(starts_after_seconds)
    .bind(expires_after_seconds)
    .execute(pool)
    .await
    .expect("insert counter with a controlled window");
}

async fn counter_exists(pool: &PgPool, policy: &FixedWindowPolicy, subject: SubjectKey) -> bool {
    sqlx::query_scalar(
        r"
SELECT EXISTS (
    SELECT 1
    FROM runlimit_fixed_windows
    WHERE
        config_fingerprint = $1
        AND subject_key = $2
)
",
    )
    .bind(policy.fingerprint().as_bytes().as_slice())
    .bind(subject.as_bytes().as_slice())
    .fetch_one(pool)
    .await
    .expect("check whether the test counter exists")
}

async fn isolated_cleanup_test_pools(maximum_connections: u32) -> (PgPool, PgPool, String) {
    let setup_pool = test_pool(1).await;
    let schema_suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos();
    let schema = format!("runlimit_cleanup_{}_{}", process::id(), schema_suffix);
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&setup_pool)
        .await
        .expect("create isolated cleanup-test schema");

    let database_url =
        std::env::var(TEST_DATABASE_URL).expect("test URL remains available during test");
    let connection_schema = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(maximum_connections)
        .after_connect(move |connection, _metadata| {
            let search_path_sql = format!("SET search_path = {connection_schema}, pg_catalog");
            Box::pin(async move {
                sqlx::query(&search_path_sql).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&database_url)
        .await
        .expect("connect isolated cleanup-test pool");
    sqlx::raw_sql(include_str!(
        "../migrations/20260723000000_create_runlimit_fixed_windows.sql"
    ))
    .execute(&pool)
    .await
    .expect("create isolated cleanup-test table");

    (setup_pool, pool, schema)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires RUNLIMIT_POSTGRES_TEST_DATABASE_URL"]
async fn cleanup_uses_an_indexable_cutoff_and_skips_locked_rows() {
    let (setup_pool, pool, schema) = isolated_cleanup_test_pools(4).await;
    let limiter = PostgresLimiter::with_config(pool.clone(), test_config());
    let locked_policy = unique_policy("cleanup-locked-expired", 1, Duration::from_secs(1));
    let expired_policy = unique_policy("cleanup-expired", 1, Duration::from_secs(1));
    let active_policy = unique_policy("cleanup-active", 1, Duration::from_secs(3_600));
    let locked_subject = key(151);
    let expired_subject = key(152);
    let active_subject = key(153);

    let mut plan_transaction = pool.begin().await.expect("begin plan transaction");
    sqlx::query("SET LOCAL enable_seqscan = off")
        .execute(&mut *plan_transaction)
        .await
        .expect("make the cleanup access path deterministic");
    let plan_sql = format!("EXPLAIN (COSTS OFF) {CLEANUP_SQL}");
    let plan = sqlx::query_scalar::<_, String>(&plan_sql)
        .bind(1_i64)
        .fetch_all(&mut *plan_transaction)
        .await
        .expect("explain the production cleanup statement");
    plan_transaction
        .rollback()
        .await
        .expect("finish plan transaction");
    let plan = plan.join("\n");
    assert!(
        plan.contains("Index Scan using runlimit_fixed_windows_expiry_idx"),
        "cleanup did not use the expiry index:\n{plan}"
    );
    assert!(
        plan.lines()
            .any(|line| line.contains("Index Cond:") && line.contains("window_expires_at")),
        "cleanup did not use expiry as an index condition:\n{plan}"
    );

    insert_counter_window(&pool, &locked_policy, locked_subject, -7_200, -3_600).await;
    insert_counter_window(&pool, &expired_policy, expired_subject, -3_600, -1_800).await;
    insert_counter_window(&pool, &active_policy, active_subject, 0, 3_600).await;

    let mut blocker = pool.begin().await.expect("begin cleanup blocker");
    sqlx::query(
        r"
SELECT 1
FROM runlimit_fixed_windows
WHERE
    config_fingerprint = $1
    AND subject_key = $2
FOR UPDATE
",
    )
    .bind(locked_policy.fingerprint().as_bytes().as_slice())
    .bind(locked_subject.as_bytes().as_slice())
    .fetch_one(&mut *blocker)
    .await
    .expect("lock the oldest expired counter");

    let first_cleanup = limiter
        .cleanup_expired(1)
        .await
        .expect("cleanup skips the locked row");
    assert_eq!(first_cleanup, 1);
    assert!(counter_exists(&pool, &locked_policy, locked_subject).await);
    assert!(!counter_exists(&pool, &expired_policy, expired_subject).await);
    assert!(counter_exists(&pool, &active_policy, active_subject).await);

    let active_only = limiter
        .cleanup_expired(1)
        .await
        .expect("cleanup ignores active rows");
    assert_eq!(active_only, 0);

    blocker.commit().await.expect("unlock expired counter");
    let unlocked_cleanup = limiter
        .cleanup_expired(1)
        .await
        .expect("cleanup removes the unlocked expired row");
    assert_eq!(unlocked_cleanup, 1);
    assert!(!counter_exists(&pool, &locked_policy, locked_subject).await);
    assert!(counter_exists(&pool, &active_policy, active_subject).await);

    let deleted_active = delete_counter(&pool, &active_policy, active_subject).await;
    drop(limiter);
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&setup_pool)
        .await
        .expect("drop isolated cleanup-test schema");
    setup_pool.close().await;
    assert_eq!(deleted_active, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires RUNLIMIT_POSTGRES_TEST_DATABASE_URL"]
async fn cleanup_timeout_cannot_late_commit_and_releases_pool_slot() {
    let (setup_pool, pool, schema) = isolated_cleanup_test_pools(1).await;
    let policy = unique_policy("cleanup-timeout", 1, Duration::from_secs(1));
    let subject = key(154);
    insert_counter_window(&pool, &policy, subject, -7_200, -3_600).await;

    let trigger_sql = format!(
        r"
CREATE FUNCTION {schema}.sleep_before_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $function$
BEGIN
    PERFORM pg_catalog.pg_sleep(1);
    RETURN OLD;
END
$function$;

CREATE TRIGGER sleep_before_delete
BEFORE DELETE ON {schema}.runlimit_fixed_windows
FOR EACH ROW
EXECUTE FUNCTION {schema}.sleep_before_delete();
"
    );
    sqlx::raw_sql(&trigger_sql)
        .execute(&setup_pool)
        .await
        .expect("create delayed cleanup trigger");

    let short_config = PostgresConfig::new()
        .with_operation_timeout(Duration::from_millis(100))
        .expect("short nonzero timeout is valid");
    let limiter = PostgresLimiter::with_config(pool.clone(), short_config);
    let error = limiter
        .cleanup_expired(1)
        .await
        .expect_err("delayed cleanup exceeds its operation deadline");
    assert!(matches!(
        error,
        MaintenanceError::TimedOutBeforeCommit { .. }
    ));
    assert!(!error.may_have_removed_rows());

    let probe: i32 = tokio::time::timeout(
        Duration::from_millis(500),
        sqlx::query_scalar("SELECT 1").fetch_one(&pool),
    )
    .await
    .expect("timed-out cleanup releases the only pool slot")
    .expect("replacement pool query succeeds");
    assert_eq!(probe, 1);

    let cancellation_config = PostgresConfig::new()
        .with_operation_timeout(Duration::from_secs(5))
        .expect("long cleanup timeout is valid");
    let cancellable_limiter = PostgresLimiter::with_config(pool.clone(), cancellation_config);
    let cancelled = tokio::time::timeout(
        Duration::from_millis(100),
        cancellable_limiter.cleanup_expired(1),
    )
    .await;
    assert!(
        cancelled.is_err(),
        "outer deadline must cancel cleanup before its configured deadline"
    );

    let probe_after_cancellation: i32 = tokio::time::timeout(
        Duration::from_millis(500),
        sqlx::query_scalar("SELECT 1").fetch_one(&pool),
    )
    .await
    .expect("cancelled cleanup releases the only pool slot")
    .expect("pool query after cancellation succeeds");
    assert_eq!(probe_after_cancellation, 1);

    // Observe through an independent connection after the injected statement
    // would have completed if either deadline had only dropped its query
    // future.
    sleep(Duration::from_millis(1_100)).await;
    let row_exists_sql = format!(
        r"
SELECT EXISTS (
    SELECT 1
    FROM {schema}.runlimit_fixed_windows
    WHERE
        config_fingerprint = $1
        AND subject_key = $2
)
"
    );
    let row_exists: bool = sqlx::query_scalar(&row_exists_sql)
        .bind(policy.fingerprint().as_bytes().as_slice())
        .bind(subject.as_bytes().as_slice())
        .fetch_one(&setup_pool)
        .await
        .expect("observe cleanup row through an independent connection");
    assert!(row_exists, "timed-out cleanup must not commit later");

    drop(limiter);
    drop(cancellable_limiter);
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&setup_pool)
        .await
        .expect("drop isolated cleanup-timeout schema");
    setup_pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires RUNLIMIT_POSTGRES_TEST_DATABASE_URL"]
async fn migration_coexists_with_an_ignore_missing_host_and_discards_errors() {
    let (setup_pool, pool, schema) = isolated_migration_test_pools(1).await;
    let limiter = PostgresLimiter::new(pool.clone());

    // Both migrators must opt in to a shared SQLx history. Exercise both run
    // orders twice so each migrator sees the other's already-applied version.
    run_test_host_migrations(&pool).await;
    limiter
        .migrate()
        .await
        .expect("Runlimit accepts the host migration version");
    run_test_host_migrations(&pool).await;
    limiter
        .migrate()
        .await
        .expect("Runlimit migration remains repeatable");

    let mut expected_versions = MIGRATOR
        .iter()
        .map(|migration| migration.version)
        .collect::<Vec<_>>();
    let applied_versions =
        sqlx::query_scalar::<_, i64>("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .expect("read shared migration history");
    expected_versions.push(TEST_HOST_MIGRATION_VERSION);
    expected_versions.sort_unstable();
    assert_eq!(applied_versions, expected_versions);

    let tables_exist = sqlx::query_as::<_, (bool, bool)>(
        r"
SELECT
    to_regclass('runlimit_test_host_marker') IS NOT NULL,
    to_regclass('runlimit_fixed_windows') IS NOT NULL
",
    )
    .fetch_one(&pool)
    .await
    .expect("check both migration products");
    assert_eq!(tables_exist, (true, true));

    // A checksum error occurs after SQLx takes its session advisory lock. The
    // failed migration connection must be closed instead of returned locked to
    // this single-connection pool.
    sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = $2")
        .bind(vec![0_u8; 48])
        .bind(PUBLISHED_CREATE_MIGRATION_VERSION)
        .execute(&pool)
        .await
        .expect("corrupt Runlimit checksum for the failure-path test");
    let locked_backend: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&pool)
        .await
        .expect("read migration backend PID");

    let error = limiter
        .migrate()
        .await
        .expect_err("modified migration checksum must fail");
    assert!(matches!(
        error,
        sqlx::migrate::MigrateError::VersionMismatch(version)
            if version == PUBLISHED_CREATE_MIGRATION_VERSION
    ));

    let replacement_backend: i32 = tokio::time::timeout(
        Duration::from_secs(2),
        sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&pool),
    )
    .await
    .expect("failed migration releases the only pool slot")
    .expect("replacement connection is usable");
    assert_ne!(
        replacement_backend, locked_backend,
        "the possibly locked migration session must not return to the pool"
    );

    drop(limiter);
    drop_migration_test_schema(setup_pool, pool, &schema).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires RUNLIMIT_POSTGRES_TEST_DATABASE_URL"]
async fn migration_upgrades_the_published_0_1_table_additively() {
    let (setup_pool, pool, schema) = isolated_migration_test_pools(1).await;
    let published_create_migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == PUBLISHED_CREATE_MIGRATION_VERSION)
        .expect("published create migration remains bundled");

    let mut connection = pool
        .acquire()
        .await
        .expect("acquire published-migration setup connection");
    connection
        .ensure_migrations_table()
        .await
        .expect("create published migration history");
    connection
        .apply(published_create_migration)
        .await
        .expect("apply published create migration");
    drop(connection);

    assert!(
        !counter_table_options(&pool)
            .await
            .iter()
            .any(|option| option.starts_with("fillfactor=")),
        "the published 0.1.0 migration unexpectedly contains storage tuning"
    );

    let limiter = PostgresLimiter::new(pool.clone());
    limiter
        .migrate()
        .await
        .expect("apply additive migrations to the published schema");

    let applied_versions =
        sqlx::query_scalar::<_, i64>("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .expect("read upgraded migration history");
    let expected_versions = MIGRATOR
        .iter()
        .map(|migration| migration.version)
        .collect::<Vec<_>>();
    assert_eq!(applied_versions, expected_versions);
    let table_options = counter_table_options(&pool).await;
    assert!(
        table_options.iter().any(|option| option == "fillfactor=80"),
        "upgraded table options do not reserve space for HOT updates: {table_options:?}"
    );

    drop(limiter);
    drop_migration_test_schema(setup_pool, pool, &schema).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires RUNLIMIT_POSTGRES_TEST_DATABASE_URL"]
async fn cancelling_migration_discards_its_session_lock() {
    let (setup_pool, pool, schema) = isolated_migration_test_pools(1).await;
    run_test_host_migrations(&pool).await;
    let migration_backend: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&pool)
        .await
        .expect("read migration backend PID");

    // Block history inspection after SQLx has acquired its session-scoped
    // migration lock, then observe that lock before cancelling the future.
    let mut blocker = setup_pool
        .begin()
        .await
        .expect("begin migration metadata blocker");
    sqlx::query(&format!(
        "LOCK TABLE {schema}._sqlx_migrations IN ACCESS EXCLUSIVE MODE"
    ))
    .execute(&mut *blocker)
    .await
    .expect("block migration metadata access");

    let limiter = PostgresLimiter::new(pool.clone());
    let migration_task = tokio::spawn({
        let limiter = limiter.clone();
        async move { limiter.migrate().await }
    });

    let mut observed_session_lock = false;
    for _ in 0..100 {
        observed_session_lock = sqlx::query_scalar(
            r"
SELECT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_locks
    WHERE
        pid = $1
        AND locktype = 'advisory'
        AND granted
)
",
        )
        .bind(migration_backend)
        .fetch_one(&setup_pool)
        .await
        .expect("inspect migration advisory lock");
        if observed_session_lock {
            break;
        }
        assert!(
            !migration_task.is_finished(),
            "migration unexpectedly finished while metadata was locked"
        );
        sleep(Duration::from_millis(10)).await;
    }
    assert!(
        observed_session_lock,
        "migration never reached its session advisory lock"
    );

    migration_task.abort();
    let cancelled = migration_task
        .await
        .expect_err("aborted migration task must be cancelled");
    assert!(cancelled.is_cancelled());
    blocker
        .rollback()
        .await
        .expect("release migration metadata blocker");

    let replacement_backend: i32 = tokio::time::timeout(
        Duration::from_secs(2),
        sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&pool),
    )
    .await
    .expect("cancelled migration releases the only pool slot")
    .expect("replacement connection is usable");
    assert_ne!(
        replacement_backend, migration_backend,
        "the cancelled migration session must not return to the pool"
    );
    tokio::time::timeout(Duration::from_secs(2), limiter.migrate())
        .await
        .expect("the cancelled session lock was released")
        .expect("Runlimit migration succeeds after cancellation");

    drop(limiter);
    drop_migration_test_schema(setup_pool, pool, &schema).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires RUNLIMIT_POSTGRES_TEST_DATABASE_URL"]
async fn migration_sets_counter_key_fillfactor_and_retains_metadata() {
    let pool = test_pool(1).await;
    let primary_key_columns = sqlx::query_scalar::<_, String>(
        r"
SELECT attributes.attname::TEXT
FROM pg_catalog.pg_constraint AS constraints
CROSS JOIN LATERAL unnest(constraints.conkey)
    WITH ORDINALITY AS key_columns(attnum, position)
INNER JOIN pg_catalog.pg_attribute AS attributes
    ON attributes.attrelid = constraints.conrelid
    AND attributes.attnum = key_columns.attnum
WHERE
    constraints.conrelid = 'runlimit_fixed_windows'::regclass
    AND constraints.contype = 'p'
ORDER BY key_columns.position
",
    )
    .fetch_all(&pool)
    .await
    .expect("read migrated primary-key columns");
    assert_eq!(primary_key_columns, ["config_fingerprint", "subject_key"]);

    let table_options = counter_table_options(&pool).await;
    assert!(
        table_options.iter().any(|option| option == "fillfactor=80"),
        "migrated table options do not reserve space for HOT updates: {table_options:?}"
    );

    let policy = unique_policy("counter-key-metadata", 3, Duration::from_secs(60));
    let subject = key(155);
    let limiter = PostgresLimiter::with_config(pool.clone(), test_config());
    assert!(
        limiter
            .check(&Check::new(&policy, subject))
            .await
            .expect("admit metadata test check")
            .is_allowed()
    );
    let metadata = sqlx::query_as::<_, (String, String)>(
        r"
SELECT policy_id, scope_id
FROM runlimit_fixed_windows
WHERE
    config_fingerprint = $1
    AND subject_key = $2
",
    )
    .bind(policy.fingerprint().as_bytes().as_slice())
    .bind(subject.as_bytes().as_slice())
    .fetch_one(&pool)
    .await
    .expect("read retained policy metadata by counter key");

    let deleted_rows = delete_counter(&pool, &policy, subject).await;
    drop(limiter);
    pool.close().await;

    assert_eq!(metadata.0, policy.id().as_str());
    assert_eq!(metadata.1, policy.scope().as_str());
    assert_eq!(deleted_rows, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires RUNLIMIT_POSTGRES_TEST_DATABASE_URL"]
async fn single_quota_denial_and_anchored_reset() {
    let pool = test_pool(4).await;
    let limiter = PostgresLimiter::with_config(pool, test_config());
    let policy = unique_policy("single", 2, Duration::from_millis(250));
    let check = Check::new(&policy, key(1));

    let first = limiter.check(&check).await.expect("first check succeeds");
    assert!(first.is_allowed());
    assert_eq!(first.remaining(), Some(1));
    assert!(first.reset_after().is_some_and(|reset| !reset.is_zero()));

    let second = limiter.check(&check).await.expect("second check succeeds");
    assert!(second.is_allowed());
    assert_eq!(second.remaining(), Some(0));

    let denied = limiter.check(&check).await.expect("denial is a decision");
    assert!(denied.is_denied());
    assert!(matches!(
        denied.denial(),
        Some(Denial::QuotaExceeded { .. })
    ));
    let retry_after = denied.retry_after().expect("quota denial has retry time");
    assert!(!retry_after.is_zero());
    assert!(retry_after <= policy.window());

    sleep(retry_after + Duration::from_millis(20)).await;
    let reset = limiter
        .check(&check)
        .await
        .expect("check after expiry succeeds");
    assert!(reset.is_allowed());
    assert_eq!(reset.remaining(), Some(1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires RUNLIMIT_POSTGRES_TEST_DATABASE_URL"]
async fn portable_policy_upper_bounds_are_stored_exactly() {
    let pool = test_pool(1).await;
    let limiter = PostgresLimiter::with_config(pool.clone(), test_config());
    let policy = unique_policy("portable-maximum", MAX_LIMIT, MAX_WINDOW);
    let subject = key(7);
    let check = Check::with_cost(&policy, subject, MAX_LIMIT).unwrap();

    let allowed = limiter.check(&check).await.expect("maximum check succeeds");

    let (stored_used, stored_window_millis): (i64, i64) = sqlx::query_as(
        r"
SELECT
    used,
    (EXTRACT(EPOCH FROM (window_expires_at - window_started_at)) * 1000)::BIGINT
FROM runlimit_fixed_windows
WHERE
    config_fingerprint = $1
    AND subject_key = $2
",
    )
    .bind(policy.fingerprint().as_bytes().as_slice())
    .bind(subject.as_bytes().as_slice())
    .fetch_one(&pool)
    .await
    .expect("read maximum counter");

    let denied = limiter
        .check(&check)
        .await
        .expect("maximum quota denial succeeds");

    let deleted_rows = delete_counter(&pool, &policy, subject).await;
    drop(limiter);
    pool.close().await;

    assert!(allowed.is_allowed());
    assert_eq!(allowed.limit(), Some(MAX_LIMIT));
    assert_eq!(allowed.remaining(), Some(0));
    assert_eq!(stored_used, i64::MAX);
    assert_eq!(
        u64::try_from(stored_window_millis).unwrap(),
        MAX_WINDOW_MILLIS
    );
    assert!(denied.is_denied());
    assert_eq!(denied.limit(), Some(MAX_LIMIT));
    assert_eq!(deleted_rows, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires RUNLIMIT_POSTGRES_TEST_DATABASE_URL"]
async fn denied_batch_rolls_back_every_counter() {
    let pool = test_pool(4).await;
    let limiter = PostgresLimiter::with_config(pool, test_config());
    let first_policy = unique_policy("batch-first", 2, Duration::from_secs(5));
    let saturated_policy = unique_policy("batch-saturated", 1, Duration::from_secs(5));
    let first_check = Check::new(&first_policy, key(2));
    let saturated_check = Check::new(&saturated_policy, key(3));

    assert!(
        limiter
            .check(&saturated_check)
            .await
            .expect("initial saturation succeeds")
            .is_allowed()
    );

    let batch = limiter
        .check_all(&[first_check, saturated_check])
        .await
        .expect("denied batch is a decision");
    assert!(matches!(
        batch,
        BatchDecision::Denied {
            index: 1,
            denial: _
        }
    ));

    let after_rollback = limiter
        .check(&first_check)
        .await
        .expect("counter remains usable");
    assert_eq!(after_rollback.remaining(), Some(1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires RUNLIMIT_POSTGRES_TEST_DATABASE_URL"]
async fn earliest_denial_skips_a_later_failing_statement() {
    let pool = test_pool(4).await;
    let limiter = PostgresLimiter::with_config(pool.clone(), test_config());
    let denied_policy = unique_policy("batch-a-denied", 1, Duration::from_secs(5));
    let failing_policy = unique_policy("batch-z-errors", 10, Duration::from_secs(5));
    let denied_subject = key(8);
    let failing_subject = key(9);
    let denied_check = Check::new(&denied_policy, denied_subject);
    let failing_check = Check::new(&failing_policy, failing_subject);

    let saturated = limiter
        .check(&denied_check)
        .await
        .expect("saturating check succeeds");
    assert!(saturated.is_allowed());

    sqlx::query(
        r"
CREATE OR REPLACE FUNCTION runlimit_test_fail_later_batch_check()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.policy_id LIKE 'test.batch-z-errors.%' THEN
        RAISE EXCEPTION 'injected failure for a later batch check';
    END IF;
    RETURN NEW;
END
$$
",
    )
    .execute(&pool)
    .await
    .expect("create scoped failure trigger function");
    sqlx::query(
        r"
DROP TRIGGER IF EXISTS runlimit_test_fail_later_batch_check
ON runlimit_fixed_windows
",
    )
    .execute(&pool)
    .await
    .expect("drop stale scoped failure trigger");
    sqlx::query(
        r"
CREATE TRIGGER runlimit_test_fail_later_batch_check
BEFORE INSERT OR UPDATE ON runlimit_fixed_windows
FOR EACH ROW
EXECUTE FUNCTION runlimit_test_fail_later_batch_check()
",
    )
    .execute(&pool)
    .await
    .expect("create scoped failure trigger");

    let injected_error = limiter.check(&failing_check).await;
    let batch = limiter.check_all(&[denied_check, failing_check]).await;

    sqlx::query(
        r"
DROP TRIGGER runlimit_test_fail_later_batch_check
ON runlimit_fixed_windows
",
    )
    .execute(&pool)
    .await
    .expect("drop scoped failure trigger");
    sqlx::query("DROP FUNCTION runlimit_test_fail_later_batch_check()")
        .execute(&pool)
        .await
        .expect("drop scoped failure trigger function");
    let deleted_rows = delete_counter(&pool, &denied_policy, denied_subject).await;

    assert!(matches!(
        injected_error,
        Err(CheckError::DefinitelyNotConsumed(_))
    ));
    assert!(matches!(
        batch.expect("later failing statement must not replace a known denial"),
        BatchDecision::Denied {
            index: 0,
            denial: _
        }
    ));
    assert_eq!(deleted_rows, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires RUNLIMIT_POSTGRES_TEST_DATABASE_URL"]
async fn a_window_expiring_exactly_at_the_clock_sample_resets() {
    let setup_pool = test_pool(1).await;
    let policy = unique_policy("exact-expiry-boundary", 1, Duration::from_secs(5));
    let subject = key(10);
    let check = Check::new(&policy, subject);

    sqlx::query(
        r"
DROP SCHEMA IF EXISTS runlimit_test_exact_clock CASCADE
",
    )
    .execute(&setup_pool)
    .await
    .expect("drop stale exact-clock schema");
    sqlx::query("CREATE SCHEMA runlimit_test_exact_clock")
        .execute(&setup_pool)
        .await
        .expect("create exact-clock schema");
    sqlx::query(
        r"
CREATE FUNCTION runlimit_test_exact_clock.clock_timestamp()
RETURNS TIMESTAMPTZ
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT TIMESTAMPTZ '2040-01-01 00:00:00+00'
$$
",
    )
    .execute(&setup_pool)
    .await
    .expect("create exact-clock function");
    sqlx::query(
        r"
INSERT INTO runlimit_fixed_windows (
    policy_id,
    scope_id,
    config_fingerprint,
    subject_key,
    window_started_at,
    window_expires_at,
    used
)
VALUES (
    $1,
    $2,
    $3,
    $4,
    TIMESTAMPTZ '2039-12-31 23:59:59.999+00',
    TIMESTAMPTZ '2040-01-01 00:00:00+00',
    1
)
",
    )
    .bind(policy.id().as_str())
    .bind(policy.scope().as_str())
    .bind(policy.fingerprint().as_bytes().as_slice())
    .bind(subject.as_bytes().as_slice())
    .execute(&setup_pool)
    .await
    .expect("insert counter expiring exactly at the test clock");

    let database_url =
        std::env::var(TEST_DATABASE_URL).expect("test URL remains available during test");
    let exact_clock_pool = PgPoolOptions::new()
        .max_connections(2)
        .after_connect(|connection, _metadata| {
            Box::pin(async move {
                sqlx::query("SET search_path = runlimit_test_exact_clock, pg_catalog, public")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&database_url)
        .await
        .expect("connect pool with the exact test clock");
    let limiter = PostgresLimiter::with_config(exact_clock_pool.clone(), test_config());

    let reset = limiter.check(&check).await;

    drop(limiter);
    exact_clock_pool.close().await;
    let deleted_rows = delete_counter(&setup_pool, &policy, subject).await;
    sqlx::query("DROP SCHEMA runlimit_test_exact_clock CASCADE")
        .execute(&setup_pool)
        .await
        .expect("drop exact-clock schema");
    setup_pool.close().await;

    let reset = reset.expect("a window expiring at the sample resets");
    assert!(reset.is_allowed());
    assert_eq!(reset.remaining(), Some(0));
    assert_eq!(deleted_rows, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires RUNLIMIT_POSTGRES_TEST_DATABASE_URL"]
async fn memory_and_postgres_share_fixed_window_transition_semantics() {
    let setup_pool = test_pool(1).await;
    let clock_schema = create_transition_clock(&setup_pool).await;
    let postgres_pool = connect_with_transition_clock(&clock_schema).await;
    let postgres = PostgresLimiter::with_config(postgres_pool.clone(), test_config());
    let memory_clock = ConformanceClock::default();
    let memory = MemoryStore::with_clock(
        MemoryStoreConfig::new(1).expect("test memory capacity is valid"),
        memory_clock.clone(),
    );
    let policy = unique_policy("fixed-window-conformance", 5, Duration::from_millis(10));
    let subject = key(11);

    let observations = async {
        let mut observations = Vec::with_capacity(FIXED_WINDOW_TRANSITIONS.len());
        for step in FIXED_WINDOW_TRANSITIONS {
            memory_clock.set(step.at_millis);
            set_transition_clock(&setup_pool, &clock_schema, step.at_millis).await?;

            let check = Check::with_cost(&policy, subject, step.cost)?;
            let memory_decision = memory.check(&check)?;
            let postgres_decision = postgres.check(&check).await?;
            observations.push((step, memory_decision, postgres_decision));
        }
        Ok::<_, Box<dyn std::error::Error>>(observations)
    }
    .await;

    let deleted_rows = delete_counter(&setup_pool, &policy, subject).await;
    drop(postgres);
    postgres_pool.close().await;
    drop_transition_clock(&setup_pool, &clock_schema).await;
    setup_pool.close().await;

    let observations = observations.expect("both backends replay the transition sequence");
    for (step, memory_decision, postgres_decision) in observations {
        assert_eq!(
            memory_decision, postgres_decision,
            "backends diverged at the '{}' transition",
            step.name
        );
        assert_eq!(
            memory_decision, step.expected,
            "memory returned the wrong '{}' transition",
            step.name
        );
        assert_eq!(
            postgres_decision, step.expected,
            "PostgreSQL returned the wrong '{}' transition",
            step.name
        );
    }
    assert_eq!(deleted_rows, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires RUNLIMIT_POSTGRES_TEST_DATABASE_URL"]
async fn set_based_batch_preserves_caller_order_and_array_alignment() {
    let pool = test_pool(4).await;
    let limiter = PostgresLimiter::with_config(pool.clone(), test_config());
    let policies = (0_u64..32)
        .map(|index| {
            unique_policy(
                &format!("set-array-{index:02}"),
                50 + index * 3,
                Duration::from_millis(1_000 + index),
            )
        })
        .collect::<Vec<_>>();
    let checks = policies
        .iter()
        .enumerate()
        .rev()
        .map(|(index, policy)| {
            Check::with_cost(
                policy,
                key(100 + u8::try_from(index).unwrap()),
                u64::try_from(index % 7 + 1).unwrap(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    let result = limiter.check_all(&checks).await;

    let fingerprints = checks
        .iter()
        .map(|check| check.policy().fingerprint().as_bytes().to_vec())
        .collect::<Vec<_>>();
    let subjects = checks
        .iter()
        .map(|check| check.subject().as_bytes().to_vec())
        .collect::<Vec<_>>();
    let stored_usage = sqlx::query_as::<_, (i64, i64, i64)>(
        r"
WITH input AS (
    SELECT *
    FROM unnest($1::BYTEA[], $2::BYTEA[])
        WITH ORDINALITY AS keys(config_fingerprint, subject_key, input_position)
)
SELECT
    input.input_position,
    windows.used,
    (EXTRACT(EPOCH FROM (
        windows.window_expires_at - windows.window_started_at
    )) * 1000)::BIGINT
FROM input
INNER JOIN runlimit_fixed_windows AS windows
    ON windows.config_fingerprint = input.config_fingerprint
    AND windows.subject_key = input.subject_key
ORDER BY input.input_position
",
    )
    .bind(fingerprints)
    .bind(subjects)
    .fetch_all(&pool)
    .await
    .expect("read set-based batch counters in caller order");

    let mut deleted_rows = 0;
    for check in &checks {
        deleted_rows += delete_counter(&pool, check.policy(), check.subject()).await;
    }

    let BatchDecision::Allowed(decisions) = result.expect("set-based batch succeeds") else {
        panic!("fresh counters must all be allowed");
    };
    assert_eq!(decisions.len(), checks.len());
    for (decision, check) in decisions.iter().zip(&checks) {
        assert!(decision.is_allowed());
        assert_eq!(decision.limit(), Some(check.policy().limit()));
        assert_eq!(
            decision.remaining(),
            Some(check.policy().limit() - check.cost())
        );
    }

    assert_eq!(stored_usage.len(), checks.len());
    for (caller_index, ((input_position, used, window_millis), check)) in
        stored_usage.iter().zip(&checks).enumerate()
    {
        assert_eq!(usize::try_from(*input_position).unwrap(), caller_index + 1);
        assert_eq!(u64::try_from(*used).unwrap(), check.cost());
        assert_eq!(
            u64::try_from(*window_millis).unwrap(),
            check.policy().window_millis()
        );
    }
    assert_eq!(deleted_rows, u64::try_from(checks.len()).unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires RUNLIMIT_POSTGRES_TEST_DATABASE_URL"]
async fn opposite_order_batches_across_pools_do_not_deadlock_or_over_admit() {
    const ROUNDS: u64 = 8;

    let first_pool = test_pool(4).await;
    let database_url =
        std::env::var(TEST_DATABASE_URL).expect("test URL remains available during test");
    let second_pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("connect second replica pool");
    let first_limiter = PostgresLimiter::with_config(first_pool.clone(), test_config());
    let second_limiter = PostgresLimiter::with_config(second_pool, test_config());
    let policy_a = Arc::new(unique_policy(
        "opposite-order-a",
        ROUNDS * 2,
        Duration::from_secs(10),
    ));
    let policy_b = Arc::new(unique_policy(
        "opposite-order-b",
        ROUNDS * 2,
        Duration::from_secs(10),
    ));
    let subject_a = key(140);
    let subject_b = key(141);
    let mut outcomes = Vec::with_capacity(usize::try_from(ROUNDS).unwrap());

    for _ in 0..ROUNDS {
        let barrier = Arc::new(Barrier::new(3));

        let first_task_limiter = first_limiter.clone();
        let first_task_barrier = Arc::clone(&barrier);
        let first_task_a = Arc::clone(&policy_a);
        let first_task_b = Arc::clone(&policy_b);
        let first_task = tokio::spawn(async move {
            let checks = [
                Check::new(&first_task_a, subject_a),
                Check::new(&first_task_b, subject_b),
            ];
            first_task_barrier.wait().await;
            first_task_limiter.check_all(&checks).await
        });

        let second_task_limiter = second_limiter.clone();
        let second_task_barrier = Arc::clone(&barrier);
        let second_task_a = Arc::clone(&policy_a);
        let second_task_b = Arc::clone(&policy_b);
        let second_task = tokio::spawn(async move {
            let checks = [
                Check::new(&second_task_b, subject_b),
                Check::new(&second_task_a, subject_a),
            ];
            second_task_barrier.wait().await;
            second_task_limiter.check_all(&checks).await
        });

        barrier.wait().await;
        outcomes.push((first_task.await, second_task.await));
    }

    let stored_a = stored_counter_usage(&first_pool, &policy_a, subject_a).await;
    let stored_b = stored_counter_usage(&first_pool, &policy_b, subject_b).await;
    let after_capacity = first_limiter
        .check_all(&[
            Check::new(&policy_a, subject_a),
            Check::new(&policy_b, subject_b),
        ])
        .await;

    let deleted_a = delete_counter(&first_pool, &policy_a, subject_a).await;
    let deleted_b = delete_counter(&first_pool, &policy_b, subject_b).await;

    for (first, second) in outcomes {
        for outcome in [first, second] {
            let outcome = outcome
                .expect("contending batch task does not panic")
                .expect("opposite-order batch completes before its deadline");
            let BatchDecision::Allowed(decisions) = outcome else {
                panic!("capacity permits every contending batch");
            };
            assert_eq!(decisions.len(), 2);
            assert!(decisions.iter().all(runlimit_core::Decision::is_allowed));
        }
    }
    assert_eq!(u64::try_from(stored_a).unwrap(), ROUNDS * 2);
    assert_eq!(u64::try_from(stored_b).unwrap(), ROUNDS * 2);
    assert!(matches!(
        after_capacity.expect("post-capacity batch is a decision"),
        BatchDecision::Denied {
            index: 0,
            denial: _
        }
    ));
    assert_eq!(deleted_a, 1);
    assert_eq!(deleted_b, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires RUNLIMIT_POSTGRES_TEST_DATABASE_URL"]
async fn concurrent_pools_never_over_admit() {
    let first_pool = test_pool(24).await;
    let database_url =
        std::env::var(TEST_DATABASE_URL).expect("test URL remains available during test");
    let second_pool = PgPoolOptions::new()
        .max_connections(24)
        .connect(&database_url)
        .await
        .expect("connect second replica pool");
    let first_limiter = PostgresLimiter::with_config(first_pool, test_config());
    let second_limiter = PostgresLimiter::with_config(second_pool, test_config());
    let policy = Arc::new(unique_policy("concurrent", 12, Duration::from_secs(10)));
    let barrier = Arc::new(Barrier::new(49));
    let mut tasks = Vec::with_capacity(48);

    for index in 0_usize..48 {
        let limiter = if index.is_multiple_of(2) {
            first_limiter.clone()
        } else {
            second_limiter.clone()
        };
        let policy = Arc::clone(&policy);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            limiter
                .check(&Check::new(&policy, key(4)))
                .await
                .expect("concurrent check completes")
                .is_allowed()
        }));
    }

    barrier.wait().await;
    let mut admitted = 0;
    for task in tasks {
        admitted += usize::from(task.await.expect("check task does not panic"));
    }

    assert_eq!(admitted, 12);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires RUNLIMIT_POSTGRES_TEST_DATABASE_URL"]
async fn concurrent_fresh_single_checks_advance_the_waiters_snapshot() {
    let pool = test_pool(6).await;
    let limiter = PostgresLimiter::with_config(pool.clone(), test_config());
    let policy = Arc::new(unique_policy(
        "concurrent-fresh-single",
        1,
        Duration::from_secs(10),
    ));
    let subject = key(156);
    let check = Check::new(&policy, subject);
    let logical_lock_id = advisory_lock_id(&check);

    let mut blocker = pool.begin().await.expect("begin logical-lock blocker");
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(logical_lock_id)
        .execute(&mut *blocker)
        .await
        .expect("hold the fresh key's logical lock");

    let barrier = Arc::new(Barrier::new(3));
    let mut tasks = Vec::with_capacity(2);
    for _ in 0..2 {
        let task_limiter = limiter.clone();
        let task_policy = Arc::clone(&policy);
        let task_barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            task_barrier.wait().await;
            task_limiter.check(&Check::new(&task_policy, subject)).await
        }));
    }
    barrier.wait().await;

    wait_for_advisory_waiters(&pool, "WITH advisory_lock AS MATERIALIZED", 2).await;

    blocker.commit().await.expect("release fresh-key lock");

    let mut allowed = 0;
    let mut denied = 0;
    for task in tasks {
        let decision = task
            .await
            .expect("fresh-key check task does not panic")
            .expect("snapshot fallback returns a decision");
        allowed += usize::from(decision.is_allowed());
        denied += usize::from(decision.is_denied());
    }
    let stored = stored_counter_usage(&pool, &policy, subject).await;
    let deleted = delete_counter(&pool, &policy, subject).await;

    assert_eq!(allowed, 1);
    assert_eq!(denied, 1);
    assert_eq!(stored, 1);
    assert_eq!(deleted, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires RUNLIMIT_POSTGRES_TEST_DATABASE_URL"]
async fn fresh_single_waiting_behind_a_batch_advances_its_snapshot() {
    let pool = test_pool(8).await;
    let limiter = PostgresLimiter::with_config(pool.clone(), test_config());
    let target_policy = Arc::new(unique_policy(
        "mixed-fresh-target",
        1,
        Duration::from_secs(10),
    ));
    let companion_policy = Arc::new(unique_policy(
        "mixed-fresh-companion",
        1,
        Duration::from_secs(10),
    ));
    let target_subject = key(157);
    let companion_subject = key(158);
    let target_check = Check::new(&target_policy, target_subject);
    let logical_lock_id = advisory_lock_id(&target_check);

    let mut blocker = pool.begin().await.expect("begin mixed-path lock blocker");
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(logical_lock_id)
        .execute(&mut *blocker)
        .await
        .expect("hold the mixed-path target's logical lock");

    let batch_limiter = limiter.clone();
    let batch_target_policy = Arc::clone(&target_policy);
    let batch_companion_policy = Arc::clone(&companion_policy);
    let batch = tokio::spawn(async move {
        batch_limiter
            .check_all(&[
                Check::new(&batch_target_policy, target_subject),
                Check::new(&batch_companion_policy, companion_subject),
            ])
            .await
    });
    wait_for_advisory_waiters(&pool, "WITH RECURSIVE acquired(position, locked)", 1).await;

    let single_limiter = limiter.clone();
    let single_policy = Arc::clone(&target_policy);
    let single = tokio::spawn(async move {
        single_limiter
            .check(&Check::new(&single_policy, target_subject))
            .await
    });
    wait_for_advisory_waiters(&pool, "WITH advisory_lock AS MATERIALIZED", 1).await;

    blocker.commit().await.expect("release mixed-path lock");

    let batch = batch
        .await
        .expect("fresh-key batch task does not panic")
        .expect("fresh-key batch succeeds");
    let single = single
        .await
        .expect("fresh-key single task does not panic")
        .expect("fresh-key single returns a decision");
    let target_stored = stored_counter_usage(&pool, &target_policy, target_subject).await;
    let companion_stored = stored_counter_usage(&pool, &companion_policy, companion_subject).await;
    let target_deleted = delete_counter(&pool, &target_policy, target_subject).await;
    let companion_deleted = delete_counter(&pool, &companion_policy, companion_subject).await;

    assert!(matches!(batch, BatchDecision::Allowed(ref decisions) if decisions.len() == 2));
    assert!(single.is_denied());
    assert_eq!(target_stored, 1);
    assert_eq!(companion_stored, 1);
    assert_eq!(target_deleted, 1);
    assert_eq!(companion_deleted, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires RUNLIMIT_POSTGRES_TEST_DATABASE_URL"]
async fn contended_check_samples_time_after_row_lock() {
    let pool = test_pool(6).await;
    let limiter = PostgresLimiter::with_config(pool.clone(), test_config());
    let policy = Arc::new(unique_policy(
        "lock-crosses-expiry",
        1,
        Duration::from_millis(200),
    ));
    let subject = key(5);

    let first = limiter
        .check(&Check::new(&policy, subject))
        .await
        .expect("first check succeeds");
    assert!(first.is_allowed());

    let mut blocker = pool.begin().await.expect("begin blocker transaction");
    sqlx::query(
        r"
SELECT 1
FROM runlimit_fixed_windows
WHERE
    config_fingerprint = $1
    AND subject_key = $2
FOR UPDATE
",
    )
    .bind(policy.fingerprint().as_bytes().as_slice())
    .bind(subject.as_bytes().as_slice())
    .fetch_one(&mut *blocker)
    .await
    .expect("lock existing counter row");

    sleep(Duration::from_millis(25)).await;
    let waiting_limiter = limiter.clone();
    let waiting_policy = Arc::clone(&policy);
    let waiting = tokio::spawn(async move {
        waiting_limiter
            .check(&Check::new(&waiting_policy, subject))
            .await
    });

    // The check starts while the original window is active, then remains
    // blocked until well after it expires.
    sleep(Duration::from_millis(250)).await;
    blocker.commit().await.expect("release counter row");

    let decision = waiting
        .await
        .expect("waiting task does not panic")
        .expect("waiting check succeeds");
    assert!(
        decision.is_allowed(),
        "a clock sampled before the row-lock wait would deny against the expired window"
    );
    assert_eq!(decision.remaining(), Some(0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires RUNLIMIT_POSTGRES_TEST_DATABASE_URL"]
async fn row_lock_timeout_releases_single_connection_pool_slot_without_consuming_quota() {
    let blocker_pool = test_pool(1).await;
    let tested_pool = test_pool(1).await;
    let normal_limiter = PostgresLimiter::with_config(blocker_pool.clone(), test_config());
    let policy = unique_policy("lock-timeout", 2, Duration::from_secs(5));
    let subject = key(6);
    let check = Check::new(&policy, subject);

    let first = normal_limiter
        .check(&check)
        .await
        .expect("first check succeeds");
    assert_eq!(first.remaining(), Some(1));

    let mut blocker = blocker_pool
        .begin()
        .await
        .expect("begin blocker transaction");
    sqlx::query(
        r"
SELECT 1
FROM runlimit_fixed_windows
WHERE
    config_fingerprint = $1
    AND subject_key = $2
FOR UPDATE
",
    )
    .bind(policy.fingerprint().as_bytes().as_slice())
    .bind(subject.as_bytes().as_slice())
    .fetch_one(&mut *blocker)
    .await
    .expect("lock existing counter row");

    let short_config = PostgresConfig::new()
        .with_operation_timeout(Duration::from_millis(75))
        .expect("short nonzero timeout is valid");
    let short_limiter = PostgresLimiter::with_config(tested_pool.clone(), short_config);
    let error = short_limiter
        .check(&check)
        .await
        .expect_err("row lock must outlive the operation deadline");
    assert!(matches!(error, CheckError::TimedOutBeforeCommit { .. }));
    assert!(!error.may_have_consumed_quota());

    let probe: i32 = tokio::time::timeout(
        Duration::from_millis(500),
        sqlx::query_scalar("SELECT 1").fetch_one(&tested_pool),
    )
    .await
    .expect("timed-out check releases the only tested-pool slot")
    .expect("replacement tested-pool query succeeds");
    assert_eq!(probe, 1);

    let cancellable_limiter = PostgresLimiter::with_config(tested_pool.clone(), test_config());
    let cancelled =
        tokio::time::timeout(Duration::from_millis(75), cancellable_limiter.check(&check)).await;
    assert!(
        cancelled.is_err(),
        "outer deadline must cancel the check before its configured deadline"
    );

    let probe_after_cancellation: i32 = tokio::time::timeout(
        Duration::from_millis(500),
        sqlx::query_scalar("SELECT 1").fetch_one(&tested_pool),
    )
    .await
    .expect("cancelled check releases the only tested-pool slot")
    .expect("tested-pool query after cancellation succeeds");
    assert_eq!(probe_after_cancellation, 1);

    blocker.commit().await.expect("release counter row");
    let after_timeout = normal_limiter
        .check(&check)
        .await
        .expect("counter remains usable");
    assert!(after_timeout.is_allowed());
    assert_eq!(after_timeout.remaining(), Some(0));

    let deleted_rows = delete_counter(&blocker_pool, &policy, subject).await;
    drop(short_limiter);
    drop(cancellable_limiter);
    drop(normal_limiter);
    tested_pool.close().await;
    blocker_pool.close().await;
    assert_eq!(deleted_rows, 1);
}
