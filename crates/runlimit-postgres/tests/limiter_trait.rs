//! Compile-time and runtime coverage for the shared limiter abstraction.

use std::{fmt::Debug, time::Duration};

use runlimit_core::{
    BatchDecision, BatchError, Check, Decision, FixedWindowPolicy, Limiter, PolicyId, ScopeId,
    SubjectKey,
};
use runlimit_memory::{MemoryStore, MemoryStoreConfig, MemoryStoreError};
use runlimit_postgres::{CheckError, PostgresLimiter};
use sqlx::postgres::PgPoolOptions;

async fn check_batch<L>(limiter: &L, checks: &[Check<'_>]) -> Result<BatchDecision, L::Error>
where
    L: Limiter,
{
    limiter.check_all(checks).await
}

async fn check_one<L>(limiter: &L, check: &Check<'_>) -> Result<Decision, L::Error>
where
    L: Limiter,
{
    limiter.check(check).await
}

fn assert_send<T: Send>(_: T) {}

fn policy(name: &str, limit: u64) -> FixedWindowPolicy {
    FixedWindowPolicy::new(
        PolicyId::new(name).expect("test policy ID is valid"),
        ScopeId::new("subject").expect("test scope ID is valid"),
        limit,
        Duration::from_secs(60),
    )
    .expect("test policy is valid")
}

fn key(byte: u8) -> SubjectKey {
    SubjectKey::from_digest([byte; 32])
}

fn expect_allowed<E: Debug>(result: Result<BatchDecision, E>) -> Vec<runlimit_core::Decision> {
    match result.expect("generic limiter call succeeds") {
        BatchDecision::Allowed(decisions) => decisions,
        BatchDecision::Denied { .. } => panic!("generic limiter call should be allowed"),
        _ => panic!("generic limiter call returned an unknown batch outcome"),
    }
}

#[tokio::test]
async fn one_generic_function_swaps_between_backends() {
    let memory = MemoryStore::new(
        MemoryStoreConfig::new(4).expect("test memory-store configuration is valid"),
    );
    let postgres = PostgresLimiter::new(
        PgPoolOptions::new()
            .connect_lazy("postgresql://runlimit:runlimit@127.0.0.1:1/runlimit")
            .expect("test database URL is valid"),
    );
    let single_policy = policy("single", 2);
    let single_check = Check::new(&single_policy, key(9));
    let duplicate_checks = [single_check, single_check];

    assert!(
        check_one(&memory, &single_check)
            .await
            .unwrap()
            .is_allowed()
    );
    assert_eq!(
        check_batch(&memory, &[]).await,
        Ok(BatchDecision::Allowed(Vec::new()))
    );
    assert_eq!(
        check_batch(&postgres, &[])
            .await
            .expect("an empty PostgreSQL batch needs no connection"),
        BatchDecision::Allowed(Vec::new())
    );
    assert!(matches!(
        check_batch(&memory, &duplicate_checks).await,
        Err(MemoryStoreError::InvalidBatch(BatchError::DuplicateKey {
            first_index: 0,
            duplicate_index: 1,
        }))
    ));
    assert!(matches!(
        check_batch(&postgres, &duplicate_checks).await,
        Err(CheckError::InvalidBatch(BatchError::DuplicateKey {
            first_index: 0,
            duplicate_index: 1,
        }))
    ));

    assert_send(Limiter::check(&memory, &single_check));
    assert_send(Limiter::check(&postgres, &single_check));
    assert_send(Limiter::check_all(&memory, &[]));
    assert_send(Limiter::check_all(&postgres, &[]));
}

#[tokio::test]
async fn generic_batch_preserves_caller_order() {
    let first_policy = policy("first", 11);
    let second_policy = policy("second", 7);
    let checks = [
        Check::with_cost(&first_policy, key(1), 3).expect("test check is valid"),
        Check::with_cost(&second_policy, key(2), 2).expect("test check is valid"),
    ];
    let memory = MemoryStore::new(
        MemoryStoreConfig::new(4).expect("test memory-store configuration is valid"),
    );

    let decisions = expect_allowed(check_batch(&memory, &checks).await);

    assert_eq!(decisions.len(), 2);
    assert_eq!(decisions[0].limit(), Some(11));
    assert_eq!(decisions[0].remaining(), Some(8));
    assert_eq!(decisions[1].limit(), Some(7));
    assert_eq!(decisions[1].remaining(), Some(5));
}
