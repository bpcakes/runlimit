use std::{env, error::Error, time::Duration};

use runlimit_core::{
    AdmissionObservation, BatchDecisionView, Check, CleanupObservation, ConsumptionStatus,
    FixedWindowPolicy, KeyHasher, PolicyId, ScopeId,
};
use runlimit_memory::{GcraStoreError, MemoryStore, MemoryStoreConfig, MemoryStoreError};

fn main() -> Result<(), Box<dyn Error>> {
    let gcra_error = GcraStoreError::from(MemoryStoreError::PoisonedShard { shard_index: 0 });
    assert!(matches!(
        gcra_error,
        GcraStoreError::Store(MemoryStoreError::PoisonedShard { shard_index: 0 })
    ));

    let cleanup = CleanupObservation::outcome_unknown(100, Duration::from_millis(5));
    assert_eq!(cleanup.removed(), None);
    assert_eq!(cleanup.consumption(), ConsumptionStatus::PossiblyConsumed);

    let client_policy = FixedWindowPolicy::new(
        PolicyId::new("auth.login")?,
        ScopeId::new("client")?,
        40,
        Duration::from_secs(60),
    )?;
    let identity_policy = FixedWindowPolicy::new(
        PolicyId::new("auth.login")?,
        ScopeId::new("identity")?,
        8,
        Duration::from_secs(60),
    )?;

    let secret = env::var("RUNLIMIT_KEY_SECRET")?;
    let key_hasher = KeyHasher::new(secret.as_bytes())?;

    // Address extraction and subject normalization remain application-owned.
    let client = key_hasher.hash_for(&client_policy, b"client-network:192.0.2.4");
    let identity = key_hasher.hash_for(&identity_policy, b"user@example.test");

    let config = MemoryStoreConfig::new(50_000)?.with_shard_count(64)?;
    let limiter = MemoryStore::new(config);
    let checks = [
        Check::new(&client_policy, client),
        Check::new(&identity_policy, identity),
    ];
    let failed_batch = AdmissionObservation::failed_batch_for_check(
        &checks[0],
        ConsumptionStatus::NotConsumed,
        Duration::from_millis(5),
    );
    assert_eq!(
        failed_batch.policy_id().map(PolicyId::as_str),
        Some("auth.login")
    );
    assert!(failed_batch.policy_fingerprint().is_some());

    let decision = limiter.check_all(&checks)?;
    match decision.view() {
        BatchDecisionView::Allowed { decisions } => {
            assert_eq!(decisions.len(), checks.len());
            println!("request admitted");
        }
        BatchDecisionView::Denied { index, denial } => match denial.retry_after_seconds() {
            Some(seconds) => {
                println!("check {index} denied; retry after {seconds} seconds");
            }
            None => println!("check {index} denied; retry time unavailable"),
        },
        BatchDecisionView::ShadowDenied { index, .. } => {
            println!("request admitted after check {index} was shadow denied");
        }
    }

    Ok(())
}
