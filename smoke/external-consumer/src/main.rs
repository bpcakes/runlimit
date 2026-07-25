use std::{env, error::Error, time::Duration};

use runlimit_core::{BatchDecision, Check, FixedWindowPolicy, KeyHasher, PolicyId, ScopeId};
use runlimit_memory::{MemoryStore, MemoryStoreConfig};

fn main() -> Result<(), Box<dyn Error>> {
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

    match limiter.check_all(&checks)? {
        BatchDecision::Allowed(decisions) => {
            assert_eq!(decisions.len(), checks.len());
            println!("request admitted");
        }
        BatchDecision::Denied { index, denial } => match denial.retry_after_seconds() {
            Some(seconds) => {
                println!("check {index} denied; retry after {seconds} seconds");
            }
            None => println!("check {index} denied; retry time unavailable"),
        },
        _ => return Err("unsupported batch decision variant".into()),
    }

    Ok(())
}
