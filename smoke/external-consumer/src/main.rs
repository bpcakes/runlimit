use std::{env, error::Error, time::Duration};

use runlimit_core::{Check, FixedWindowPolicy, KeyHasher, PolicyId, ScopeId};
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

    let decision = limiter.check_all(&checks)?;
    if let Some(decisions) = decision.allowed_decisions() {
        assert_eq!(decisions.len(), checks.len());
        println!("request admitted");
    } else if decision.is_enforced_denial() {
        let index = decision.denied_index().expect("denials name an input");
        let denial = decision.denial().expect("denials include details");
        match denial.retry_after_seconds() {
            Some(seconds) => {
                println!("check {index} denied; retry after {seconds} seconds");
            }
            None => println!("check {index} denied; retry time unavailable"),
        }
    } else if decision.is_shadow_denied() {
        println!("request admitted after shadow denial");
    } else {
        return Err("unsupported batch decision state".into());
    }

    Ok(())
}
