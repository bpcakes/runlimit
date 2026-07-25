//! Serde wire-contract and validation tests.

#![cfg(feature = "serde")]

use std::time::Duration;

use runlimit_core::{
    BatchDecision, Decision, Denial, FixedWindowPolicy, GcraPolicy, MAX_WINDOW_MILLIS, PolicyId,
    QuotaMode, ScopeId,
};
use serde_json::json;

#[test]
fn identifiers_use_validated_string_values() {
    let policy = PolicyId::new("auth/login:v2").unwrap();
    let scope = ScopeId::new("client-ip_64").unwrap();

    assert_eq!(
        serde_json::to_value(&policy).unwrap(),
        json!("auth/login:v2")
    );
    assert_eq!(
        serde_json::from_value::<PolicyId>(json!("auth/login:v2")).unwrap(),
        policy
    );
    assert_eq!(
        serde_json::from_value::<ScopeId>(json!("client-ip_64")).unwrap(),
        scope
    );
    assert!(serde_json::from_value::<PolicyId>(json!("auth login")).is_err());
    assert!(serde_json::from_value::<ScopeId>(json!("")).is_err());
}

#[test]
fn policy_wire_shape_recomputes_its_fingerprint() {
    let policy = FixedWindowPolicy::new(
        PolicyId::new("auth.login").unwrap(),
        ScopeId::new("identity").unwrap(),
        8,
        Duration::from_millis(60_001),
    )
    .unwrap();

    let value = serde_json::to_value(&policy).unwrap();
    assert_eq!(
        value,
        json!({
            "id": "auth.login",
            "scope": "identity",
            "limit": 8,
            "window_millis": 60_001,
            "quota_mode": "enforce"
        })
    );

    let decoded: FixedWindowPolicy = serde_json::from_value(value).unwrap();
    assert_eq!(decoded, policy);
    assert_eq!(decoded.fingerprint(), policy.fingerprint());
}

#[test]
fn policy_deserialization_cannot_supply_or_bypass_derived_state() {
    assert!(
        serde_json::from_value::<FixedWindowPolicy>(json!({
            "id": "auth.login",
            "scope": "identity",
            "limit": 8,
            "window_millis": 60_000,
            "fingerprint": "untrusted"
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<FixedWindowPolicy>(json!({
            "id": "auth login",
            "scope": "identity",
            "limit": 8,
            "window_millis": 60_000
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<FixedWindowPolicy>(json!({
            "id": "auth.login",
            "scope": "identity",
            "limit": 0,
            "window_millis": 60_000
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<FixedWindowPolicy>(json!({
            "id": "auth.login",
            "scope": "identity",
            "limit": 8,
            "window_millis": MAX_WINDOW_MILLIS + 1
        }))
        .is_err()
    );
}

#[test]
fn policy_modes_default_to_enforcement_and_do_not_change_fingerprints() {
    let value = json!({
        "id": "auth.login",
        "scope": "identity",
        "limit": 8,
        "window_millis": 60_000
    });
    let enforced: FixedWindowPolicy = serde_json::from_value(value.clone()).unwrap();
    let shadow: FixedWindowPolicy = serde_json::from_value(json!({
        "id": "auth.login",
        "scope": "identity",
        "limit": 8,
        "window_millis": 60_000,
        "quota_mode": "shadow"
    }))
    .unwrap();

    assert_eq!(enforced.quota_mode(), QuotaMode::Enforce);
    assert_eq!(shadow.quota_mode(), QuotaMode::Shadow);
    assert_eq!(enforced.fingerprint(), shadow.fingerprint());
}

#[test]
fn gcra_policy_has_a_validated_wire_contract() {
    let policy = GcraPolicy::new(
        PolicyId::new("api.read").unwrap(),
        ScopeId::new("account").unwrap(),
        10,
        Duration::from_millis(1_500),
        20,
    )
    .unwrap()
    .with_quota_mode(QuotaMode::Shadow);
    let value = serde_json::to_value(&policy).unwrap();

    assert_eq!(
        value,
        json!({
            "id": "api.read",
            "scope": "account",
            "quota": 10,
            "period_millis": 1_500,
            "burst_capacity": 20,
            "quota_mode": "shadow"
        })
    );
    assert_eq!(serde_json::from_value::<GcraPolicy>(value).unwrap(), policy);
}

#[test]
fn decisions_and_denials_have_exact_tagged_wire_shapes() {
    let allowed = Decision::allowed(8, 7, Duration::new(1, 234_567));
    let quota_denial = Denial::QuotaExceeded {
        capacity: 8,
        retry_after: Duration::new(2, 345_678),
    };
    let denied = Decision::denied(quota_denial);
    let storage_denial = Denial::StorageCapacity { retry_after: None };

    assert_eq!(
        serde_json::to_value(allowed).unwrap(),
        json!({
            "outcome": "allowed",
            "capacity": 8,
            "available": 7,
            "replenishes_after": {"secs": 1, "nanos": 234_567}
        })
    );
    assert_eq!(
        serde_json::to_value(denied).unwrap(),
        json!({
            "outcome": "denied",
            "denial": {
                "reason": "quota_exceeded",
                "capacity": 8,
                "retry_after": {"secs": 2, "nanos": 345_678}
            }
        })
    );
    assert_eq!(
        serde_json::to_value(storage_denial).unwrap(),
        json!({
            "reason": "storage_capacity",
            "retry_after": null
        })
    );

    assert_eq!(
        serde_json::from_value::<Decision>(serde_json::to_value(allowed).unwrap()).unwrap(),
        allowed
    );
    assert_eq!(
        serde_json::from_value::<Decision>(serde_json::to_value(denied).unwrap()).unwrap(),
        denied
    );
    assert_eq!(
        serde_json::from_value::<Denial>(serde_json::to_value(storage_denial).unwrap()).unwrap(),
        storage_denial
    );
}

#[test]
fn decision_deserialization_rejects_impossible_metadata() {
    assert!(
        serde_json::from_value::<Decision>(json!({
            "outcome": "allowed",
            "capacity": 8,
            "available": 9,
            "replenishes_after": {"secs": 1, "nanos": 0}
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<Decision>(json!({
            "outcome": "allowed",
            "capacity": 0,
            "available": 0,
            "replenishes_after": {"secs": 1, "nanos": 0}
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<Decision>(json!({
            "outcome": "allowed",
            "capacity": 8,
            "available": 7,
            "replenishes_after": {"secs": 1, "nanos": 0},
            "unexpected": true
        }))
        .is_err()
    );
}

#[test]
fn invalid_constructed_decisions_are_not_serialized() {
    assert!(serde_json::to_value(Decision::allowed(8, 9, Duration::from_secs(1))).is_err());
}

#[test]
fn zero_response_durations_round_trip_without_losing_backend_metadata() {
    let values = [
        Decision::allowed(8, 7, Duration::ZERO),
        Decision::denied(Denial::QuotaExceeded {
            capacity: 8,
            retry_after: Duration::ZERO,
        }),
        Decision::denied(Denial::StorageCapacity {
            retry_after: Some(Duration::ZERO),
        }),
    ];

    for decision in values {
        let value = serde_json::to_value(decision).unwrap();
        assert_eq!(serde_json::from_value::<Decision>(value).unwrap(), decision);
    }
}

#[test]
fn shadow_decisions_round_trip_but_storage_capacity_cannot_be_shadowed() {
    let decision = Decision::shadow_denied(Denial::QuotaExceeded {
        capacity: 8,
        retry_after: Duration::from_secs(1),
    });
    let value = serde_json::to_value(decision).unwrap();

    assert_eq!(
        value,
        json!({
            "outcome": "shadow_denied",
            "denial": {
                "reason": "quota_exceeded",
                "capacity": 8,
                "retry_after": {"secs": 1, "nanos": 0}
            }
        })
    );
    assert_eq!(serde_json::from_value::<Decision>(value).unwrap(), decision);
    assert!(
        serde_json::to_value(Decision::shadow_denied(Denial::StorageCapacity {
            retry_after: None
        }))
        .is_err()
    );
}

#[test]
fn batch_decisions_round_trip_and_reject_denied_members_in_allowed_batches() {
    let allowed = BatchDecision::Allowed(vec![
        Decision::allowed(8, 7, Duration::from_secs(60)),
        Decision::allowed(3, 1, Duration::from_millis(750)),
    ]);
    let denied = BatchDecision::Denied {
        index: 1,
        denial: Denial::StorageCapacity {
            retry_after: Some(Duration::from_millis(5)),
        },
    };

    assert_eq!(
        serde_json::from_value::<BatchDecision>(serde_json::to_value(&allowed).unwrap()).unwrap(),
        allowed
    );
    assert_eq!(
        serde_json::from_value::<BatchDecision>(serde_json::to_value(&denied).unwrap()).unwrap(),
        denied
    );
    assert_eq!(
        serde_json::to_value(&denied).unwrap(),
        json!({
            "outcome": "denied",
            "index": 1,
            "denial": {
                "reason": "storage_capacity",
                "retry_after": {"secs": 0, "nanos": 5_000_000}
            }
        })
    );

    assert!(
        serde_json::from_value::<BatchDecision>(json!({
            "outcome": "allowed",
            "decisions": [{
                "outcome": "denied",
                "denial": {
                    "reason": "quota_exceeded",
                    "capacity": 8,
                    "retry_after": {"secs": 1, "nanos": 0}
                }
            }]
        }))
        .is_err()
    );
    assert!(
        serde_json::to_value(BatchDecision::Allowed(vec![Decision::denied(
            Denial::QuotaExceeded {
                capacity: 8,
                retry_after: Duration::from_secs(1),
            }
        )]))
        .is_err()
    );
}
