use std::{
    collections::{
        BTreeSet, HashMap,
        hash_map::{Entry as MapEntry, RandomState},
    },
    hash::BuildHasher,
    sync::{Mutex, MutexGuard},
    time::Duration,
};

use runlimit_core::{
    BatchDecision, BatchError, Check, CounterKey, Decision, Denial, validate_batch,
};
use thiserror::Error;

use crate::{Clock, MemoryStoreConfig, SystemClock};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry {
    used: u64,
    expires_at_millis: u128,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Expiration {
    expires_at_millis: u128,
    key: CounterKey,
}

#[derive(Debug)]
struct Shard {
    capacity: usize,
    latest_observed_millis: u128,
    entries: HashMap<CounterKey, Entry>,
    expirations: BTreeSet<Expiration>,
}

impl Shard {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            latest_observed_millis: 0,
            entries: HashMap::new(),
            expirations: BTreeSet::new(),
        }
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.expirations.clear();
    }

    fn prune_expired(&mut self, now_millis: u128, maximum: usize) {
        for _ in 0..maximum {
            let Some(expiration) = self.expirations.first() else {
                break;
            };
            if expiration.expires_at_millis > now_millis {
                break;
            }

            let expiration = self
                .expirations
                .pop_first()
                .expect("the first expiration was present");
            let removed = self.entries.remove(&expiration.key);
            debug_assert_eq!(
                removed.map(|entry| entry.expires_at_millis),
                Some(expiration.expires_at_millis),
                "the entry and expiration indexes diverged"
            );
        }
    }

    fn capacity_retry_after(&self, now_millis: u128) -> Option<Duration> {
        self.expirations.first().map(|expiration| {
            duration_from_millis(
                expiration
                    .expires_at_millis
                    .saturating_sub(now_millis)
                    .max(1),
            )
        })
    }

    fn quota_denial(&self, check: &PreparedCheck, now_millis: u128) -> Option<Denial> {
        let entry = self
            .entries
            .get(&check.counter_key)
            .filter(|entry| entry.expires_at_millis > now_millis)?;
        (check.cost > check.limit - entry.used).then(|| Denial::QuotaExceeded {
            limit: check.limit,
            retry_after: duration_from_millis(entry.expires_at_millis.saturating_sub(now_millis)),
        })
    }

    fn consume(&mut self, check: &PreparedCheck, now_millis: u128) -> Decision {
        let expires_at_millis = now_millis + u128::from(check.window_millis);
        let fresh_entry = Entry {
            used: check.cost,
            expires_at_millis,
        };
        let fresh_expiration = Expiration {
            expires_at_millis,
            key: check.counter_key,
        };

        match self.entries.entry(check.counter_key) {
            MapEntry::Occupied(mut occupied) => {
                if occupied.get().expires_at_millis > now_millis {
                    let entry = occupied.get_mut();
                    entry.used += check.cost;
                    return Decision::allowed(
                        check.limit,
                        check.limit - entry.used,
                        duration_from_millis(entry.expires_at_millis.saturating_sub(now_millis)),
                    );
                }

                let expired = *occupied.get();
                let removed = self.expirations.remove(&Expiration {
                    expires_at_millis: expired.expires_at_millis,
                    key: check.counter_key,
                });
                debug_assert!(removed, "an expired entry must have an expiration");
                let replaced = occupied.insert(fresh_entry);
                debug_assert_eq!(replaced, expired);
            }
            MapEntry::Vacant(vacant) => {
                vacant.insert(fresh_entry);
            }
        }

        let inserted = self.expirations.insert(fresh_expiration);
        debug_assert!(inserted, "an inserted entry must have one expiration");
        Decision::allowed(
            check.limit,
            check.limit - check.cost,
            duration_from_millis(expires_at_millis.saturating_sub(now_millis)),
        )
    }
}

#[derive(Debug)]
struct PreparedCheck {
    input_index: usize,
    counter_key: CounterKey,
    shard_index: usize,
    shard_position: usize,
    limit: u64,
    window_millis: u64,
    cost: u64,
}

impl PreparedCheck {
    fn new(input_index: usize, check: &Check<'_>, shard_index: usize) -> Self {
        Self {
            input_index,
            counter_key: check.counter_key(),
            shard_index,
            shard_position: 0,
            limit: check.policy().limit(),
            window_millis: check.policy().window_millis(),
            cost: check.cost(),
        }
    }
}

/// A sharded, hard-bounded, process-local fixed-window store.
///
/// The store never evicts an active key to admit a new one. Every check touches
/// only the shards required by that check and performs a bounded amount of
/// expiry cleanup. An atomic batch locks its shards in deterministic order.
///
/// If application code panics while a shard is locked, that shard remains
/// poisoned and every later operation touching it fails closed with
/// [`MemoryStoreError::PoisonedShard`]. Replace the store explicitly rather
/// than automatically resetting quota for counters whose consistency is
/// unknown.
pub struct MemoryStore<C = SystemClock> {
    config: MemoryStoreConfig,
    clock: C,
    shard_hasher: RandomState,
    shards: Box<[Mutex<Shard>]>,
}

impl MemoryStore<SystemClock> {
    /// Creates a store using the system monotonic clock.
    pub fn new(config: MemoryStoreConfig) -> Self {
        Self::with_clock(config, SystemClock::new())
    }
}

impl<C: Clock> MemoryStore<C> {
    /// Creates a store using a caller-supplied monotonic clock.
    ///
    /// Supplying a clock is primarily useful for deterministic tests.
    pub fn with_clock(config: MemoryStoreConfig, clock: C) -> Self {
        let shards = (0..config.shard_count())
            .map(|index| Mutex::new(Shard::new(config.shard_capacity(index))))
            .collect::<Vec<_>>()
            .into_boxed_slice();

        Self {
            config,
            clock,
            shard_hasher: RandomState::new(),
            shards,
        }
    }

    /// Evaluates and, when allowed, consumes one check.
    ///
    /// # Errors
    ///
    /// Returns an error without allowing the request when the target shard is
    /// poisoned.
    pub fn check(&self, check: &Check<'_>) -> Result<Decision, MemoryStoreError> {
        let counter_key = check.counter_key();
        let shard_index = self.shard_index(&counter_key);
        let prepared = PreparedCheck::new(0, check, shard_index);
        let mut shard = self.lock_shard(shard_index)?;
        let observed_millis = self.clock.now().as_millis();
        let now_millis = observed_millis.max(shard.latest_observed_millis);
        shard.latest_observed_millis = now_millis;
        shard.prune_expired(now_millis, self.config.max_expired_removals_per_check());

        if let Some(denial) = shard.quota_denial(&prepared, now_millis) {
            return Ok(Decision::denied(denial));
        }
        if !shard.entries.contains_key(&counter_key) && shard.entries.len() >= shard.capacity {
            return Ok(Decision::denied(Denial::StorageCapacity {
                retry_after: shard.capacity_retry_after(now_millis),
            }));
        }

        Ok(shard.consume(&prepared, now_millis))
    }

    /// Evaluates a batch atomically.
    ///
    /// If any check is denied, none of the checks consumes quota. Returned
    /// allowed decisions preserve input order.
    ///
    /// # Errors
    ///
    /// Returns an error before quota consumption when the batch exceeds its
    /// configured bound, contains a duplicate key, or a touched shard is
    /// poisoned.
    ///
    #[allow(clippy::too_many_lines)]
    pub fn check_all(&self, checks: &[Check<'_>]) -> Result<BatchDecision, MemoryStoreError> {
        validate_batch(checks, self.config.max_batch_size())?;
        if checks.is_empty() {
            return Ok(BatchDecision::Allowed(Vec::new()));
        }

        let mut prepared = Vec::with_capacity(checks.len());
        for (input_index, check) in checks.iter().enumerate() {
            let counter_key = check.counter_key();
            prepared.push(PreparedCheck::new(
                input_index,
                check,
                self.shard_index(&counter_key),
            ));
        }

        let mut shard_indexes = prepared
            .iter()
            .map(|check| check.shard_index)
            .collect::<Vec<_>>();
        shard_indexes.sort_unstable();
        shard_indexes.dedup();
        for check in &mut prepared {
            check.shard_position =
                shard_indexes.partition_point(|index| *index < check.shard_index);
            debug_assert_eq!(
                shard_indexes.get(check.shard_position),
                Some(&check.shard_index)
            );
        }

        let mut locked_shards = self.lock_shards(&shard_indexes)?;
        let observed_millis = self.clock.now().as_millis();
        let now_millis = locked_shards
            .iter()
            .map(|(_, shard)| shard.latest_observed_millis)
            .fold(observed_millis, u128::max);
        let mut checks_per_shard = vec![0_usize; locked_shards.len()];
        for check in &prepared {
            checks_per_shard[check.shard_position] += 1;
        }
        for ((_, shard), check_count) in locked_shards.iter_mut().zip(checks_per_shard) {
            shard.latest_observed_millis = now_millis;
            let cleanup_limit = self
                .config
                .max_expired_removals_per_check()
                .saturating_mul(check_count);
            shard.prune_expired(now_millis, cleanup_limit);
        }

        let mut pending_insertions = vec![0_usize; locked_shards.len()];
        for check in &prepared {
            let shard = &locked_shards[check.shard_position].1;
            if let Some(denial) = shard.quota_denial(check, now_millis) {
                return Ok(BatchDecision::Denied {
                    index: check.input_index,
                    denial,
                });
            }

            if !shard.entries.contains_key(&check.counter_key) {
                let projected_len = shard.entries.len() + pending_insertions[check.shard_position];
                if projected_len >= shard.capacity {
                    return Ok(BatchDecision::Denied {
                        index: check.input_index,
                        denial: Denial::StorageCapacity {
                            retry_after: shard.capacity_retry_after(now_millis),
                        },
                    });
                }
                pending_insertions[check.shard_position] += 1;
            }
        }

        let mut decisions = Vec::with_capacity(prepared.len());
        for check in &prepared {
            let shard = &mut locked_shards[check.shard_position].1;
            decisions.push(shard.consume(check, now_millis));
        }

        Ok(BatchDecision::Allowed(decisions))
    }

    /// Returns current storage usage.
    ///
    /// # Errors
    ///
    /// Returns an error if a shard is poisoned.
    pub fn stats(&self) -> Result<MemoryStoreStats, MemoryStoreError> {
        let shard_indexes = (0..self.shards.len()).collect::<Vec<_>>();
        let locked_shards = self.lock_shards(&shard_indexes)?;
        Ok(MemoryStoreStats {
            entries: locked_shards
                .iter()
                .map(|(_, shard)| shard.entries.len())
                .sum(),
            capacity: self.config.max_keys(),
            shard_count: self.config.shard_count(),
        })
    }

    /// Removes every stored counter.
    ///
    /// # Errors
    ///
    /// Returns an error if a shard is poisoned.
    pub fn clear(&self) -> Result<(), MemoryStoreError> {
        let shard_indexes = (0..self.shards.len()).collect::<Vec<_>>();
        let mut locked_shards = self.lock_shards(&shard_indexes)?;
        for (_, shard) in &mut locked_shards {
            shard.clear();
        }
        Ok(())
    }

    fn shard_index(&self, key: &CounterKey) -> usize {
        #[allow(clippy::cast_possible_truncation)]
        let hash = self.shard_hasher.hash_one(key) as usize;
        hash % self.shards.len()
    }

    fn lock_shard(&self, index: usize) -> Result<MutexGuard<'_, Shard>, MemoryStoreError> {
        self.shards[index]
            .lock()
            .map_err(|_| MemoryStoreError::PoisonedShard { shard_index: index })
    }

    fn lock_shards<'a>(
        &'a self,
        indexes: &[usize],
    ) -> Result<Vec<(usize, MutexGuard<'a, Shard>)>, MemoryStoreError> {
        let mut locked = Vec::with_capacity(indexes.len());
        for &index in indexes {
            locked.push((index, self.lock_shard(index)?));
        }
        Ok(locked)
    }
}

fn duration_from_millis(millis: u128) -> Duration {
    Duration::from_millis(
        u64::try_from(millis)
            .expect("a counter's remaining duration cannot exceed its portable policy window"),
    )
}

/// Current bounded-store usage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryStoreStats {
    entries: usize,
    capacity: usize,
    shard_count: usize,
}

impl MemoryStoreStats {
    /// Returns the number of stored counters.
    pub const fn entries(self) -> usize {
        self.entries
    }

    /// Returns the hard maximum number of stored counters.
    pub const fn capacity(self) -> usize {
        self.capacity
    }

    /// Returns the number of independently locked shards.
    pub const fn shard_count(self) -> usize {
        self.shard_count
    }
}

/// A fail-closed in-memory store error.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MemoryStoreError {
    /// The atomic batch violated a backend-independent structural requirement.
    #[error(transparent)]
    InvalidBatch(#[from] BatchError),
    /// A shard mutex was poisoned and remains unavailable.
    #[error("memory-store shard {shard_index} is poisoned and unavailable")]
    PoisonedShard {
        /// Poisoned shard index.
        shard_index: usize,
    },
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        thread,
        time::Duration,
    };

    use runlimit_core::{
        BatchDecision, BatchError, Check, Decision, Denial, FixedWindowPolicy, MAX_LIMIT,
        MAX_WINDOW, MAX_WINDOW_MILLIS, PolicyId, ScopeId, SubjectKey,
    };

    use super::{Entry, Expiration, MemoryStore, MemoryStoreError};
    use crate::{Clock, MemoryStoreConfig};

    #[derive(Clone, Default)]
    struct ManualClock {
        now_millis: Arc<AtomicU64>,
    }

    impl ManualClock {
        fn advance(&self, duration: Duration) {
            let millis = u64::try_from(duration.as_millis()).unwrap();
            self.now_millis.fetch_add(millis, Ordering::Relaxed);
        }

        fn set(&self, duration: Duration) {
            let millis = u64::try_from(duration.as_millis()).unwrap();
            self.now_millis.store(millis, Ordering::Relaxed);
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> Duration {
            Duration::from_millis(self.now_millis.load(Ordering::Relaxed))
        }
    }

    #[derive(Clone, Default)]
    struct PanicOnceClock {
        panic_next: Arc<AtomicBool>,
    }

    impl PanicOnceClock {
        fn panic_once(&self) {
            self.panic_next.store(true, Ordering::Relaxed);
        }
    }

    impl Clock for PanicOnceClock {
        fn now(&self) -> Duration {
            assert!(
                !self.panic_next.swap(false, Ordering::Relaxed),
                "panic from test clock"
            );
            Duration::ZERO
        }
    }

    #[derive(Clone)]
    struct WideManualClock {
        now_millis: Arc<Mutex<u128>>,
    }

    impl WideManualClock {
        fn new(now_millis: u128) -> Self {
            Self {
                now_millis: Arc::new(Mutex::new(now_millis)),
            }
        }

        fn advance(&self, millis: u128) {
            let mut now_millis = self.now_millis.lock().unwrap();
            *now_millis += millis;
        }
    }

    impl Clock for WideManualClock {
        fn now(&self) -> Duration {
            let millis = *self.now_millis.lock().unwrap();
            let seconds = u64::try_from(millis / 1_000).unwrap();
            let subsec_millis = u32::try_from(millis % 1_000).unwrap();
            Duration::new(seconds, subsec_millis * 1_000_000)
        }
    }

    fn policy(policy_id: &str, scope_id: &str, limit: u64, window: Duration) -> FixedWindowPolicy {
        FixedWindowPolicy::new(
            PolicyId::new(policy_id).unwrap(),
            ScopeId::new(scope_id).unwrap(),
            limit,
            window,
        )
        .unwrap()
    }

    fn subject(byte: u8) -> SubjectKey {
        SubjectKey::from_digest([byte; 32])
    }

    #[test]
    fn enforces_quota_and_reports_exact_retry_duration() {
        let clock = ManualClock::default();
        let store = MemoryStore::with_clock(MemoryStoreConfig::new(8).unwrap(), clock.clone());
        let policy = policy("auth.login", "client", 2, Duration::from_secs(60));
        let check = Check::new(&policy, subject(1));

        let first = store.check(&check).unwrap();
        assert!(first.is_allowed());
        assert_eq!(first.remaining(), Some(1));
        assert_eq!(first.retry_after(), None);

        let second = store.check(&check).unwrap();
        assert!(second.is_allowed());
        assert_eq!(second.remaining(), Some(0));

        let denied = store.check(&check).unwrap();
        assert!(!denied.is_allowed());
        assert_eq!(denied.retry_after(), Some(Duration::from_secs(60)));

        clock.advance(Duration::from_secs(10));
        assert_eq!(
            store.check(&check).unwrap().retry_after(),
            Some(Duration::from_secs(50))
        );

        clock.advance(Duration::from_secs(50));
        let reset = store.check(&check).unwrap();
        assert!(reset.is_allowed());
        assert_eq!(reset.remaining(), Some(1));
        assert_eq!(reset.reset_after(), Some(Duration::from_secs(60)));
    }

    #[test]
    fn single_check_matches_a_one_element_batch_across_state_transitions() {
        #[derive(Clone, Copy)]
        struct Step {
            now: Duration,
            subject: u8,
            cost: u64,
            expected: Decision,
        }

        let config = MemoryStoreConfig::new(2)
            .unwrap()
            .with_shard_count(1)
            .unwrap()
            .with_max_expired_removals_per_check(1)
            .unwrap();
        let single_clock = ManualClock::default();
        let batch_clock = ManualClock::default();
        let single_store = MemoryStore::with_clock(config.clone(), single_clock.clone());
        let batch_store = MemoryStore::with_clock(config, batch_clock.clone());
        let policy = policy("auth.login", "client", 5, Duration::from_millis(10));
        let steps = [
            Step {
                now: Duration::ZERO,
                subject: 1,
                cost: 2,
                expected: Decision::allowed(5, 3, Duration::from_millis(10)),
            },
            Step {
                now: Duration::from_millis(3),
                subject: 1,
                cost: 2,
                expected: Decision::allowed(5, 1, Duration::from_millis(7)),
            },
            Step {
                now: Duration::from_millis(3),
                subject: 1,
                cost: 2,
                expected: Decision::denied(Denial::QuotaExceeded {
                    limit: 5,
                    retry_after: Duration::from_millis(7),
                }),
            },
            Step {
                now: Duration::from_millis(9),
                subject: 1,
                cost: 1,
                expected: Decision::allowed(5, 0, Duration::from_millis(1)),
            },
            Step {
                now: Duration::from_millis(10),
                subject: 1,
                cost: 3,
                expected: Decision::allowed(5, 2, Duration::from_millis(10)),
            },
            Step {
                now: Duration::from_millis(8),
                subject: 1,
                cost: 1,
                expected: Decision::allowed(5, 1, Duration::from_millis(10)),
            },
            Step {
                now: Duration::from_millis(10),
                subject: 2,
                cost: 1,
                expected: Decision::allowed(5, 4, Duration::from_millis(10)),
            },
            Step {
                now: Duration::from_millis(10),
                subject: 3,
                cost: 1,
                expected: Decision::denied(Denial::StorageCapacity {
                    retry_after: Some(Duration::from_millis(10)),
                }),
            },
            Step {
                now: Duration::from_millis(20),
                subject: 3,
                cost: 1,
                expected: Decision::allowed(5, 4, Duration::from_millis(10)),
            },
        ];

        for (index, step) in steps.into_iter().enumerate() {
            single_clock.set(step.now);
            batch_clock.set(step.now);
            let check = Check::with_cost(&policy, subject(step.subject), step.cost).unwrap();

            let single = single_store.check(&check).unwrap();
            let batch = batch_store
                .check_all(std::slice::from_ref(&check))
                .unwrap()
                .try_into_single_decision()
                .expect("a one-element batch returns one decision");

            assert_eq!(single, batch, "step {index}");
            assert_eq!(single, step.expected, "step {index}");
        }

        assert_eq!(single_store.stats().unwrap(), batch_store.stats().unwrap());
    }

    #[test]
    fn windows_remain_exact_across_the_u64_millisecond_boundary() {
        let clock = WideManualClock::new(u128::from(u64::MAX));
        let store = MemoryStore::with_clock(MemoryStoreConfig::new(1).unwrap(), clock.clone());
        let policy = policy("auth.login", "client", MAX_LIMIT, MAX_WINDOW);
        let check = Check::with_cost(&policy, subject(1), MAX_LIMIT).unwrap();

        let first = store.check(&check).unwrap();
        assert!(first.is_allowed());
        assert_eq!(first.remaining(), Some(0));
        assert_eq!(first.reset_after(), Some(MAX_WINDOW));

        let denied = store.check(&check).unwrap();
        assert!(denied.is_denied());
        assert_eq!(denied.retry_after(), Some(MAX_WINDOW));

        clock.advance(u128::from(MAX_WINDOW_MILLIS - 1));
        let nearly_reset = store.check(&check).unwrap();
        assert!(nearly_reset.is_denied());
        assert_eq!(nearly_reset.retry_after(), Some(Duration::from_millis(1)));

        clock.advance(1);
        let reset = store.check(&check).unwrap();
        assert!(reset.is_allowed());
        assert_eq!(reset.reset_after(), Some(MAX_WINDOW));
    }

    #[test]
    fn policy_configuration_changes_use_independent_counters() {
        let store = MemoryStore::with_clock(
            MemoryStoreConfig::new(2)
                .unwrap()
                .with_shard_count(1)
                .unwrap(),
            ManualClock::default(),
        );
        let strict = policy("auth.login", "client", 1, Duration::from_secs(60));
        let relaxed = policy("auth.login", "client", 2, Duration::from_secs(60));
        let key = subject(1);

        assert!(store.check(&Check::new(&strict, key)).unwrap().is_allowed());
        assert!(
            store
                .check(&Check::new(&relaxed, key))
                .unwrap()
                .is_allowed()
        );
        assert_eq!(store.stats().unwrap().entries(), 2);
    }

    #[test]
    fn capacity_exhaustion_does_not_evict_an_active_entry() {
        let store = MemoryStore::with_clock(
            MemoryStoreConfig::new(1)
                .unwrap()
                .with_shard_count(1)
                .unwrap(),
            ManualClock::default(),
        );
        let policy = policy("auth.login", "client", 10, Duration::from_secs(60));

        assert!(
            store
                .check(&Check::new(&policy, subject(1)))
                .unwrap()
                .is_allowed()
        );
        let denied = store.check(&Check::new(&policy, subject(2))).unwrap();
        assert!(!denied.is_allowed());
        assert_eq!(denied.retry_after(), Some(Duration::from_secs(60)));
        assert_eq!(store.stats().unwrap().entries(), 1);
    }

    #[test]
    fn default_configuration_can_use_its_entire_capacity() {
        let store =
            MemoryStore::with_clock(MemoryStoreConfig::new(64).unwrap(), ManualClock::default());
        let policy = policy("auth.login", "client", 10, Duration::from_secs(60));

        for byte in 0..64 {
            assert!(
                store
                    .check(&Check::new(&policy, subject(byte)))
                    .unwrap()
                    .is_allowed()
            );
        }

        let denied = store.check(&Check::new(&policy, subject(64))).unwrap();
        assert!(denied.is_denied());
        assert_eq!(store.stats().unwrap().entries(), 64);
    }

    #[test]
    fn expiry_cleanup_is_bounded_and_capacity_remains_hard_bounded() {
        let clock = ManualClock::default();
        let config = MemoryStoreConfig::new(3)
            .unwrap()
            .with_shard_count(1)
            .unwrap()
            .with_max_expired_removals_per_check(1)
            .unwrap();
        let store = MemoryStore::with_clock(config, clock.clone());
        let policy = policy("auth.login", "client", 10, Duration::from_secs(1));

        for byte in 1..=3 {
            assert!(
                store
                    .check(&Check::new(&policy, subject(byte)))
                    .unwrap()
                    .is_allowed()
            );
        }
        clock.advance(Duration::from_secs(1));

        assert!(
            store
                .check(&Check::new(&policy, subject(4)))
                .unwrap()
                .is_allowed()
        );
        assert_eq!(store.stats().unwrap().entries(), 3);

        assert!(
            store
                .check(&Check::new(&policy, subject(5)))
                .unwrap()
                .is_allowed()
        );
        assert_eq!(store.stats().unwrap().entries(), 3);
    }

    #[test]
    fn an_atomic_batch_receives_the_cleanup_budget_for_each_check() {
        let clock = ManualClock::default();
        let config = MemoryStoreConfig::new(3)
            .unwrap()
            .with_shard_count(1)
            .unwrap()
            .with_max_expired_removals_per_check(1)
            .unwrap();
        let store = MemoryStore::with_clock(config, clock.clone());
        let policy = policy("auth.login", "client", 10, Duration::from_secs(1));

        for byte in 1..=3 {
            assert!(
                store
                    .check(&Check::new(&policy, subject(byte)))
                    .unwrap()
                    .is_allowed()
            );
        }
        clock.advance(Duration::from_secs(1));

        let checks = [4, 5, 6].map(|byte| Check::new(&policy, subject(byte)));
        let result = store.check_all(&checks).unwrap();
        assert!(matches!(result, BatchDecision::Allowed(ref decisions) if decisions.len() == 3));
        assert_eq!(store.stats().unwrap().entries(), 3);
    }

    #[test]
    fn auxiliary_expiry_index_remains_bounded_across_many_windows() {
        let clock = ManualClock::default();
        let store = MemoryStore::with_clock(
            MemoryStoreConfig::new(1)
                .unwrap()
                .with_shard_count(1)
                .unwrap(),
            clock.clone(),
        );
        let policy = policy("auth.login", "client", 1, Duration::from_millis(1));
        let check = Check::new(&policy, subject(1));

        for _ in 0..1_000 {
            assert!(store.check(&check).unwrap().is_allowed());
            clock.advance(Duration::from_millis(1));
        }

        let shard = store.shards[0].lock().unwrap();
        assert_eq!(shard.entries.len(), 1);
        assert_eq!(shard.expirations.len(), 1);
    }

    #[test]
    fn targeted_expired_refresh_keeps_indexes_aligned_for_single_and_batch() {
        for use_batch in [false, true] {
            let clock = ManualClock::default();
            let store = MemoryStore::with_clock(
                MemoryStoreConfig::new(2)
                    .unwrap()
                    .with_shard_count(1)
                    .unwrap()
                    .with_max_expired_removals_per_check(1)
                    .unwrap(),
                clock.clone(),
            );
            let policy = policy("auth.login", "client", 10, Duration::from_millis(2));
            let earlier = Check::new(&policy, subject(1));
            let target = Check::new(&policy, subject(2));

            assert!(store.check(&earlier).unwrap().is_allowed());
            clock.advance(Duration::from_millis(1));
            assert!(store.check(&target).unwrap().is_allowed());
            clock.advance(Duration::from_millis(2));

            let decision = if use_batch {
                store
                    .check_all(std::slice::from_ref(&target))
                    .unwrap()
                    .try_into_single_decision()
                    .expect("a one-element batch returns one decision")
            } else {
                store.check(&target).unwrap()
            };
            assert_eq!(decision, Decision::allowed(10, 9, Duration::from_millis(2)));

            let key = target.counter_key();
            let shard = store.shards[0].lock().unwrap();
            assert_eq!(shard.entries.len(), 1);
            assert_eq!(shard.expirations.len(), 1);
            assert_eq!(
                shard.entries.get(&key),
                Some(&Entry {
                    used: 1,
                    expires_at_millis: 5,
                })
            );
            assert!(shard.expirations.contains(&Expiration {
                expires_at_millis: 5,
                key,
            }));
        }
    }

    #[test]
    fn a_denied_batch_does_not_consume_other_checks() {
        let store = MemoryStore::with_clock(
            MemoryStoreConfig::new(8)
                .unwrap()
                .with_shard_count(1)
                .unwrap(),
            ManualClock::default(),
        );
        let exhausted = policy("auth.login", "client", 1, Duration::from_secs(60));
        let untouched = policy("auth.login", "identity", 1, Duration::from_secs(60));
        let exhausted_check = Check::new(&exhausted, subject(1));
        let untouched_check = Check::new(&untouched, subject(2));

        assert!(store.check(&exhausted_check).unwrap().is_allowed());
        let result = store
            .check_all(&[exhausted_check, untouched_check])
            .unwrap();
        assert!(matches!(result, BatchDecision::Denied { index: 0, .. }));

        assert!(
            store
                .check(&Check::new(&untouched, subject(2)))
                .unwrap()
                .is_allowed()
        );
    }

    #[test]
    fn duplicate_keys_are_rejected_before_consumption() {
        let store =
            MemoryStore::with_clock(MemoryStoreConfig::new(8).unwrap(), ManualClock::default());
        let alpha = policy("auth.alpha", "client", 2, Duration::from_secs(60));
        let beta = policy("auth.beta", "client", 2, Duration::from_secs(60));
        let checks = [
            Check::new(&beta, subject(1)),
            Check::new(&beta, subject(1)),
            Check::new(&alpha, subject(2)),
            Check::new(&alpha, subject(2)),
        ];

        assert_eq!(
            store.check_all(&checks),
            Err(MemoryStoreError::InvalidBatch(BatchError::DuplicateKey {
                first_index: 0,
                duplicate_index: 1,
            }))
        );
        assert_eq!(store.stats().unwrap().entries(), 0);
    }

    #[test]
    fn concurrent_checks_never_over_admit() {
        let store = Arc::new(MemoryStore::with_clock(
            MemoryStoreConfig::new(8).unwrap(),
            ManualClock::default(),
        ));
        let policy = Arc::new(policy("auth.login", "client", 25, Duration::from_secs(60)));

        let allowed = (0..100)
            .map(|_| {
                let store = Arc::clone(&store);
                let policy = Arc::clone(&policy);
                thread::spawn(move || {
                    store
                        .check(&Check::new(&policy, subject(1)))
                        .unwrap()
                        .is_allowed()
                })
            })
            .map(|thread| usize::from(thread.join().unwrap()))
            .sum::<usize>();

        assert_eq!(allowed, 25);
    }

    #[test]
    fn a_poisoned_default_shard_remains_fail_closed() {
        let clock = PanicOnceClock::default();
        let store = MemoryStore::with_clock(
            MemoryStoreConfig::new(1)
                .unwrap()
                .with_shard_count(1)
                .unwrap(),
            clock.clone(),
        );
        let policy = policy("auth.login", "client", 1, Duration::from_secs(60));
        let exhausted = Check::new(&policy, subject(1));
        let new_key = Check::new(&policy, subject(2));

        assert!(store.check(&exhausted).unwrap().is_allowed());
        clock.panic_once();
        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = store.check(&new_key);
        }));
        assert!(panic_result.is_err());

        let poisoned = Err(MemoryStoreError::PoisonedShard { shard_index: 0 });
        assert_eq!(store.check(&exhausted), poisoned);
        assert_eq!(store.check(&new_key), poisoned);
        assert_eq!(store.check(&exhausted), poisoned);
        assert_eq!(
            store.stats(),
            Err(MemoryStoreError::PoisonedShard { shard_index: 0 })
        );
        assert_eq!(
            store.clear(),
            Err(MemoryStoreError::PoisonedShard { shard_index: 0 })
        );
    }
}
