use std::{
    collections::{BTreeSet, HashMap},
    fmt,
    hash::{BuildHasherDefault, Hash, Hasher},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use runlimit_core::{
    AdmissionObservation, AdmissionOperation, AdmissionOutcome, BatchDecision, CapacityObservation,
    Check, CleanupObservation, ConsumptionStatus, CounterKey, Decision, Denial, GcraPolicy,
    Limiter, Observation, Observer, QuotaMode, observe_safely, validate_batch,
};

use crate::{Clock, MemoryStoreConfig, MemoryStoreError, MemoryStoreStats, SystemClock};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry {
    tat_scaled: u128,
    expires_at_millis: u128,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Expiration {
    expires_at_millis: u128,
    key: CounterKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrehashedCounterKey(CounterKey);

impl Hash for PrehashedCounterKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(counter_key_hash(self.0));
    }
}

#[derive(Default)]
struct PassThroughHasher(u64);

impl Hasher for PassThroughHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(byte);
        }
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }
}

type EntryMap = HashMap<PrehashedCounterKey, Entry, BuildHasherDefault<PassThroughHasher>>;

#[derive(Debug)]
struct Shard {
    capacity: usize,
    latest_observed_millis: u128,
    entries: EntryMap,
    expirations: BTreeSet<Expiration>,
}

impl Shard {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            latest_observed_millis: 0,
            entries: HashMap::with_hasher(BuildHasherDefault::default()),
            expirations: BTreeSet::new(),
        }
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.expirations.clear();
    }

    fn prune_expired(&mut self, now_millis: u128, maximum: usize) -> usize {
        let mut removed_count = 0;
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
            let removed = self.entries.remove(&PrehashedCounterKey(expiration.key));
            debug_assert_eq!(
                removed.map(|entry| entry.expires_at_millis),
                Some(expiration.expires_at_millis),
                "the entry and expiration indexes diverged"
            );
            removed_count += usize::from(removed.is_some());
        }
        removed_count
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

    fn evaluate(
        &self,
        check: &PreparedCheck,
        now_millis: u128,
    ) -> Result<PendingAllowance, EvaluationError> {
        let scaled_now = now_millis
            .checked_mul(u128::from(check.quota))
            .ok_or(EvaluationError::Arithmetic)?;
        let active_tat = self
            .entries
            .get(&PrehashedCounterKey(check.counter_key))
            .filter(|entry| entry.expires_at_millis > now_millis)
            .map_or(scaled_now, |entry| entry.tat_scaled.max(scaled_now));
        let increment = u128::from(check.cost)
            .checked_mul(u128::from(check.period_millis))
            .ok_or(EvaluationError::Arithmetic)?;
        let candidate = active_tat
            .checked_add(increment)
            .ok_or(EvaluationError::Arithmetic)?;
        let burst_span = u128::from(check.burst_capacity)
            .checked_mul(u128::from(check.period_millis))
            .ok_or(EvaluationError::Arithmetic)?;
        let ceiling = scaled_now
            .checked_add(burst_span)
            .ok_or(EvaluationError::Arithmetic)?;

        if candidate > ceiling {
            let retry_millis = div_ceil(candidate - ceiling, u128::from(check.quota));
            return Err(EvaluationError::Quota(Denial::QuotaExceeded {
                capacity: check.burst_capacity,
                retry_after: duration_from_millis(retry_millis),
            }));
        }

        let available = (ceiling - candidate) / u128::from(check.period_millis);
        let replenish_millis = div_ceil(candidate - scaled_now, u128::from(check.quota));
        let expires_at_millis = now_millis
            .checked_add(replenish_millis)
            .ok_or(EvaluationError::Arithmetic)?;

        Ok(PendingAllowance {
            tat_scaled: candidate,
            expires_at_millis,
            available: u64::try_from(available)
                .expect("available allowance cannot exceed the u64 burst capacity"),
            replenishes_after: duration_from_millis(replenish_millis),
        })
    }

    fn consume(&mut self, check: &PreparedCheck, allowance: PendingAllowance) -> Decision {
        let fresh_entry = Entry {
            tat_scaled: allowance.tat_scaled,
            expires_at_millis: allowance.expires_at_millis,
        };
        if let Some(previous) = self
            .entries
            .insert(PrehashedCounterKey(check.counter_key), fresh_entry)
        {
            let removed = self.expirations.remove(&Expiration {
                expires_at_millis: previous.expires_at_millis,
                key: check.counter_key,
            });
            debug_assert!(removed, "a replaced entry must have one expiration");
        }
        let inserted = self.expirations.insert(Expiration {
            expires_at_millis: allowance.expires_at_millis,
            key: check.counter_key,
        });
        debug_assert!(inserted, "an inserted entry must have one expiration");

        Decision::allowed(
            check.burst_capacity,
            allowance.available,
            allowance.replenishes_after,
        )
    }
}

#[derive(Clone, Copy, Debug)]
enum EvaluationError {
    Quota(Denial),
    Arithmetic,
}

#[derive(Clone, Copy, Debug)]
struct PendingAllowance {
    tat_scaled: u128,
    expires_at_millis: u128,
    available: u64,
    replenishes_after: Duration,
}

#[derive(Clone, Copy, Debug)]
struct PreparedCheck {
    input_index: usize,
    counter_key: CounterKey,
    shard_index: usize,
    shard_position: usize,
    quota: u64,
    period_millis: u64,
    burst_capacity: u64,
    cost: u64,
    quota_mode: QuotaMode,
}

impl PreparedCheck {
    fn new(input_index: usize, check: &Check<'_, GcraPolicy>, shard_index: usize) -> Self {
        Self {
            input_index,
            counter_key: check.counter_key(),
            shard_index,
            shard_position: 0,
            quota: check.policy().quota(),
            period_millis: check.policy().period_millis(),
            burst_capacity: check.policy().burst_capacity(),
            cost: check.cost(),
            quota_mode: check.policy().quota_mode(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct CleanupEffect {
    requested: usize,
    removed: usize,
    elapsed: Duration,
}

#[derive(Clone, Copy, Debug)]
struct ShardEffect {
    shard_index: usize,
    cleanup: CleanupEffect,
    used: usize,
    capacity: usize,
}

#[derive(Debug)]
struct Evaluation<T> {
    value: T,
    shard_effects: Vec<ShardEffect>,
}

/// A hard-bounded, process-local generic-cell-rate-algorithm store.
///
/// Each key occupies one constant-size entry. The store refuses to evict
/// active entries, performs bounded cleanup per check, and preserves atomic
/// all-or-nothing batches in caller order.
pub struct GcraStore<C = SystemClock> {
    config: MemoryStoreConfig,
    clock: C,
    shards: Box<[Mutex<Shard>]>,
    observer: Option<Arc<dyn Observer>>,
}

impl<C> fmt::Debug for GcraStore<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let poisoned_shards = self
            .shards
            .iter()
            .filter(|shard| shard.is_poisoned())
            .count();
        formatter
            .debug_struct("GcraStore")
            .field("config", &self.config)
            .field("has_observer", &self.observer.is_some())
            .field("poisoned_shards", &poisoned_shards)
            .field("shard_state", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl GcraStore<SystemClock> {
    /// Creates a store using the system monotonic clock.
    pub fn new(config: MemoryStoreConfig) -> Self {
        Self::with_clock(config, SystemClock::new())
    }
}

impl<C: Clock> GcraStore<C> {
    /// Creates a store using a caller-supplied monotonic clock.
    pub fn with_clock(config: MemoryStoreConfig, clock: C) -> Self {
        let shards = (0..config.shard_count())
            .map(|index| Mutex::new(Shard::new(config.shard_capacity(index))))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            config,
            clock,
            shards,
            observer: None,
        }
    }

    /// Returns this store with an operational observer.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn Observer>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Evaluates and, when allowed, consumes one GCRA check.
    ///
    /// # Errors
    ///
    /// Fails closed when the target shard is poisoned or exact arithmetic
    /// cannot represent the caller-supplied clock value.
    pub fn check(&self, check: &Check<'_, GcraPolicy>) -> Result<Decision, MemoryStoreError> {
        let started = Instant::now();
        let result = self.check_inner(check);
        let elapsed = started.elapsed();
        match &result {
            Ok(evaluation) => {
                self.observe_shard_effects(&evaluation.shard_effects);
                self.observe_admission(
                    AdmissionOperation::Check,
                    1,
                    Some(check),
                    decision_outcome(&evaluation.value),
                    decision_consumption(&evaluation.value),
                    elapsed,
                );
            }
            Err(_) => self.observe_admission(
                AdmissionOperation::Check,
                1,
                Some(check),
                AdmissionOutcome::Failed,
                ConsumptionStatus::NotConsumed,
                elapsed,
            ),
        }
        result.map(|evaluation| evaluation.value)
    }

    fn check_inner(
        &self,
        check: &Check<'_, GcraPolicy>,
    ) -> Result<Evaluation<Decision>, MemoryStoreError> {
        let counter_key = check.counter_key();
        let shard_index = self.shard_index(&counter_key);
        let prepared = PreparedCheck::new(0, check, shard_index);
        let mut shard = self.lock_shard(shard_index)?;
        let observed_millis = self.clock.now().as_millis();
        let now_millis = observed_millis.max(shard.latest_observed_millis);
        let evaluated = match shard.evaluate(&prepared, now_millis) {
            Err(EvaluationError::Arithmetic) => {
                return Err(MemoryStoreError::ArithmeticOverflow);
            }
            result => result,
        };
        shard.latest_observed_millis = now_millis;
        let cleanup_requested = self.config.max_expired_removals_per_check();
        let cleanup_started = Instant::now();
        let cleanup_removed = shard.prune_expired(now_millis, cleanup_requested);
        let cleanup_elapsed = cleanup_started.elapsed();

        let decision = match evaluated {
            Ok(allowance) => {
                if !shard
                    .entries
                    .contains_key(&PrehashedCounterKey(counter_key))
                    && shard.entries.len() >= shard.capacity
                {
                    Decision::denied(Denial::StorageCapacity {
                        retry_after: shard.capacity_retry_after(now_millis),
                    })
                } else {
                    shard.consume(&prepared, allowance)
                }
            }
            Err(EvaluationError::Quota(denial)) => {
                if prepared.quota_mode == QuotaMode::Shadow {
                    Decision::shadow_denied(denial)
                } else {
                    Decision::denied(denial)
                }
            }
            Err(EvaluationError::Arithmetic) => unreachable!("arithmetic was preflighted"),
        };

        Ok(Evaluation {
            value: decision,
            shard_effects: vec![ShardEffect {
                shard_index,
                cleanup: CleanupEffect {
                    requested: cleanup_requested,
                    removed: cleanup_removed,
                    elapsed: cleanup_elapsed,
                },
                used: shard.entries.len(),
                capacity: shard.capacity,
            }],
        })
    }

    /// Evaluates an atomic batch of GCRA checks.
    ///
    /// Allowed decisions preserve input order. A denied or shadow-denied batch
    /// consumes no quota.
    ///
    /// # Errors
    ///
    /// Fails closed for invalid batches, poisoned shards, an unsatisfiable
    /// per-shard batch, or arithmetic overflow.
    #[allow(clippy::too_many_lines)]
    pub fn check_all(
        &self,
        checks: &[Check<'_, GcraPolicy>],
    ) -> Result<BatchDecision, MemoryStoreError> {
        let started = Instant::now();
        let result = self.check_all_inner(checks);
        let elapsed = started.elapsed();
        match &result {
            Ok(evaluation) => {
                self.observe_shard_effects(&evaluation.shard_effects);
                let relevant_check = batch_relevant_check(checks, &evaluation.value);
                self.observe_admission(
                    AdmissionOperation::Batch,
                    checks.len(),
                    relevant_check,
                    batch_outcome(&evaluation.value),
                    batch_consumption(&evaluation.value, checks.is_empty()),
                    elapsed,
                );
            }
            Err(_) => self.observe_admission(
                AdmissionOperation::Batch,
                checks.len(),
                None,
                AdmissionOutcome::Failed,
                ConsumptionStatus::NotConsumed,
                elapsed,
            ),
        }
        result.map(|evaluation| evaluation.value)
    }

    #[allow(clippy::too_many_lines)]
    fn check_all_inner(
        &self,
        checks: &[Check<'_, GcraPolicy>],
    ) -> Result<Evaluation<BatchDecision>, MemoryStoreError> {
        validate_batch(checks, self.config.max_batch_size())?;
        if checks.is_empty() {
            return Ok(Evaluation {
                value: BatchDecision::Allowed(Vec::new()),
                shard_effects: Vec::new(),
            });
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
        }

        let mut checks_per_shard = vec![0_usize; shard_indexes.len()];
        for check in &prepared {
            checks_per_shard[check.shard_position] += 1;
        }
        for (&shard_index, &key_count) in shard_indexes.iter().zip(&checks_per_shard) {
            let capacity = self.config.shard_capacity(shard_index);
            if key_count > capacity {
                return Err(MemoryStoreError::BatchExceedsShardCapacity {
                    shard_index,
                    key_count,
                    capacity,
                });
            }
        }

        let mut locked_shards = self.lock_shards(&shard_indexes)?;
        let observed_millis = self.clock.now().as_millis();
        let now_millis = locked_shards
            .iter()
            .map(|(_, shard)| shard.latest_observed_millis)
            .fold(observed_millis, u128::max);
        let mut evaluations = Vec::with_capacity(prepared.len());
        for check in &prepared {
            match locked_shards[check.shard_position]
                .1
                .evaluate(check, now_millis)
            {
                Err(EvaluationError::Arithmetic) => {
                    return Err(MemoryStoreError::ArithmeticOverflow);
                }
                evaluation => evaluations.push(evaluation),
            }
        }
        let mut cleanup_effects = Vec::with_capacity(locked_shards.len());
        for ((_, shard), &check_count) in locked_shards.iter_mut().zip(&checks_per_shard) {
            shard.latest_observed_millis = now_millis;
            let requested = self
                .config
                .max_expired_removals_per_check()
                .saturating_mul(check_count);
            let cleanup_started = Instant::now();
            let removed = shard.prune_expired(now_millis, requested);
            cleanup_effects.push(CleanupEffect {
                requested,
                removed,
                elapsed: cleanup_started.elapsed(),
            });
        }

        let mut pending_insertions = vec![0_usize; locked_shards.len()];
        let mut allowances = Vec::with_capacity(prepared.len());
        for (check, evaluation) in prepared.iter().zip(evaluations) {
            let shard = &locked_shards[check.shard_position].1;
            let allowance = match evaluation {
                Ok(allowance) => allowance,
                Err(EvaluationError::Quota(denial)) => {
                    let value = if check.quota_mode == QuotaMode::Shadow {
                        BatchDecision::ShadowDenied {
                            index: check.input_index,
                            denial,
                        }
                    } else {
                        BatchDecision::Denied {
                            index: check.input_index,
                            denial,
                        }
                    };
                    return Ok(Evaluation {
                        value,
                        shard_effects: collect_shard_effects(&locked_shards, &cleanup_effects),
                    });
                }
                Err(EvaluationError::Arithmetic) => unreachable!("arithmetic was preflighted"),
            };

            if !shard
                .entries
                .contains_key(&PrehashedCounterKey(check.counter_key))
            {
                let projected_len = shard.entries.len() + pending_insertions[check.shard_position];
                if projected_len >= shard.capacity {
                    return Ok(Evaluation {
                        value: BatchDecision::Denied {
                            index: check.input_index,
                            denial: Denial::StorageCapacity {
                                retry_after: shard.capacity_retry_after(now_millis),
                            },
                        },
                        shard_effects: collect_shard_effects(&locked_shards, &cleanup_effects),
                    });
                }
                pending_insertions[check.shard_position] += 1;
            }
            allowances.push(allowance);
        }

        let mut decisions = Vec::with_capacity(prepared.len());
        for (check, allowance) in prepared.iter().zip(allowances) {
            decisions.push(
                locked_shards[check.shard_position]
                    .1
                    .consume(check, allowance),
            );
        }
        Ok(Evaluation {
            value: BatchDecision::Allowed(decisions),
            shard_effects: collect_shard_effects(&locked_shards, &cleanup_effects),
        })
    }

    /// Returns current bounded storage use.
    ///
    /// # Errors
    ///
    /// Returns an error if any shard is poisoned.
    pub fn stats(&self) -> Result<MemoryStoreStats, MemoryStoreError> {
        let indexes = (0..self.shards.len()).collect::<Vec<_>>();
        let locked = self.lock_shards(&indexes)?;
        Ok(MemoryStoreStats::from_parts(
            locked.iter().map(|(_, shard)| shard.entries.len()).sum(),
            self.config.max_keys(),
            self.config.shard_count(),
        ))
    }

    /// Removes every stored counter.
    ///
    /// # Errors
    ///
    /// Returns an error if any shard is poisoned.
    pub fn clear(&self) -> Result<(), MemoryStoreError> {
        let indexes = (0..self.shards.len()).collect::<Vec<_>>();
        let mut locked = self.lock_shards(&indexes)?;
        for (_, shard) in &mut locked {
            shard.clear();
        }
        Ok(())
    }

    /// Rebuilds poisoned shards by discarding their untrusted counter state.
    pub fn recover_poisoned(&self) -> usize {
        let mut locked = Vec::with_capacity(self.shards.len());
        for (index, mutex) in self.shards.iter().enumerate() {
            match mutex.lock() {
                Ok(shard) => locked.push((index, mutex, shard, false)),
                Err(poisoned) => locked.push((index, mutex, poisoned.into_inner(), true)),
            }
        }
        let mut recovered = 0;
        for (index, mutex, shard, poisoned) in &mut locked {
            if *poisoned {
                **shard = Shard::new(self.config.shard_capacity(*index));
                mutex.clear_poison();
                recovered += 1;
            }
        }
        recovered
    }

    fn observe_shard_effects(&self, effects: &[ShardEffect]) {
        let Some(observer) = &self.observer else {
            return;
        };
        for effect in effects {
            observe_safely(
                observer.as_ref(),
                &Observation::Cleanup(CleanupObservation::new(
                    effect.cleanup.requested,
                    Some(usize_to_u64(effect.cleanup.removed)),
                    effect.cleanup.elapsed,
                    ConsumptionStatus::Consumed,
                )),
            );
            observe_safely(
                observer.as_ref(),
                &Observation::Capacity(CapacityObservation::new(
                    usize_to_u64(effect.used),
                    usize_to_u64(effect.capacity),
                    Some(effect.shard_index),
                )),
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_admission(
        &self,
        operation: AdmissionOperation,
        batch_size: usize,
        check: Option<&Check<'_, GcraPolicy>>,
        outcome: AdmissionOutcome,
        consumption: ConsumptionStatus,
        elapsed: Duration,
    ) {
        let Some(observer) = &self.observer else {
            return;
        };
        let (policy_id, scope_id) = check.map_or((None, None), |check| {
            (Some(check.policy().id()), Some(check.policy().scope()))
        });
        observe_safely(
            observer.as_ref(),
            &Observation::Admission(AdmissionObservation::new(
                operation,
                batch_size,
                policy_id,
                scope_id,
                outcome,
                consumption,
                elapsed,
            )),
        );
    }

    fn shard_index(&self, key: &CounterKey) -> usize {
        #[allow(clippy::cast_possible_truncation)]
        let hash = counter_key_hash(*key) as usize;
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

fn collect_shard_effects(
    locked_shards: &[(usize, MutexGuard<'_, Shard>)],
    cleanup_effects: &[CleanupEffect],
) -> Vec<ShardEffect> {
    debug_assert_eq!(locked_shards.len(), cleanup_effects.len());
    locked_shards
        .iter()
        .zip(cleanup_effects)
        .map(|((shard_index, shard), cleanup)| ShardEffect {
            shard_index: *shard_index,
            cleanup: *cleanup,
            used: shard.entries.len(),
            capacity: shard.capacity,
        })
        .collect()
}

fn decision_outcome(decision: &Decision) -> AdmissionOutcome {
    if !decision.would_deny() {
        return AdmissionOutcome::Allowed;
    }
    if decision.is_shadow_denied() {
        return AdmissionOutcome::ShadowDenied;
    }
    match decision.denial() {
        Some(Denial::QuotaExceeded { .. }) => AdmissionOutcome::QuotaDenied,
        Some(Denial::StorageCapacity { .. }) => AdmissionOutcome::CapacityDenied,
        _ => AdmissionOutcome::Failed,
    }
}

fn decision_consumption(decision: &Decision) -> ConsumptionStatus {
    if decision.would_deny() {
        ConsumptionStatus::NotConsumed
    } else {
        ConsumptionStatus::Consumed
    }
}

fn batch_outcome(decision: &BatchDecision) -> AdmissionOutcome {
    match decision {
        BatchDecision::Allowed(_) => AdmissionOutcome::Allowed,
        BatchDecision::ShadowDenied { .. } => AdmissionOutcome::ShadowDenied,
        BatchDecision::Denied {
            denial: Denial::QuotaExceeded { .. },
            ..
        } => AdmissionOutcome::QuotaDenied,
        BatchDecision::Denied {
            denial: Denial::StorageCapacity { .. },
            ..
        } => AdmissionOutcome::CapacityDenied,
        _ => AdmissionOutcome::Failed,
    }
}

fn batch_consumption(decision: &BatchDecision, empty: bool) -> ConsumptionStatus {
    if matches!(decision, BatchDecision::Allowed(_)) && !empty {
        ConsumptionStatus::Consumed
    } else {
        ConsumptionStatus::NotConsumed
    }
}

fn batch_relevant_check<'checks, 'policy>(
    checks: &'checks [Check<'policy, GcraPolicy>],
    decision: &BatchDecision,
) -> Option<&'checks Check<'policy, GcraPolicy>> {
    match decision {
        BatchDecision::Allowed(decisions) if decisions.len() == 1 => checks.first(),
        BatchDecision::Denied { index, .. } | BatchDecision::ShadowDenied { index, .. } => {
            checks.get(*index)
        }
        _ => None,
    }
}

fn counter_key_hash(key: CounterKey) -> u64 {
    leading_u64(key.subject().as_bytes())
        ^ leading_u64(key.fingerprint().as_bytes()).rotate_left(32)
}

const fn leading_u64(bytes: &[u8; 32]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

const fn div_ceil(numerator: u128, denominator: u128) -> u128 {
    numerator / denominator
        + if numerator.is_multiple_of(denominator) {
            0
        } else {
            1
        }
}

fn duration_from_millis(millis: u128) -> Duration {
    Duration::from_millis(
        u64::try_from(millis)
            .expect("GCRA policy validation bounds every reported duration to u64"),
    )
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

impl<C: Clock> Limiter for GcraStore<C> {
    type Policy = GcraPolicy;
    type Error = MemoryStoreError;

    async fn check(&self, check: &Check<'_, Self::Policy>) -> Result<Decision, Self::Error> {
        GcraStore::check(self, check)
    }

    async fn check_all(
        &self,
        checks: &[Check<'_, Self::Policy>],
    ) -> Result<BatchDecision, Self::Error> {
        GcraStore::check_all(self, checks)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Barrier, Mutex,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        thread,
        time::Duration,
    };

    use runlimit_core::{
        AdmissionOutcome, BatchDecision, Check, ConsumptionStatus, Decision, Denial, GcraPolicy,
        MAX_LIMIT, Observation, Observer, PolicyId, QuotaMode, ScopeId, SubjectKey,
    };

    use super::GcraStore;
    use crate::{Clock, MemoryStoreConfig, MemoryStoreError};

    #[derive(Clone, Default)]
    struct ManualClock {
        millis: Arc<AtomicU64>,
    }

    impl ManualClock {
        fn advance(&self, duration: Duration) {
            self.millis.fetch_add(
                u64::try_from(duration.as_millis()).unwrap(),
                Ordering::Relaxed,
            );
        }

        fn set(&self, duration: Duration) {
            self.millis.store(
                u64::try_from(duration.as_millis()).unwrap(),
                Ordering::Relaxed,
            );
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> Duration {
            Duration::from_millis(self.millis.load(Ordering::Relaxed))
        }
    }

    #[derive(Clone, Copy)]
    struct MaximumClock;

    impl Clock for MaximumClock {
        fn now(&self) -> Duration {
            Duration::new(u64::MAX, 999_999_999)
        }
    }

    #[derive(Clone, Default)]
    struct SwitchableExtremeClock {
        extreme: Arc<AtomicBool>,
    }

    impl SwitchableExtremeClock {
        fn use_extreme_time(&self) {
            self.extreme.store(true, Ordering::Relaxed);
        }
    }

    impl Clock for SwitchableExtremeClock {
        fn now(&self) -> Duration {
            if self.extreme.load(Ordering::Relaxed) {
                Duration::new(u64::MAX, 999_999_999)
            } else {
                Duration::ZERO
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RecordedObservation {
        Admission {
            outcome: AdmissionOutcome,
            consumption: ConsumptionStatus,
        },
        Cleanup {
            removed: Option<u64>,
        },
        Capacity {
            used: u64,
            capacity: u64,
        },
    }

    #[derive(Default)]
    struct RecordingObserver {
        observations: Mutex<Vec<RecordedObservation>>,
    }

    impl RecordingObserver {
        fn take(&self) -> Vec<RecordedObservation> {
            std::mem::take(
                &mut *self
                    .observations
                    .lock()
                    .expect("recording observer mutex remains healthy"),
            )
        }
    }

    impl Observer for RecordingObserver {
        fn observe(&self, observation: &Observation<'_>) {
            let recorded = match observation {
                Observation::Admission(admission) => RecordedObservation::Admission {
                    outcome: admission.outcome(),
                    consumption: admission.consumption(),
                },
                Observation::Cleanup(cleanup) => RecordedObservation::Cleanup {
                    removed: cleanup.removed(),
                },
                Observation::Capacity(capacity) => RecordedObservation::Capacity {
                    used: capacity.used(),
                    capacity: capacity.capacity(),
                },
                _ => return,
            };
            self.observations
                .lock()
                .expect("recording observer mutex remains healthy")
                .push(recorded);
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct ReferenceBucket {
        quota: u128,
        period_millis: u128,
        capacity: u64,
        tokens_scaled: u128,
        last_millis: u64,
    }

    impl ReferenceBucket {
        fn new(quota: u64, period_millis: u64, capacity: u64) -> Self {
            Self {
                quota: u128::from(quota),
                period_millis: u128::from(period_millis),
                capacity,
                tokens_scaled: u128::from(capacity) * u128::from(period_millis),
                last_millis: 0,
            }
        }

        fn check(&mut self, now_millis: u64, cost: u64) -> Decision {
            assert!(now_millis >= self.last_millis);
            let maximum = u128::from(self.capacity) * self.period_millis;
            let elapsed = u128::from(now_millis - self.last_millis);
            self.tokens_scaled = maximum.min(self.tokens_scaled + elapsed * self.quota);
            self.last_millis = now_millis;

            let requested = u128::from(cost) * self.period_millis;
            if requested > self.tokens_scaled {
                return Decision::denied(Denial::QuotaExceeded {
                    capacity: self.capacity,
                    retry_after: reference_duration(reference_div_ceil(
                        requested - self.tokens_scaled,
                        self.quota,
                    )),
                });
            }

            self.tokens_scaled -= requested;
            Decision::allowed(
                self.capacity,
                u64::try_from(self.tokens_scaled / self.period_millis)
                    .expect("reference availability fits the configured capacity"),
                reference_duration(reference_div_ceil(maximum - self.tokens_scaled, self.quota)),
            )
        }
    }

    fn reference_div_ceil(numerator: u128, denominator: u128) -> u128 {
        numerator.div_ceil(denominator)
    }

    fn reference_duration(millis: u128) -> Duration {
        Duration::from_millis(
            u64::try_from(millis).expect("small reference-model durations fit in u64"),
        )
    }

    fn policy(id: &str, quota: u64, period: Duration, burst_capacity: u64) -> GcraPolicy {
        GcraPolicy::new(
            PolicyId::new(id).unwrap(),
            ScopeId::new("client").unwrap(),
            quota,
            period,
            burst_capacity,
        )
        .unwrap()
    }

    fn subject(byte: u8) -> SubjectKey {
        SubjectKey::from_digest([byte; 32])
    }

    #[test]
    fn matches_rational_token_bucket_reference_across_small_parameter_space() {
        for quota in 1_u64..=5 {
            for period_millis in 1_u64..=10 {
                for capacity in 1_u64..=5 {
                    let clock = ManualClock::default();
                    let store =
                        GcraStore::with_clock(MemoryStoreConfig::new(1).unwrap(), clock.clone());
                    let id = format!("reference.{quota}.{period_millis}.{capacity}");
                    let policy = policy(&id, quota, Duration::from_millis(period_millis), capacity);
                    let mut reference = ReferenceBucket::new(quota, period_millis, capacity);
                    let mut now_millis = 0_u64;

                    for step in 0_u64..40 {
                        now_millis += match step % 5 {
                            0 | 2 => 0,
                            1 => 1,
                            3 => 2,
                            _ => 3,
                        };
                        clock.set(Duration::from_millis(now_millis));
                        let cost = 1 + (step * 7 + quota + period_millis) % capacity;
                        let expected = reference.check(now_millis, cost);
                        let actual = store
                            .check(&Check::with_cost(&policy, subject(1), cost).unwrap())
                            .unwrap();

                        assert_eq!(
                            actual, expected,
                            "quota={quota}, period={period_millis}ms, capacity={capacity}, \
                             step={step}, now={now_millis}ms, cost={cost}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn quota_three_per_ten_millis_rounds_fractional_boundaries_up() {
        let clock = ManualClock::default();
        let store = GcraStore::with_clock(MemoryStoreConfig::new(1).unwrap(), clock.clone());
        let policy = policy("api.fractional", 3, Duration::from_millis(10), 4);
        let subject = subject(1);

        assert_eq!(
            store.check(&Check::with_cost(&policy, subject, 4).unwrap()),
            Ok(Decision::allowed(4, 0, Duration::from_millis(14)))
        );
        clock.set(Duration::from_millis(3));
        assert_eq!(
            store.check(&Check::new(&policy, subject)),
            Ok(Decision::denied(Denial::QuotaExceeded {
                capacity: 4,
                retry_after: Duration::from_millis(1),
            }))
        );
        clock.set(Duration::from_millis(4));
        assert_eq!(
            store.check(&Check::new(&policy, subject)),
            Ok(Decision::allowed(4, 0, Duration::from_millis(13)))
        );
    }

    #[test]
    fn quota_above_period_milliseconds_replenishes_multiple_units_per_tick() {
        let clock = ManualClock::default();
        let store = GcraStore::with_clock(MemoryStoreConfig::new(1).unwrap(), clock.clone());
        let policy = policy("api.fast", 10, Duration::from_millis(1), 12);
        let subject = subject(1);

        assert_eq!(
            store.check(&Check::with_cost(&policy, subject, 12).unwrap()),
            Ok(Decision::allowed(12, 0, Duration::from_millis(2)))
        );
        assert_eq!(
            store.check(&Check::new(&policy, subject)),
            Ok(Decision::denied(Denial::QuotaExceeded {
                capacity: 12,
                retry_after: Duration::from_millis(1),
            }))
        );
        clock.set(Duration::from_millis(1));
        assert_eq!(
            store.check(&Check::with_cost(&policy, subject, 10).unwrap()),
            Ok(Decision::allowed(12, 0, Duration::from_millis(2)))
        );
    }

    #[test]
    fn weighted_burst_refills_at_exact_integer_boundaries() {
        let clock = ManualClock::default();
        let store = GcraStore::with_clock(MemoryStoreConfig::new(8).unwrap(), clock.clone());
        let policy = policy("api.read", 2, Duration::from_secs(1), 4);
        let check = Check::with_cost(&policy, subject(1), 3).unwrap();

        assert_eq!(
            store.check(&check),
            Ok(Decision::allowed(4, 1, Duration::from_millis(1_500)))
        );
        assert_eq!(
            store.check(&Check::new(&policy, subject(1))),
            Ok(Decision::allowed(4, 0, Duration::from_secs(2)))
        );
        assert_eq!(
            store.check(&Check::new(&policy, subject(1))),
            Ok(Decision::denied(Denial::QuotaExceeded {
                capacity: 4,
                retry_after: Duration::from_millis(500),
            }))
        );

        clock.advance(Duration::from_millis(499));
        assert_eq!(
            store.check(&Check::new(&policy, subject(1))),
            Ok(Decision::denied(Denial::QuotaExceeded {
                capacity: 4,
                retry_after: Duration::from_millis(1),
            }))
        );
        clock.advance(Duration::from_millis(1));
        assert_eq!(
            store.check(&Check::new(&policy, subject(1))),
            Ok(Decision::allowed(4, 0, Duration::from_secs(2)))
        );

        clock.advance(Duration::from_secs(2));
        assert_eq!(
            store.check(&Check::new(&policy, subject(1))),
            Ok(Decision::allowed(4, 3, Duration::from_millis(500)))
        );
    }

    #[test]
    fn regressing_clocks_cannot_refill_quota_early() {
        let clock = ManualClock::default();
        clock.set(Duration::from_secs(10));
        let store = GcraStore::with_clock(MemoryStoreConfig::new(2).unwrap(), clock.clone());
        let policy = policy("api.write", 1, Duration::from_secs(1), 1);
        let check = Check::new(&policy, subject(1));

        assert!(store.check(&check).unwrap().is_allowed());
        clock.set(Duration::from_secs(1));
        assert_eq!(
            store.check(&check),
            Ok(Decision::denied(Denial::QuotaExceeded {
                capacity: 1,
                retry_after: Duration::from_secs(1),
            }))
        );
    }

    #[test]
    fn bounded_expiry_cleanup_releases_hard_capacity() {
        let clock = ManualClock::default();
        let config = MemoryStoreConfig::new(3)
            .unwrap()
            .with_max_expired_removals_per_check(1)
            .unwrap();
        let store = GcraStore::with_clock(config, clock.clone());
        let policy = policy("api.read", 1, Duration::from_millis(10), 1);

        for byte in 1..=3 {
            assert!(
                store
                    .check(&Check::new(&policy, subject(byte)))
                    .unwrap()
                    .is_allowed()
            );
        }
        assert!(
            store
                .check(&Check::new(&policy, subject(4)))
                .unwrap()
                .is_denied()
        );

        clock.advance(Duration::from_millis(10));
        assert!(
            store
                .check(&Check::new(&policy, subject(4)))
                .unwrap()
                .is_allowed()
        );
        assert_eq!(store.stats().unwrap().entries(), 3);
    }

    #[test]
    fn concurrent_same_key_checks_consume_exactly_one_burst() {
        const ATTEMPTS: usize = 32;
        const BURST: usize = 7;

        let store =
            GcraStore::with_clock(MemoryStoreConfig::new(1).unwrap(), ManualClock::default());
        let policy = policy(
            "api.concurrent",
            1,
            Duration::from_secs(60),
            u64::try_from(BURST).unwrap(),
        );
        let check = Check::new(&policy, subject(1));
        let barrier = Arc::new(Barrier::new(ATTEMPTS + 1));

        let decisions = thread::scope(|scope| {
            let mut handles = Vec::with_capacity(ATTEMPTS);
            let store_ref = &store;
            for _ in 0..ATTEMPTS {
                let barrier = Arc::clone(&barrier);
                handles.push(scope.spawn(move || {
                    barrier.wait();
                    store_ref.check(&check).unwrap()
                }));
            }
            barrier.wait();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("admission thread does not panic"))
                .collect::<Vec<_>>()
        });

        assert_eq!(
            decisions
                .iter()
                .filter(|decision| !decision.would_deny())
                .count(),
            BURST
        );
        assert_eq!(
            decisions
                .iter()
                .filter(|decision| {
                    matches!(decision.denial(), Some(Denial::QuotaExceeded { .. }))
                })
                .count(),
            ATTEMPTS - BURST
        );
        assert_eq!(store.stats().unwrap().entries(), 1);
    }

    #[test]
    fn allowed_batches_return_exact_decisions_in_input_order() {
        let store =
            GcraStore::with_clock(MemoryStoreConfig::new(2).unwrap(), ManualClock::default());
        let slow = policy("api.slow", 1, Duration::from_millis(10), 3);
        let fast = policy("api.fast", 4, Duration::from_millis(10), 5);
        let checks = [
            Check::with_cost(&fast, subject(1), 3).unwrap(),
            Check::with_cost(&slow, subject(1), 2).unwrap(),
        ];

        assert_eq!(
            store.check_all(&checks),
            Ok(BatchDecision::Allowed(vec![
                Decision::allowed(5, 2, Duration::from_millis(8)),
                Decision::allowed(3, 1, Duration::from_millis(20)),
            ]))
        );
    }

    #[test]
    fn enforced_quota_denial_rolls_back_earlier_batch_members() {
        let store =
            GcraStore::with_clock(MemoryStoreConfig::new(3).unwrap(), ManualClock::default());
        let policy = policy("api.quota-rollback", 1, Duration::from_millis(100), 1);
        let exhausted = Check::new(&policy, subject(1));
        let earlier = Check::new(&policy, subject(2));
        assert!(store.check(&exhausted).unwrap().is_allowed());

        assert!(matches!(
            store.check_all(&[earlier, exhausted]).unwrap(),
            BatchDecision::Denied {
                index: 1,
                denial: Denial::QuotaExceeded { .. },
            }
        ));
        assert!(
            store.check(&earlier).unwrap().is_allowed(),
            "a quota-denied batch must not consume an earlier member"
        );
    }

    #[test]
    fn storage_capacity_denial_rolls_back_earlier_batch_members() {
        let store =
            GcraStore::with_clock(MemoryStoreConfig::new(2).unwrap(), ManualClock::default());
        let policy = policy("api.capacity-rollback", 1, Duration::from_millis(100), 2);
        let earlier = Check::new(&policy, subject(1));
        let occupying = Check::new(&policy, subject(2));
        let new_key = Check::new(&policy, subject(3));
        assert!(store.check(&earlier).unwrap().is_allowed());
        assert!(store.check(&occupying).unwrap().is_allowed());

        assert!(matches!(
            store.check_all(&[earlier, new_key]).unwrap(),
            BatchDecision::Denied {
                index: 1,
                denial: Denial::StorageCapacity { .. },
            }
        ));
        assert!(
            store.check(&earlier).unwrap().is_allowed(),
            "a capacity-denied batch must not consume an earlier member"
        );
    }

    #[test]
    fn atomic_batches_preserve_order_and_roll_back_on_shadow_denial() {
        let store =
            GcraStore::with_clock(MemoryStoreConfig::new(8).unwrap(), ManualClock::default());
        let shadow =
            policy("api.read", 1, Duration::from_secs(1), 1).with_quota_mode(QuotaMode::Shadow);
        let first = Check::new(&shadow, subject(1));
        let second = Check::new(&shadow, subject(2));

        assert!(store.check(&first).unwrap().is_allowed());
        assert!(matches!(
            store.check_all(&[first, second]).unwrap(),
            BatchDecision::ShadowDenied { index: 0, .. }
        ));
        assert!(
            store.check(&second).unwrap().is_allowed(),
            "a shadow-denied batch must not consume any member"
        );
    }

    #[test]
    fn storage_capacity_is_enforced_for_shadow_policies() {
        let store =
            GcraStore::with_clock(MemoryStoreConfig::new(1).unwrap(), ManualClock::default());
        let shadow =
            policy("api.read", 1, Duration::from_secs(1), 1).with_quota_mode(QuotaMode::Shadow);

        assert!(
            store
                .check(&Check::new(&shadow, subject(1)))
                .unwrap()
                .is_allowed()
        );
        let decision = store.check(&Check::new(&shadow, subject(2))).unwrap();
        assert!(decision.is_enforced_denial());
        assert!(matches!(
            decision.denial(),
            Some(Denial::StorageCapacity { .. })
        ));
    }

    #[test]
    fn extreme_clock_values_fail_closed_without_mutation() {
        let store = GcraStore::with_clock(MemoryStoreConfig::new(1).unwrap(), MaximumClock);
        let policy = policy("api.read", MAX_LIMIT, Duration::from_millis(1), 1);
        let check = Check::new(&policy, subject(1));

        assert_eq!(
            store.check(&check),
            Err(MemoryStoreError::ArithmeticOverflow)
        );
        assert_eq!(store.stats().unwrap().entries(), 0);
    }

    #[test]
    fn arithmetic_preflight_preserves_expired_entries_and_emits_only_failure() {
        let clock = SwitchableExtremeClock::default();
        let observer = Arc::new(RecordingObserver::default());
        let store = GcraStore::with_clock(MemoryStoreConfig::new(1).unwrap(), clock.clone())
            .with_observer(observer.clone());
        let ordinary = policy("api.ordinary", 1, Duration::from_millis(1), 1);
        assert!(
            store
                .check(&Check::new(&ordinary, subject(1)))
                .unwrap()
                .is_allowed()
        );
        observer.take();

        clock.use_extreme_time();
        let overflowing = policy("api.overflowing", MAX_LIMIT, Duration::from_millis(1), 1);
        assert_eq!(
            store.check(&Check::new(&overflowing, subject(2))),
            Err(MemoryStoreError::ArithmeticOverflow)
        );
        assert_eq!(
            store.stats().unwrap().entries(),
            1,
            "arithmetic preflight must fail before pruning the now-expired entry"
        );
        assert_eq!(
            observer.take(),
            vec![RecordedObservation::Admission {
                outcome: AdmissionOutcome::Failed,
                consumption: ConsumptionStatus::NotConsumed,
            }]
        );
    }

    #[test]
    fn generic_limiter_contract_selects_gcra_policy() {
        fn accepts_gcra_limiter<L: runlimit_core::Limiter<Policy = GcraPolicy>>(_limiter: &L) {}

        let store =
            GcraStore::with_clock(MemoryStoreConfig::new(1).unwrap(), ManualClock::default());
        accepts_gcra_limiter(&store);
    }
}
