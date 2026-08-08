use runlimit_core::{BatchError, ConsumptionStatus};
use thiserror::Error;

/// Failure from a quota check.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CheckError {
    /// The atomic batch violated a backend-independent structural requirement.
    #[error(transparent)]
    InvalidBatch(#[from] BatchError),

    /// `PostgreSQL` did not commit the transaction, so no quota was consumed.
    #[error("PostgreSQL rate-limit check failed before commit; quota was not consumed")]
    DefinitelyNotConsumed(#[source] sqlx::Error),

    /// Commit confirmation was lost, so quota may or may not have been consumed.
    #[error("PostgreSQL rate-limit commit outcome is unknown; quota may have been consumed")]
    CommitOutcomeUnknown(#[source] sqlx::Error),

    /// The pool-acquisition budget or operation deadline elapsed before commit
    /// started.
    #[error("PostgreSQL rate-limit check timed out while {operation}; quota was not consumed")]
    TimedOutBeforeCommit {
        /// Database phase that exhausted the deadline.
        operation: &'static str,
    },

    /// The operation deadline elapsed after commit started.
    #[error("PostgreSQL rate-limit commit timed out; quota may have been consumed")]
    CommitTimedOut,

    /// Persisted state violated an invariant guaranteed by the migration.
    #[error("PostgreSQL rate-limit storage invariant failed: {0}")]
    StorageInvariant(&'static str),

    /// A rolled-back single check produced malformed response metadata.
    #[error(
        "PostgreSQL rate-limit single-check response invariant failed after rollback; quota was not consumed"
    )]
    ResponseInvariant,

    /// A committed single check produced malformed response metadata.
    #[error(
        "PostgreSQL rate-limit single-check response invariant failed after commit; quota was consumed"
    )]
    CommittedResponseInvariant,
}

impl CheckError {
    /// Reports whether the failed operation may have consumed quota.
    pub const fn may_have_consumed_quota(&self) -> bool {
        matches!(
            self,
            Self::CommitOutcomeUnknown(_) | Self::CommitTimedOut | Self::CommittedResponseInvariant
        )
    }
}

/// Failure from bounded expired-window cleanup.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MaintenanceError {
    /// `PostgreSQL` did not commit the cleanup transaction, so no rows were
    /// removed.
    #[error("PostgreSQL expired-window cleanup failed before commit; no rows were removed")]
    Database(#[source] sqlx::Error),
    /// The pool-acquisition budget or operation deadline elapsed before cleanup
    /// commit started.
    #[error("PostgreSQL expired-window cleanup timed out while {operation}; no rows were removed")]
    TimedOutBeforeCommit {
        /// Database phase that exhausted the deadline.
        operation: &'static str,
    },
    /// Commit confirmation was lost, so rows may or may not have been removed.
    #[error(
        "PostgreSQL expired-window cleanup commit outcome is unknown; rows may have been removed"
    )]
    CommitOutcomeUnknown(#[source] sqlx::Error),
    /// The operation deadline elapsed after cleanup commit started.
    #[error("PostgreSQL expired-window cleanup commit timed out; rows may have been removed")]
    CommitTimedOut,
}

impl MaintenanceError {
    /// Reports whether the failed cleanup may have committed row removals.
    pub const fn may_have_removed_rows(&self) -> bool {
        matches!(self, Self::CommitOutcomeUnknown(_) | Self::CommitTimedOut)
    }
}

pub(crate) const fn check_error_consumption(error: &CheckError) -> ConsumptionStatus {
    match error {
        CheckError::CommitOutcomeUnknown(_) | CheckError::CommitTimedOut => {
            ConsumptionStatus::PossiblyConsumed
        }
        CheckError::CommittedResponseInvariant => ConsumptionStatus::Consumed,
        _ => ConsumptionStatus::NotConsumed,
    }
}
