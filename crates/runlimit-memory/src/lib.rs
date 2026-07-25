//! Hard-bounded, process-local rate-limit storage.
//!
//! [`MemoryStore`] implements the same anchored fixed-window model as the
//! `PostgreSQL` backend while deliberately refusing to evict live entries. When
//! a shard is full, a new subject is denied until bounded cleanup frees space.
//! An atomic batch that can never fit in one shard returns a structural
//! [`MemoryStoreError`] instead of a retryable capacity denial.

mod clock;
mod config;
mod store;

pub use clock::{Clock, SystemClock};
pub use config::{MemoryStoreConfig, MemoryStoreConfigError};
pub use store::{MemoryStore, MemoryStoreError, MemoryStoreStats};
