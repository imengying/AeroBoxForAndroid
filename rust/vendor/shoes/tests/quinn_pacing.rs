//! Run the vendored pacer's own unit tests without enabling Quinn's upstream
//! default C-backed test crypto dependencies.
use std::time::{Duration, Instant};

#[path = "../../quinn-proto/src/connection/pacing.rs"]
mod pacing;
