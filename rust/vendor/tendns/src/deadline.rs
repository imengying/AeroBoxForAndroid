use std::{fmt, future::Future};

use anyhow::{Context, Result, ensure};
use tokio::time::Instant;

/// A tendns-enforced deadline elapsed, before or during an operation.
///
/// Available through `anyhow::Error::downcast_ref` for resolver deadlines and
/// the default [`crate::Exchange::exchange_with_deadline`] implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeoutError;

impl fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DNS operation timed out")
    }
}

impl std::error::Error for TimeoutError {}

pub(crate) fn check(deadline: Instant) -> Result<()> {
    ensure!(Instant::now() < deadline, TimeoutError);
    Ok(())
}

pub(crate) async fn timeout_at<F: Future>(deadline: Instant, work: F) -> Result<F::Output> {
    // Tokio polls work before its timer, so guard both entry and completion.
    check(deadline)?;
    let result = tokio::time::timeout_at(deadline, work)
        .await
        .context(TimeoutError)?;
    check(deadline)?;
    Ok(result)
}
