// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use tracing::Level;
use tracing_appender::non_blocking::{NonBlockingBuilder, WorkerGuard};

pub(crate) fn init() -> Result<WorkerGuard, Box<dyn Error + Send + Sync>> {
    let (writer, guard) = NonBlockingBuilder::default()
        .buffered_lines_limit(1024)
        .lossy(true)
        .finish(std::io::stderr());
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_ansi(false)
        .with_writer(writer)
        .try_init()?;
    Ok(guard)
}
