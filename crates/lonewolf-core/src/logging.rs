// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::error::Error;
use std::io::IsTerminal;

use time::macros::format_description;
use tracing::Level;
use tracing_appender::non_blocking::{NonBlockingBuilder, WorkerGuard};
use tracing_subscriber::fmt::time::UtcTime;

pub(crate) fn init() -> Result<WorkerGuard, Box<dyn Error + Send + Sync>> {
    let ansi = std::io::stderr().is_terminal()
        && env::var_os("NO_COLOR").is_none_or(|value| value.is_empty())
        && env::var_os("TERM").is_none_or(|value| value != "dumb");
    let (writer, guard) = NonBlockingBuilder::default()
        .buffered_lines_limit(1024)
        .lossy(true)
        .finish(std::io::stderr());
    tracing_subscriber::fmt()
        .with_timer(UtcTime::new(format_description!(
            "[year]:[month]:[day] [hour]:[minute]:[second]"
        )))
        .with_max_level(Level::INFO)
        .with_ansi(ansi)
        .with_writer(writer)
        .try_init()?;
    Ok(guard)
}
