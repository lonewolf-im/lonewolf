// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::error::Error;
use std::io::IsTerminal;

use time::macros::format_description;
use tracing_appender::non_blocking::{NonBlockingBuilder, WorkerGuard};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::time::UtcTime;

use crate::config::LogLevel;

pub(crate) fn init(level: LogLevel) -> Result<WorkerGuard, Box<dyn Error + Send + Sync>> {
    let filter = match level {
        LogLevel::Off => LevelFilter::OFF,
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Trace => LevelFilter::TRACE,
    };
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
        .with_max_level(filter)
        .with_ansi(ansi)
        .with_writer(writer)
        .try_init()?;
    Ok(guard)
}
