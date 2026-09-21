// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use compio::runtime::Runtime;

pub mod config;
mod error;
mod logging;
mod shutdown;

use config::Config;
pub use error::RunError;

pub struct BuildInfo {
    pub version: &'static str,
    pub branch: &'static str,
    pub commit: &'static str,
}

/// Runs on the calling thread until Ctrl+C or, on Unix, SIGTERM requests shutdown.
/// Installs the global tracing subscriber and flushes logs before returning.
pub fn run(config_path: Option<&Path>, build: BuildInfo) -> Result<(), RunError> {
    let _logging_guard = logging::init().map_err(RunError::Logging)?;
    tracing::info!(
        version = build.version,
        branch = build.branch,
        commit = build.commit,
        "lonewolf is starting..."
    );

    let _config = Config::load(config_path).map_err(RunError::Config)?;
    {
        let runtime = Runtime::new().map_err(RunError::Runtime)?;
        tracing::info!("waiting for stop signal... (press Ctrl+C to stop the server)");
        runtime
            .block_on(shutdown::wait())
            .map_err(RunError::Signal)?;
        tracing::info!("received stop signal... gracefully shutting down...");
    }

    tracing::info!("heading back to the den");
    Ok(())
}
