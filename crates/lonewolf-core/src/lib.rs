// SPDX-License-Identifier: Apache-2.0

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

use std::path::Path;

use compio::runtime::Runtime;

pub mod config;
mod error;
mod logging;
mod panic;
mod shutdown;
mod storage;

use config::Config;
pub use error::RunError;
use storage::StoreRegistry;

pub struct BuildInfo {
    pub version: &'static str,
    pub branch: &'static str,
    pub commit: &'static str,
}

/// Runs on the calling thread until SIGINT or SIGTERM requests shutdown.
/// Installs the global panic hook and tracing subscriber, and flushes logs before returning.
/// Opens storage and the enabled admin listener before waiting for shutdown.
pub fn run(config_path: Option<&Path>, build: BuildInfo) -> Result<(), RunError> {
    panic::init(&build);

    let config = Config::load(config_path).map_err(RunError::Config)?;

    let _logging_guard = logging::init(config.logging.level).map_err(RunError::Logging)?;
    tracing::info!(
        version = build.version,
        branch = build.branch,
        commit = build.commit,
        "lonewolf is starting..."
    );

    {
        let mut stores = StoreRegistry::new(&config.storage);
        let account_store = config
            .account
            .storage
            .as_deref()
            .unwrap_or(&config.storage.default);
        let accounts = stores.accounts(account_store)?;
        let runtime = Runtime::new().map_err(RunError::Runtime)?;
        runtime.block_on(async {
            if config.admin.enabled {
                let server = lonewolf_admin::Server::bind(&config.admin.socket_path, accounts)
                    .map_err(RunError::Admin)?;
                return server.run(shutdown::wait()).await.map_err(RunError::Admin);
            }
            shutdown::wait().await.map_err(RunError::Signal)
        })?;
    }

    tracing::info!("heading back to the den");
    Ok(())
}
