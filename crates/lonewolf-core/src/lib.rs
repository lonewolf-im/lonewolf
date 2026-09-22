// SPDX-License-Identifier: Apache-2.0

//! Owns process startup and shutdown, including global diagnostics, shared
//! storage, and worker runtimes.

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

use std::env;
use std::io;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use compio::runtime::Runtime;
use lonewolf_util::core_dispatcher::CoreDispatcher;
use lonewolf_util::pool::PooledChunkAllocator;

pub mod config;
mod error;
mod logging;
mod panic;
mod shutdown;
mod storage;

use config::Config;
pub use error::RunError;
use storage::StoreRegistry;

const DISPATCH_QUEUE_CAPACITY: NonZeroUsize = NonZeroUsize::new(256).unwrap();
const WORKER_SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

pub struct BuildInfo {
    pub version: &'static str,
    pub branch: &'static str,
    pub commit: &'static str,
}

/// Runs until SIGINT, SIGTERM, or a service failure.
///
/// Replaces the process panic hook and installs global logging. Worker threads
/// are joined and buffered logs are flushed before returning. Configuration
/// paths follow [`Config::load`]. `LONEWOLF_WORKER_COUNT` overrides the detected
/// parallelism and must be a positive integer.
///
/// # Errors
///
/// Returns [`RunError::Config`] for invalid configuration or
/// [`RunError::WorkerCount`] if worker count selection fails. Startup failures
/// identify logging, stanza pool, runtime, dispatcher, storage, or admin
/// initialization in [`RunError`]. Signal and worker shutdown failures also
/// return [`RunError`]. If service execution and worker shutdown both fail, the
/// service error wins.
///
/// # Panics
///
/// Panics if called from a panicking thread while installing the panic hook.
pub fn run(config_path: Option<&Path>, build: BuildInfo) -> Result<(), RunError> {
    panic::init(&build);

    let config = Config::load(config_path).map_err(RunError::Config)?;
    let worker_count = worker_count().map_err(RunError::WorkerCount)?;

    let _logging_guard = logging::init(config.logging.level).map_err(RunError::Logging)?;
    tracing::info!(
        version = build.version,
        branch = build.branch,
        commit = build.commit,
        "lonewolf is starting..."
    );
    let stanza_pool = Arc::new(
        PooledChunkAllocator::try_new(
            config
                .xmpp
                .stanza_pool_config(worker_count)
                .map_err(RunError::StanzaPool)?,
        )
        .map_err(RunError::StanzaPool)?,
    );
    tracing::info!(
        reserved_bytes = stanza_pool.config().total_bytes.get(),
        shards_per_bucket = stanza_pool.config().shards_per_bucket.get(),
        "stanza arena pool initialized"
    );

    {
        let mut stores = StoreRegistry::new(&config.storage);
        let account_store = config
            .account
            .storage
            .as_deref()
            .unwrap_or(&config.storage.default);
        let runtime = Runtime::new().map_err(RunError::Runtime)?;
        let dispatcher = CoreDispatcher::new(worker_count, DISPATCH_QUEUE_CAPACITY)
            .map_err(RunError::Dispatcher)?;
        tracing::info!(worker_count = worker_count.get(), "core dispatcher started");
        runtime.block_on(async {
            let result = async {
                let accounts = stores.accounts(account_store)?;
                if config.admin.enabled {
                    let server = lonewolf_admin::Server::bind(&config.admin.socket_path, accounts)
                        .map_err(RunError::Admin)?;
                    return server.run(shutdown::wait()).await.map_err(RunError::Admin);
                }
                shutdown::wait().await.map_err(RunError::Signal)
            }
            .await;
            let stopped = dispatcher
                .shutdown(WORKER_SHUTDOWN_GRACE)
                .await
                .map_err(RunError::DispatcherShutdown);
            if stopped.is_ok() {
                tracing::info!("core dispatcher stopped");
            }
            result.and(stopped)
        })?;
    }

    tracing::info!("heading back to the den");
    Ok(())
}

fn worker_count() -> io::Result<NonZeroUsize> {
    match env::var("LONEWOLF_WORKER_COUNT") {
        Ok(value) => value.parse().map_err(|_| invalid_worker_count()),
        Err(env::VarError::NotPresent) => thread::available_parallelism(),
        Err(env::VarError::NotUnicode(_)) => Err(invalid_worker_count()),
    }
}

fn invalid_worker_count() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "LONEWOLF_WORKER_COUNT must be a positive integer",
    )
}
