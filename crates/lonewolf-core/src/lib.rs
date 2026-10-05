// SPDX-License-Identifier: Apache-2.0

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

use std::collections::BTreeSet;
use std::env;
use std::future::{Future, pending};
use std::io;
use std::num::NonZeroUsize;
use std::path::Path;
use std::pin::pin;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use compio::runtime::Runtime;
use futures_channel::oneshot;
use futures_util::future::{Either, join, select};
use lonewolf_extension::{Extension, Extensions};
use lonewolf_storage::RedbStorage;
use lonewolf_util::core_dispatcher::CoreDispatcher;
use lonewolf_util::pool::PooledChunkAllocator;

mod account_deletion;
mod c2s;
pub mod config;
mod delivery;
mod error;
pub mod hosts;
mod logging;
mod order;
mod panic;
pub mod router;
mod shutdown;
mod storage;

use config::Config;
pub use error::RunError;
use hosts::Hosts;
use router::Router;
use router::local::LocalRouter;
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
/// Returns [`RunError`] for invalid configuration, startup, service, or shutdown
/// failures. If service execution and worker shutdown both fail, the service
/// error wins.
///
/// # Panics
///
/// Panics if called from a panicking thread while installing the panic hook.
pub fn run(config_path: Option<&Path>, build: BuildInfo) -> Result<(), RunError> {
    run_with_extensions(config_path, build, Extensions::default())
}

/// Uses the lifecycle and process-wide side effects of [`run`].
/// Enabled extensions must exist in the supplied catalog and have disjoint stanza routes.
pub fn run_with_extensions(
    config_path: Option<&Path>,
    build: BuildInfo,
    mut extensions: Extensions<Arc<PooledChunkAllocator>, RedbStorage>,
) -> Result<(), RunError> {
    panic::init(&build);

    let config = Config::load(config_path).map_err(RunError::Config)?;
    let hosts =
        Hosts::new(&config.hosts, config.xmpp.default_host.as_deref()).map_err(RunError::Hosts)?;
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
            let mut listeners = None;
            let mut router = None;
            let mut shutdown_deadline = None;
            let result = async {
                let storage = stores.storage(account_store)?;
                let referenced = config
                    .hosts
                    .values()
                    .flat_map(|host| host.extensions.iter().map(String::as_str))
                    .collect::<BTreeSet<_>>();
                for name in referenced {
                    let extension: Arc<dyn Extension<Arc<PooledChunkAllocator>, RedbStorage>> =
                        match name {
                            lonewolf_extension::roster::NAME => {
                                let limits = config
                                    .hosts
                                    .iter()
                                    .filter_map(|(domain, host)| {
                                        host.roster.map(|roster| {
                                            (
                                                domain.as_str().into(),
                                                lonewolf_extension::roster::RosterLimits {
                                                    max_pending_subscription_requests: roster
                                                        .max_pending_subscription_requests,
                                                },
                                            )
                                        })
                                    })
                                    .collect();
                                Arc::new(lonewolf_extension::roster::Roster::new(limits))
                            }
                            lonewolf_extension::offline::NAME => {
                                let limits = config
                                    .hosts
                                    .iter()
                                    .filter_map(|(domain, host)| {
                                        host.offline.map(|offline| {
                                            (
                                                domain.as_str().into(),
                                                lonewolf_extension::offline::OfflineLimits {
                                                    max_messages_per_account: offline
                                                        .max_messages_per_account,
                                                },
                                            )
                                        })
                                    })
                                    .collect();
                                Arc::new(lonewolf_extension::offline::Offline::new(limits))
                            }
                            _ => continue,
                        };
                    extensions
                        .register(extension)
                        .map_err(RunError::ExtensionCatalog)?;
                }
                let enabled_extensions = config
                    .hosts
                    .iter()
                    .map(|(domain, host)| {
                        extensions
                            .enable(host.extensions.iter().map(String::as_str))
                            .map(|registry| (domain.clone(), registry))
                            .map_err(|source| RunError::Extensions {
                                host: domain.clone(),
                                source,
                            })
                    })
                    .collect::<Result<_, _>>()?;
                let (deleter, deletions) = account_deletion::channel();
                let admin = if config.admin.enabled {
                    Some(
                        lonewolf_admin::Server::bind(
                            &config.admin.socket_path,
                            storage.clone(),
                            deleter,
                        )
                        .map_err(RunError::Admin)?,
                    )
                } else {
                    None
                };
                let local = LocalRouter::start(&dispatcher.handle(), Arc::clone(&stanza_pool))
                    .await
                    .map_err(RunError::Router)?;
                let router_handle = router
                    .insert(Router::new(hosts.clone(), local).with_extensions(enabled_extensions))
                    .handle();
                let deletion_router = router_handle.clone();
                let deletion_storage = storage.clone();
                let listeners = listeners.insert(
                    c2s::Listeners::start(
                        &config.c2s,
                        &config.limits.c2s,
                        hosts,
                        storage,
                        router_handle,
                        &dispatcher.handle(),
                        Arc::clone(&stanza_pool),
                    )
                    .await
                    .map_err(|failure| {
                        shutdown_deadline = Some(failure.deadline);
                        RunError::C2s(failure.error)
                    })?,
                );
                run_services(
                    admin,
                    listeners,
                    &mut shutdown_deadline,
                    account_deletion::run(
                        deletions,
                        &deletion_storage,
                        &deletion_router,
                        &stanza_pool,
                    ),
                )
                .await
            }
            .await;
            let deadline =
                shutdown_deadline.unwrap_or_else(|| Instant::now() + WORKER_SHUTDOWN_GRACE);
            let listeners_stopped = match listeners {
                Some(mut listeners) => {
                    listeners.stop(deadline);
                    compio::time::timeout_at(deadline, listeners.join())
                        .await
                        .unwrap_or_else(|_| Err(shutdown_timeout()))
                        .map_err(RunError::C2s)
                }
                None => Ok(()),
            };
            let router_stopped = match router {
                Some(router) => compio::time::timeout_at(deadline, router.shutdown())
                    .await
                    .unwrap_or_else(|_| Err(shutdown_timeout()))
                    .map_err(RunError::RouterShutdown),
                None => Ok(()),
            };
            let stopped = dispatcher
                .shutdown_at(deadline)
                .await
                .map_err(RunError::DispatcherShutdown);
            if stopped.is_ok() {
                tracing::info!("core dispatcher stopped");
            }
            result
                .and(stopped)
                .and(listeners_stopped)
                .and(router_stopped)
        })?;
    }

    tracing::info!("heading back to the den");
    Ok(())
}

async fn run_services(
    admin: Option<lonewolf_admin::Server>,
    listeners: &mut c2s::Listeners,
    shutdown_deadline: &mut Option<Instant>,
    deletions: impl Future<Output = ()>,
) -> Result<(), RunError> {
    let admin_enabled = admin.is_some();
    let (stop_admin, stopped) = oneshot::channel::<()>();
    // The admin service can wait for accepted deletions while it drains.
    let mut services = pin!(async move {
        let server = async move {
            match admin {
                Some(server) => server
                    .run(async move {
                        let _ = stopped.await;
                        Ok(())
                    })
                    .await
                    .map_err(RunError::Admin),
                None => pending().await,
            }
        };
        let (result, ()) = join(server, deletions).await;
        result
    });
    let result = {
        let shutdown = async {
            match select(pin!(shutdown::wait()), pin!(listeners.failure())).await {
                Either::Left((result, _)) => result.map_err(RunError::Signal),
                Either::Right((error, _)) => Err(RunError::C2s(error)),
            }
        };
        match select(services.as_mut(), pin!(shutdown)).await {
            Either::Left((result, _)) => Either::Right(result),
            Either::Right((result, _)) => Either::Left(result),
        }
    };
    let deadline = Instant::now() + WORKER_SHUTDOWN_GRACE;
    *shutdown_deadline = Some(deadline);
    listeners.stop(deadline);
    drop(stop_admin);
    let drain = async {
        let services = async {
            match result {
                Either::Left(result) if admin_enabled => result.and(services.await),
                Either::Left(result) | Either::Right(result) => result,
            }
        };
        let (services, listeners) = join(services, listeners.join()).await;
        services.and(listeners.map_err(RunError::C2s))
    };
    compio::time::timeout_at(deadline, drain)
        .await
        .unwrap_or_else(|_| Err(RunError::DispatcherShutdown(shutdown_timeout())))
}

fn shutdown_timeout() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "services exceeded shutdown deadline",
    )
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
