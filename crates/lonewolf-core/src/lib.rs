// SPDX-License-Identifier: Apache-2.0

#[cfg(not(unix))]
compile_error!("Lonewolf supports Unix targets only.");

use std::collections::BTreeMap;
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
use lonewolf_extension::{Extensions, HostSelection};
use lonewolf_storage::RedbStorage;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_util::core_dispatcher::CoreDispatcher;
use lonewolf_util::pool::PooledChunkAllocator;
use prometheus_client::registry::Registry;

mod account_deletion;
mod acme;
mod c2s;
pub mod config;
mod delivery;
mod error;
pub mod hosts;
mod logging;
mod metrics;
mod order;
mod panic;
pub(crate) mod router;
mod shutdown;
mod stages;
mod storage;
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod test_support;

use config::Config;
pub use error::RunError;
use hosts::Hosts;
pub use router::RouterFailure;
use router::local::LocalRouter;
use router::{Router, ServiceRoute};
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

/// Enabled extensions must have disjoint stanza routes.
pub fn run_with_extensions(
    config_path: Option<&Path>,
    build: BuildInfo,
    extensions: Extensions<Arc<PooledChunkAllocator>, RedbStorage>,
) -> Result<(), RunError> {
    run_internal(config_path, build, extensions, acme::LoadOptions::default())
}

#[cfg(feature = "test-support")]
pub fn run_with_acme_clock(
    config_path: Option<&Path>,
    build: BuildInfo,
    clock: lonewolf_acme::test_support::TestClock,
) -> Result<(), RunError> {
    run_internal(
        config_path,
        build,
        Extensions::default(),
        acme::LoadOptions { clock: Some(clock) },
    )
}

fn run_internal(
    config_path: Option<&Path>,
    build: BuildInfo,
    mut extensions: Extensions<Arc<PooledChunkAllocator>, RedbStorage>,
    acme_options: acme::LoadOptions,
) -> Result<(), RunError> {
    panic::init(&build);

    let config = Config::load(config_path).map_err(RunError::Config)?;
    let hosts =
        Hosts::new(&config.hosts, config.xmpp.default_host.as_deref()).map_err(RunError::Hosts)?;
    let worker_count = worker_count().map_err(RunError::WorkerCount)?;

    let (_logging_guard, dropped_logs) =
        logging::init(config.logging.level).map_err(RunError::Logging)?;
    let effective_uid = nix::unistd::geteuid();
    if effective_uid.is_root() {
        tracing::warn!(
            effective_uid = effective_uid.as_raw(),
            "lonewolf is running as root; use an unprivileged user"
        );
    }
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
            let mut stop_signal = pin!(shutdown::wait());
            let mut acme = None;
            let mut listeners = None;
            let mut router = None;
            let mut shutdown_deadline = None;
            let result = async {
                match startup_until_signal(
                    acme::supervise("load", acme_options.load(&config, hosts.clone())),
                    stop_signal.as_mut(),
                    &mut shutdown_deadline,
                )
                .await?
                {
                    Some(loaded) => acme = loaded,
                    None => return Ok(()),
                }
                let storage = stores.storage(account_store)?;
                for factory in lonewolf_extension::builtin() {
                    extensions
                        .register_factory(factory)
                        .map_err(RunError::ExtensionCatalog)?;
                }
                let selections: Vec<HostSelection<'_>> = config
                    .hosts
                    .iter()
                    .map(|(domain, host)| HostSelection {
                        domain,
                        extensions: &host.extensions,
                        options: &host.options,
                    })
                    .collect();
                let enabled_extensions =
                    extensions
                        .enable(&selections)
                        .map_err(|error| RunError::Extensions {
                            host: error.host,
                            source: error.source,
                        })?;
                let mut services = BTreeMap::new();
                for registry in enabled_extensions.values() {
                    for (domain, handler) in registry.services() {
                        if hosts.is_local_host(domain) || services.contains_key(domain) {
                            return Err(RunError::ServiceDomain {
                                domain: domain.clone(),
                            });
                        }
                        services.insert(
                            domain.clone(),
                            ServiceRoute {
                                domain: Arc::from(domain.as_str()),
                                handler: Arc::clone(handler),
                            },
                        );
                        tracing::info!(service_domain = %domain, "service registered");
                    }
                }
                let mut server_metrics = metrics::ServerMetrics::new(&build, dropped_logs);
                server_metrics.registry().register_collector(Box::new(
                    metrics::StorageCollector::new(
                        stores
                            .opened()
                            .map(|(name, storage)| (name.to_owned(), storage.clone()))
                            .collect(),
                    ),
                ));
                server_metrics.registry().register_collector(Box::new(
                    metrics::StanzaPoolCollector::new(Arc::clone(&stanza_pool)),
                ));
                if let Some(acme) = &acme {
                    server_metrics
                        .registry()
                        .register_collector(Box::new(metrics::AcmeCollector::new(acme.status())));
                }
                let metrics_server = if config.metrics.enabled {
                    Some(
                        lonewolf_metrics::MetricsServer::bind(config.metrics.address)
                            .await
                            .map_err(RunError::Metrics)?,
                    )
                } else {
                    None
                };
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
                let local = LocalRouter::with_options(
                    Arc::clone(&stanza_pool),
                    config
                        .limits
                        .c2s
                        .max_directed_presence_recipients_per_resource,
                    worker_count,
                );
                let serving_router = router.insert(
                    Router::new(hosts.clone(), local)
                        .with_extensions(enabled_extensions)
                        .with_services(services),
                );
                serving_router.register_metrics(server_metrics.registry());
                let router_handle = serving_router.handle();
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
                        server_metrics.registry(),
                    )
                    .await
                    .map_err(|failure| {
                        shutdown_deadline = Some(failure.deadline);
                        RunError::C2s(failure.error)
                    })?,
                );
                let registry = server_metrics.into_registry();
                run_services(
                    BackgroundServices {
                        admin,
                        metrics: metrics_server.map(|server| (server, registry)),
                        acme: acme.as_mut(),
                    },
                    listeners,
                    serving_router,
                    &mut shutdown_deadline,
                    stop_signal.as_mut(),
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
            if let Err(RunError::Acme { phase, .. }) = &result {
                tracing::error!(phase, "ACME service failed");
            }
            if let Some(router) = &router {
                router.stop();
            }
            if let Some(listeners) = listeners.as_mut() {
                listeners.stop(deadline);
            }
            let acme_stopped = match acme.as_mut() {
                Some(acme) => acme.drain(deadline).await,
                None => Ok(()),
            };
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
                .and(acme_stopped)
        })?;
    }

    tracing::info!("heading back to the den");
    Ok(())
}

async fn startup_until_signal<T>(
    load: impl Future<Output = Result<T, RunError>>,
    signal: impl Future<Output = io::Result<()>>,
    shutdown_deadline: &mut Option<Instant>,
) -> Result<Option<T>, RunError> {
    match select(pin!(signal), pin!(load)).await {
        Either::Left((result, _)) => {
            *shutdown_deadline = Some(Instant::now() + WORKER_SHUTDOWN_GRACE);
            result.map_err(RunError::Signal)?;
            Ok(None)
        }
        Either::Right((result, _)) => result.map(Some),
    }
}

struct BackgroundServices<'a> {
    admin: Option<lonewolf_admin::Server>,
    metrics: Option<(lonewolf_metrics::MetricsServer, Arc<Registry>)>,
    acme: Option<&'a mut acme::AcmeServices>,
}

async fn run_services<A: ChunkAllocator + Clone>(
    background: BackgroundServices<'_>,
    listeners: &mut c2s::Listeners,
    router: &mut Router<A>,
    shutdown_deadline: &mut Option<Instant>,
    stop_signal: impl Future<Output = io::Result<()>>,
    deletions: impl Future<Output = ()>,
) -> Result<(), RunError> {
    let BackgroundServices {
        admin,
        metrics,
        acme,
    } = background;
    let (stop_metrics, metrics_stopped) = oneshot::channel::<()>();
    let metrics_task = metrics.map(|(server, registry)| {
        compio::runtime::spawn(server.run(registry, async move {
            let _ = metrics_stopped.await;
        }))
    });
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
    let acme_enabled = acme.is_some();
    let (stop_acme, acme_stopped) = oneshot::channel::<Instant>();
    let acme_done = std::cell::Cell::new(false);
    let mut acme_service = pin!(async {
        match acme {
            Some(acme) => {
                let result = acme
                    .run(async { acme_stopped.await.unwrap_or_else(|_| Instant::now()) })
                    .await;
                acme_done.set(true);
                result
            }
            None => pending().await,
        }
    });
    let (primary, services_done) = {
        let external_shutdown = async {
            tracing::info!("waiting for stop signal... (press Ctrl+C to stop the server)");
            let external = async {
                match select(pin!(stop_signal), pin!(listeners.failure())).await {
                    Either::Left((result, _)) => result.map_err(RunError::Signal),
                    Either::Right((error, _)) => Err(RunError::C2s(error)),
                }
            };
            match select(pin!(router.failure()), pin!(external)).await {
                Either::Left((failure, _)) => {
                    tracing::error!(
                        component = "router",
                        shard_id = failure.shard_id,
                        reason = "panicked",
                        "router service failed"
                    );
                    Err(RunError::RouterFailed(failure))
                }
                Either::Right((result, _)) => result,
            }
        };
        let shutdown = async {
            match select(pin!(external_shutdown), acme_service.as_mut()).await {
                Either::Left((result, _)) | Either::Right((result, _)) => result,
            }
        };
        match select(services.as_mut(), pin!(shutdown)).await {
            Either::Left((result, _)) => (result, true),
            Either::Right((result, _)) => (result, false),
        }
    };
    let router_failure = match router.state() {
        router::RouterState::Failed(failure) => Some(failure),
        _ => None,
    };
    router.stop();
    let deadline = Instant::now() + WORKER_SHUTDOWN_GRACE;
    *shutdown_deadline = Some(deadline);
    listeners.stop(deadline);
    let _ = stop_acme.send(deadline);
    drop(stop_admin);
    drop(stop_metrics);
    let drain = async {
        let services = async {
            if !services_done && admin_enabled {
                services.await
            } else {
                Ok(())
            }
        };
        let metrics = async {
            match metrics_task {
                Some(task) => task
                    .await
                    .map_err(|_| RunError::Metrics(io::Error::other("metrics service panicked"))),
                None => Ok(()),
            }
        };
        let acme = async {
            if acme_enabled && !acme_done.get() {
                acme_service.await
            } else {
                Ok(())
            }
        };
        let (((services, listeners), metrics), acme) =
            join(join(join(services, listeners.join()), metrics), acme).await;
        services
            .and(listeners.map_err(RunError::C2s))
            .and(metrics)
            .and(acme)
    };
    primary.and(drain_services_until(deadline, router_failure, drain).await)
}

async fn drain_services_until(
    deadline: Instant,
    router_failure: Option<router::RouterFailure>,
    drain: impl Future<Output = Result<(), RunError>>,
) -> Result<(), RunError> {
    compio::time::timeout_at(deadline, drain)
        .await
        .unwrap_or_else(|_| {
            Err(match router_failure {
                Some(failure) => RunError::RouterFailed(failure),
                None => RunError::DispatcherShutdown(shutdown_timeout()),
            })
        })
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

#[cfg(test)]
mod supervision_tests {
    use super::*;
    use router::RouterFailure;

    #[test]
    fn primary_acme_failure_survives_a_cleanup_deadline() -> io::Result<()> {
        Runtime::new()?.block_on(async {
            let primary = Err::<(), _>(RunError::Acme {
                phase: "manager",
                source: Box::new(lonewolf_acme::ManagerError::State(
                    lonewolf_acme::StateError::StateUncertain,
                )),
            });
            let result = primary.and(drain_services_until(Instant::now(), None, pending()).await);
            assert!(matches!(
                result,
                Err(RunError::Acme {
                    phase: "manager",
                    ..
                })
            ));
        });
        Ok(())
    }

    #[test]
    fn bounded_service_drain_keeps_observed_router_failure_primary() -> io::Result<()> {
        Runtime::new()?.block_on(async {
            let failure = RouterFailure { shard_id: 2 };
            let result = drain_services_until(Instant::now(), Some(failure), pending()).await;
            assert!(matches!(result, Err(RunError::RouterFailed(actual)) if actual == failure));
            let result = drain_services_until(Instant::now(), None, pending()).await;
            assert!(matches!(result, Err(RunError::DispatcherShutdown(error)) if error.kind() == io::ErrorKind::TimedOut));
        });
        Ok(())
    }
}
