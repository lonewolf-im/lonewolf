// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::time::Instant;

use futures_util::FutureExt as _;
use lonewolf_util::arena::ChunkAllocator;

use crate::connection::ListenerSet;
use crate::router::{Router, RouterFailure, RouterState};
use crate::s2s::outbound::RemoteRouter;
use crate::{RunError, shutdown_timeout};

pub(crate) struct Serving<A: ChunkAllocator> {
    pub(crate) router: Option<Router<A>>,
    pub(crate) remote: Option<RemoteRouter<A>>,
    pub(crate) c2s: Option<ListenerSet>,
    pub(crate) s2s: Option<ListenerSet>,
    deadline: Option<Instant>,
}

impl<A: ChunkAllocator + Clone> Serving<A> {
    pub(crate) fn new() -> Self {
        Self {
            router: None,
            remote: None,
            c2s: None,
            s2s: None,
            deadline: None,
        }
    }

    pub(crate) fn stop(&mut self, deadline: Instant) {
        if self.deadline.is_some() {
            return;
        }
        self.deadline = Some(deadline);
        if let Some(router) = &self.router {
            router.stop();
        }
        if let Some(remote) = &self.remote {
            remote.stop();
        }
        if let Some(listeners) = &mut self.c2s {
            listeners.stop(deadline);
        }
        if let Some(listeners) = &mut self.s2s {
            listeners.stop(deadline);
        }
    }

    pub(crate) fn router_failure(&self) -> Option<RouterFailure> {
        match self.router.as_ref().map(Router::state) {
            Some(RouterState::Failed(failure)) => Some(failure),
            _ => None,
        }
    }

    pub(crate) async fn join(
        &mut self,
        deadline: Instant,
        acme_drain: impl Future<Output = Result<(), RunError>>,
    ) -> ServingJoin {
        let deadline = self.deadline.unwrap_or(deadline);
        let Self {
            router,
            remote,
            c2s,
            s2s,
            ..
        } = self;
        collect_join(
            join_listeners(s2s.as_mut(), deadline, RunError::S2s),
            acme_drain,
            join_listeners(c2s.as_mut(), deadline, RunError::C2s),
            async {
                match remote {
                    Some(remote) => remote.join(deadline).await.map_err(RunError::S2s),
                    None => Ok(()),
                }
            },
            async {
                match router.take() {
                    Some(router) => compio::time::timeout_at(deadline, router.shutdown())
                        .await
                        .unwrap_or_else(|_| Err(shutdown_timeout()))
                        .map_err(RunError::RouterShutdown),
                    None => Ok(()),
                }
            },
        )
        .await
    }
}

struct ListenerJoin {
    result: Result<(), RunError>,
    drain_deadline_exceeded: bool,
}

async fn join_listeners(
    listeners: Option<&mut ListenerSet>,
    deadline: Instant,
    error: fn(std::io::Error) -> RunError,
) -> ListenerJoin {
    match listeners {
        Some(listeners) => {
            let result = futures_util::select_biased! {
                result = listeners.join().fuse() => Some(result),
                _ = compio::time::sleep_until(deadline).fuse() => None,
            };
            let drain_deadline_exceeded = result.is_none() || listeners.drain_deadline_exceeded();
            ListenerJoin {
                result: result
                    .unwrap_or_else(|| Err(shutdown_timeout()))
                    .map_err(error),
                drain_deadline_exceeded,
            }
        }
        None => ListenerJoin {
            result: Ok(()),
            drain_deadline_exceeded: false,
        },
    }
}

async fn collect_join(
    s2s: impl Future<Output = ListenerJoin>,
    acme_drain: impl Future<Output = Result<(), RunError>>,
    c2s: impl Future<Output = ListenerJoin>,
    remote: impl Future<Output = Result<(), RunError>>,
    router: impl Future<Output = Result<(), RunError>>,
) -> ServingJoin {
    let s2s = s2s.await;
    let acme_drain = acme_drain.await;
    let c2s = c2s.await;
    let remote = remote.await;
    let router = router.await;
    ServingJoin {
        s2s,
        acme_drain,
        c2s,
        remote,
        router,
    }
}

pub(crate) struct ServiceJoin {
    pub(crate) primary: Result<(), RunError>,
    pub(crate) admin: Result<(), RunError>,
    pub(crate) metrics: Result<(), RunError>,
    pub(crate) acme: Result<(), RunError>,
    pub(crate) drain: Result<(), RunError>,
    pub(crate) router_failure: Option<RouterFailure>,
}

pub(crate) struct ServingJoin {
    s2s: ListenerJoin,
    acme_drain: Result<(), RunError>,
    c2s: ListenerJoin,
    remote: Result<(), RunError>,
    router: Result<(), RunError>,
}

impl ServingJoin {
    pub(crate) fn acme_service_failure_phase(
        &self,
        services: &ServiceJoin,
    ) -> Option<&'static str> {
        if services.primary.is_err()
            || services.drain.is_err()
            || services.admin.is_err()
            || self.remote.is_err()
            || services.metrics.is_err()
            || self.c2s.drain_deadline_exceeded
            || self.s2s.drain_deadline_exceeded
        {
            return None;
        }
        match &services.acme {
            Err(RunError::Acme { phase, .. }) => Some(*phase),
            _ => None,
        }
    }

    pub(crate) fn normal(
        self,
        services: ServiceJoin,
        dispatcher: Result<(), RunError>,
    ) -> Result<(), RunError> {
        let drain = if self.s2s.drain_deadline_exceeded || self.c2s.drain_deadline_exceeded {
            Err(match services.router_failure {
                Some(failure) => RunError::RouterFailed(failure),
                None => RunError::DispatcherShutdown(shutdown_timeout()),
            })
        } else {
            services.drain
        };
        services
            .primary
            .and(drain)
            .and(services.admin)
            .and(self.remote)
            .and(services.metrics)
            .and(services.acme)
            .and(self.c2s.result)
            .and(self.s2s.result)
            .and(dispatcher)
            .and(self.router)
            .and(self.acme_drain)
    }

    pub(crate) fn startup(
        self,
        primary: Result<(), RunError>,
        dispatcher: Result<(), RunError>,
    ) -> Result<(), RunError> {
        primary
            .and(dispatcher)
            .and(self.c2s.result)
            .and(self.s2s.result)
            .and(self.remote)
            .and(self.router)
            .and(self.acme_drain)
    }
}

#[cfg(test)]
mod tests;
