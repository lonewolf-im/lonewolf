// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::io;
use std::panic::AssertUnwindSafe;
use std::pin::pin;
use std::time::Instant;

use futures_util::FutureExt;
use futures_util::future::{Either, select};
use lonewolf_acme::{
    CertificateMaterial, CertificateValidity, Challenges, Http01Server, InstallError, Installer,
    ManagedHost, Manager, ManagerError, ManagerOptions, PreparedInstall, StatusHandle,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use crate::RunError;
use crate::config::{Config, HostTlsSource, managed_dns_name};
use crate::hosts::{Hosts, PreparedCertificate};

pub(crate) struct HostInstaller {
    hosts: Hosts,
}

impl Installer for HostInstaller {
    type Prepared = PreparedCertificate;

    fn prepare(
        &self,
        host: &ManagedHost,
        material: &CertificateMaterial,
    ) -> Result<PreparedInstall<Self::Prepared>, InstallError> {
        let candidate = self
            .hosts
            .prepare_managed_material(
                &host.xmpp_domain,
                material
                    .chain
                    .iter()
                    .cloned()
                    .map(CertificateDer::from)
                    .collect(),
                PrivatePkcs8KeyDer::from(material.private_key_pkcs8.to_vec()).into(),
            )
            .map_err(|_| InstallError::Invalid)?;
        let (not_before_unix, not_after_unix) = candidate.validity();
        Ok(PreparedInstall {
            candidate,
            validity: CertificateValidity {
                not_before_unix,
                not_after_unix,
            },
        })
    }

    fn activate(&self, prepared: Self::Prepared) {
        prepared.activate();
    }
}

pub(crate) struct AcmeServices {
    http: Option<Http01Server>,
    manager: Manager<HostInstaller>,
    status: StatusHandle,
}

impl AcmeServices {
    pub(crate) async fn load(config: &Config, hosts: Hosts) -> Result<Option<Self>, RunError> {
        let managed = managed_hosts(config)?;
        if managed.is_empty() {
            return Ok(None);
        }
        let challenges = Challenges::new(&managed).map_err(|error| failure("hosts", error))?;
        let http = Http01Server::bind(&config.letsencrypt.listen, challenges.clone())
            .await
            .map_err(|error| io_failure("HTTP bind", error))?;
        let manager = Manager::load(
            ManagerOptions {
                directory_url: config.letsencrypt.directory_url.clone(),
                state_path: config.letsencrypt.state_path.clone(),
                ca_certificates_path: config.letsencrypt.ca_certificates_path.clone(),
                hosts: managed,
            },
            challenges,
            HostInstaller { hosts },
        )
        .await
        .map_err(|error| failure("load", error))?;
        for (index, address) in http
            .local_addrs()
            .map_err(|error| io_failure("HTTP address", error))?
            .iter()
            .enumerate()
        {
            tracing::info!(
                phase = "HTTP",
                listener_index = index,
                port = address.port(),
                "ACME listener bound"
            );
        }
        let status = manager.status();
        Ok(Some(Self {
            http: Some(http),
            manager,
            status,
        }))
    }

    pub(crate) fn status(&self) -> StatusHandle {
        self.status.clone()
    }

    pub(crate) async fn run(
        &mut self,
        shutdown: impl Future<Output = Instant>,
    ) -> Result<(), RunError> {
        let http = self
            .http
            .take()
            .ok_or_else(|| failure("HTTP", ManagerError::Task))?;
        let shutdown = shutdown.shared();
        let http_stop = shutdown.clone();
        let manager_stop = shutdown.clone();
        run_pair(
            async move {
                http.run(http_stop)
                    .await
                    .map_err(|error| io_failure("HTTP", error))
            },
            async {
                self.manager
                    .run(manager_stop)
                    .await
                    .map_err(|error| failure("manager", error))
            },
            || shutdown.peek().is_some(),
        )
        .await
    }

    pub(crate) async fn drain(&mut self, deadline: Instant) -> Result<(), RunError> {
        self.http.take();
        self.manager
            .drain(deadline)
            .await
            .map_err(|error| failure("drain", error))
    }
}

fn managed_hosts(config: &Config) -> Result<Vec<ManagedHost>, RunError> {
    config
        .hosts
        .iter()
        .filter(|(_, host)| {
            matches!(
                host.tls.as_ref().map(|tls| &tls.source),
                Some(HostTlsSource::LetsEncrypt)
            )
        })
        .map(|(domain, _)| {
            let dns_name = managed_dns_name(domain)
                .map_err(|_| failure("host identity", ManagerError::Task))?;
            Ok(ManagedHost {
                xmpp_domain: domain.clone(),
                dns_name,
            })
        })
        .collect()
}

async fn run_pair(
    http: impl Future<Output = Result<(), RunError>>,
    manager: impl Future<Output = Result<(), RunError>>,
    stopping: impl Fn() -> bool,
) -> Result<(), RunError> {
    let http = pin!(supervise("HTTP", http));
    let manager = pin!(supervise("manager", manager));
    // Poll the responder before the manager can publish a challenge.
    match select(http, manager).await {
        Either::Left((result, remaining)) => {
            result?;
            if !stopping() {
                return Err(failure("HTTP exit", ManagerError::Task));
            }
            remaining.await
        }
        Either::Right((result, remaining)) => {
            result?;
            if !stopping() {
                return Err(failure("manager exit", ManagerError::Task));
            }
            remaining.await
        }
    }
}

pub(crate) async fn supervise<T>(
    phase: &'static str,
    service: impl Future<Output = Result<T, RunError>>,
) -> Result<T, RunError> {
    AssertUnwindSafe(service)
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(failure(phase, ManagerError::Task)))
}

fn failure(
    phase: &'static str,
    source: impl std::error::Error + Send + Sync + 'static,
) -> RunError {
    RunError::Acme {
        phase,
        source: Box::new(source),
    }
}

fn io_failure(phase: &'static str, source: io::Error) -> RunError {
    failure(
        phase,
        io::Error::new(source.kind(), "ACME listener operation failed"),
    )
}

#[cfg(test)]
mod tests;
