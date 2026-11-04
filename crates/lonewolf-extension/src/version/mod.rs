// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::sync::Arc;

use lonewolf_storage::Storage;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{BuildError, Element, StanzaErrorCondition};
use serde::Deserialize;

use crate::discovery::DiscoScope;
use crate::iq::{
    IqError, IqFuture, IqHandler, IqReply, IqRequest, IqRequestType, IqRoute, IqScope,
};
use crate::{
    Effects, Extension, ExtensionFactory, HostOptions, OptionsError, RegistrationError, Slots,
};

pub const NAME: &str = "version";
pub const NAMESPACE: &str = "jabber:iq:version";
pub const SOFTWARE_NAME: &str = "Lonewolf";

pub struct VersionFactory {
    server_version: &'static str,
}

impl VersionFactory {
    pub const fn new(server_version: &'static str) -> Self {
        Self { server_version }
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct VersionOptions {
    show_os: bool,
}

impl<A: ChunkAllocator, S: Storage> ExtensionFactory<A, S> for VersionFactory {
    fn name(&self) -> &'static str {
        NAME
    }

    fn build(&self, hosts: &[HostOptions<'_>]) -> Result<Arc<dyn Extension<A, S>>, OptionsError> {
        let mut os_hosts = BTreeSet::<Box<str>>::new();
        for host in hosts {
            let Some(table) = host.options else {
                continue;
            };
            let options = table
                .clone()
                .try_into::<VersionOptions>()
                .map_err(|error| OptionsError {
                    domain: host.domain.into(),
                    reason: error.to_string(),
                })?;
            if options.show_os {
                os_hosts.insert(host.domain.into());
            }
        }
        Ok(Arc::new(Version {
            server_version: self.server_version,
            os_hosts,
        }))
    }
}

struct Version {
    server_version: &'static str,
    os_hosts: BTreeSet<Box<str>>,
}

impl Version {
    fn answer<A: ChunkAllocator>(
        &self,
        request: &IqRequest<'_, A>,
        response: &mut Arena<A>,
    ) -> Result<IqReply<A>, IqError> {
        let os = self
            .os_hosts
            .contains(request.target.domainpart())
            .then_some(std::env::consts::OS);
        let payload = reply_in(self.server_version, os, response)
            .map_err(|_| StanzaErrorCondition::ResourceConstraint)?;
        Ok(IqReply::new(Some(payload), Effects::none()))
    }
}

impl<A: ChunkAllocator, S: Storage> Extension<A, S> for Version {
    fn name(&self) -> &'static str {
        NAME
    }

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, S>,
    ) -> Result<(), RegistrationError> {
        slots.iq(
            IqRoute {
                scope: IqScope::Server,
                kind: IqRequestType::Get,
                namespace: NAMESPACE,
                name: "query",
            },
            self,
        )?;
        slots.disco_feature(DiscoScope::Server, NAMESPACE);
        Ok(())
    }
}

impl<A: ChunkAllocator, S: Storage> IqHandler<A, S> for Version {
    fn get<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        _transaction: &'a S::Read,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move { self.answer(&request, response) })
    }
}

fn reply_in<A: ChunkAllocator>(
    server_version: &str,
    os: Option<&str>,
    arena: &mut Arena<A>,
) -> Result<Element, BuildError> {
    let name = Element::builder_in("name", NAMESPACE, arena)?
        .text(SOFTWARE_NAME)?
        .build()?;
    let version = Element::builder_in("version", NAMESPACE, arena)?
        .text(server_version)?
        .build()?;
    let os = match os {
        Some(os) => Some(
            Element::builder_in("os", NAMESPACE, arena)?
                .text(os)?
                .build()?,
        ),
        None => None,
    };
    let mut query = Element::builder_in("query", NAMESPACE, arena)?
        .child(name)?
        .child(version)?;
    if let Some(os) = os {
        query = query.child(os)?;
    }
    query.build()
}

#[cfg(test)]
mod tests;
