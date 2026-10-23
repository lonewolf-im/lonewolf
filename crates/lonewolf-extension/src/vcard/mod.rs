// SPDX-License-Identifier: Apache-2.0

mod xml;

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;

use lonewolf_storage::account::AccountKey;
use lonewolf_storage::vcard::{MAX_VCARD_BYTES, VCardError, VCardQuota, VCardReads, VCardWrites};
use lonewolf_storage::{Storage, StorageErrorKind};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{Element, StanzaErrorCondition};
use serde::Deserialize;

use crate::delivery::{Failure, FailureKind, HandlerError, HostLookup};
use crate::discovery::DiscoScope;
use crate::iq::{
    IqDestinationRule, IqError, IqFuture, IqHandler, IqReply, IqRequest, IqRequestKey,
    IqRequestType, IqRoute, IqScope,
};
use crate::{
    Effects, Extension, ExtensionFactory, HostOptions, OptionsError, RegistrationError, Slots,
};

pub const NAME: &str = "vcard";
pub const NAMESPACE: &str = "vcard-temp";

pub struct VCardFactory;

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct VCardOptions {
    max_bytes: NonZeroUsize,
}

impl Default for VCardOptions {
    fn default() -> Self {
        Self {
            max_bytes: VCardQuota::default().max_bytes,
        }
    }
}

impl<A: ChunkAllocator, S: Storage> ExtensionFactory<A, S> for VCardFactory {
    fn name(&self) -> &'static str {
        NAME
    }

    fn build(&self, hosts: &[HostOptions<'_>]) -> Result<Arc<dyn Extension<A, S>>, OptionsError> {
        let mut limits = BTreeMap::new();
        for host in hosts {
            if let Some(table) = host.options {
                let options =
                    table
                        .clone()
                        .try_into::<VCardOptions>()
                        .map_err(|error| OptionsError {
                            domain: host.domain.into(),
                            reason: error.to_string(),
                        })?;
                if options.max_bytes.get() > MAX_VCARD_BYTES {
                    return Err(OptionsError {
                        domain: host.domain.into(),
                        reason: "max_bytes exceeds 1048576".into(),
                    });
                }
                limits.insert(
                    host.domain.into(),
                    VCardQuota {
                        max_bytes: options.max_bytes,
                    },
                );
            }
        }
        Ok(Arc::new(VCard::new(limits)))
    }
}

#[derive(Default)]
pub struct VCard {
    limits: BTreeMap<Box<str>, VCardQuota>,
}

impl VCard {
    pub fn new(limits: BTreeMap<Box<str>, VCardQuota>) -> Self {
        Self { limits }
    }

    fn quota(&self, owner: &AccountKey) -> VCardQuota {
        self.limits.get(owner.domain()).copied().unwrap_or_default()
    }
}

impl<A: ChunkAllocator, S: Storage> Extension<A, S> for VCard {
    fn name(&self) -> &'static str {
        NAME
    }

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, S>,
    ) -> Result<(), RegistrationError> {
        for kind in [IqRequestType::Get, IqRequestType::Set] {
            slots.iq(
                IqRoute {
                    scope: IqScope::Account,
                    kind,
                    namespace: NAMESPACE,
                    name: "vCard",
                },
                self.clone(),
            )?;
        }
        slots.iq_destination(
            IqRequestKey {
                kind: IqRequestType::Set,
                namespace: NAMESPACE,
                name: "vCard",
            },
            IqDestinationRule::SenderBare,
        )?;
        slots.disco_feature(DiscoScope::Server, NAMESPACE);
        slots.disco_feature(DiscoScope::Account, NAMESPACE);
        Ok(())
    }
}

impl<A: ChunkAllocator, S: Storage> IqHandler<A, S> for VCard {
    fn get<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        transaction: &'a S::Read,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            let result = async {
                if request.target.resourcepart().is_some() || request.target.localpart().is_none() {
                    return Err(StanzaErrorCondition::ServiceUnavailable.into());
                }
                let owner = AccountKey::try_from(request.target)
                    .map_err(|_| HandlerError::from(StanzaErrorCondition::InternalServerError))?;
                let stored = transaction
                    .vcard(&owner)
                    .await
                    .map_err(|error| storage_error(error, "vcard_read"))?;
                let Some(stored) = stored else {
                    return Err(if request.target == request.sender.bare() {
                        StanzaErrorCondition::ItemNotFound
                    } else {
                        StanzaErrorCondition::ServiceUnavailable
                    }
                    .into());
                };
                let payload = xml::decode(&stored.xml, response).await?;
                Ok(IqReply::new(Some(payload), Effects::none()))
            }
            .await;
            result.map_err(IqError::without_payload)
        })
    }

    fn get_missing_account(
        &self,
        _request: IqRequest<'_, A>,
        _response: &mut Arena<A>,
    ) -> Result<Option<Element>, IqError> {
        Err(IqError::without_payload(
            StanzaErrorCondition::ServiceUnavailable.into(),
        ))
    }

    fn set<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        transaction: &'a mut S::Write,
        _hosts: &'a dyn HostLookup,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            let result = async {
                if request.target != request.sender.bare() {
                    return Err(StanzaErrorCondition::Forbidden.into());
                }
                let owner = AccountKey::try_from(request.sender.bare())
                    .map_err(|_| HandlerError::from(StanzaErrorCondition::InternalServerError))?;
                let quota = self.quota(&owner);
                let document = xml::encode(
                    &request.payload,
                    request.lang,
                    request.space,
                    quota,
                    response,
                )
                .await?;
                transaction
                    .replace_vcard(&owner, &document, quota)
                    .await
                    .map_err(|error| match error {
                        VCardError::QuotaExceeded => xml::byte_quota(quota.max_bytes.get()),
                        error => storage_error(error, "vcard_write"),
                    })?;
                Ok(IqReply::new(None, Effects::none()))
            }
            .await;
            result.map_err(IqError::without_payload)
        })
    }
}

fn failure(kind: StorageErrorKind, operation: &'static str) -> HandlerError {
    HandlerError::Internal {
        condition: StanzaErrorCondition::InternalServerError,
        failure: Failure {
            kind: FailureKind::Storage(kind),
            operation,
        },
    }
}

fn storage_error(error: VCardError, operation: &'static str) -> HandlerError {
    match error {
        VCardError::NoAccount => StanzaErrorCondition::ServiceUnavailable.into(),
        VCardError::QuotaExceeded => StanzaErrorCondition::ResourceConstraint.into(),
        VCardError::Storage(error) => failure(error.kind(), operation),
    }
}

#[cfg(test)]
mod tests;
