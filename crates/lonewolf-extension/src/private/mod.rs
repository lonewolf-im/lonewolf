// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;

use lonewolf_storage::account::AccountKey;
use lonewolf_storage::private::{
    PrivateXmlChange, PrivateXmlError, PrivateXmlQuota, PrivateXmlReads, PrivateXmlWrites,
};
use lonewolf_storage::{Storage, StorageErrorKind};
use lonewolf_util::arena::{Arena, ArenaError, ArenaRead, ChunkAllocator};
use lonewolf_xmpp::stanza::{
    BuildError, Element, ElementRef, NodeRef, StanzaErrorCondition, StanzaErrorText, XML_NAMESPACE,
};
use serde::Deserialize;

use crate::delivery::{Failure, FailureKind, HandlerError, HostLookup};
use crate::detached::{self, EncodeError, Inherited};
use crate::discovery::DiscoScope;
use crate::iq::{
    IqDestinationRule, IqError, IqFuture, IqHandler, IqReply, IqRequest, IqRequestKey,
    IqRequestType, IqRoute, IqScope, XmlSpace,
};
use crate::{
    Effects, Extension, ExtensionFactory, HostOptions, OptionsError, RegistrationError, Slots,
};

pub const NAME: &str = "private";
pub const NAMESPACE: &str = "jabber:iq:private";

const STREAM_NAMESPACE: &str = "http://etherx.jabber.org/streams";

pub struct PrivateFactory;

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PrivateOptions {
    max_items: NonZeroUsize,
    max_bytes: NonZeroUsize,
}

impl Default for PrivateOptions {
    fn default() -> Self {
        let quota = PrivateXmlQuota::default();
        Self {
            max_items: quota.max_items,
            max_bytes: quota.max_bytes,
        }
    }
}

impl<A: ChunkAllocator, S: Storage> ExtensionFactory<A, S> for PrivateFactory {
    fn name(&self) -> &'static str {
        NAME
    }

    fn build(&self, hosts: &[HostOptions<'_>]) -> Result<Arc<dyn Extension<A, S>>, OptionsError> {
        let mut quotas = BTreeMap::new();
        for host in hosts {
            if let Some(table) = host.options {
                let options = table
                    .clone()
                    .try_into::<PrivateOptions>()
                    .map_err(|error| OptionsError {
                        domain: host.domain.into(),
                        reason: error.to_string(),
                    })?;
                quotas.insert(
                    host.domain.into(),
                    PrivateXmlQuota {
                        max_items: options.max_items,
                        max_bytes: options.max_bytes,
                    },
                );
            }
        }
        Ok(Arc::new(Private { quotas }))
    }
}

struct Private {
    quotas: BTreeMap<Box<str>, PrivateXmlQuota>,
}

impl Private {
    fn quota(&self, owner: &AccountKey) -> PrivateXmlQuota {
        self.quotas.get(owner.domain()).copied().unwrap_or_default()
    }
}

impl<A: ChunkAllocator, S: Storage> Extension<A, S> for Private {
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
                    name: "query",
                },
                self.clone(),
            )?;
            slots.iq_destination(
                IqRequestKey {
                    kind,
                    namespace: NAMESPACE,
                    name: "query",
                },
                IqDestinationRule::SenderBare,
            )?;
        }
        slots.disco_feature(DiscoScope::Server, NAMESPACE);
        Ok(())
    }
}

impl<A: ChunkAllocator, S: Storage> IqHandler<A, S> for Private {
    fn get<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        transaction: &'a S::Read,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            let result = async {
                let owner = owner(&request)?;
                let mut elements = elements(&request.payload)?;
                let element = match (elements.pop(), elements.is_empty()) {
                    (Some(element), true) => element,
                    (Some(_), false) => {
                        return Err(described(StanzaErrorCondition::BadRequest, MULTIPLE));
                    }
                    (None, _) => {
                        return Err(described(StanzaErrorCondition::NotAcceptable, NO_ELEMENT));
                    }
                };
                let stored = transaction
                    .private_xml(&owner, element.namespace(), element.name())
                    .await
                    .map_err(|error| storage_error(error, "private_xml_read"))?;
                let child = match stored {
                    Some(stored) => decode(&stored.xml, &element, response).await?,
                    None => Element::builder_in(element.name(), element.namespace(), response)
                        .and_then(|builder| builder.build())
                        .map_err(build_error)?,
                };
                let query = Element::builder_in("query", NAMESPACE, response)
                    .and_then(|builder| builder.child(child))
                    .and_then(|builder| builder.build())
                    .map_err(build_error)?;
                Ok(IqReply::new(Some(query), Effects::none()))
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
                let owner = owner(&request)?;
                let elements = elements(&request.payload)?;
                if elements.is_empty() {
                    return Err(described(StanzaErrorCondition::NotAcceptable, NO_ELEMENT));
                }
                let quota = self.quota(&owner);
                let inherited = inherited(&request)?;
                let mut documents = Vec::with_capacity(elements.len());
                for element in &elements {
                    let document = if is_empty(element)? {
                        None
                    } else {
                        let document = detached::encode(
                            element,
                            inherited,
                            usize::MAX,
                            NonZeroUsize::MAX,
                            response,
                            |root| {
                                root.name() == element.name()
                                    && root.namespace() == element.namespace()
                            },
                        )
                        .await
                        .map_err(encode_error)?;
                        Some(document)
                    };
                    documents.push(document);
                }
                let changes = elements
                    .iter()
                    .zip(&documents)
                    .map(|(element, document)| PrivateXmlChange {
                        namespace: element.namespace(),
                        name: element.name(),
                        xml: document.as_deref(),
                    })
                    .collect::<Vec<_>>();
                transaction
                    .update_private_xml(&owner, &changes, quota)
                    .await
                    .map_err(|error| match error {
                        PrivateXmlError::QuotaExceeded => quota_error(quota),
                        error => storage_error(error, "private_xml_write"),
                    })?;
                Ok(IqReply::new(None, Effects::none()))
            }
            .await;
            result.map_err(IqError::without_payload)
        })
    }
}

const NO_ELEMENT: &str =
    "Include one child element with its own namespace in the private XML query.";
const RESERVED: &str = "Private XML cannot use an empty or reserved namespace, such as one that starts with jabber: or http://jabber.org/.";
const TEXT: &str = "A private XML query can contain only child elements.";
const MULTIPLE: &str = "Request one private XML element at a time.";
const SPACE: &str = "Private XML must use an xml:space value of default or preserve.";

fn owner<A: ChunkAllocator>(request: &IqRequest<'_, A>) -> Result<AccountKey, HandlerError> {
    if request.target != request.sender.bare() {
        return Err(StanzaErrorCondition::Forbidden.into());
    }
    AccountKey::try_from(request.target)
        .map_err(|_| HandlerError::from(StanzaErrorCondition::InternalServerError))
}

fn elements<'a, R: ArenaRead>(
    query: &ElementRef<'a, R>,
) -> Result<Vec<ElementRef<'a, R>>, HandlerError> {
    let mut elements = Vec::new();
    for node in query.children().map_err(|_| internal())? {
        match node.map_err(|_| internal())? {
            NodeRef::Text(text) => {
                if !text
                    .bytes()
                    .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
                {
                    return Err(described(StanzaErrorCondition::BadRequest, TEXT));
                }
            }
            NodeRef::Element(element) => {
                if reserved(element.namespace()) {
                    return Err(described(StanzaErrorCondition::NotAcceptable, RESERVED));
                }
                elements.push(element);
            }
        }
    }
    Ok(elements)
}

fn reserved(namespace: &str) -> bool {
    namespace.is_empty()
        || namespace.starts_with("jabber:")
        || namespace.starts_with("http://jabber.org/")
        || namespace == "vcard-temp"
        || namespace == STREAM_NAMESPACE
}

fn is_empty<R: ArenaRead>(element: &ElementRef<'_, R>) -> Result<bool, HandlerError> {
    Ok(element
        .attributes()
        .map_err(|_| internal())?
        .next()
        .is_none()
        && element.children().map_err(|_| internal())?.next().is_none())
}

fn inherited<'a, A: ChunkAllocator>(
    request: &IqRequest<'a, A>,
) -> Result<Inherited<'a>, HandlerError> {
    let lang = request
        .payload
        .attribute("lang", XML_NAMESPACE)
        .map_err(|_| internal())?;
    let space = request
        .payload
        .attribute("space", XML_NAMESPACE)
        .map_err(|_| internal())?;
    Ok(Inherited {
        lang: lang.or(request.lang),
        space: space.map(XmlSpace::from_attribute).or(request.space),
    })
}

async fn decode<A: ChunkAllocator, R: ArenaRead>(
    xml: &str,
    requested: &ElementRef<'_, R>,
    response: &mut Arena<A>,
) -> Result<Element, HandlerError> {
    let corrupt = || failure(StorageErrorKind::CorruptData, "private_xml_decode");
    let bytes = NonZeroUsize::new(xml.len()).ok_or_else(corrupt)?;
    let parsed = detached::parse(xml, bytes).await.map_err(|_| corrupt())?;
    let root = parsed
        .value()
        .resolve(parsed.arena())
        .map_err(|_| corrupt())?;
    if root.name() != requested.name() || root.namespace() != requested.namespace() {
        return Err(corrupt());
    }
    root.clone_in(response).map_err(build_error)
}

fn described(condition: StanzaErrorCondition, text: &'static str) -> HandlerError {
    HandlerError::described(condition, StanzaErrorText::Static(text))
}

fn internal() -> HandlerError {
    StanzaErrorCondition::InternalServerError.into()
}

fn quota_error(quota: PrivateXmlQuota) -> HandlerError {
    HandlerError::described(
        StanzaErrorCondition::ResourceConstraint,
        StanzaErrorText::TwoLimits {
            parts: &[
                "Private XML storage for this account is limited to ",
                " elements and ",
                " bytes. Remove stored elements or store less XML.",
            ],
            values: [quota.max_items.get(), quota.max_bytes.get()],
        },
    )
}

fn encode_error(error: EncodeError) -> HandlerError {
    match error {
        EncodeError::InvalidSpace | EncodeError::InheritedSpace => {
            described(StanzaErrorCondition::BadRequest, SPACE)
        }
        EncodeError::TooLarge { .. } => {
            build_error(BuildError::Allocation(ArenaError::CapacityOverflow))
        }
        EncodeError::TooManyAttributes => described(
            StanzaErrorCondition::ResourceConstraint,
            "Private XML has too many XML attributes. Reduce the attributes of the stored element.",
        ),
        EncodeError::Build(error) => build_error(error),
        EncodeError::Internal => internal(),
    }
}

fn build_error(error: BuildError) -> HandlerError {
    match error {
        BuildError::Allocation(ArenaError::ArenaLimitExceeded | ArenaError::CapacityOverflow) => {
            described(
                StanzaErrorCondition::ResourceConstraint,
                "Private XML exceeds the XML processing memory limit. Simplify the stored XML.",
            )
        }
        BuildError::Allocation(_) => StanzaErrorCondition::ResourceConstraint.into(),
        BuildError::TreeLimitExceeded => described(
            StanzaErrorCondition::ResourceConstraint,
            "Private XML exceeds the XML tree depth or node limit. Simplify the stored XML.",
        ),
        _ => internal(),
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

fn storage_error(error: PrivateXmlError, operation: &'static str) -> HandlerError {
    match error {
        PrivateXmlError::NoAccount => StanzaErrorCondition::ServiceUnavailable.into(),
        PrivateXmlError::QuotaExceeded => StanzaErrorCondition::ResourceConstraint.into(),
        PrivateXmlError::Storage(error) => failure(error.kind(), operation),
    }
}

#[cfg(test)]
mod tests;
