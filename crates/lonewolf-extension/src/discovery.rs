// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::{Arena, ArenaRead, ChunkAllocator, HandleError};
use lonewolf_xmpp::stanza::{BuildError, Element, ElementRef};

pub const INFO_NAMESPACE: &str = "http://jabber.org/protocol/disco#info";
pub const ITEMS_NAMESPACE: &str = "http://jabber.org/protocol/disco#items";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryKind {
    Info,
    Items,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Query<'a> {
    pub kind: QueryKind,
    /// A node name that the response must repeat.
    pub node: Option<&'a str>,
}

impl<'a> Query<'a> {
    /// Parses a discovery query and ignores its children.
    pub fn parse<R: ArenaRead>(payload: ElementRef<'a, R>) -> Result<Option<Self>, HandleError> {
        if payload.name() != "query" {
            return Ok(None);
        }
        let kind = match payload.namespace() {
            INFO_NAMESPACE => QueryKind::Info,
            ITEMS_NAMESPACE => QueryKind::Items,
            _ => return Ok(None),
        };
        Ok(Some(Self {
            kind,
            node: payload.attribute("node", "")?,
        }))
    }
}

/// Builds an info result with identities before features.
pub fn info_in<A: ChunkAllocator>(
    node: Option<&str>,
    identities: &[Identity],
    features: &[&str],
    arena: &mut Arena<A>,
) -> Result<Element, BuildError> {
    let mut children = Vec::with_capacity(identities.len() + features.len());
    for identity in identities {
        let mut builder = Element::builder_in("identity", INFO_NAMESPACE, arena)?
            .attribute("category", "", identity.category)?
            .attribute("type", "", identity.kind)?;
        if let Some(name) = identity.name {
            builder = builder.attribute("name", "", name)?;
        }
        children.push(builder.build()?);
    }
    for feature in features {
        children.push(
            Element::builder_in("feature", INFO_NAMESPACE, arena)?
                .attribute("var", "", feature)?
                .build()?,
        );
    }
    let mut query = Element::builder_in("query", INFO_NAMESPACE, arena)?;
    if let Some(node) = node {
        query = query.attribute("node", "", node)?;
    }
    for child in children {
        query = query.child(child)?;
    }
    query.build()
}

pub fn item_in<A: ChunkAllocator>(
    jid: &str,
    node: Option<&str>,
    name: Option<&str>,
    arena: &mut Arena<A>,
) -> Result<Element, BuildError> {
    let mut item =
        Element::builder_in("item", ITEMS_NAMESPACE, arena)?.attribute("jid", "", jid)?;
    if let Some(node) = node {
        item = item.attribute("node", "", node)?;
    }
    if let Some(name) = name {
        item = item.attribute("name", "", name)?;
    }
    item.build()
}

/// Builds an items result with entries in input order.
pub fn items_in<A: ChunkAllocator>(
    node: Option<&str>,
    items: &[Element],
    arena: &mut Arena<A>,
) -> Result<Element, BuildError> {
    let mut query = Element::builder_in("query", ITEMS_NAMESPACE, arena)?;
    if let Some(node) = node {
        query = query.attribute("node", "", node)?;
    }
    for item in items {
        query = query.child(*item)?;
    }
    query.build()
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DiscoScope {
    /// The served domain itself.
    Server,
    /// A local account's bare JID.
    Account,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Identity {
    pub category: &'static str,
    pub kind: &'static str,
    pub name: Option<&'static str>,
}

/// Each scope's identities and features, and the service domains, are sorted and unique.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Discovery {
    server: Entity,
    account: Entity,
    services: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Entity {
    identities: Vec<Identity>,
    features: Vec<&'static str>,
}

impl Discovery {
    pub fn identities(&self, scope: DiscoScope) -> &[Identity] {
        &self.entity(scope).identities
    }

    pub fn features(&self, scope: DiscoScope) -> &[&'static str] {
        &self.entity(scope).features
    }

    /// Service domains registered on this host.
    pub fn services(&self) -> &[String] {
        &self.services
    }

    pub(crate) fn add_identity(&mut self, scope: DiscoScope, identity: Identity) {
        let identities = &mut self.entity_mut(scope).identities;
        if let Err(index) = identities.binary_search(&identity) {
            identities.insert(index, identity);
        }
    }

    pub(crate) fn add_feature(&mut self, scope: DiscoScope, feature: &'static str) {
        let features = &mut self.entity_mut(scope).features;
        if let Err(index) = features.binary_search(&feature) {
            features.insert(index, feature);
        }
    }

    pub(crate) fn add_service(&mut self, domain: &str) {
        if let Err(index) = self
            .services
            .binary_search_by(|entry| entry.as_str().cmp(domain))
        {
            self.services.insert(index, domain.into());
        }
    }

    fn entity(&self, scope: DiscoScope) -> &Entity {
        match scope {
            DiscoScope::Server => &self.server,
            DiscoScope::Account => &self.account,
        }
    }

    fn entity_mut(&mut self, scope: DiscoScope) -> &mut Entity {
        match scope {
            DiscoScope::Server => &mut self.server,
            DiscoScope::Account => &mut self.account,
        }
    }
}
