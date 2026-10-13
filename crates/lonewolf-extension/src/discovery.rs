// SPDX-License-Identifier: Apache-2.0

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
