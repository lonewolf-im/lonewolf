// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::presence::PresenceTransition;

mod registration;
mod shard;
mod shards;

pub(crate) use registration::{
    DirectedWithdrawal, Mailbox, MailboxEntry, Registration, ResourceMatch, RetireCause,
    SessionHandle, SessionLiveness, StoredRelease, release_deferred,
};
pub(in crate::router) use shard::DirectedRecipient;
pub(crate) use shards::LocalRouter;
pub(super) use shards::LocalRouterHandle;

#[derive(Clone, Copy)]
pub(crate) struct AvailabilityChange {
    previous: Option<i8>,
    pub(crate) current: Option<i8>,
}

impl AvailabilityChange {
    pub(crate) fn between(previous: Option<i8>, current: Option<i8>) -> Self {
        Self { previous, current }
    }

    pub(crate) fn transition(self) -> PresenceTransition {
        match (self.previous, self.current) {
            (_, None) => PresenceTransition::Unavailable,
            (None, Some(_)) => PresenceTransition::Initial,
            (Some(_), Some(_)) => PresenceTransition::Update,
        }
    }

    pub(crate) fn became_available(self) -> bool {
        self.transition() == PresenceTransition::Initial
    }

    pub(crate) fn became_eligible(self) -> bool {
        self.current.is_some_and(|priority| priority >= 0)
            && self.previous.is_none_or(|priority| priority < 0)
    }

    pub(crate) fn became_unavailable(self) -> bool {
        self.current.is_none() && self.previous.is_some()
    }
}
