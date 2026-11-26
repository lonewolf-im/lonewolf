// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::delivery::Failure;
use lonewolf_extension::presence::PresenceRequestType;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{
    ApplicationCondition, BuildError, IqType, MessageType, RoutedStanza, Stanza, StanzaBuilder,
    StanzaErrorClass, StanzaErrorCondition, StanzaErrorText, StanzaType,
};

use super::StageFailure;
use crate::delivery::{report_failure, report_server_failure};
use crate::router::Registration;

pub(crate) mod checks;
pub(crate) mod iq;
pub(crate) mod message;
pub(crate) mod peer;
pub(crate) mod presence;

pub(crate) enum Origin<'o, A: ChunkAllocator> {
    Session(&'o Registration<A>),
    Remote {
        local: &'o str,
        #[expect(
            dead_code,
            reason = "The origin carries both authenticated stream identities."
        )]
        remote: &'o str,
    },
    Service {
        domain: &'o str,
    },
}

impl<'o, A: ChunkAllocator + Clone> Origin<'o, A> {
    pub(crate) fn sender(&self) -> Option<&'o AccountKey> {
        match self {
            Self::Session(registration) => Some(registration.account()),
            Self::Remote { .. } | Self::Service { .. } => None,
        }
    }

    pub(crate) fn session(&self) -> Option<&'o Registration<A>> {
        match self {
            Self::Session(registration) => Some(registration),
            Self::Remote { .. } | Self::Service { .. } => None,
        }
    }

    pub(crate) fn detaches(&self) -> bool {
        matches!(self, Self::Session(_))
    }

    pub(crate) fn report(&self, failure: Failure, account: Option<&AccountKey>) {
        if let Some(account) = account {
            report_failure(failure, account);
        } else {
            match self {
                Self::Remote { local, .. } => report_server_failure(failure, local),
                Self::Service { domain } => report_server_failure(failure, domain),
                Self::Session(registration) => report_failure(failure, registration.account()),
            }
        }
    }
}

pub(crate) fn rejection_reply<A: ChunkAllocator + Clone>(
    allocator: &A,
    source: &RoutedStanza<A>,
    condition: StanzaErrorCondition,
    application: Option<ApplicationCondition>,
    text: StanzaErrorText,
) -> Result<RoutedStanza<A>, StageFailure> {
    let mut arena = Arena::try_new_in(Default::default(), allocator.clone())?;
    let source = source.resolve()?.clone_in(&mut arena)?;
    let reply = source
        .error_reply_described_in(&mut arena, condition, application, text)?
        .build()?;
    Ok(RoutedStanza::from_parts(reply, arena))
}

pub(crate) fn peer_rejection_reply<A: ChunkAllocator + Clone>(
    allocator: &A,
    source: &RoutedStanza<A>,
    condition: StanzaErrorCondition,
    application: Option<ApplicationCondition>,
    text: StanzaErrorText,
) -> Result<Option<RoutedStanza<A>>, StageFailure> {
    let eligible = match source.resolve()?.stanza_type() {
        StanzaType::Message(kind) => kind != MessageType::Error,
        StanzaType::Iq(kind) => matches!(kind, IqType::Get | IqType::Set),
        StanzaType::Presence(kind) => PresenceRequestType::from_subscription_stanza(kind).is_some(),
    };
    if eligible {
        rejection_reply(allocator, source, condition, application, text).map(Some)
    } else {
        Ok(None)
    }
}

pub(crate) fn outbound_blocked_reply_in<'a, A: ChunkAllocator>(
    source: &Stanza,
    arena: &'a mut Arena<A>,
) -> Result<StanzaBuilder<'a, A>, BuildError> {
    source.error_reply_with_class_in(
        arena,
        StanzaErrorCondition::NotAcceptable,
        StanzaErrorClass::Cancel,
        Some(ApplicationCondition {
            name: "blocked",
            namespace: "urn:xmpp:blocking:errors",
        }),
        StanzaErrorText::Static("You have blocked communication with this address."),
    )
}

pub(crate) fn outbound_blocked_reply<A: ChunkAllocator + Clone>(
    allocator: &A,
    source: &RoutedStanza<A>,
) -> Result<RoutedStanza<A>, StageFailure> {
    let mut arena = Arena::try_new_in(Default::default(), allocator.clone())?;
    let source = source.resolve()?.clone_in(&mut arena)?;
    let reply = outbound_blocked_reply_in(&source, &mut arena)?.build()?;
    Ok(RoutedStanza::from_parts(reply, arena))
}

#[cfg(test)]
mod tests;
