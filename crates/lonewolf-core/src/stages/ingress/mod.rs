// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::delivery::Failure;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{
    ApplicationCondition, RoutedStanza, StanzaErrorCondition, StanzaErrorText,
};

use super::StageFailure;
use crate::delivery::{report_failure, report_server_failure};
use crate::router::Registration;

pub(crate) mod checks;
pub(crate) mod iq;
pub(crate) mod message;

pub(crate) enum Origin<'o, A: ChunkAllocator> {
    Session(&'o Registration<A>),
    Remote {
        local: &'o str,
        #[expect(dead_code)]
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

    #[cfg_attr(not(test), expect(dead_code))]
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

#[cfg(test)]
mod tests;
