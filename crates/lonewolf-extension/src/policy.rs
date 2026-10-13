// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::Storage;
use lonewolf_storage::account::AccountKey;
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::stanza::{
    ApplicationCondition, IqType, MessageType, StanzaErrorCondition, StanzaType,
};

use crate::ExtensionFuture;
use crate::delivery::HandlerError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// The account sends the stanza to the peer.
    Outbound,
    /// The peer sends the stanza to the account.
    Inbound,
}

pub struct PolicyRequest<'a> {
    /// The local account whose policy applies.
    pub account: &'a AccountKey,
    pub direction: Direction,
    /// The addressed recipient for outbound checks and sender for inbound checks.
    pub peer: JidRef<'a>,
    pub kind: StanzaType,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    Allow,
    /// Rejections are suppressed for presence, error messages, and IQ responses.
    Reject {
        condition: StanzaErrorCondition,
        application: Option<ApplicationCondition>,
    },
    /// Dropped IQ requests receive a service-unavailable error after stanza filtering.
    Drop,
}

impl Verdict {
    /// Drop outranks Reject, which outranks Allow; the earlier rejection wins a tie.
    pub fn strictest(self, other: Self) -> Self {
        match (self, other) {
            (Self::Drop, _) | (_, Self::Drop) => Self::Drop,
            (Self::Reject { .. }, _) => self,
            _ => other,
        }
    }

    /// Suppresses rejection replies that could cause loops and answers dropped IQ requests.
    pub fn for_stanza(self, kind: StanzaType) -> Self {
        match self {
            Self::Drop if matches!(kind, StanzaType::Iq(IqType::Get | IqType::Set)) => {
                Self::Reject {
                    condition: StanzaErrorCondition::ServiceUnavailable,
                    application: None,
                }
            }
            Self::Reject { .. }
                if matches!(
                    kind,
                    StanzaType::Presence(_)
                        | StanzaType::Message(MessageType::Error)
                        | StanzaType::Iq(IqType::Result | IqType::Error)
                ) =>
            {
                Self::Drop
            }
            verdict => verdict,
        }
    }
}

pub type PolicyFuture<'a> = ExtensionFuture<'a, Result<Verdict, HandlerError>>;

pub trait PolicyHandler<S: Storage>: Send + Sync {
    /// Uses one consistent snapshot and must not write or deliver.
    fn check<'a>(
        &'a self,
        request: PolicyRequest<'a>,
        transaction: &'a S::Read,
    ) -> PolicyFuture<'a>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use lonewolf_xmpp::stanza::PresenceType;

    #[test]
    fn drop_outranks_every_verdict_in_both_orders() {
        for verdict in [
            Verdict::Allow,
            Verdict::Drop,
            Verdict::Reject {
                condition: StanzaErrorCondition::Forbidden,
                application: None,
            },
        ] {
            assert_eq!(verdict.strictest(Verdict::Drop), Verdict::Drop);
            assert_eq!(Verdict::Drop.strictest(verdict), Verdict::Drop);
        }
    }

    #[test]
    fn strictest_keeps_the_earlier_rejection() {
        let first = Verdict::Reject {
            condition: StanzaErrorCondition::Forbidden,
            application: None,
        };
        let second = Verdict::Reject {
            condition: StanzaErrorCondition::NotAcceptable,
            application: Some(ApplicationCondition {
                name: "blocked",
                namespace: "urn:test",
            }),
        };
        assert_eq!(first.strictest(second), first);
        assert_eq!(second.strictest(first), second);
        assert_eq!(first.strictest(Verdict::Allow), first);
        assert_eq!(Verdict::Allow.strictest(first), first);
    }

    #[test]
    fn rejected_stanzas_that_cannot_receive_errors_are_dropped() {
        let rejection = Verdict::Reject {
            condition: StanzaErrorCondition::Forbidden,
            application: None,
        };
        for kind in [
            StanzaType::Presence(PresenceType::Available),
            StanzaType::Presence(PresenceType::Error),
            StanzaType::Message(MessageType::Error),
            StanzaType::Iq(IqType::Result),
            StanzaType::Iq(IqType::Error),
        ] {
            assert_eq!(rejection.for_stanza(kind), Verdict::Drop);
            assert_eq!(Verdict::Allow.for_stanza(kind), Verdict::Allow);
        }
        for kind in [
            StanzaType::Message(MessageType::Chat),
            StanzaType::Iq(IqType::Get),
        ] {
            assert_eq!(rejection.for_stanza(kind), rejection);
        }
        assert_eq!(
            Verdict::Drop.for_stanza(StanzaType::Message(MessageType::Chat)),
            Verdict::Drop
        );
    }

    #[test]
    fn dropped_iq_requests_are_rejected_and_other_stanzas_stay_dropped() {
        let service_unavailable = Verdict::Reject {
            condition: StanzaErrorCondition::ServiceUnavailable,
            application: None,
        };
        let competing_rejection = Verdict::Reject {
            condition: StanzaErrorCondition::Forbidden,
            application: None,
        };
        for kind in [StanzaType::Iq(IqType::Get), StanzaType::Iq(IqType::Set)] {
            assert_eq!(Verdict::Drop.for_stanza(kind), service_unavailable);
            assert_eq!(
                Verdict::Drop
                    .strictest(competing_rejection)
                    .for_stanza(kind),
                service_unavailable
            );
        }
        for kind in [
            StanzaType::Iq(IqType::Result),
            StanzaType::Iq(IqType::Error),
            StanzaType::Presence(PresenceType::Available),
            StanzaType::Presence(PresenceType::Unavailable),
            StanzaType::Presence(PresenceType::Subscribe),
            StanzaType::Presence(PresenceType::Subscribed),
            StanzaType::Presence(PresenceType::Unsubscribe),
            StanzaType::Presence(PresenceType::Unsubscribed),
            StanzaType::Presence(PresenceType::Probe),
            StanzaType::Presence(PresenceType::Error),
            StanzaType::Message(MessageType::Normal),
            StanzaType::Message(MessageType::Chat),
            StanzaType::Message(MessageType::Groupchat),
            StanzaType::Message(MessageType::Headline),
            StanzaType::Message(MessageType::Error),
        ] {
            assert_eq!(Verdict::Drop.for_stanza(kind), Verdict::Drop);
        }
    }
}
