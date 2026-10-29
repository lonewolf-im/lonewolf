// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{
    IqType, MessageType, PresenceType, RoutedStanza, StanzaErrorCondition, StanzaKind, StanzaType,
};

use crate::router::RouterHandle;
use crate::s2s::metrics::{BounceCondition, DropReason};

fn eligible(kind: StanzaType) -> bool {
    matches!(kind,
        StanzaType::Message(kind) if kind != MessageType::Error
    ) || matches!(
        kind,
        StanzaType::Iq(IqType::Get | IqType::Set)
            | StanzaType::Presence(
                PresenceType::Subscribe
                    | PresenceType::Subscribed
                    | PresenceType::Unsubscribe
                    | PresenceType::Unsubscribed
            )
    )
}

fn reply<A: ChunkAllocator + Clone>(
    stanza: &RoutedStanza<A>,
    condition: StanzaErrorCondition,
    allocator: A,
) -> Option<RoutedStanza<A>> {
    let mut arena = Arena::try_new_in(Default::default(), allocator).ok()?;
    let source = stanza.resolve().ok()?.clone_in(&mut arena).ok()?;
    let reply = source
        .error_reply_described_in(&mut arena, condition, None, condition.default_text())
        .ok()?
        .build()
        .ok()?;
    Some(RoutedStanza::from_parts(reply, arena))
}

pub(crate) async fn bounce<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    stanza: &RoutedStanza<A>,
    condition: StanzaErrorCondition,
) {
    let Some(remote) = router.remote_router() else {
        return;
    };
    let Ok(view) = stanza.resolve() else {
        return;
    };
    if !eligible(view.stanza_type()) {
        remote.inner.metrics.dropped(DropReason::NotBounceable, 1);
        return;
    }
    let Some(reply) = reply(stanza, condition, remote.inner.allocator.clone()) else {
        tracing::debug!(outcome = "build_failed", "s2s bounce discarded");
        return;
    };
    let result = match view.kind() {
        StanzaKind::Message => {
            if !reply
                .resolve()
                .ok()
                .and_then(|view| {
                    view.to()
                        .ok()
                        .flatten()
                        .map(|to| to.resourcepart().is_some())
                })
                .unwrap_or(false)
            {
                return;
            }
            router.route_full(reply).await
        }
        StanzaKind::Iq => router.route_full(reply).await,
        StanzaKind::Presence => router.route_presence_error(reply).await,
    };
    match result {
        Ok(()) => remote.inner.metrics.bounced(match condition {
            StanzaErrorCondition::ResourceConstraint => BounceCondition::ResourceConstraint,
            StanzaErrorCondition::RemoteServerNotFound => BounceCondition::RemoteServerNotFound,
            _ => BounceCondition::RemoteServerTimeout,
        }),
        Err(error) => tracing::debug!(%error, "s2s bounce delivery failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::super::manager_tests::stanza;
    use super::*;

    #[test]
    fn bounce_eligibility_excludes_errors_results_and_ordinary_presence() {
        for kind in [
            MessageType::Normal,
            MessageType::Chat,
            MessageType::Groupchat,
            MessageType::Headline,
        ] {
            assert!(eligible(StanzaType::Message(kind)));
        }
        assert!(!eligible(StanzaType::Message(MessageType::Error)));
        for kind in [IqType::Get, IqType::Set] {
            assert!(eligible(StanzaType::Iq(kind)));
        }
        for kind in [IqType::Result, IqType::Error] {
            assert!(!eligible(StanzaType::Iq(kind)));
        }
        for kind in [
            PresenceType::Subscribe,
            PresenceType::Subscribed,
            PresenceType::Unsubscribe,
            PresenceType::Unsubscribed,
        ] {
            assert!(eligible(StanzaType::Presence(kind)));
        }
        for kind in [
            PresenceType::Available,
            PresenceType::Unavailable,
            PresenceType::Probe,
            PresenceType::Error,
        ] {
            assert!(!eligible(StanzaType::Presence(kind)));
        }
    }

    #[test]
    fn replies_swap_addresses_and_preserve_the_selected_error_condition()
    -> Result<(), Box<dyn std::error::Error>> {
        compio::runtime::Runtime::new()?.block_on(async {
            for (xml, expected) in [
                ("<message from='alice@localhost/desk' to='bob@remote.test'><body>payload</body></message>", StanzaType::Message(MessageType::Error)),
                ("<iq from='alice@localhost/desk' to='bob@remote.test' type='get' id='request'><query xmlns='urn:test'/></iq>", StanzaType::Iq(IqType::Error)),
                ("<presence from='alice@localhost/desk' to='bob@remote.test' type='subscribe'/>", StanzaType::Presence(PresenceType::Error)),
            ] {
                let source = stanza(xml).await?;
                for (condition, name) in [
                    (StanzaErrorCondition::RemoteServerNotFound, "remote-server-not-found"),
                    (StanzaErrorCondition::RemoteServerTimeout, "remote-server-timeout"),
                    (StanzaErrorCondition::ResourceConstraint, "resource-constraint"),
                ] {
                    let reply = reply(&source, condition, lonewolf_util::arena::GlobalChunkAllocator).ok_or("reply")?;
                    let view = reply.resolve()?;
                    assert_eq!(view.stanza_type(), expected);
                    assert_eq!(view.to()?.ok_or("to")?.to_string(), "alice@localhost/desk");
                    assert_eq!(view.from()?.ok_or("from")?.to_string(), "bob@remote.test");
                    let mut output = String::new();
                    view.write_xml(&mut output)?;
                    assert!(output.contains(name), "{output}");
                }
            }
            Ok(())
        })
    }
}
