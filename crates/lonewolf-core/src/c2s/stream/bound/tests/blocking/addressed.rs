// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::stages::ingress::checks::{Snapshot, check_from, parties};
use lonewolf_extension::policy::{Direction, Verdict};

#[test]
fn addressed_policy_matrix_uses_authenticated_sender() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[]).await?;
        let router = router()?;
        let handle = router.handle();
        let owner = fixture.registration.account();
        let mut arena = Arena::try_new(ArenaConfig::default())?;
        let owner_jid = Jid::parse_in("bob@localhost/phone", &mut arena)?;
        let local = Jid::parse_in("alice@localhost/desk", &mut arena)?;
        let remote = Jid::parse_in("alice@remote.test/desk", &mut arena)?;
        let component = Jid::parse_in("room@irc.example.test/desk", &mut arena)?;
        let local_account = AccountKey::try_from(local.resolve(&arena)?.bare())?;
        let mut write = fixture.storage.begin_write().await?;
        write
            .create_account(NewAccount {
                key: local_account.clone(),
                credentials: credentials(),
            })
            .await?;
        write.commit().await?;
        let before_block = fixture.storage.begin_read().await?;
        let mut write = fixture.storage.begin_write().await?;
        let rules = [
            RosterJid::from(local.resolve(&arena)?),
            RosterJid::from(remote.resolve(&arena)?),
            RosterJid::from(component.resolve(&arena)?),
        ];
        write
            .change_blocklist(owner, BlockChange::Block(&rules))
            .await?;
        write.commit().await?;
        let alice = handle
            .register(&local_account, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let bob = handle
            .register(owner, Some("phone"), NonZeroUsize::MIN)
            .await?;
        let snapshot = fixture.storage.begin_read().await?;

        for (peer, inbound_origin, inbound_namespace) in [
            (local, Origin::Session(&alice), StanzaNamespace::Client),
            (
                remote,
                Origin::Remote {
                    local: "localhost",
                    remote: "remote.test",
                },
                StanzaNamespace::Server,
            ),
            (
                component,
                Origin::Service {
                    domain: "irc.example.test",
                },
                StanzaNamespace::ComponentAccept,
            ),
        ] {
            let outbound_origin = Origin::Session(&bob);
            for (direction, origin, from, to, namespace) in [
                (
                    Direction::Inbound,
                    &inbound_origin,
                    peer,
                    owner_jid,
                    inbound_namespace,
                ),
                (
                    Direction::Outbound,
                    &outbound_origin,
                    owner_jid,
                    peer,
                    StanzaNamespace::Client,
                ),
            ] {
                for kind in [
                    StanzaType::Message(MessageType::Chat),
                    StanzaType::Message(MessageType::Normal),
                    StanzaType::Message(MessageType::Groupchat),
                    StanzaType::Message(MessageType::Headline),
                    StanzaType::Message(MessageType::Error),
                    StanzaType::Iq(IqType::Get),
                    StanzaType::Iq(IqType::Set),
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
                ] {
                    let stanza = Stanza::builder_in(kind, namespace, &mut arena)
                        .id(Some("addressed"))?
                        .to(Some(to))?
                        .build()?;
                    let view = stanza.resolve(&arena)?;
                    let endpoints = parties(&handle, origin, to.resolve(&arena)?, kind.kind())
                        .map_err(|_| "party lookup failed")?;
                    if kind == StanzaType::Message(MessageType::Chat) {
                        let previous = check_from(
                            &handle,
                            &fixture.storage,
                            origin.sender(),
                            endpoints.recipient.as_ref(),
                            &view,
                            Some(from.resolve(&arena)?),
                            Snapshot::Ordered(&before_block),
                        )
                        .await
                        .map_err(|_| "snapshot check failed")?;
                        assert_eq!(previous, Verdict::Allow);
                    }
                    let actual = check_from(
                        &handle,
                        &fixture.storage,
                        origin.sender(),
                        endpoints.recipient.as_ref(),
                        &view,
                        Some(from.resolve(&arena)?),
                        Snapshot::Ordered(&snapshot),
                    )
                    .await
                    .map_err(|_| "policy evaluation failed")?;
                    let matches = match (direction, kind) {
                        (
                            _,
                            StanzaType::Iq(IqType::Result | IqType::Error)
                            | StanzaType::Message(MessageType::Error)
                            | StanzaType::Presence(PresenceType::Error),
                        )
                        | (Direction::Inbound, StanzaType::Presence(_)) => actual == Verdict::Drop,
                        (Direction::Outbound, _) => actual == Verdict::OutboundBlocked,
                        (Direction::Inbound, _) => matches!(
                            actual,
                            Verdict::Reject {
                                condition: StanzaErrorCondition::ServiceUnavailable,
                                application: None,
                                ..
                            }
                        ),
                    };
                    assert!(matches, "{direction:?} {namespace:?} {kind:?}: {actual:?}");
                }
            }
        }
        drop(snapshot);
        drop(before_block);
        drop(bob);
        drop(alice);
        router.shutdown().await?;
        fixture.finish().await
    })
}
