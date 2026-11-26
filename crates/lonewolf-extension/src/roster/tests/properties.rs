// SPDX-License-Identifier: Apache-2.0

use proptest::prelude::*;

use super::{
    AccountKey, PresenceRequest, PresenceRequestType, RecordingDelivery, Roster, RosterJid,
    RosterReads, Storage, SubscriptionState, TestPresenceHandler, TestRoster, account, block_on,
    create_account, roster, subscription_stanza,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Subscription {
    Absent,
    Pending,
    Preapproved,
    Granted,
}

impl Subscription {
    fn after(self, kind: PresenceRequestType) -> Self {
        use PresenceRequestType::{Subscribe, Subscribed, Unsubscribe, Unsubscribed};
        match (kind, self) {
            (Subscribe, Self::Preapproved | Self::Granted)
            | (Subscribed, Self::Pending | Self::Granted) => Self::Granted,
            (Subscribe, _) => Self::Pending,
            (Subscribed, _) | (Unsubscribe, Self::Preapproved) => Self::Preapproved,
            (Unsubscribed | Unsubscribe, _) => Self::Absent,
            _ => unreachable!("expected subscription presence"),
        }
    }
}

async fn check_sequence(
    fixture: &TestRoster,
    accounts: &[AccountKey; 2],
    steps: &[(bool, PresenceRequestType)],
) -> Result<(), Box<dyn std::error::Error>> {
    let contacts = accounts.each_ref().map(RosterJid::from);
    let hosts = RecordingDelivery::default();
    let roster = Roster::default();
    let mut subscriptions = [Subscription::Absent; 2];
    // Dropping this transaction gives each generated sequence the same two empty rosters.
    let mut tx = fixture.storage.begin_write().await?;
    for &(side, kind) in steps {
        let sender = usize::from(side);
        let target = 1 - sender;
        let stanza =
            subscription_stanza(kind, accounts[sender].as_str(), accounts[target].as_str())?;
        let view = stanza.resolve()?;
        let request = PresenceRequest {
            kind,
            sender: view.from()?.ok_or("missing sender")?,
            target: view.to()?.ok_or("missing recipient")?,
            stanza: &stanza,
        };
        TestPresenceHandler::receive(&roster, request, &mut tx, &hosts)
            .await
            .expect("local subscription transition");

        let subscriber = match kind {
            PresenceRequestType::Subscribe | PresenceRequestType::Unsubscribe => sender,
            _ => target,
        };
        subscriptions[subscriber] = subscriptions[subscriber].after(kind);
        for owner in 0..2 {
            let other = 1 - owner;
            let outgoing = subscriptions[owner];
            let incoming = subscriptions[other];
            let expected = match (
                outgoing == Subscription::Granted,
                incoming == Subscription::Granted,
            ) {
                (false, false) => SubscriptionState::None,
                (true, false) => SubscriptionState::To,
                (false, true) => SubscriptionState::From,
                (true, true) => SubscriptionState::Both,
            };
            let item = tx
                .roster_subscription(&accounts[owner], &contacts[other])
                .await?
                .unwrap_or_default();
            assert_eq!(item.state, expected);
            assert_eq!(item.pending_out, outgoing == Subscription::Pending);
            assert_eq!(item.approved, incoming == Subscription::Preapproved);
            assert_eq!(
                tx.pending_request_exists(&accounts[owner], &contacts[other])
                    .await?,
                incoming == Subscription::Pending
            );
        }
    }
    Ok(())
}

#[test]
#[ignore = "runs in the XMPP property workflow"]
fn property_roster_subscription_transitions() {
    let (_directory, fixture) = roster();
    let accounts = ["alice@example.com", "bob@example.com"].map(account);
    for user in &accounts {
        create_account(&fixture, user);
    }
    let kind = prop::sample::select(&[
        PresenceRequestType::Subscribe,
        PresenceRequestType::Subscribed,
        PresenceRequestType::Unsubscribe,
        PresenceRequestType::Unsubscribed,
    ]);
    proptest!(|(steps in prop::collection::vec((any::<bool>(), kind), 1..=16))| {
        block_on(check_sequence(&fixture, &accounts, &steps)).expect("check both local rosters");
    });
}
