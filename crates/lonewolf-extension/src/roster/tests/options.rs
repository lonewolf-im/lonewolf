// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;
use std::num::NonZeroUsize;

use futures_executor::block_on;
use lonewolf_storage::roster::{PendingSubscription, RosterJid, RosterReads, RosterWrites};
use lonewolf_storage::{RedbStorage, Storage, WriteTransaction};
use lonewolf_util::arena::GlobalChunkAllocator;
use lonewolf_xmpp::stanza::StanzaErrorCondition;

use super::{RecordingDelivery, SubscribeCall, account, create_account, roster};
use crate::delivery::HandlerError;
use crate::presence::{PresenceRequest, PresenceRequestType};
use crate::roster::RosterFactory;
use crate::{Extensions, HostSelection};

#[test]
fn factory_applies_defaults_and_host_specific_pending_limits() -> Result<(), Box<dyn Error>> {
    let domains = [
        "default.example",
        "empty.example",
        "small.example",
        "large.example",
    ];
    let options = [
        BTreeMap::new(),
        BTreeMap::from([("roster".into(), toml::Table::new())]),
        BTreeMap::from([(
            "roster".into(),
            toml::from_str("max_pending_subscription_requests = 7")?,
        )]),
        BTreeMap::from([(
            "roster".into(),
            toml::from_str("max_pending_subscription_requests = 11")?,
        )]),
    ];
    let names = ["roster".into()];
    let selections = domains
        .iter()
        .zip(&options)
        .map(|(domain, options)| HostSelection {
            domain,
            extensions: &names,
            options,
        })
        .collect::<Vec<_>>();
    let mut catalog = Extensions::<GlobalChunkAllocator, RedbStorage>::default();
    catalog.register_factory(Box::new(RosterFactory))?;
    let enabled = catalog.enable(&selections)?;
    let (_directory, roster) = roster();
    create_account(&roster, &account("first@example.com"));
    create_account(&roster, &account("second@example.com"));
    for (domain, limit) in domains.into_iter().zip([100, 100, 7, 11]) {
        let owner = account(&format!("owner@{domain}"));
        create_account(&roster, &owner);
        block_on(async {
            let mut transaction = roster.storage.begin_write().await?;
            for index in 1..limit {
                transaction
                    .put_pending_request(
                        &owner,
                        PendingSubscription {
                            sender: RosterJid::from(&account(&format!(
                                "pending{index}@example.com"
                            ))),
                            stanza: Box::from(b"stored".as_slice()),
                        },
                        NonZeroUsize::MAX,
                    )
                    .await?;
            }
            let handler = enabled[domain]
                .presence()
                .find(PresenceRequestType::Subscribe)
                .ok_or("missing roster handler")?;
            let hosts = RecordingDelivery::default();
            for (sender, expected) in [
                ("first@example.com", Ok(())),
                (
                    "second@example.com",
                    Err(HandlerError::Stanza(
                        StanzaErrorCondition::ResourceConstraint,
                    )),
                ),
            ] {
                let call = SubscribeCall::new(sender, owner.as_str());
                let view = call.stanza.resolve()?;
                let result = handler
                    .receive(
                        PresenceRequest {
                            kind: PresenceRequestType::Subscribe,
                            sender: view.from()?.ok_or("missing sender")?,
                            target: view.to()?.ok_or("missing target")?,
                            stanza: &call.stanza,
                        },
                        &mut transaction,
                        &hosts,
                    )
                    .await;
                assert_eq!(result.map(|_| ()), expected, "{domain}");
            }
            assert_eq!(
                transaction.pending_requests(&owner).await?.len(),
                limit,
                "{domain}"
            );
            transaction.commit().await?;
            Ok::<_, Box<dyn Error>>(())
        })?;
    }
    Ok(())
}
