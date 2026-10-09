// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use futures_executor::block_on;
use lonewolf_storage::offline::OfflineReads;
use lonewolf_storage::{RedbStorage, Storage, WriteTransaction};
use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::stanza::StanzaErrorCondition;

use super::{MESSAGE, TestOffline, TestResult, key, received_at, stanza};
use crate::delivery::HandlerError;
use crate::message::{StoreOutcome, UndeliverableMessage};
use crate::offline::OfflineFactory;
use crate::{Extensions, HostSelection};

#[test]
fn factory_applies_defaults_and_host_specific_message_limits() -> TestResult {
    let domains = [
        "default.example",
        "empty.example",
        "small.example",
        "large.example",
    ];
    let options = [
        BTreeMap::new(),
        BTreeMap::from([("offline".into(), toml::Table::new())]),
        BTreeMap::from([(
            "offline".into(),
            toml::from_str("max_messages_per_account = 7")?,
        )]),
        BTreeMap::from([(
            "offline".into(),
            toml::from_str("max_messages_per_account = 11")?,
        )]),
    ];
    let names = ["offline".into()];
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
    catalog.register_factory(Box::new(OfflineFactory))?;
    let enabled = catalog.enable(&selections)?;
    block_on(async {
        let test = TestOffline::new(
            BTreeMap::new(),
            &[
                "owner@default.example",
                "owner@empty.example",
                "owner@small.example",
                "owner@large.example",
            ],
        )
        .await?;
        let stanza = stanza(MESSAGE).await?;
        let mut scratch = Arena::try_new(ArenaConfig::default())?;
        let mut transaction = test.storage.begin_write().await?;
        for (domain, limit) in domains.into_iter().zip([100, 100, 7, 11]) {
            let recipient = key(&format!("owner@{domain}"))?;
            let handler = enabled[domain]
                .messages()
                .ok_or("missing offline handler")?;
            for _ in 0..limit {
                let result = handler
                    .store(
                        UndeliverableMessage {
                            recipient: &recipient,
                            stanza: &stanza,
                            received_at: received_at(),
                        },
                        &mut transaction,
                        &mut scratch,
                    )
                    .await;
                assert!(
                    matches!(result, Ok(StoreOutcome::Stored(_))),
                    "{domain}: {result:?}"
                );
            }
            assert_eq!(
                handler
                    .store(
                        UndeliverableMessage {
                            recipient: &recipient,
                            stanza: &stanza,
                            received_at: received_at()
                        },
                        &mut transaction,
                        &mut scratch
                    )
                    .await,
                Err(HandlerError::Stanza(
                    StanzaErrorCondition::ResourceConstraint
                )),
                "{domain}"
            );
            assert_eq!(
                transaction.offline_count(&recipient).await?,
                limit,
                "{domain}"
            );
        }
        transaction.commit().await?;
        Ok(())
    })
}
