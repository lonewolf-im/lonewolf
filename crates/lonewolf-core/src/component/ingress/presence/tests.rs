// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;
use std::num::NonZeroUsize;
use std::sync::Arc;

use compio::runtime::Runtime;
use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramSha1Verifier, ScramVerifier,
};
use lonewolf_extension::Extensions;
use lonewolf_extension::blocking::{Blocking, NAME};
use lonewolf_storage::account::{AccountKey, AccountWrites, NewAccount};
use lonewolf_storage::blocking::{BlockChange, BlockingWrites};
use lonewolf_storage::roster::RosterJid;
use lonewolf_storage::{RedbStorage, Storage, WriteTransaction};
use lonewolf_util::arena::{Arena, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{
    PresenceType, RoutedStanza, Stanza, StanzaErrorCondition, StanzaNamespace, StanzaType,
    error_element_in,
};

use super::super::{Context, dispatch};
use crate::Config;
use crate::component::metrics::ComponentMetrics;
use crate::component::registry::ComponentRegistry;
use crate::delivery::WorkGroup;
use crate::hosts::Hosts;
use crate::router::{Router, local::LocalRouter};

#[test]
fn component_presence_errors_follow_the_recipient_host_policy() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        const DOMAIN: &str = "muc.localhost";
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("state.redb"))?;
        let config = Config::default();
        let registry = ComponentRegistry::new(
            &config.components,
            crate::component::credentials::load(&config.components)?,
            &config.limits.components,
            ComponentMetrics::new(1, 1),
        );
        let mut arena = Arena::try_new(Default::default())?;
        let target = Jid::parse_in("bob@localhost/phone", &mut arena)?;
        let peer = Jid::parse_in("room@muc.localhost/guest", &mut arena)?;
        let owner = AccountKey::try_from(target.resolve(&arena)?.bare())?;
        let mut write = storage.begin_write().await?;
        write
            .create_account(NewAccount {
                key: owner.clone(),
                credentials: ScramCredentials::new(ScramVerifier::Sha1(ScramSha1Verifier::new(
                    [1; 16],
                    SCRAM_POLICY_ITERATIONS,
                    [2; 20],
                    [3; 20],
                ))),
            })
            .await?;
        write
            .change_blocklist(
                &owner,
                BlockChange::Block(&[RosterJid::from(peer.resolve(&arena)?)]),
            )
            .await?;
        write.commit().await?;
        let namespace = StanzaNamespace::ComponentAccept;
        let kind = StanzaType::Presence(PresenceType::Error);
        let condition = StanzaErrorCondition::ServiceUnavailable;
        let error = error_element_in(
            namespace,
            condition,
            None,
            condition.default_text(),
            &mut arena,
        )?;
        let stanza = Stanza::builder_in(kind, namespace, &mut arena)
            .from(Some(peer))?
            .to(Some(target))?
            .child(error)?
            .build()?;
        let stanza = RoutedStanza::from_parts(stanza, arena);
        for names in [&[NAME][..], &[][..]] {
            let mut extensions = Extensions::default();
            extensions.register(Arc::new(Blocking))?;
            let router = Router::new(
                Hosts::new(&config.hosts, None)?,
                LocalRouter::new(GlobalChunkAllocator),
            )
            .with_extensions(BTreeMap::from([(
                "localhost".into(),
                extensions.enable_host("localhost", names.iter().copied())?,
            )]));
            let mut work = WorkGroup::new();
            let context = Context {
                router: router.handle(),
                storage: storage.clone(),
                allocator: GlobalChunkAllocator,
                work: work.handle(),
                registry: registry.clone(),
                connection_id: 1,
            };
            let phone = context
                .router
                .register(&owner, Some("phone"), NonZeroUsize::MIN)
                .await?;
            dispatch(&context, DOMAIN, stanza.clone())
                .await
                .map_err(|_| "component dispatch")?;
            let delivered = phone.take_queued();
            assert_eq!(delivered.len(), usize::from(names.is_empty()));
            if let Some(entry) = delivered.first() {
                assert_eq!(entry.stanza.resolve()?.stanza_type(), kind);
            }
            drop(phone);
            work.drain().await;
            router.shutdown().await?;
        }
        Ok(())
    })
}
