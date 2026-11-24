// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;
use std::num::NonZeroUsize;
use std::sync::Arc;

use compio::runtime::Runtime;
use lonewolf_extension::Extensions;
use lonewolf_extension::ping::{NAME, NAMESPACE, Ping};
use lonewolf_storage::RedbStorage;
use lonewolf_util::arena::{Arena, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{Element, IqType, RoutedStanza, Stanza, StanzaNamespace, StanzaType};

use super::{Context, dispatch};
use crate::Config;
use crate::component::credentials;
use crate::component::metrics::ComponentMetrics;
use crate::component::registry::ComponentRegistry;
use crate::config::ComponentLimits;
use crate::delivery::WorkGroup;
use crate::hosts::Hosts;
use crate::router::{Router, local::LocalRouter};

const DOMAIN: &str = "muc.localhost";
const SENDER: &str = "room@muc.localhost/guest";

fn ping(id: &str) -> Result<RoutedStanza<GlobalChunkAllocator>, Box<dyn Error>> {
    let mut arena = Arena::try_new(Default::default())?;
    let from = Jid::parse_in(SENDER, &mut arena)?;
    let to = Jid::parse_in("localhost", &mut arena)?;
    let payload = Element::builder_in("ping", NAMESPACE, &mut arena)?.build()?;
    let stanza = Stanza::builder_in(
        StanzaType::Iq(IqType::Get),
        StanzaNamespace::ComponentAccept,
        &mut arena,
    )
    .from(Some(from))?
    .to(Some(to))?
    .id(Some(id))?
    .child(payload)?
    .build()?;
    Ok(RoutedStanza::from_parts(stanza, arena))
}

#[test]
fn component_iq_answers_keep_attachment_selection_on_busy_detached_and_stopped_routes()
-> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        let config = Config::default();
        let components = toml::from_str(
            "[domains.'muc.localhost']\nsecret='component-test-secret-0001'\nmax_connections=2",
        )?;
        let limits = ComponentLimits {
            max_queued_stanzas: NonZeroUsize::MIN,
            ..config.limits.components
        };
        let metrics = ComponentMetrics::new(1, 1);
        let registry = ComponentRegistry::new(
            &components,
            credentials::load(&components)?,
            &limits,
            Arc::clone(&metrics),
        );
        let mut requesting = registry
            .attach(DOMAIN)
            .map_err(|_| "requesting attachment")?;
        let mut survivor = registry
            .attach(DOMAIN)
            .map_err(|_| "surviving attachment")?;
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("state.redb"))?;
        let mut extensions = Extensions::default();
        extensions.register(Arc::new(Ping))?;
        let router = Router::new(
            Hosts::new(&config.hosts, None)?,
            LocalRouter::new(GlobalChunkAllocator),
        )
        .with_extensions(BTreeMap::from([(
            "localhost".into(),
            extensions.enable_host("localhost", [NAME])?,
        )]));
        let mut work = WorkGroup::new();
        let mut context = Context {
            router: router.handle(),
            storage,
            allocator: GlobalChunkAllocator,
            work: work.handle(),
            registry: registry.clone(),
            connection_id: survivor.id(),
        };

        dispatch(&context, DOMAIN, ping("survivor")?)
            .await
            .map_err(|_| "survivor dispatch")?;
        let reply = survivor.try_next().ok_or("survivor answer")?;
        assert_eq!(reply.resolve()?.id()?, Some("survivor"));
        assert!(requesting.try_next().is_none());
        context.connection_id = requesting.id();

        dispatch(&context, DOMAIN, ping("first")?)
            .await
            .map_err(|_| "first dispatch")?;
        dispatch(&context, DOMAIN, ping("busy")?)
            .await
            .map_err(|_| "busy dispatch")?;
        let reply = requesting.try_next().ok_or("first answer")?;
        assert_eq!(
            reply.resolve()?.stanza_type(),
            StanzaType::Iq(IqType::Result)
        );
        assert_eq!(reply.resolve()?.id()?, Some("first"));
        assert!(requesting.try_next().is_none());
        assert!(survivor.try_next().is_none());

        let detached = requesting.detach();
        assert_eq!(detached.moved, 0);
        assert!(detached.stranded.is_empty());
        dispatch(&context, DOMAIN, ping("detached")?)
            .await
            .map_err(|_| "detached dispatch")?;
        let reply = survivor
            .try_next()
            .ok_or("answer to the surviving attachment")?;
        let view = reply.resolve()?;
        assert_eq!(view.stanza_type(), StanzaType::Iq(IqType::Result));
        assert_eq!(view.id()?, Some("detached"));
        assert_eq!(view.from()?.ok_or("from")?.as_str(), "localhost");
        assert_eq!(view.to()?.ok_or("to")?.as_str(), SENDER);

        registry.stop();
        dispatch(&context, DOMAIN, ping("stopped")?)
            .await
            .map_err(|_| "stopped dispatch")?;
        assert!(survivor.try_next().is_none());

        let mut root = prometheus_client::registry::Registry::default();
        metrics.register(&mut root);
        let mut output = String::new();
        prometheus_client::encoding::text::encode(&mut output, &root)?;
        for reason in ["queue_full", "stopped"] {
            let expected = format!("component_admission_rejections_total{{reason=\"{reason}\"}} 1");
            assert!(output.lines().any(|line| line == expected), "{output}");
        }

        drop(survivor);
        work.drain().await;
        router.shutdown().await?;
        Ok(())
    })
}
