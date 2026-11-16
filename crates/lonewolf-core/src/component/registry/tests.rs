// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::num::NonZeroUsize;

use std::future::Future;
use std::sync::Barrier;
use std::thread;
use std::time::Duration;

use compio::runtime::Runtime;
use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{MessageType, Stanza, StanzaNamespace, StanzaType};

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
type Registry = ComponentRegistry<GlobalChunkAllocator>;
type Link = ComponentLink<GlobalChunkAllocator>;

fn run(test: impl Future<Output = TestResult>) -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), test))?
}

fn registry(
    policy: ComponentBalancing,
    connections: usize,
    capacity: usize,
    bytes: usize,
) -> TestResult<Registry> {
    let mut config: ComponentsConfig =
        toml::from_str("[domains.'muc.localhost']\nsecret='component-test-secret-0001'")?;
    let domain = config.domains.get_mut("muc.localhost").ok_or("domain")?;
    domain.balancing = policy;
    domain.max_connections = NonZeroUsize::new(connections).ok_or("connections")?;
    let limits = ComponentLimits {
        max_queued_stanzas: NonZeroUsize::new(capacity).ok_or("capacity")?,
        max_queued_bytes: NonZeroUsize::new(bytes).ok_or("bytes")?,
        ..ComponentLimits::default()
    };
    let secrets = super::super::credentials::load(&config)?;
    Ok(Registry::new(
        &config,
        secrets,
        &limits,
        ComponentMetrics::new(1, 1),
    ))
}

fn stanza(
    from: Option<&str>,
    to: &str,
    id: &str,
) -> TestResult<RoutedStanza<GlobalChunkAllocator>> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let from = from
        .map(|from| Jid::parse_in(from, &mut arena))
        .transpose()?;
    let to = Jid::parse_in(to, &mut arena)?;
    let stanza = Stanza::builder_in(
        StanzaType::Message(MessageType::Chat),
        StanzaNamespace::Client,
        &mut arena,
    )
    .from(from)?
    .to(Some(to))?
    .id(Some(id))?
    .build()?;
    Ok(RoutedStanza::from_parts(stanza, arena))
}

fn id(stanza: &RoutedStanza<GlobalChunkAllocator>) -> TestResult<String> {
    Ok(stanza.resolve()?.id()?.ok_or("id")?.into())
}

fn message(
    key: usize,
    sequence: usize,
    policy: ComponentBalancing,
) -> TestResult<RoutedStanza<GlobalChunkAllocator>> {
    let resource = if matches!(
        policy,
        ComponentBalancing::BareSource | ComponentBalancing::BareDestination
    ) {
        sequence % 3
    } else {
        key % 3
    };
    stanza(
        Some(&format!("user{key}@source.test/r{resource}")),
        &format!("room{key}@muc.localhost/r{resource}"),
        &format!("{key}:{sequence}"),
    )
}

fn owners(links: &mut [Link]) -> TestResult<BTreeMap<usize, u64>> {
    let mut owners = BTreeMap::new();
    for link in links {
        let mut count = 0;
        let mut sequences = BTreeMap::new();
        while let Some(stanza) = link.try_next() {
            let id = id(&stanza)?;
            let (key, sequence) = id.split_once(':').ok_or("flow ID")?;
            let key: usize = key.parse()?;
            let sequence: usize = sequence.parse()?;
            if let Some(previous) = owners.insert(key, link.id()) {
                assert_eq!(previous, link.id());
            }
            if let Some(previous) = sequences.insert(key, sequence) {
                assert!(previous < sequence);
            }
            count += 1;
        }
        assert!(count > 0);
    }
    Ok(owners)
}

fn render(registry: &Registry) -> TestResult<String> {
    let mut root = prometheus_client::registry::Registry::default();
    registry
        .inner
        .metrics
        .register(root.sub_registry_with_prefix("lonewolf"));
    let mut output = String::new();
    prometheus_client::encoding::text::encode(&mut output, &root)?;
    Ok(output)
}

fn sample(registry: &Registry, expected: &str) -> TestResult {
    let output = render(registry)?;
    assert!(output.lines().any(|line| line == expected), "{output}");
    Ok(())
}

#[test]
fn detached_and_unknown_domains_reject_admission() -> TestResult {
    let registry = registry(ComponentBalancing::Source, 1, 4, 4096)?;
    assert_eq!(
        registry.secret("muc.localhost"),
        Some(&ComponentSecret::new("component-test-secret-0001")?)
    );
    assert_eq!(registry.secret("unknown.localhost"), None);
    assert_eq!(
        registry.enqueue("muc.localhost", stanza(None, "muc.localhost", "one")?),
        Err(EnqueueError::NotConnected)
    );
    assert_eq!(
        registry.enqueue(
            "unknown.localhost",
            stanza(None, "unknown.localhost", "two")?
        ),
        Err(EnqueueError::NotConnected)
    );
    sample(
        &registry,
        "lonewolf_component_admission_rejections_total{reason=\"not_connected\"} 2",
    )?;
    Ok(())
}

#[test]
fn producers_preserve_their_order_through_next() -> TestResult {
    run(async {
        let registry = registry(ComponentBalancing::Source, 1, 256, 65536)?;
        let mut link = registry.attach("muc.localhost").map_err(|_| "attach")?;
        let mut producers = Vec::with_capacity(2);
        for producer in 0..2 {
            let registry = registry.clone();
            producers.push(thread::spawn(move || -> Result<(), String> {
                for sequence in 0..100 {
                    let stanza = message(producer, sequence, ComponentBalancing::Source)
                        .map_err(|error| error.to_string())?;
                    registry
                        .enqueue("muc.localhost", stanza)
                        .map_err(|error| format!("{error:?}"))?;
                }
                Ok(())
            }));
        }
        for producer in producers {
            producer.join().map_err(|_| "producer panic")??;
        }
        let mut expected = [0, 0];
        for _ in 0..200 {
            let stanza = link.next().await.ok_or("stanza")?;
            let id = id(&stanza)?;
            let (producer, sequence) = id.split_once(':').ok_or("ID")?;
            let producer: usize = producer.parse()?;
            assert_eq!(sequence.parse::<usize>()?, expected[producer]);
            expected[producer] += 1;
        }
        assert_eq!(expected, [100, 100]);
        assert_eq!(registry.inner.snapshot().stanzas, 0);
        assert_eq!(registry.inner.snapshot().bytes, 0);
        Ok(())
    })
}

#[test]
fn stanza_and_byte_limits_release_reservations_when_received() -> TestResult {
    run(async {
        let source = stanza(Some("alice@source.test/r"), "muc.localhost", "0")?;
        let mut xml = String::new();
        source.resolve()?.write_xml(&mut xml)?;
        for (capacity, bytes) in [(1, 65536), (4, xml.len())] {
            let registry = registry(ComponentBalancing::Source, 1, capacity, bytes)?;
            let mut link = registry.attach("muc.localhost").map_err(|_| "attach")?;
            registry
                .enqueue("muc.localhost", source.clone())
                .map_err(|_| "enqueue")?;
            assert_eq!(registry.inner.snapshot().stanzas, 1);
            assert_eq!(registry.inner.snapshot().bytes, xml.len() as u64);
            assert_eq!(
                registry.enqueue("muc.localhost", source.clone()),
                Err(EnqueueError::Busy)
            );
            assert_eq!(registry.inner.snapshot().bytes, xml.len() as u64);
            link.next().await.ok_or("stanza")?;
            assert_eq!(registry.inner.snapshot().stanzas, 0);
            assert_eq!(registry.inner.snapshot().bytes, 0);
            registry
                .enqueue("muc.localhost", source.clone())
                .map_err(|_| "released")?;
            sample(
                &registry,
                "lonewolf_component_admission_rejections_total{reason=\"queue_full\"} 1",
            )?;
        }
        Ok(())
    })
}

#[test]
fn attachment_caps_and_reconnection_preserve_new_ids() -> TestResult {
    for capacity in [1, 3] {
        let registry = registry(ComponentBalancing::Source, capacity, 4, 4096)?;
        assert_eq!(
            registry.attach("unknown.localhost").err(),
            Some(AttachError::Unknown)
        );
        let mut links = (0..capacity)
            .map(|_| registry.attach("muc.localhost").map_err(|_| "attach"))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            registry.attach("muc.localhost").err(),
            Some(AttachError::Conflict)
        );
        let old = links.remove(0);
        let old_id = old.id();
        assert!(old.detach().stranded.is_empty());
        let replacement = registry.attach("muc.localhost").map_err(|_| "reattach")?;
        assert_ne!(replacement.id(), old_id);
    }
    Ok(())
}

#[test]
fn keyed_policies_keep_each_key_on_one_connection() -> TestResult {
    for policy in [
        ComponentBalancing::Source,
        ComponentBalancing::BareSource,
        ComponentBalancing::Destination,
        ComponentBalancing::BareDestination,
    ] {
        let registry = registry(policy, 3, 1024, 1048576)?;
        let mut links = (0..3)
            .map(|_| registry.attach("muc.localhost").map_err(|_| "attach"))
            .collect::<Result<Vec<_>, _>>()?;
        for sequence in 0..1000 {
            registry
                .enqueue("muc.localhost", message(sequence % 50, sequence, policy)?)
                .map_err(|_| "enqueue")?;
        }
        assert_eq!(owners(&mut links)?.len(), 50);
    }
    Ok(())
}

#[test]
fn removing_an_attachment_remaps_only_its_keys_and_moves_queued_stanzas() -> TestResult {
    for policy in [
        ComponentBalancing::Source,
        ComponentBalancing::BareSource,
        ComponentBalancing::Destination,
        ComponentBalancing::BareDestination,
    ] {
        let registry = registry(policy, 3, 2048, 1048576)?;
        let mut links = (0..3)
            .map(|_| registry.attach("muc.localhost").map_err(|_| "attach"))
            .collect::<Result<Vec<_>, _>>()?;
        for key in 0..50 {
            registry
                .enqueue("muc.localhost", message(key, key, policy)?)
                .map_err(|_| "probe")?;
        }
        let before = owners(&mut links)?;
        for sequence in 0..1000 {
            registry
                .enqueue("muc.localhost", message(sequence % 50, sequence, policy)?)
                .map_err(|_| "enqueue")?;
        }
        let removed = links.remove(1);
        let removed_id = removed.id();
        let expected_moved = (0..1000)
            .filter(|sequence| before[&(sequence % 50)] == removed_id)
            .count() as u64;
        let detached = removed.detach();
        assert!(detached.stranded.is_empty());
        assert_eq!(detached.moved, expected_moved);
        let after = owners(&mut links)?;
        for (key, previous) in before {
            if previous != removed_id {
                assert_eq!(after[&key], previous);
            } else {
                assert_ne!(after[&key], removed_id);
            }
        }
        sample(
            &registry,
            &format!("lonewolf_component_moved_stanzas_total {expected_moved}"),
        )?;
    }
    Ok(())
}

#[test]
fn random_balancing_reaches_all_connections_without_concentrating_traffic() -> TestResult {
    let registry = registry(ComponentBalancing::Random, 3, 3000, 1048576)?;
    let mut links = (0..3)
        .map(|_| registry.attach("muc.localhost").map_err(|_| "attach"))
        .collect::<Result<Vec<_>, _>>()?;
    for sequence in 0..3000 {
        registry
            .enqueue(
                "muc.localhost",
                message(0, sequence, ComponentBalancing::Random)?,
            )
            .map_err(|_| "enqueue")?;
    }
    let counts: Vec<_> = links
        .iter_mut()
        .map(|link| {
            let mut count = 0;
            while link.try_next().is_some() {
                count += 1;
            }
            count
        })
        .collect();
    assert_eq!(counts.iter().sum::<usize>(), 3000);
    assert!(counts.iter().all(|count| *count > 0 && *count <= 1800));
    Ok(())
}

#[test]
fn full_queues_do_not_spill_and_detach_returns_stranded_fifo() -> TestResult {
    let registry = registry(ComponentBalancing::Source, 2, 2, 65536)?;
    let mut first = registry.attach("muc.localhost").map_err(|_| "first")?;
    let second = registry.attach("muc.localhost").map_err(|_| "second")?;
    for sequence in 0..2 {
        registry
            .reply(
                "muc.localhost",
                first.id(),
                message(0, sequence, ComponentBalancing::Source)?,
            )
            .map_err(|_| "fill")?;
    }
    for sequence in 2..4 {
        registry
            .reply(
                "muc.localhost",
                second.id(),
                message(0, sequence, ComponentBalancing::Source)?,
            )
            .map_err(|_| "fill")?;
    }
    assert_eq!(
        registry.reply(
            "muc.localhost",
            first.id(),
            message(0, 4, ComponentBalancing::Source)?
        ),
        Err(EnqueueError::Busy)
    );
    let detached = second.detach();
    assert_eq!(detached.moved, 0);
    assert_eq!(
        detached
            .stranded
            .iter()
            .map(id)
            .collect::<TestResult<Vec<_>>>()?,
        ["0:2", "0:3"]
    );
    assert_eq!(id(&first.try_next().ok_or("first")?)?, "0:0");
    assert_eq!(id(&first.try_next().ok_or("second")?)?, "0:1");
    for sequence in 4..6 {
        registry
            .enqueue(
                "muc.localhost",
                message(0, sequence, ComponentBalancing::Source)?,
            )
            .map_err(|_| "refill")?;
    }
    let detached = first.detach();
    assert_eq!(
        detached
            .stranded
            .iter()
            .map(id)
            .collect::<TestResult<Vec<_>>>()?,
        ["0:4", "0:5"]
    );
    assert_eq!(registry.inner.snapshot().stanzas, 0);
    Ok(())
}

#[test]
fn replies_pin_the_instance_then_fall_back_after_detach() -> TestResult {
    let registry = registry(ComponentBalancing::Random, 2, 8, 65536)?;
    let mut first = registry.attach("muc.localhost").map_err(|_| "first")?;
    let mut second = registry.attach("muc.localhost").map_err(|_| "second")?;
    registry
        .reply(
            "muc.localhost",
            first.id(),
            message(0, 0, ComponentBalancing::Random)?,
        )
        .map_err(|_| "reply")?;
    assert_eq!(id(&first.try_next().ok_or("reply")?)?, "0:0");
    assert!(second.try_next().is_none());
    let previous = first.id();
    first.detach();
    registry
        .reply(
            "muc.localhost",
            previous,
            message(0, 1, ComponentBalancing::Random)?,
        )
        .map_err(|_| "fallback")?;
    assert_eq!(id(&second.try_next().ok_or("fallback")?)?, "0:1");
    Ok(())
}

#[test]
fn missing_source_uses_the_domain_key() -> TestResult {
    let registry = registry(ComponentBalancing::Source, 3, 8, 65536)?;
    let source = stanza(None, "muc.localhost", "none")?;
    assert_eq!(
        balancing_key(ComponentBalancing::Source, "muc.localhost", &source),
        Some("muc.localhost")
    );
    assert_eq!(
        balancing_key(ComponentBalancing::BareSource, "muc.localhost", &source),
        Some("muc.localhost")
    );
    let mut links = (0..3)
        .map(|_| registry.attach("muc.localhost").map_err(|_| "attach"))
        .collect::<Result<Vec<_>, _>>()?;
    registry
        .enqueue("muc.localhost", source)
        .map_err(|_| "enqueue")?;
    registry
        .enqueue(
            "muc.localhost",
            stanza(Some("muc.localhost"), "muc.localhost", "domain")?,
        )
        .map_err(|_| "enqueue")?;
    let counts: Vec<_> = links
        .iter_mut()
        .map(|link| {
            let mut count = 0;
            while link.try_next().is_some() {
                count += 1;
            }
            count
        })
        .collect();
    assert_eq!(counts.iter().sum::<usize>(), 2);
    assert_eq!(counts.iter().filter(|count| **count == 2).count(), 1);
    Ok(())
}

#[test]
fn stop_and_link_cleanup_record_drops_once_and_clear_queue_gauges() -> TestResult {
    let registry = registry(ComponentBalancing::Source, 2, 8, 65536)?;
    let first = registry.attach("muc.localhost").map_err(|_| "first")?;
    let second = registry.attach("muc.localhost").map_err(|_| "second")?;
    registry
        .reply(
            "muc.localhost",
            first.id(),
            message(0, 0, ComponentBalancing::Source)?,
        )
        .map_err(|_| "enqueue")?;
    registry
        .reply(
            "muc.localhost",
            second.id(),
            message(0, 1, ComponentBalancing::Source)?,
        )
        .map_err(|_| "enqueue")?;
    assert_eq!(registry.inner.snapshot().stanzas, 2);
    drop(first);
    sample(
        &registry,
        "lonewolf_component_dropped_stanzas_total{reason=\"not_bounceable\"} 1",
    )?;
    registry.stop();
    assert_eq!(
        registry.attach("muc.localhost").err(),
        Some(AttachError::Stopped)
    );
    assert_eq!(
        registry.enqueue("muc.localhost", message(0, 2, ComponentBalancing::Source)?),
        Err(EnqueueError::Stopped)
    );
    assert_eq!(
        registry.reply(
            "muc.localhost",
            second.id(),
            message(0, 2, ComponentBalancing::Source)?
        ),
        Err(EnqueueError::Stopped)
    );
    assert_eq!(second.discard(), 1);
    sample(
        &registry,
        "lonewolf_component_dropped_stanzas_total{reason=\"shutdown\"} 1",
    )?;
    sample(
        &registry,
        "lonewolf_component_admission_rejections_total{reason=\"stopped\"} 2",
    )?;
    sample(&registry, "lonewolf_component_queued_stanzas 0")?;
    sample(&registry, "lonewolf_component_queued_bytes 0")?;
    Ok(())
}

#[test]
fn stale_link_cleanup_never_removes_its_replacement() -> TestResult {
    let registry = registry(ComponentBalancing::Source, 1, 4, 4096)?;
    let old = registry.attach("muc.localhost").map_err(|_| "old")?;
    registry.inner.slots["muc.localhost"]
        .attachments
        .lock()
        .clear();
    let mut replacement = registry.attach("muc.localhost").map_err(|_| "new")?;
    drop(old);
    registry
        .enqueue("muc.localhost", stanza(None, "muc.localhost", "live")?)
        .map_err(|_| "enqueue")?;
    assert_eq!(id(&replacement.try_next().ok_or("replacement")?)?, "live");
    Ok(())
}

#[test]
fn detach_and_concurrent_admission_preserve_the_moved_keys_order() -> TestResult {
    let registry = registry(ComponentBalancing::Source, 2, 4096, 1048576)?;
    let mut first = registry.attach("muc.localhost").map_err(|_| "first")?;
    let mut second = registry.attach("muc.localhost").map_err(|_| "second")?;
    let mut chosen = None;
    for key in 0..1000 {
        registry
            .enqueue(
                "muc.localhost",
                message(key, 0, ComponentBalancing::Source)?,
            )
            .map_err(|_| "probe")?;
        if first.try_next().is_some() {
            chosen = Some(key);
            break;
        }
        second.try_next().ok_or("second probe")?;
    }
    let key = chosen.ok_or("no first-connection key")?;
    for sequence in 0..512 {
        registry
            .enqueue(
                "muc.localhost",
                message(key, sequence, ComponentBalancing::Source)?,
            )
            .map_err(|_| "old")?;
    }
    let barrier = Arc::new(Barrier::new(3));
    let slot = registry.inner.slots["muc.localhost"].attachments.lock();
    let detach_start = Arc::clone(&barrier);
    let detach = thread::spawn(move || {
        detach_start.wait();
        first.detach()
    });
    let enqueue_start = Arc::clone(&barrier);
    let producer_registry = registry.clone();
    let producer = thread::spawn(move || -> Result<(), String> {
        enqueue_start.wait();
        for sequence in 512..1512 {
            let stanza = message(key, sequence, ComponentBalancing::Source)
                .map_err(|error| error.to_string())?;
            producer_registry
                .enqueue("muc.localhost", stanza)
                .map_err(|error| format!("{error:?}"))?;
        }
        Ok(())
    });
    barrier.wait();
    drop(slot);
    let detached = detach.join().map_err(|_| "detach panic")?;
    producer.join().map_err(|_| "producer panic")??;
    assert!(detached.stranded.is_empty());
    assert!(detached.moved >= 512);
    for sequence in 0..1512 {
        assert_eq!(
            id(&second.try_next().ok_or("ordered stanza")?)?,
            format!("{key}:{sequence}")
        );
    }
    assert!(second.try_next().is_none());
    Ok(())
}

#[test]
fn pooled_registry_is_send_and_sync() {
    fn requires_send_sync<T: Send + Sync>() {}
    requires_send_sync::<ComponentRegistry<Arc<lonewolf_util::pool::PooledChunkAllocator>>>();
}

#[test]
fn balancing_keys_borrow_the_selected_full_or_bare_address() -> TestResult {
    let stanza = stanza(
        Some("alice@source.test/desk"),
        "room@muc.localhost/occupant",
        "keys",
    )?;
    let view = stanza.resolve()?;
    let from = view.from()?.ok_or("from")?;
    let to = view.to()?.ok_or("to")?;
    for (policy, expected, pointer) in [
        (
            ComponentBalancing::Source,
            "alice@source.test/desk",
            from.as_str().as_ptr(),
        ),
        (
            ComponentBalancing::BareSource,
            "alice@source.test",
            from.as_str().as_ptr(),
        ),
        (
            ComponentBalancing::Destination,
            "room@muc.localhost/occupant",
            to.as_str().as_ptr(),
        ),
        (
            ComponentBalancing::BareDestination,
            "room@muc.localhost",
            to.as_str().as_ptr(),
        ),
    ] {
        let key = balancing_key(policy, "muc.localhost", &stanza).ok_or("key")?;
        assert_eq!(key, expected);
        assert_eq!(key.as_ptr(), pointer);
    }
    Ok(())
}

#[test]
fn closed_attachment_rejects_without_spilling_and_releases_failed_reservations() -> TestResult {
    let registry = registry(ComponentBalancing::Source, 2, 4, 65536)?;
    let first = registry.attach("muc.localhost").map_err(|_| "first")?;
    let mut second = registry.attach("muc.localhost").map_err(|_| "second")?;
    registry
        .reply(
            "muc.localhost",
            first.id(),
            message(0, 0, ComponentBalancing::Source)?,
        )
        .map_err(|_| "first queue")?;
    registry
        .reply(
            "muc.localhost",
            second.id(),
            message(0, 1, ComponentBalancing::Source)?,
        )
        .map_err(|_| "second queue")?;
    let before = registry.inner.snapshot();
    assert_eq!(before.stanzas, 2);
    first.receiver.as_ref().ok_or("receiver")?.close();
    assert_eq!(
        registry.reply(
            "muc.localhost",
            first.id(),
            message(0, 2, ComponentBalancing::Source)?
        ),
        Err(EnqueueError::NotConnected)
    );
    assert_eq!(registry.inner.snapshot().stanzas, before.stanzas);
    assert_eq!(registry.inner.snapshot().bytes, before.bytes);
    sample(
        &registry,
        "lonewolf_component_admission_rejections_total{reason=\"not_connected\"} 1",
    )?;
    drop(first);
    assert_eq!(id(&second.try_next().ok_or("second queue")?)?, "0:1");
    assert!(second.try_next().is_none());
    registry
        .reply(
            "muc.localhost",
            second.id(),
            message(0, 3, ComponentBalancing::Source)?,
        )
        .map_err(|_| "second queue")?;
    registry.stop();
    drop(second);
    sample(
        &registry,
        "lonewolf_component_dropped_stanzas_total{reason=\"shutdown\"} 1",
    )?;
    sample(&registry, "lonewolf_component_queued_stanzas 0")?;
    sample(&registry, "lonewolf_component_queued_bytes 0")?;
    Ok(())
}

#[test]
fn a_full_selected_queue_never_spills_to_an_empty_connection() -> TestResult {
    let registry = registry(ComponentBalancing::Source, 2, 1, 4096)?;
    let mut links = [
        registry.attach("muc.localhost").map_err(|_| "first")?,
        registry.attach("muc.localhost").map_err(|_| "second")?,
    ];
    registry
        .enqueue("muc.localhost", message(0, 0, ComponentBalancing::Source)?)
        .map_err(|_| "enqueue")?;
    let owner = links
        .iter()
        .position(|link| link.counters.stanzas.load(Ordering::Relaxed) == 1)
        .ok_or("owner")?;
    assert_eq!(
        registry.enqueue("muc.localhost", message(0, 1, ComponentBalancing::Source)?),
        Err(EnqueueError::Busy)
    );
    assert!(links[1 - owner].try_next().is_none());
    assert_eq!(
        id(&links[owner].try_next().ok_or("original stanza")?)?,
        "0:0"
    );
    sample(
        &registry,
        "lonewolf_component_admission_rejections_total{reason=\"queue_full\"} 1",
    )?;
    Ok(())
}

#[test]
fn detaching_moves_fifo_and_transfers_the_full_queue_reservation() -> TestResult {
    let registry = registry(ComponentBalancing::Source, 2, 4, 4096)?;
    let first = registry.attach("muc.localhost").map_err(|_| "first")?;
    let mut second = registry.attach("muc.localhost").map_err(|_| "second")?;
    let counters = Arc::clone(&first.counters);
    let source = message(0, 0, ComponentBalancing::Source)?;
    let mut xml = String::new();
    source.resolve()?.write_xml(&mut xml)?;
    registry
        .reply("muc.localhost", first.id(), source)
        .map_err(|_| "first stanza")?;
    registry
        .reply(
            "muc.localhost",
            first.id(),
            message(0, 1, ComponentBalancing::Source)?,
        )
        .map_err(|_| "second stanza")?;
    let detached = first.detach();
    assert_eq!(detached.moved, 2);
    assert!(detached.stranded.is_empty());
    assert_eq!(counters.stanzas.load(Ordering::Relaxed), 0);
    assert_eq!(counters.bytes.load(Ordering::Relaxed), 0);
    sample(&registry, "lonewolf_component_moved_stanzas_total 2")?;
    sample(&registry, "lonewolf_component_queued_stanzas 2")?;
    sample(
        &registry,
        &format!("lonewolf_component_queued_bytes {}", xml.len() * 2),
    )?;
    assert_eq!(id(&second.try_next().ok_or("first moved stanza")?)?, "0:0");
    assert_eq!(id(&second.try_next().ok_or("second moved stanza")?)?, "0:1");
    sample(&registry, "lonewolf_component_queued_stanzas 0")?;
    sample(&registry, "lonewolf_component_queued_bytes 0")?;
    Ok(())
}

#[test]
fn closed_full_queues_report_not_connected_and_release_failed_reservations() -> TestResult {
    let registry = registry(ComponentBalancing::Source, 1, 1, 65536)?;
    let mut link = registry.attach("muc.localhost").map_err(|_| "attach")?;
    registry
        .enqueue("muc.localhost", message(0, 0, ComponentBalancing::Source)?)
        .map_err(|_| "fill")?;
    let before = registry.inner.snapshot();
    link.receiver.as_ref().ok_or("receiver")?.close();
    assert_eq!(
        registry.reply(
            "muc.localhost",
            link.id(),
            message(0, 1, ComponentBalancing::Source)?
        ),
        Err(EnqueueError::NotConnected)
    );
    assert_eq!(registry.inner.snapshot().stanzas, before.stanzas);
    assert_eq!(registry.inner.snapshot().bytes, before.bytes);
    sample(
        &registry,
        "lonewolf_component_admission_rejections_total{reason=\"not_connected\"} 1",
    )?;
    assert!(!render(&registry)?.contains("reason=\"queue_full\""));
    assert_eq!(id(&link.try_next().ok_or("retained stanza")?)?, "0:0");
    assert_eq!(registry.inner.snapshot().stanzas, 0);
    assert_eq!(registry.inner.snapshot().bytes, 0);
    Ok(())
}
