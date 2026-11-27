// SPDX-License-Identifier: Apache-2.0

use std::time::Instant;

use crate::support::component::room::{
    CLIENT, CONFIG, DOMAIN, ROOM, SECRET, client, connect, numbered, ping, through_ping,
};
use crate::support::component::{ComponentClient, NAMESPACE, TEST_TIMEOUT as TIMEOUT, traffic};
use crate::support::xml::Element;
use crate::support::{C2sSuite, Client, PASSWORD, STREAM_ERRORS, TestResult, barrier};

const ALICE: &str = "alice@localhost/desk";
const BOB: &str = "bob@localhost/phone";

fn occupant(from: &str, to: &str, kind: &str, ns: &str) -> String {
    let attr = if kind.is_empty() {
        String::new()
    } else {
        format!(" type='{kind}'")
    };
    format!("<presence xmlns='{ns}'{attr} from='{from}' to='{to}'/>")
}

fn join(client: &mut Client, component: &mut ComponentClient, jid: &str, nick: &str) -> TestResult {
    let target = format!("{ROOM}/{nick}");
    client.send(&format!("<presence to='{target}'/>"))?;
    component.expect_xml(&occupant(jid, &target, "", NAMESPACE))
}

fn reflect_presence(
    component: &mut ComponentClient,
    client: &mut Client,
    source: &str,
    target: &str,
    kind: &str,
) -> TestResult {
    component.send(&occupant(source, target, kind, NAMESPACE))?;
    client.expect_xml(&occupant(source, target, kind, CLIENT))
}

fn groupchat(ns: &str, from: &str, to: &str, id: &str) -> String {
    format!(
        "<message xmlns='{ns}' type='groupchat' from='{from}' to='{to}' id='{id}'><body>room message</body></message>"
    )
}

#[test]
fn room_joins_echoes_leave_and_session_end_reach_both_occupants_and_the_component() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut room = connect(&suite)?;
    let mut alice = client(&suite, "alice", "desk")?;
    let mut bob = client(&suite, "bob", "phone")?;
    join(&mut alice, &mut room, ALICE, "a")?;
    reflect_presence(&mut room, &mut alice, &format!("{ROOM}/a"), ALICE, "")?;
    join(&mut bob, &mut room, BOB, "b")?;
    reflect_presence(&mut room, &mut bob, &format!("{ROOM}/a"), BOB, "")?;
    reflect_presence(&mut room, &mut alice, &format!("{ROOM}/b"), ALICE, "")?;
    reflect_presence(&mut room, &mut bob, &format!("{ROOM}/b"), BOB, "")?;
    alice.send(&groupchat(CLIENT, ALICE, ROOM, "hello"))?;
    room.expect_xml(&groupchat(NAMESPACE, ALICE, ROOM, "hello"))?;
    for (socket, jid) in [(&mut alice, ALICE), (&mut bob, BOB)] {
        room.send(&groupchat(NAMESPACE, &format!("{ROOM}/a"), jid, "hello"))?;
        socket.expect_xml(&groupchat(CLIENT, &format!("{ROOM}/a"), jid, "hello"))?;
    }
    bob.send(&format!("<presence type='unavailable' to='{ROOM}/b'/>"))?;
    room.expect_xml(&occupant(
        BOB,
        &format!("{ROOM}/b"),
        "unavailable",
        NAMESPACE,
    ))?;
    reflect_presence(
        &mut room,
        &mut alice,
        &format!("{ROOM}/b"),
        ALICE,
        "unavailable",
    )?;
    alice.close()?;
    room.expect_xml(&occupant(
        ALICE,
        &format!("{ROOM}/a"),
        "unavailable",
        NAMESPACE,
    ))?;
    traffic(&suite, "message", 2, 1)?;
    traffic(&suite, "presence", 5, 4)?;
    bob.close()?;
    room.close()?;
    suite.stop()
}

fn authenticate_attempt(room: &mut ComponentClient) -> TestResult<bool> {
    let header = room.open(DOMAIN, None)?;
    room.send_handshake_for(SECRET, &header.id)?;
    let response = room.receive()?;
    if response.name == "handshake" {
        response.assert_xml(&format!("<handshake xmlns='{NAMESPACE}'/>"))?;
        return Ok(true);
    }
    response.assert_xml("<stream:error xmlns:stream='http://etherx.jabber.org/streams'><conflict xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>")?;
    room.expect_footer()?;
    room.shutdown_write()?;
    room.expect_eof()?;
    Ok(false)
}

#[test]
fn disconnected_room_rejects_messages_until_a_fresh_stream_accepts_the_users_rejoin() -> TestResult
{
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut alice = client(&suite, "alice", "desk")?;
    let mut room = connect(&suite)?;
    join(&mut alice, &mut room, ALICE, "a")?;
    room.close()?;
    suite.wait_for_metric("lonewolf_component_streams 0")?;
    alice.send(&groupchat(CLIENT, ALICE, ROOM, "away"))?;
    alice.expect_xml(&format!("<message xmlns='{CLIENT}' type='error' from='{ROOM}' to='{ALICE}' id='away'><body>room message</body><error type='wait'><remote-server-timeout xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The service at this domain is not connected. Try again later.</text></error></message>"))?;
    let deadline = Instant::now() + TIMEOUT;
    let mut room = loop {
        if Instant::now() >= deadline {
            return Err("room reconnect timed out".into());
        }
        let mut room = ComponentClient::connect(suite.component_address(0)?)?;
        if authenticate_attempt(&mut room)? {
            assert!(
                Instant::now() < deadline,
                "room reconnect exceeded its deadline"
            );
            break room;
        }
    };
    join(&mut alice, &mut room, ALICE, "a")?;
    alice.send(&groupchat(CLIENT, ALICE, ROOM, "back"))?;
    room.expect_xml(&groupchat(NAMESPACE, ALICE, ROOM, "back"))?;
    room.send(&groupchat(NAMESPACE, &format!("{ROOM}/a"), ALICE, "back"))?;
    alice.expect_xml(&groupchat(CLIENT, &format!("{ROOM}/a"), ALICE, "back"))?;
    suite.wait_for_metric("lonewolf_component_authentications_total{outcome=\"success\"} 2")?;
    suite.wait_for_metric("lonewolf_component_streams_closed_total{outcome=\"stream_end\"} 1")?;
    suite.wait_for_metric(
        "lonewolf_component_admission_rejections_total{reason=\"not_connected\"} 1",
    )?;
    traffic(&suite, "message", 1, 1)?;
    alice.close()?;
    room.expect_xml(&occupant(
        ALICE,
        &format!("{ROOM}/a"),
        "unavailable",
        NAMESPACE,
    ))?;
    room.close()?;
    suite.wait_for_metric("lonewolf_component_streams_closed_total{outcome=\"stream_end\"} 2")?;
    suite.stop()
}

#[test]
fn an_accidental_second_instance_leaves_fifty_messages_on_the_original_stream_in_order()
-> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut first = connect(&suite)?;
    let mut second = ComponentClient::connect(suite.component_address(0)?)?;
    assert!(!authenticate_attempt(&mut second)?);
    let mut alice = client(&suite, "alice", "desk")?;
    for n in 0..50 {
        alice.send(&numbered(CLIENT, ALICE, ROOM, &format!("dup-{n}")))?;
    }
    barrier(&mut alice)?;
    for n in 0..50 {
        first.expect_xml(&numbered(NAMESPACE, ALICE, ROOM, &format!("dup-{n}")))?;
    }
    ping(&mut first, "last")?;
    assert!(through_ping(&mut first, "last")?.is_empty());
    traffic(&suite, "message", 0, 50)?;
    suite.wait_for_metric("lonewolf_component_authentications_total{outcome=\"conflict\"} 1")?;
    alice.close()?;
    first.close()?;
    suite.stop()
}

#[test]
fn two_local_components_exchange_an_iq_with_the_original_id_and_payload() -> TestResult {
    let mut suite = C2sSuite::with_components(&format!(
        "{CONFIG}\n[components.domains.'pubsub.localhost']\nsecret='{SECRET}'"
    ))?;
    let mut room = connect(&suite)?;
    let mut pubsub = ComponentClient::authenticated(&suite, "pubsub.localhost", SECRET)?;
    let request = format!(
        "<iq xmlns='{NAMESPACE}' type='get' from='{ROOM}' to='node@pubsub.localhost' id='cross'><query xmlns='urn:test:room'/></iq>"
    );
    room.send(&request)?;
    pubsub.expect_xml(&request)?;
    let reply = format!(
        "<iq xmlns='{NAMESPACE}' type='result' from='node@pubsub.localhost' to='{ROOM}' id='cross'><answer xmlns='urn:test:room'>published</answer></iq>"
    );
    pubsub.send(&reply)?;
    room.expect_xml(&reply)?;
    traffic(&suite, "iq", 2, 2)?;
    room.close()?;
    pubsub.close()?;
    suite.stop()
}

#[test]
fn twenty_rate_limited_room_messages_arrive_in_order_on_a_live_stream() -> TestResult {
    let mut suite = C2sSuite::with_components(&format!(
        "{CONFIG}\n[limits.components]\nincoming_stanzas_per_connection={{per_second=5,burst=5}}"
    ))?;
    let mut alice = client(&suite, "alice", "desk")?;
    let mut room = connect(&suite)?;
    let mut batch = String::new();
    for n in 0..20 {
        batch.push_str(&numbered(NAMESPACE, ROOM, ALICE, &format!("rate-{n}")));
    }
    room.send_raw(&batch)?;
    for n in 0..20 {
        alice.expect_xml(&numbered(CLIENT, ROOM, ALICE, &format!("rate-{n}")))?;
    }
    let sample =
        "lonewolf_component_rate_limited_total{limit=\"incoming_stanzas_per_connection\"} ";
    assert!(
        suite
            .scrape_metrics()?
            .lines()
            .find_map(|line| line.strip_prefix(sample))
            .ok_or("stanza rate limiter never delayed the batch")?
            .parse::<u64>()?
            > 0
    );
    ping(&mut room, "still-live")?;
    assert!(through_ping(&mut room, "still-live")?.is_empty());
    traffic(&suite, "message", 20, 0)?;
    room.close()?;
    alice.close()?;
    suite.stop()
}

#[test]
fn deleting_a_joined_account_withdraws_its_full_jid_from_the_room() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut room = connect(&suite)?;
    let mut alice = client(&suite, "alice", "desk")?;
    join(&mut alice, &mut room, ALICE, "a")?;
    suite.delete_account("alice")?;
    alice.expect_stream_error("not-authorized")?;
    room.expect_xml(&occupant(
        ALICE,
        &format!("{ROOM}/a"),
        "unavailable",
        NAMESPACE,
    ))?;
    traffic(&suite, "presence", 0, 2)?;
    ping(&mut room, "withdrawn")?;
    assert!(through_ping(&mut room, "withdrawn")?.is_empty());
    room.close()?;
    suite.stop()
}

#[test]
fn default_configuration_reports_no_component_listener_or_metrics() -> TestResult {
    let mut suite = C2sSuite::start()?;
    assert!(suite.component.is_none());
    assert!(!suite.scrape_metrics()?.contains("lonewolf_component_"));
    assert!(suite.stop_with_component_state()?.is_none());
    Ok(())
}

fn family_total(metrics: &str, family: &str) -> TestResult<u64> {
    let mut total = 0;
    for line in metrics.lines() {
        let Some(suffix) = line
            .strip_prefix("lonewolf_component_")
            .and_then(|name| name.strip_prefix(family))
        else {
            continue;
        };
        if suffix.starts_with(['{', ' ']) {
            let (_, value) = suffix.rsplit_once(' ').ok_or("missing counter value")?;
            total += value.parse::<u64>()?;
        }
    }
    Ok(total)
}

fn verify_recovery(before: &str, after: &str, moved: usize) -> TestResult {
    for (family, delta) in [
        ("moved_stanzas_total", moved as u64),
        ("bounces_total", 0),
        ("dropped_stanzas_total", 0),
        ("admission_rejections_total", 0),
    ] {
        assert_eq!(
            family_total(after, family)?,
            family_total(before, family)? + delta,
            "{family}"
        );
    }
    Ok(())
}

type Sockets = [Option<ComponentClient>; 3];
const SENDERS: [&str; 6] = [
    "u1@localhost/desk",
    "u2@localhost/desk",
    "u3@localhost/desk",
    "u4@localhost/desk",
    "u5@localhost/desk",
    "u6@localhost/desk",
];
const USERS: usize = SENDERS.len();
type Owners = [Option<usize>; USERS];

struct Phase {
    tag: &'static str,
    next: [usize; USERS],
    end: [usize; USERS],
}

impl Phase {
    fn admit(
        tag: &'static str,
        clients: &mut [Client],
        sequence: &mut [usize; USERS],
        counts: [usize; USERS],
    ) -> TestResult<Self> {
        let start = *sequence;
        for (i, socket) in clients.iter_mut().enumerate() {
            let from = SENDERS[i];
            for _ in 0..counts[i] {
                let id = format!("{tag}-u{}-{}", i + 1, sequence[i]);
                socket.send(&numbered(CLIENT, from, ROOM, &id))?;
                sequence[i] += 1;
            }
            barrier(socket)?;
        }
        Ok(Self {
            tag,
            next: start,
            end: *sequence,
        })
    }

    fn record(&mut self, stanza: &Element, socket: usize, owners: &mut Owners) -> TestResult {
        let i = SENDERS
            .iter()
            .position(|jid| stanza.attribute("from") == Some(*jid))
            .ok_or("unknown source")?;
        assert!(
            self.next[i] < self.end[i],
            "extra stanza for user {}",
            i + 1
        );
        let id = format!("{}-u{}-{}", self.tag, i + 1, self.next[i]);
        stanza.assert_xml(&numbered(NAMESPACE, SENDERS[i], ROOM, &id))?;
        assert_eq!(
            *owners[i].get_or_insert(socket),
            socket,
            "source changed owner"
        );
        self.next[i] += 1;
        Ok(())
    }

    fn finish(mut self, sockets: &mut Sockets, mut owners: Owners) -> TestResult<Owners> {
        for (i, slot) in sockets.iter_mut().enumerate() {
            if let Some(socket) = slot {
                let id = format!("fence-{}-{i}", self.tag);
                ping(socket, &id)?;
                for stanza in through_ping(socket, &id)? {
                    self.record(&stanza, i, &mut owners)?;
                }
            }
        }
        assert_eq!(self.next, self.end, "incomplete phase {}", self.tag);
        Ok(owners)
    }

    fn remove(
        mut self,
        suite: &C2sSuite,
        sockets: &mut Sockets,
        removed: usize,
        owners: Owners,
    ) -> TestResult<Owners> {
        let before = suite.scrape_metrics()?;
        let mut closing = sockets[removed].take().ok_or("missing closing socket")?;
        closing.send("</stream:stream>")?;
        let mut prefix_owners = owners;
        while let Some(stanza) = closing.receive_or_footer()? {
            self.record(&stanza, removed, &mut prefix_owners)?;
        }
        closing.shutdown_write()?;
        closing.expect_eof()?;
        suite.wait_for_metric("lonewolf_component_streams 2")?;
        let moved = (0..USERS)
            .filter(|&i| owners[i] == Some(removed))
            .map(|i| self.end[i] - self.next[i])
            .sum();
        let retained = owners.map(|owner| owner.filter(|i| *i != removed));
        let survivors = self.finish(sockets, retained)?;
        verify_recovery(&before, &suite.scrape_metrics()?, moved)?;
        Ok(survivors)
    }
}

fn verify_membership(suite: &C2sSuite, sockets: &mut Sockets, label: &str) -> TestResult {
    suite.wait_for_metric("lonewolf_component_streams 3")?;
    for (i, socket) in sockets.iter_mut().enumerate() {
        let socket = socket.as_mut().ok_or("missing attachment")?;
        let id = format!("member-{label}-{i}");
        ping(socket, &id)?;
        assert!(through_ping(socket, &id)?.is_empty());
    }
    Ok(())
}

#[test]
fn scaled_room_preserves_survivor_affinity_and_moves_each_admitted_fifo_tail_once() -> TestResult {
    let mut suite = C2sSuite::with_components(&format!("{CONFIG}\nmax_connections=3"))?;
    let mut sockets = [
        Some(connect(&suite)?),
        Some(connect(&suite)?),
        Some(connect(&suite)?),
    ];
    let mut clients: Vec<_> = (1..=USERS)
        .map(|n| client(&suite, &format!("u{n}"), "desk"))
        .collect::<TestResult<_>>()?;
    let mut sequence = [0; USERS];
    let empty = [None; USERS];
    let initial = suite.scrape_metrics()?;
    verify_membership(&suite, &mut sockets, "initial")?;
    let mut owners = Phase::admit("initial", &mut clients, &mut sequence, [20; USERS])?
        .finish(&mut sockets, empty)?;
    for (round, depart, reconnect) in [
        (0, "non-owner-close", "first-rejoin"),
        (1, "owner-close", "last-rejoin"),
    ] {
        let old_u1 = owners[0].ok_or("u1 owner")?;
        let removed = if round == 0 {
            (0..3).find(|i| *i != old_u1).ok_or("nonowner")?
        } else {
            old_u1
        };
        let phase = Phase::admit(depart, &mut clients, &mut sequence, [20; USERS])?;
        let mut survivors = phase.remove(&suite, &mut sockets, removed, owners)?;
        if round == 0 {
            assert_eq!(survivors[0], Some(old_u1));
        }
        let mut counts = survivors.map(|i| usize::from(i.is_none()));
        if round == 1 {
            counts[0] = 20;
        }
        let tag = if round == 0 {
            "survivor-map"
        } else {
            "u1-continuation"
        };
        survivors = Phase::admit(tag, &mut clients, &mut sequence, counts)?
            .finish(&mut sockets, survivors)?;
        assert!(survivors.iter().all(Option::is_some));
        if round == 1 {
            assert_ne!(survivors[0], Some(removed));
        }
        sockets[removed] = Some(connect(&suite)?);
        verify_membership(&suite, &mut sockets, reconnect)?;
        owners = Phase::admit(reconnect, &mut clients, &mut sequence, [20; USERS])?
            .finish(&mut sockets, empty)?;
        for (old, new) in survivors.iter().zip(owners) {
            assert!(
                new == *old || new == Some(removed),
                "survivor key switched to another previous survivor"
            );
        }
    }
    for socket in &mut clients {
        barrier(socket)?;
    }
    traffic(&suite, "message", 0, sequence.iter().sum::<usize>() as u64)?;
    let after = suite.scrape_metrics()?;
    for family in [
        "bounces_total",
        "dropped_stanzas_total",
        "admission_rejections_total",
    ] {
        assert_eq!(
            family_total(&initial, family)?,
            family_total(&after, family)?,
            "{family}"
        );
    }
    for socket in sockets.iter_mut().flatten() {
        socket.close()?;
    }
    for socket in &mut clients {
        socket.close()?;
    }
    suite.stop()
}

fn keyed_policy(policy: &str) -> TestResult {
    let mut suite = C2sSuite::with_components(&format!(
        "{CONFIG}\nmax_connections=2\nbalancing='{policy}'"
    ))?;
    let mut sockets = [connect(&suite)?, connect(&suite)?];
    let mut first = client(&suite, "alice", "desk")?;
    let (mut second, second_jid) = if policy == "bare_source" {
        (
            suite.connect("alice", PASSWORD, "phone")?,
            "alice@localhost/phone",
        )
    } else {
        (client(&suite, "bob", "phone")?, BOB)
    };
    let mut expected = Vec::new();
    for n in 0..20 {
        for (socket, from) in [(&mut first, ALICE), (&mut second, second_jid)] {
            let target = if policy == "bare_source" && from == ALICE {
                "other@muc.localhost/dest"
            } else {
                "room@muc.localhost/nick"
            };
            let id = format!("{policy}-{}-{n}", expected.len());
            socket.send(&numbered(CLIENT, from, target, &id))?;
            barrier(socket)?;
            expected.push(numbered(NAMESPACE, from, target, &id));
        }
    }
    let mut owners = 0;
    for (i, socket) in sockets.iter_mut().enumerate() {
        let id = format!("keyed-fence-{i}");
        ping(socket, &id)?;
        let stanzas = through_ping(socket, &id)?;
        if !stanzas.is_empty() {
            owners += 1;
            assert_eq!(stanzas.len(), expected.len());
            for (stanza, xml) in stanzas.iter().zip(&expected) {
                stanza.assert_xml(xml)?;
            }
        }
    }
    assert_eq!(owners, 1);
    traffic(&suite, "message", 0, 40)?;
    for socket in &mut sockets {
        socket.close()?;
    }
    first.close()?;
    second.close()?;
    suite.stop()
}

#[test]
fn bare_source_keeps_two_resources_of_one_sender_on_one_connection() -> TestResult {
    keyed_policy("bare_source")
}

#[test]
fn destination_keeps_multiple_senders_to_one_occupant_on_one_connection() -> TestResult {
    keyed_policy("destination")
}

#[test]
fn random_balancing_partitions_a_fixed_192_message_sample_across_three_connections() -> TestResult {
    let mut suite =
        C2sSuite::with_components(&format!("{CONFIG}\nmax_connections=3\nbalancing='random'"))?;
    let mut sockets = [connect(&suite)?, connect(&suite)?, connect(&suite)?];
    let mut alice = client(&suite, "alice", "desk")?;
    let before = suite.scrape_metrics()?;
    let mut counts = [0; 3];
    for window in 0..12 {
        let start = window * 16;
        let mut seen = [false; 16];
        for n in start..start + 16 {
            alice.send(&numbered(CLIENT, ALICE, ROOM, &n.to_string()))?;
        }
        barrier(&mut alice)?;
        for (i, socket) in sockets.iter_mut().enumerate() {
            let id = format!("random-{window}-{i}");
            ping(socket, &id)?;
            let mut previous = None;
            for stanza in through_ping(socket, &id)? {
                let id = stanza
                    .attribute("id")
                    .ok_or("unidentified random message")?;
                let n: usize = id.parse()?;
                assert!((start..start + 16).contains(&n));
                assert!(
                    previous.is_none_or(|p| p < n),
                    "socket reordered its subsequence"
                );
                previous = Some(n);
                assert!(
                    !std::mem::replace(&mut seen[n - start], true),
                    "duplicate {n}"
                );
                stanza.assert_xml(&numbered(NAMESPACE, ALICE, ROOM, id))?;
                counts[i] += 1;
            }
        }
        assert!(seen.into_iter().all(|received| received));
    }
    eprintln!("first fixed traffic sample (192 ordinary messages): {counts:?}");
    traffic(&suite, "message", 0, 192)?;
    verify_recovery(&before, &suite.scrape_metrics()?, 0)?;
    for socket in &mut sockets {
        socket.close()?;
    }
    alice.close()?;
    suite.stop()
}

#[test]
fn shutdown_of_busy_room_and_client_drains_whole_stanzas_before_the_terminal_footer() -> TestResult
{
    use std::sync::mpsc;
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut alice = client(&suite, "alice", "desk")?;
    let mut room = connect(&suite)?;
    let (ready, receipts) = mpsc::channel();
    let (go_client, resume_client) = mpsc::channel();
    let (go_room, resume_room) = mpsc::channel();
    std::thread::scope(|scope| -> TestResult {
        let client_ready = ready.clone();
        let client_worker=scope.spawn(move || -> Result<(),String> {
            let mut run=|| -> TestResult {
                alice.send(&numbered(CLIENT,ALICE,ROOM,"to-room-0"))?;
                alice.expect_xml(&numbered(CLIENT,ROOM,ALICE,"to-client-0"))?;
                client_ready.send("client")?;
                resume_client.recv_timeout(TIMEOUT)?;
                let mut batch=String::new();
                for n in 1..=16 {batch.push_str(&numbered(CLIENT,ALICE,ROOM,&format!("to-room-{n}")));}
                alice.send(&batch)?;
                let mut next=1;
                loop {
                    let stanza=alice.receive()?;
                    if stanza.namespace==crate::support::xml::STREAM_NAMESPACE {
                        stanza.assert_xml(&format!("<stream:error xmlns:stream='http://etherx.jabber.org/streams'><system-shutdown xmlns='{STREAM_ERRORS}'/></stream:error>"))?;
                        break;
                    }
                    if stanza.attribute("type")==Some("error") {
                        assert_eq!(stanza.attribute("from"),Some(ROOM));
                        assert_eq!(stanza.attribute("to"),Some(ALICE));
                        stanza.child(CLIENT,"error")?.child("urn:ietf:params:xml:ns:xmpp-stanzas","remote-server-timeout")?;
                    } else {
                        assert!(next<=16);
                        stanza.assert_xml(&numbered(CLIENT,ROOM,ALICE,&format!("to-client-{next}")))?;
                        next+=1;
                    }
                }
                alice.expect_end()
            };
            run().map_err(|error|error.to_string())
        });
        let room_worker=scope.spawn(move || -> Result<(),String> {
            let mut run=|| -> TestResult {
                room.send(&numbered(NAMESPACE,ROOM,ALICE,"to-client-0"))?;
                room.expect_xml(&numbered(NAMESPACE,ALICE,ROOM,"to-room-0"))?;
                ready.send("component")?;
                resume_room.recv_timeout(TIMEOUT)?;
                let mut batch=String::new();
                for n in 1..=16 {batch.push_str(&numbered(NAMESPACE,ROOM,ALICE,&format!("to-client-{n}")));}
                room.send(&batch)?;
                let mut next=1;
                loop {
                    let stanza=room.receive()?;
                    if stanza.namespace==crate::support::xml::STREAM_NAMESPACE {
                        stanza.assert_xml(&format!("<stream:error xmlns:stream='http://etherx.jabber.org/streams'><system-shutdown xmlns='{STREAM_ERRORS}'/></stream:error>"))?;
                        break;
                    }
                    assert!(next<=16);
                    stanza.assert_xml(&numbered(NAMESPACE,ALICE,ROOM,&format!("to-room-{next}")))?;
                    next+=1;
                }
                room.expect_footer()?;
                room.send("</stream:stream>")?;
                room.shutdown_write()?;
                room.expect_eof()
            };
            run().map_err(|error|error.to_string())
        });
        let a = receipts.recv_timeout(TIMEOUT)?;
        let b = receipts.recv_timeout(TIMEOUT)?;
        assert_ne!(a, b);
        traffic(&suite, "message", 1, 1)?;
        go_client.send(())?;
        go_room.send(())?;
        let state = suite
            .stop_with_component_state()?
            .ok_or("missing component shutdown receipt")?;
        for worker in [client_worker, room_worker] {
            worker
                .join()
                .map_err(|_| "shutdown peer panicked")?
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        }
        assert_eq!(state.connections, 0);
        assert_eq!(state.streams, 0);
        assert_eq!(state.streams_closed_shutdown, 1);
        assert_eq!(state.streams_closed_total, 1);
        Ok(())
    })
}
