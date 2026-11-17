// SPDX-License-Identifier: Apache-2.0

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use crate::support::component::{ComponentClient, NAMESPACE};
use crate::support::xml::Element;
use crate::support::{C2sSuite, Client, PASSWORD, STREAM_ERRORS, TestResult, barrier};

const DOMAIN: &str = "muc.localhost";
const SECRET: &str = "component-test-secret-0001";
const TARGET: &str = "room@muc.localhost/member";
const ERRORS: &str = "urn:ietf:params:xml:ns:xmpp-stanzas";
const NOT_CONNECTED: &str = "The service at this domain is not connected. Try again later.";
const C2S_LIMITS: &str = "max_stanza_bytes=524288\nincoming_xml_per_connection={bytes_per_second=67108864,burst_bytes=67108864}\nincoming_stanzas_per_connection={per_second=2000,burst=2000}";
const CONFIG: &str = "[components.domains.'muc.localhost']\nsecret='component-test-secret-0001'\nmax_connections=2\n[components.domains.'pubsub.localhost']\nsecret='component-test-secret-0001'\n[limits.components]\nmax_queued_stanzas=4\nincoming_xml_per_connection={bytes_per_second=67108864,burst_bytes=67108864}\nincoming_stanzas_per_connection={per_second=2000,burst=2000}";
const QUEUE_FULL: &str = "lonewolf_component_admission_rejections_total{reason=\"queue_full\"}";

#[derive(Clone)]
struct Input {
    name: &'static str,
    kind: &'static str,
    id: String,
    from: String,
    payload: String,
}
impl Input {
    fn xml(&self, namespace: &str) -> String {
        let kind = if self.kind.is_empty() {
            String::new()
        } else {
            format!(" type='{}'", self.kind)
        };
        format!(
            "<{} xmlns='{namespace}'{kind} from='{}' to='{TARGET}' id='{}'>{}</{}>",
            self.name, self.from, self.id, self.payload, self.name
        )
    }
    fn bounceable(&self) -> bool {
        (self.name == "message" && self.kind != "error")
            || (self.name == "iq" && matches!(self.kind, "get" | "set"))
    }
    fn assert_bounce(&self, stanza: &Element, namespace: &str) -> TestResult {
        stanza.assert_xml(&format!("<{} xmlns='{namespace}' type='error' from='{TARGET}' to='{}' id='{}'>{}<error type='wait'><remote-server-timeout xmlns='{ERRORS}'/><text xmlns='{ERRORS}' xml:lang='en'>{NOT_CONNECTED}</text></error></{}>", self.name, self.from, self.id, self.payload, self.name))
    }
}
fn counter(metrics: &str, sample: &str) -> u64 {
    metrics
        .lines()
        .find_map(|line| {
            line.strip_prefix(sample)
                .and_then(|tail| tail.strip_prefix(' '))
                .and_then(|value| value.parse().ok())
        })
        .unwrap_or(0)
}
fn sample(suite: &C2sSuite, name: &str) -> TestResult<u64> {
    Ok(counter(&suite.scrape_metrics()?, name))
}
fn assert_recovery(suite: &C2sSuite, moved: usize, bounced: usize, dropped: usize) -> TestResult {
    let metrics = suite.scrape_metrics()?;
    for (name, expected) in [
        ("lonewolf_component_moved_stanzas_total", moved),
        ("lonewolf_component_bounces_total", bounced),
        (
            "lonewolf_component_dropped_stanzas_total{reason=\"not_bounceable\"}",
            dropped,
        ),
        (
            "lonewolf_component_dropped_stanzas_total{reason=\"shutdown\"}",
            0,
        ),
    ] {
        assert_eq!(counter(&metrics, name), expected as u64, "{name}");
    }
    Ok(())
}
fn suite() -> TestResult<C2sSuite> {
    C2sSuite::with_components_limits(CONFIG, C2S_LIMITS)
}

enum Sender<'a> {
    Client(&'a mut Client),
    Service(&'a mut ComponentClient),
}
impl Sender<'_> {
    fn send(&mut self, xml: &str) -> TestResult {
        match self {
            Self::Client(client) => client.send(xml),
            Self::Service(client) => client.send(xml),
        }
    }
    fn receive(&mut self) -> TestResult<Element> {
        match self {
            Self::Client(client) => client.receive(),
            Self::Service(client) => client.receive(),
        }
    }
    fn namespace(&self) -> &'static str {
        match self {
            Self::Client(_) => "jabber:client",
            Self::Service(_) => NAMESPACE,
        }
    }
    fn from(&self) -> &'static str {
        match self {
            Self::Client(_) => "alice@localhost/desk",
            Self::Service(_) => "sender@pubsub.localhost/source",
        }
    }
    fn ping(&mut self) -> TestResult {
        self.send(&format!("<iq type='get' from='{}' to='localhost' id='admission'><ping xmlns='urn:xmpp:ping'/></iq>", self.from()))
    }
    fn expect_ping(&self, stanza: &Element) -> TestResult {
        stanza.assert_xml(&format!(
            "<iq xmlns='{}' type='result' from='localhost' to='{}' id='admission'/>",
            self.namespace(),
            self.from()
        ))
    }
}
fn pressure(
    suite: &C2sSuite,
    sender: &mut Sender<'_>,
    mixed: bool,
    prefix: &str,
) -> TestResult<Vec<Input>> {
    let baseline = sample(suite, QUEUE_FULL)?;
    let body = "x".repeat(131_072);
    let mut accepted = Vec::new();
    for n in 0..256 {
        let (name, kind, payload) = match (mixed, n % 4) {
            (true, 0) => (
                "message",
                "error",
                format!(
                    "<body>{body}</body><error type='cancel'><service-unavailable xmlns='{ERRORS}'/></error>"
                ),
            ),
            (_, 1) => (
                "iq",
                "get",
                "<query xmlns='urn:test:loss'><item>preserve</item></query>".into(),
            ),
            (true, 3) => ("presence", "", "<status>directed</status>".into()),
            _ => ("message", "chat", format!("<body>{body}</body>")),
        };
        let input = Input {
            name,
            kind,
            payload,
            id: format!("{prefix}{n}"),
            from: sender.from().into(),
        };
        sender.send(&input.xml(sender.namespace()))?;
        sender.ping()?;
        let mut reply = sender.receive()?;
        let rejected_reply = reply.attribute("id") == Some(input.id.as_str());
        if rejected_reply {
            assert!(input.bounceable());
            assert_eq!(reply.attribute("type"), Some("error"));
            assert_eq!(reply.attribute("from"), Some(TARGET));
            assert_eq!(reply.attribute("to"), Some(sender.from()));
            reply
                .child(sender.namespace(), "error")?
                .child(ERRORS, "resource-constraint")?;
            reply = sender.receive()?;
        }
        sender.expect_ping(&reply)?;
        let rejected = sample(suite, QUEUE_FULL)? > baseline;
        assert_eq!(rejected_reply, rejected && input.bounceable());
        if rejected {
            assert!(accepted.len() >= 4);
            return Ok(accepted);
        }
        accepted.push(input);
    }
    Err("socket pressure did not reach the bounded queue".into())
}
fn written_prefix(component: &mut ComponentClient, accepted: &[Input]) -> TestResult<usize> {
    component.send("</stream:stream>")?;
    let mut count = 0;
    while let Some(stanza) = component.receive_or_footer()? {
        let expected = accepted.get(count).ok_or("unadmitted component output")?;
        stanza.assert_xml(&expected.xml(NAMESPACE))?;
        count += 1;
    }
    component.shutdown_write()?;
    component.expect_eof()?;
    Ok(count)
}
fn recover(sender: &mut Sender<'_>, tail: &[Input]) -> TestResult<usize> {
    let mut bounced = 0;
    for input in tail.iter().filter(|input| input.bounceable()) {
        input.assert_bounce(&sender.receive()?, sender.namespace())?;
        bounced += 1;
    }
    sender.ping()?;
    let reply = sender.receive()?;
    sender.expect_ping(&reply)?;
    Ok(bounced)
}

fn graceful(check_detached: bool) -> TestResult {
    let mut suite = suite()?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    let accepted = pressure(&suite, &mut Sender::Client(&mut alice), true, "mixed")?;
    let written = written_prefix(&mut component, &accepted)?;
    suite.wait_for_metric("lonewolf_component_connections 0")?;
    let tail = &accepted[written..];
    eprintln!(
        "graceful mixed: admitted={}, written={written}, tail={}",
        accepted.len(),
        tail.len()
    );
    let bounced = recover(&mut Sender::Client(&mut alice), tail)?;
    assert_recovery(&suite, 0, bounced, tail.len() - bounced)?;
    if check_detached {
        let before = sample(
            &suite,
            "lonewolf_component_admission_rejections_total{reason=\"not_connected\"}",
        )?;
        let next = Input {
            name: "iq",
            kind: "get",
            id: "after-disconnect".into(),
            from: "alice@localhost/desk".into(),
            payload: "<query xmlns='urn:test:loss'/>".into(),
        };
        alice.send(&next.xml("jabber:client"))?;
        next.assert_bounce(&alice.receive()?, "jabber:client")?;
        suite.wait_for_metric(&format!(
            "lonewolf_component_admission_rejections_total{{reason=\"not_connected\"}} {}",
            before + 1
        ))?;
        assert_recovery(&suite, 0, bounced, tail.len() - bounced)?;
    }
    alice.close()?;
    suite.stop()
}
#[test]
fn graceful_disconnect_accounts_for_the_observed_mixed_fifo_tail_once() -> TestResult {
    graceful(false)
}
#[test]
fn post_disconnect_iq_is_rejected_synchronously_after_detachment() -> TestResult {
    graceful(true)
}

#[test]
fn reset_recovers_a_nonempty_eligible_tail_without_bouncing_written_stanzas() -> TestResult {
    let mut suite = suite()?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    let accepted = pressure(&suite, &mut Sender::Client(&mut alice), true, "reset")?;
    component.reset()?;
    suite.wait_for_metric("lonewolf_component_connections 0")?;
    let metrics = suite.scrape_metrics()?;
    let written: usize = ["message", "iq", "presence"]
        .into_iter()
        .map(|kind| {
            counter(
                &metrics,
                &format!("lonewolf_component_stanzas_sent_total{{kind=\"{kind}\"}}"),
            ) as usize
        })
        .sum();
    let bounced = counter(&metrics, "lonewolf_component_bounces_total") as usize;
    let dropped = counter(
        &metrics,
        "lonewolf_component_dropped_stanzas_total{reason=\"not_bounceable\"}",
    ) as usize;
    assert!(bounced > 0, "reset must exercise recovery");
    let tail_len = bounced + dropped;
    assert!(written + tail_len <= accepted.len());
    assert!(
        accepted.len() - written - tail_len <= 1,
        "only the active write may be lost"
    );
    let tail = &accepted[accepted.len() - tail_len..];
    assert_eq!(recover(&mut Sender::Client(&mut alice), tail)?, bounced);
    assert_eq!(
        tail.iter().filter(|input| !input.bounceable()).count(),
        dropped
    );
    assert_recovery(&suite, 0, bounced, dropped)?;
    alice.close()?;
    suite.stop()
}

#[test]
fn stranded_service_sender_replies_return_to_its_component_with_original_addresses() -> TestResult {
    let mut suite = suite()?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    let mut pubsub = ComponentClient::authenticated(&suite, "pubsub.localhost", SECRET)?;
    let accepted = pressure(&suite, &mut Sender::Service(&mut pubsub), false, "service")?;
    let written = written_prefix(&mut component, &accepted)?;
    suite.wait_for_metric("lonewolf_component_streams 1")?;
    let tail = &accepted[written..];
    eprintln!(
        "graceful service: admitted={}, written={written}, tail={}",
        accepted.len(),
        tail.len()
    );
    assert_eq!(
        recover(&mut Sender::Service(&mut pubsub), tail)?,
        tail.len()
    );
    assert_recovery(&suite, 0, tail.len(), 0)?;
    pubsub.close()?;
    suite.stop()
}

fn ping(component: &mut ComponentClient, id: &str) -> TestResult {
    component.send(&format!("<iq type='get' from='muc.localhost' to='localhost' id='{id}'><ping xmlns='urn:xmpp:ping'/></iq>"))
}
fn through_ping(component: &mut ComponentClient, id: &str) -> TestResult<Vec<Element>> {
    let mut result = Vec::new();
    loop {
        let stanza = component.receive()?;
        if stanza.attribute("id") == Some(id) {
            stanza.assert_xml(&format!("<iq xmlns='{NAMESPACE}' type='result' from='localhost' to='muc.localhost' id='{id}'/>"))?;
            return Ok(result);
        }
        result.push(stanza);
    }
}
fn instances(
    suite: &C2sSuite,
    alice: &mut Client,
) -> TestResult<(ComponentClient, ComponentClient)> {
    let mut first = ComponentClient::authenticated(suite, DOMAIN, SECRET)?;
    let mut second = ComponentClient::authenticated(suite, DOMAIN, SECRET)?;
    alice.send(&format!(
        "<message type='chat' to='{TARGET}' id='owner'><body>owner</body></message>"
    ))?;
    barrier(alice)?;
    ping(&mut first, "first")?;
    ping(&mut second, "second")?;
    let a = through_ping(&mut first, "first")?;
    let b = through_ping(&mut second, "second")?;
    assert_eq!(a.len() + b.len(), 1);
    let marker = a.first().or_else(|| b.first()).ok_or("marker missing")?;
    assert_eq!(marker.attribute("id"), Some("owner"));
    Ok(if a.is_empty() {
        (second, first)
    } else {
        (first, second)
    })
}
#[test]
fn graceful_failover_preserves_the_unwritten_tail_and_routes_new_traffic_to_the_survivor()
-> TestResult {
    let mut suite = suite()?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let (mut selected, mut survivor) = instances(&suite, &mut alice)?;
    let accepted = pressure(&suite, &mut Sender::Client(&mut alice), false, "failover")?;
    let written = written_prefix(&mut selected, &accepted)?;
    suite.wait_for_metric("lonewolf_component_streams 1")?;
    let tail = &accepted[written..];
    eprintln!(
        "graceful failover: admitted={}, written={written}, tail={}",
        accepted.len(),
        tail.len()
    );
    for input in tail {
        survivor.expect_xml(&input.xml(NAMESPACE))?;
    }
    barrier(&mut alice)?;
    assert_recovery(&suite, tail.len(), 0, 0)?;
    alice.send(&format!(
        "<message type='chat' to='{TARGET}' id='after-failover'><body>next</body></message>"
    ))?;
    survivor.expect_xml(&format!("<message xmlns='{NAMESPACE}' type='chat' from='alice@localhost/desk' to='{TARGET}' id='after-failover'><body>next</body></message>"))?;
    ping(&mut survivor, "end")?;
    assert!(through_ping(&mut survivor, "end")?.is_empty());
    survivor.close()?;
    alice.close()?;
    suite.stop()
}

fn fill_reply_queue(
    suite: &C2sSuite,
    component: &mut ComponentClient,
    alice: &mut Client,
) -> TestResult<usize> {
    let rejected = sample(suite, QUEUE_FULL)?;
    let payload = "x".repeat(131_072);
    for n in 0..256 {
        component.send(&format!("<iq type='get' from='muc.localhost' to='localhost' id='target{n}'><query xmlns='urn:test:loss'>{payload}</query></iq>"))?;
        component.send("<message type='chat' from='muc.localhost' to='alice@localhost/desk' id='fill-ack'><body>processed</body></message>")?;
        alice.expect_xml("<message xmlns='jabber:client' type='chat' from='muc.localhost' to='alice@localhost/desk' id='fill-ack'><body>processed</body></message>")?;
        if sample(suite, QUEUE_FULL)? > rejected {
            return Ok(n as usize);
        }
    }
    Err("target reply queue did not fill".into())
}
#[test]
fn reset_with_a_pressured_survivor_bounces_tail_that_cannot_move() -> TestResult {
    let mut suite = suite()?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let (selected, mut survivor) = instances(&suite, &mut alice)?;
    let target_admitted = fill_reply_queue(&suite, &mut survivor, &mut alice)?;
    let accepted = pressure(&suite, &mut Sender::Client(&mut alice), false, "full")?;
    selected.reset()?;
    suite.wait_for_metric("lonewolf_component_streams 1")?;
    let metrics = suite.scrape_metrics()?;
    let bounced = counter(&metrics, "lonewolf_component_bounces_total") as usize;
    let moved = counter(&metrics, "lonewolf_component_moved_stanzas_total") as usize;
    assert!(bounced > 0, "the full target must strand eligible input");
    let tail = &accepted[accepted
        .len()
        .checked_sub(bounced + moved)
        .ok_or("invalid recovery count")?..];
    for n in 0..target_admitted {
        let reply = survivor.receive()?;
        assert_eq!(reply.attribute("id"), Some(format!("target{n}").as_str()));
        assert_eq!(reply.attribute("type"), Some("error"));
    }
    for input in &tail[..moved] {
        survivor.expect_xml(&input.xml(NAMESPACE))?;
    }
    assert_eq!(
        recover(&mut Sender::Client(&mut alice), &tail[moved..])?,
        bounced
    );
    assert_recovery(&suite, moved, bounced, 0)?;
    ping(&mut survivor, "end")?;
    assert!(through_ping(&mut survivor, "end")?.is_empty());
    survivor.close()?;
    suite.wait_for_metric("lonewolf_component_connections 0")?;
    let final_metrics = suite.scrape_metrics()?;
    let sent: usize = ["message", "iq", "presence"]
        .into_iter()
        .map(|kind| {
            counter(
                &final_metrics,
                &format!("lonewolf_component_stanzas_sent_total{{kind=\"{kind}\"}}"),
            ) as usize
        })
        .sum();
    let control_stanzas = ["owner", "first", "second", "end"].len();
    let written = sent
        .checked_sub(target_admitted + moved + control_stanzas)
        .ok_or("invalid sent count")?;
    let unresolved = accepted
        .len()
        .checked_sub(written + moved + bounced)
        .ok_or("replayed input")?;
    assert!(unresolved <= 1, "only A's active write may be lost");
    alice.close()?;
    suite.stop()
}

fn shutdown_drop_sample(address: SocketAddr) -> TestResult<Option<u64>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = (|| -> std::io::Result<String> {
            let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(10))?;
            socket.set_read_timeout(Some(Duration::from_secs(10)))?;
            socket.set_write_timeout(Some(Duration::from_secs(10)))?;
            socket.write_all(
                b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )?;
            let mut response = String::new();
            socket.read_to_string(&mut response)?;
            Ok(response)
        })();
        match response {
            Ok(response) if response.starts_with("HTTP/1.1 200 ") => {
                let value = counter(
                    &response,
                    "lonewolf_component_dropped_stanzas_total{reason=\"shutdown\"}",
                );
                if value > 0 {
                    return Ok(Some(value));
                }
            }
            Ok(response) if response.is_empty() => return Ok(None),
            Ok(response) => return Err(format!("unexpected metrics response: {response}").into()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::NotConnected
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            return Err("shutdown drop sample did not complete".into());
        }
    }
}
#[test]
fn server_shutdown_sends_no_bounces_before_client_shutdown_and_discards_queued_input() -> TestResult
{
    let mut suite = suite()?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    let accepted = pressure(&suite, &mut Sender::Client(&mut alice), true, "shutdown")?;
    let metrics_address = suite.metrics_address();
    std::thread::scope(|scope| -> TestResult {
        let component_peer = scope.spawn(move || -> Result<Option<u64>, String> {
            let read = || -> TestResult<Option<u64>> {
                let mut count = 0;
                loop {
                    let stanza = component.receive()?;
                    if stanza.name == "error"
                        && stanza.namespace == "http://etherx.jabber.org/streams"
                    {
                        stanza.child(STREAM_ERRORS, "system-shutdown")?;
                        break;
                    }
                    stanza
                        .assert_xml(&accepted.get(count).ok_or("extra output")?.xml(NAMESPACE))?;
                    count += 1;
                }
                component.expect_footer()?;
                component.send("</stream:stream>")?;
                component.shutdown_write()?;
                component.expect_eof()?;
                shutdown_drop_sample(metrics_address)
            };
            let mut read = read;
            read().map_err(|error| error.to_string())
        });
        let client_peer = scope.spawn(move || -> Result<(), String> {
            let read = || -> TestResult {
                alice.expect_xml("<stream:error xmlns:stream='http://etherx.jabber.org/streams'><system-shutdown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>")?;
                alice.expect_footer()?;
                alice.send("</stream:stream>")?;
                alice.expect_eof()
            };
            let mut read = read;
            read().map_err(|error| error.to_string())
        });
        let state = suite
            .stop_with_component_state()?
            .ok_or("shutdown receipt")?;
        let sample = component_peer
            .join()
            .map_err(|_| "component reader panicked")?
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
        client_peer
            .join()
            .map_err(|_| "client reader panicked")?
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
        eprintln!(
            "shutdown drop scrape={sample:?}; exact drop count is pinned by controlled session coverage"
        );
        assert_eq!(state.connections, 0);
        assert_eq!(state.streams, 0);
        assert_eq!(state.streams_closed_shutdown, 1);
        assert_eq!(state.streams_closed_total, 1);
        Ok(())
    })
}
