// SPDX-License-Identifier: Apache-2.0

use super::measurement::{self, Monitor};
use super::setup::CapacityClient as Client;
use super::{C2sSuite, TestResult};
use serde_json::{Value, json};
use socket2::SockRef;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

fn clients(server: &C2sSuite) -> TestResult<Vec<Client>> {
    let mut clients = Vec::with_capacity(64);
    for index in 0..64 {
        let name = format!("c{index:02}");
        server.account(&name)?;
        clients.push(Client::connect(server, &name, "capacity-password", "r")?);
    }
    Ok(clients)
}

fn message(recipient: &str, id: usize, bytes: usize) -> String {
    let mut xml = format!("<message to='{recipient}' type='chat' id='m{id}'><body>");
    let suffix = "</body></message>";
    assert!(xml.len() + suffix.len() < bytes);
    xml.extend(std::iter::repeat_n('x', bytes - xml.len() - suffix.len()));
    xml.push_str(suffix);
    assert_eq!(xml.len(), bytes);
    xml
}

fn barrier(client: &mut Client, id: usize) -> TestResult<usize> {
    client.send(&format!(
        "<iq type='get' id='b{id}'><query xmlns='jabber:iq:roster'/></iq>"
    ))?;
    receive_barrier(client, id)
}

fn receive_barrier(client: &mut Client, id: usize) -> TestResult<usize> {
    let wanted = format!("b{id}");
    let mut errors = 0;
    loop {
        let reply = client.receive()?;
        if reply.name == "iq" && reply.attribute("id") == Some(wanted.as_str()) {
            assert_eq!(reply.attribute("type"), Some("result"), "{reply:?}");
            return Ok(errors);
        }
        assert_eq!(
            reply.attribute("type"),
            Some("error"),
            "unexpected sender reply: {reply:?}"
        );
        errors += 1;
    }
}

fn pair_work(
    mut sender: Client,
    mut receiver: Client,
    recipient: usize,
    count: usize,
    bytes: usize,
) -> TestResult<(Client, Client, Vec<u64>, u64)> {
    let before_bytes = receiver.received_xml_bytes();
    let mut latencies = Vec::with_capacity(count);
    for first in (0..count).step_by(8) {
        let mut times = Vec::with_capacity(8);
        for id in first..count.min(first + 8) {
            let xml = message(&format!("c{recipient:02}@localhost/r"), id, bytes);
            times.push(Instant::now());
            sender.send(&xml)?;
        }
        for (offset, time) in times.into_iter().enumerate() {
            let reply = receiver.receive()?;
            reply.assert_name("jabber:client", "message");
            assert_ne!(reply.attribute("type"), Some("error"));
            assert_eq!(
                reply.attribute("id"),
                Some(format!("m{}", first + offset).as_str())
            );
            latencies.push(time.elapsed().as_micros().try_into()?);
        }
    }
    assert_eq!(barrier(&mut sender, count)?, 0);
    let bytes = receiver.received_xml_bytes() - before_bytes;
    Ok((sender, receiver, latencies, bytes))
}

fn pairs(
    clients: Vec<Client>,
    count: usize,
    bytes: usize,
) -> TestResult<(Vec<Client>, Vec<u64>, u64)> {
    thread::scope(|scope| {
        let mut handles = Vec::new();
        let mut resources = clients.into_iter();
        for pair in 0..32 {
            let sender = resources.next().ok_or("missing sender")?;
            let receiver = resources.next().ok_or("missing receiver")?;
            handles.push(scope.spawn(move || {
                pair_work(sender, receiver, pair * 2 + 1, count, bytes)
                    .map_err(|error| error.to_string())
            }));
        }
        let mut clients = Vec::with_capacity(64);
        let mut latencies = Vec::with_capacity(count * 32);
        let mut received_bytes = 0;
        for handle in handles {
            let (sender, receiver, samples, bytes) = handle
                .join()
                .map_err(|_| "workload thread panicked")?
                .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
            clients.push(sender);
            clients.push(receiver);
            latencies.extend(samples);
            received_bytes += bytes;
        }
        Ok((clients, latencies, received_bytes))
    })
}

pub fn run(name: &str, server: &C2sSuite, multiplier: usize, poll: bool) -> TestResult<Value> {
    match name {
        "cold_idle" => {
            let cold = measurement::idle(server.pid());
            let cold_diagnostics = server.diagnostics()?;
            let clients = clients(server)?;
            let bound = measurement::idle(server.pid());
            let value = json!({"cold_samples":cold,"bound_samples":bound,"bound_resources":clients.len(),
                "cold_diagnostics":cold_diagnostics,"bound_diagnostics":server.diagnostics()?});
            drop(clients);
            Ok(value)
        }
        "post_large_idle" => {
            let mut clients = clients(server)?;
            let before = measurement::idle(server.pid());
            let monitor = Monitor::start(server.pid());
            let mut received_bytes = 0;
            for index in 0..64 {
                let target = if index % 2 == 0 { index + 1 } else { index - 1 };
                clients[index].send(&message(
                    &format!("c{target:02}@localhost/r"),
                    index,
                    32768,
                ))?;
                let start_bytes = clients[target].received_xml_bytes();
                let reply = clients[target].receive()?;
                received_bytes += clients[target].received_xml_bytes() - start_bytes;
                reply.assert_name("jabber:client", "message");
                assert_eq!(reply.attribute("id"), Some(format!("m{index}").as_str()));
            }
            let activity = monitor.finish();
            let after = measurement::idle(server.pid());
            Ok(
                json!({"before_samples":before,"after_samples":after,"activity":activity,
                "bound_resources":clients.len(),"generated_messages":64,"received_messages":64,"generated_client_xml_bytes":64*32768,"received_server_xml_bytes":received_bytes,
                "diagnostics":server.diagnostics()?}),
            )
        }
        "live_routing" => {
            let clients = clients(server)?;
            let (clients, _, _) = pairs(clients, 16, 1024)?;
            let before = server.diagnostics()?;
            let monitor = Monitor::start(server.pid());
            let stopped = Arc::new(AtomicBool::new(false));
            let stop = Arc::clone(&stopped);
            let poller = thread::scope(|scope| -> TestResult<Value> {
                let poller = poll.then(|| {
                    scope.spawn(move || {
                        let mut snapshots = Vec::new();
                        while !stop.load(Ordering::Relaxed) {
                            if let Ok(Some(snapshot)) = server.diagnostics() {
                                snapshots.push(snapshot);
                            }
                            thread::park_timeout(Duration::from_secs(1));
                        }
                        snapshots
                    })
                });
                let start = Instant::now();
                let result = pairs(clients, 128 * multiplier, 1024);
                let elapsed = start.elapsed();
                stopped.store(true, Ordering::Relaxed);
                let snapshots = poller
                    .map(|handle| {
                        handle.thread().unpark();
                        handle.join().unwrap_or_default()
                    })
                    .unwrap_or_default();
                let (clients, latencies, received_bytes) = result?;
                let activity = monitor.finish();
                let value = json!({"elapsed_us":elapsed.as_micros(),"delivered_messages":latencies.len(),"generated_client_xml_bytes":latencies.len()*1024,
                    "delivered_messages_per_second":latencies.len() as f64/elapsed.as_secs_f64(),"send_to_receive":measurement::latency(latencies),
                    "received_server_xml_bytes":received_bytes,"activity":activity,"active_resources":clients.len(),"before_diagnostics":before,"after_diagnostics":server.diagnostics()?,"poll_snapshots":snapshots});
                Ok(value)
            })?;
            Ok(poller)
        }
        "storage_contention" => contention(server, multiplier),
        "reconnect_replay" => reconnect(server),
        "slow_reader" => slow_reader(server),
        _ => Err("unknown workload".into()),
    }
}

fn contention(server: &C2sSuite, multiplier: usize) -> TestResult<Value> {
    let mut clients = clients(server)?;
    for index in 0..32 {
        server.account(&format!("o{index:02}"))?;
    }
    let idle = clients.split_off(32);
    let before = server.diagnostics()?;
    let monitor = Monitor::start(server.pid());
    let start = Instant::now();
    let (senders, latencies) = thread::scope(|scope| -> TestResult<_> {
        let handles: Vec<_> = clients.into_iter().enumerate().map(|(index, mut sender)| scope.spawn(move || -> Result<_,String> {
            let mut latencies = Vec::new();
            for first in (0..16 * multiplier).step_by(8) {
                let mut times = Vec::new();
                for id in first..(16 * multiplier).min(first + 8) {
                    let time = Instant::now();
                    sender.send(&message(&format!("o{index:02}@localhost"),id,1024)).map_err(|error|error.to_string())?;
                    sender.send(&format!("<iq type='get' id='b{id}'><query xmlns='jabber:iq:roster'/></iq>")).map_err(|error|error.to_string())?;
                    times.push(time);
                }
                for (offset,time) in times.into_iter().enumerate() {
                    let errors = receive_barrier(&mut sender,first + offset).map_err(|error|error.to_string())?;
                    if errors != 0 {return Err("offline store returned an error".into());}
                    latencies.push(u64::try_from(time.elapsed().as_micros()).map_err(|error|error.to_string())?);
                }
            }
            Ok((sender, latencies))
        })).collect();
        let mut senders = Vec::new();
        let mut latencies = Vec::new();
        for handle in handles {
            let (sender, samples) = handle
                .join()
                .map_err(|_| "contention thread panicked")?
                .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
            senders.push(sender);
            latencies.extend(samples);
        }
        Ok((senders, latencies))
    })?;
    let elapsed = start.elapsed();
    let activity = monitor.finish();
    Ok(
        json!({"elapsed_us":elapsed.as_micros(),"completed_message_barrier_pairs":latencies.len(),
        "completed_pairs_per_second":latencies.len() as f64/elapsed.as_secs_f64(),"generated_client_xml_bytes":latencies.len()*1024,
        "message_to_barrier":measurement::latency(latencies),"active_resources":senders.len()+idle.len(),
        "before_diagnostics":before,"after_diagnostics":server.diagnostics()?,"activity":activity}),
    )
}

fn reconnect(server: &C2sSuite) -> TestResult<Value> {
    let mut clients = clients(server)?;
    for mut recipient in clients.drain(..8) {
        recipient.close()?;
    }
    for (index, sender) in clients.iter_mut().enumerate().take(8) {
        for id in 0..64 {
            sender.send(&message(&format!("c{index:02}@localhost"), id, 1024))?;
        }
        assert_eq!(barrier(sender, 64)?, 0);
    }
    let before = server.diagnostics()?;
    let monitor = Monitor::start(server.pid());
    let start = Instant::now();
    let (reconnected, reconnect_times, presence_times) = thread::scope(|scope| -> TestResult<_> {
        let handles: Vec<_> = (0..8)
            .map(|index| {
                scope.spawn(move || -> Result<_, String> {
                    let start = Instant::now();
                    let mut client =
                        Client::connect(server, &format!("c{index:02}"), "capacity-password", "r")
                            .map_err(|error| error.to_string())?;
                    let presence = Instant::now();
                    client
                        .send("<presence/>")
                        .map_err(|error| error.to_string())?;
                    let mut count = 0;
                    while count < 64 {
                        let reply = client.receive().map_err(|error| error.to_string())?;
                        if reply.name != "message" {
                            continue;
                        }
                        if reply.attribute("id") != Some(format!("m{count}").as_str()) {
                            return Err("replay order changed".into());
                        }
                        count += 1;
                    }
                    let last = Instant::now();
                    barrier(&mut client, 1000).map_err(|error| error.to_string())?;
                    Ok((
                        client,
                        u64::try_from(last.duration_since(start).as_micros())
                            .map_err(|error| error.to_string())?,
                        u64::try_from(last.duration_since(presence).as_micros())
                            .map_err(|error| error.to_string())?,
                    ))
                })
            })
            .collect();
        let mut resources = Vec::new();
        let mut reconnect_times = Vec::new();
        let mut presence_times = Vec::new();
        for handle in handles {
            let (client, reconnect, presence) = handle
                .join()
                .map_err(|_| "reconnect thread panicked")?
                .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
            resources.push(client);
            reconnect_times.push(reconnect);
            presence_times.push(presence);
        }
        Ok((resources, reconnect_times, presence_times))
    })?;
    server.wait_replay_acknowledgements(8)?;
    let elapsed = start.elapsed();
    let activity = monitor.finish();
    Ok(
        json!({"elapsed_us":elapsed.as_micros(),"replayed_messages":512,"generated_client_xml_bytes":512*1024,
        "replayed_messages_per_second":512.0/elapsed.as_secs_f64(),"reconnect_to_last_record_us":reconnect_times,"presence_to_last_record_us":presence_times,
        "sample_limit":"eight reconnects per repetition; no stable p99 estimate",
        "active_resources":clients.len()+reconnected.len(),"before_diagnostics":before,"after_diagnostics":server.diagnostics()?,"activity":activity,"final_memory":measurement::sample(server.pid(),0)}),
    )
}

fn slow_reader(server: &C2sSuite) -> TestResult<Value> {
    let mut clients = clients(server)?;
    let mut receiver = clients.remove(1);
    let mut sender = clients.remove(0);
    let original_buffer = SockRef::from(&receiver.transport().sock).recv_buffer_size()?;
    SockRef::from(&receiver.transport().sock).set_recv_buffer_size(4096)?;
    let effective = SockRef::from(&receiver.transport().sock).recv_buffer_size()?;
    let before = server.diagnostics()?;
    let monitor = Monitor::start(server.pid());
    let start = Instant::now();
    let (
        attempted,
        errors,
        delivered,
        retired,
        pressure,
        recovery,
        recovery_buffer,
        pressure_us,
        recovery_us,
    ) = thread::scope(|scope| -> TestResult<_> {
        let writer = scope.spawn(move || -> Result<_, String> {
            let mut attempted = 0;
            let mut errors = 0;
            for first in (0..512).step_by(8) {
                for id in first..first + 8 {
                    sender
                        .send(&message("c01@localhost/r", id, 32768))
                        .map_err(|error| error.to_string())?;
                    attempted += 1;
                }
                errors += barrier(&mut sender, first).map_err(|error| error.to_string())?;
            }
            Ok((sender, attempted, errors))
        });
        thread::sleep(Duration::from_secs(5));
        let pressure_us = start.elapsed().as_micros();
        let pressure = monitor.finish();
        SockRef::from(&receiver.transport().sock).set_recv_buffer_size(original_buffer / 2)?;
        let recovery_buffer = SockRef::from(&receiver.transport().sock).recv_buffer_size()?;
        let recovery_start = Instant::now();
        let recovery = Monitor::start(server.pid());
        let mut delivered = 0;
        let mut retired = false;
        if receiver
            .send("<iq type='get' id='finish'><query xmlns='jabber:iq:roster'/></iq>")
            .is_err()
        {
            retired = true;
        }
        while !retired {
            match receiver.receive() {
                Ok(reply)
                    if reply.name == "message" && reply.attribute("type") != Some("error") =>
                {
                    delivered += 1;
                }
                Ok(reply) if reply.name == "iq" && reply.attribute("id") == Some("finish") => {
                    break;
                }
                Ok(reply) if reply.namespace == xml_stream_namespace() => {
                    retired = true;
                    break;
                }
                Ok(_) => {}
                Err(error) => {
                    if error.to_string().contains("timed out")
                        || error.to_string().contains("temporarily unavailable")
                    {
                        return Err(error);
                    }
                    retired = true;
                    break;
                }
            }
        }
        let (mut sender, attempted, errors) = writer
            .join()
            .map_err(|_| "slow sender panicked")?
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
        let more_errors = barrier(&mut sender, 10000)?;
        if !retired {
            delivered += barrier_drain(&mut receiver, 10001)?;
        }
        Ok((
            attempted,
            errors + more_errors,
            delivered,
            retired,
            pressure,
            recovery.finish(),
            recovery_buffer,
            pressure_us,
            recovery_start.elapsed().as_micros(),
        ))
    })?;
    Ok(
        json!({"elapsed_us":start.elapsed().as_micros(),"attempted_messages":attempted,"delivered_messages":delivered,"sender_error_messages":errors,
        "receiver_retired":retired,"unread_seconds":5,"original_receive_buffer_bytes":original_buffer,"restore_receive_buffer_request_bytes":original_buffer / 2,"effective_recovery_receive_buffer_bytes":recovery_buffer,"pressure_elapsed_us":pressure_us,"recovery_elapsed_us":recovery_us,"requested_receive_buffer_bytes":4096,"effective_receive_buffer_bytes":effective,
        "generated_client_xml_bytes":attempted*32768,"setup_resources":clients.len()+2,
        "before_diagnostics":before,"after_diagnostics":server.diagnostics()?,"pressure_activity":pressure,"recovery_activity":recovery,"recovery_memory":measurement::sample(server.pid(),0)}),
    )
}

fn xml_stream_namespace() -> &'static str {
    "http://etherx.jabber.org/streams"
}

fn barrier_drain(client: &mut Client, id: usize) -> TestResult<usize> {
    client.send(&format!(
        "<iq type='get' id='b{id}'><query xmlns='jabber:iq:roster'/></iq>"
    ))?;
    let wanted = format!("b{id}");
    let mut delivered = 0;
    loop {
        let reply = client.receive()?;
        if reply.name == "iq" && reply.attribute("id") == Some(wanted.as_str()) {
            return Ok(delivered);
        }
        if reply.name == "message" && reply.attribute("type") != Some("error") {
            delivered += 1;
        }
    }
}
