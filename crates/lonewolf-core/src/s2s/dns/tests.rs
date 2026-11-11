// SPDX-License-Identifier: Apache-2.0

use std::net::{TcpListener, UdpSocket as StdUdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use compio::runtime::Runtime;
use hickory_proto::rr::Record;
use hickory_proto::rr::rdata::{A, AAAA, CNAME, SRV};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Seen = Arc<Mutex<Vec<(String, RecordType)>>>;

struct Server {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<io::Result<()>>>,
    seen: Seen,
}

impl Server {
    fn start(
        mut respond: impl FnMut(&Message) -> Vec<Message> + Send + 'static,
    ) -> io::Result<Self> {
        Self::with_services(move |query| {
            if query.queries[0]
                .name()
                .to_ascii()
                .starts_with("_xmpps-server.")
            {
                vec![response(query, ResponseCode::NXDomain, vec![])]
            } else {
                respond(query)
            }
        })
    }

    fn with_services(
        mut respond: impl FnMut(&Message) -> Vec<Message> + Send + 'static,
    ) -> io::Result<Self> {
        let socket = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let address = socket.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let seen: Seen = Arc::default();
        let observed = seen.clone();
        let thread = thread::spawn(move || {
            let mut buffer = [0; 65535];
            loop {
                let (length, peer) = socket.recv_from(&mut buffer)?;
                if stopped.load(Ordering::Acquire) {
                    return Ok(());
                }
                let query = Message::from_vec(&buffer[..length]).map_err(io::Error::other)?;
                assert!(query.metadata.recursion_desired);
                assert_eq!(query.edns.as_ref().map(Edns::max_payload), Some(1232));
                observed
                    .lock()
                    .map_err(|_| io::Error::other("query lock poisoned"))?
                    .push((
                        query.queries[0].name().to_ascii(),
                        query.queries[0].query_type(),
                    ));
                for response in respond(&query) {
                    socket.send_to(&response.to_vec().map_err(io::Error::other)?, peer)?;
                }
            }
        });
        Ok(Self {
            address,
            stop,
            thread: Some(thread),
            seen,
        })
    }

    fn resolver(&self) -> io::Result<Resolver> {
        let mut config = crate::config::S2sConfig::default();
        config.dns.nameservers.push(self.address);
        Resolver::new(&config)
    }

    fn queries(&self) -> Vec<(String, RecordType)> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let wake = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        wake.send_to(&[], self.address).unwrap();
        self.thread.take().unwrap().join().unwrap().unwrap();
    }
}

fn response(query: &Message, code: ResponseCode, records: Vec<Record>) -> Message {
    let mut reply = Message::response(query.metadata.id, query.metadata.op_code);
    reply.queries.clone_from(&query.queries);
    reply.metadata.response_code = code;
    reply.answers = records;
    reply
}

fn record(name: &str, data: RData) -> Record {
    Record::from_rdata(Name::from_ascii(name).unwrap(), 0, data)
}

fn srv(query: &Message, target: &str, port: u16) -> Message {
    response(
        query,
        ResponseCode::NoError,
        vec![record(
            &query.queries[0].name().to_ascii(),
            RData::SRV(SRV::new(0, 0, port, Name::from_ascii(target).unwrap())),
        )],
    )
}

fn address(query: &Message) -> Message {
    let data = match query.queries[0].query_type() {
        RecordType::AAAA => RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
        RecordType::A => RData::A(A(Ipv4Addr::LOCALHOST)),
        _ => panic!("unexpected address query"),
    };
    response(
        query,
        ResponseCode::NoError,
        vec![record(&query.queries[0].name().to_ascii(), data)],
    )
}

fn resolve(resolver: &Resolver, domain: &str) -> Result<Resolved, ResolveError> {
    Runtime::new().unwrap().block_on(resolver.resolve(domain))
}

fn bind_dns_sockets() -> io::Result<(TcpListener, StdUdpSocket)> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        // TCP and UDP allocate ports independently, so both reservations must succeed.
        match StdUdpSocket::bind(listener.local_addr()?) {
            Ok(udp) => return Ok((listener, udp)),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse && Instant::now() < deadline => {
            }
            Err(error) => return Err(error),
        }
    }
}

fn starttls_endpoint(address: SocketAddr) -> Endpoint {
    Endpoint {
        address,
        tls_mode: TlsMode::StartTls,
    }
}

fn assert_endpoints(result: Resolved, via: ResolvedVia, port: u16) {
    assert_eq!(result.via, via);
    assert_eq!(
        result.endpoints,
        vec![
            starttls_endpoint(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port)),
            starttls_endpoint(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port))
        ]
    );
}

#[test]
fn priority_and_inclusive_weighted_order() {
    let targets = vec![
        (2, 0, "last"),
        (1, 5, "five"),
        (1, 0, "zero"),
        (1, 3, "three"),
    ];
    let records = targets
        .into_iter()
        .map(|(priority, weight, name)| {
            (
                priority,
                weight,
                SrvTarget {
                    name: name.into(),
                    port: 5269,
                    tls_mode: TlsMode::StartTls,
                },
            )
        })
        .collect();
    let mut choices = [(8, 0), (8, 8), (5, 5), (0, 0)].into_iter();
    let ordered = order_srv(records, &mut |total| {
        let (expected, value) = choices.next().unwrap();
        assert_eq!(total, expected);
        Ok(value)
    })
    .unwrap();
    assert_eq!(
        ordered.iter().map(|t| t.name.as_ref()).collect::<Vec<_>>(),
        ["zero", "three", "five", "last"]
    );
    assert!(choices.next().is_none());
}

#[test]
fn resolv_conf_comments_zones_limit_and_empty() {
    assert_eq!(
        parse_resolv_conf(
            "# nameserver 192.0.2.9\nnameserver fe80::1%eth0\nsearch example\nnameserver 192.0.2.1 # first\nnameserver ::1 ; local\nnameserver 192.0.2.2\nnameserver 192.0.2.3"
        ),
        vec![
            "192.0.2.1:53".parse().unwrap(),
            "[::1]:53".parse().unwrap(),
            "192.0.2.2:53".parse().unwrap()
        ]
    );
    assert_eq!(parse_resolv_conf(""), vec!["127.0.0.1:53".parse().unwrap()]);
}

#[test]
fn literals_and_static_routes_bypass_dns_and_deduplicate() -> TestResult {
    let server = Server::start(|_| panic!("DNS must be bypassed"))?;
    let mut resolver = server.resolver()?;
    resolver.routes.insert(
        "static.example".into(),
        vec![
            "127.0.0.2:5270".parse()?,
            "[::1]:5280".parse()?,
            "127.0.0.2:5270".parse()?,
        ],
    );
    let result = resolve(&resolver, "static.example").unwrap();
    assert_eq!(result.via, ResolvedVia::Static);
    assert_eq!(
        result.endpoints,
        vec![
            starttls_endpoint("127.0.0.2:5270".parse()?),
            starttls_endpoint("[::1]:5280".parse()?)
        ]
    );
    for (domain, endpoint) in [
        ("192.0.2.1", "192.0.2.1:5269"),
        ("[2001:db8::1]", "[2001:db8::1]:5269"),
    ] {
        let result = resolve(&resolver, domain).unwrap();
        assert_eq!(result.via, ResolvedVia::Literal);
        assert_eq!(result.endpoints, vec![starttls_endpoint(endpoint.parse()?)]);
    }
    assert!(server.queries().is_empty());
    assert_eq!(
        resolve(&resolver, "bad domain").unwrap_err(),
        ResolveError::InvalidDomain
    );
    Ok(())
}

#[test]
fn single_dot_disables_service_without_fallback() -> TestResult {
    let server = Server::start(|q| vec![srv(q, ".", 0)])?;
    assert_eq!(
        resolve(&server.resolver()?, "remote.example").unwrap_err(),
        ResolveError::NoService
    );
    assert_both_services(&server.queries());
    assert_eq!(server.queries().len(), 2);
    Ok(())
}

#[test]
fn nxdomain_nodata_servfail_refused_srv_fall_back() -> TestResult {
    for code in [
        ResponseCode::NXDomain,
        ResponseCode::NoError,
        ResponseCode::ServFail,
        ResponseCode::Refused,
    ] {
        let server = Server::start(move |q| {
            vec![if q.queries[0].query_type() == RecordType::SRV {
                response(q, code, vec![])
            } else {
                address(q)
            }]
        })?;
        assert_endpoints(
            resolve(&server.resolver()?, "remote.example").unwrap(),
            ResolvedVia::Fallback,
            5269,
        );
        assert_eq!(server.queries().len(), 4);
    }
    Ok(())
}

#[test]
fn failed_fallback_distinguishes_negative_from_unavailable() -> TestResult {
    for code in [
        ResponseCode::NXDomain,
        ResponseCode::NoError,
        ResponseCode::ServFail,
        ResponseCode::Refused,
    ] {
        let server = Server::start(move |q| vec![response(q, code, vec![])])?;
        let expected = if matches!(code, ResponseCode::NXDomain | ResponseCode::NoError) {
            ResolveError::NotFound
        } else {
            ResolveError::Unavailable
        };
        assert_eq!(
            resolve(&server.resolver()?, "remote.example").unwrap_err(),
            expected
        );
    }
    Ok(())
}

#[test]
fn srv_target_failure_never_falls_back() -> TestResult {
    let server = Server::start(|q| {
        vec![if q.queries[0].query_type() == RecordType::SRV {
            srv(q, "missing.example.", 5270)
        } else {
            response(q, ResponseCode::NXDomain, vec![])
        }]
    })?;
    assert_eq!(
        resolve(&server.resolver()?, "remote.example").unwrap_err(),
        ResolveError::NotFound
    );
    assert!(
        server
            .queries()
            .iter()
            .all(|(name, kind)| *kind == RecordType::SRV || name == "missing.example.")
    );
    Ok(())
}

#[test]
fn srv_ipv6_first_idna_and_cname_final_owner_only() -> TestResult {
    let server = Server::start(|q| {
        if q.queries[0].query_type() == RecordType::SRV {
            return vec![srv(q, "target.example.", 5270)];
        }
        let kind = q.queries[0].query_type();
        let data = if kind == RecordType::AAAA {
            RData::AAAA(AAAA(Ipv6Addr::LOCALHOST))
        } else {
            RData::A(A(Ipv4Addr::LOCALHOST))
        };
        vec![response(
            q,
            ResponseCode::NoError,
            vec![
                record("unrelated.example.", data.clone()),
                record(
                    "target.example.",
                    RData::CNAME(CNAME(Name::from_ascii("final.example.").unwrap())),
                ),
                record("final.example.", data),
            ],
        )]
    })?;
    assert_endpoints(
        resolve(&server.resolver()?, "bücher.example").unwrap(),
        ResolvedVia::Srv,
        5270,
    );
    let queries = server.queries();
    for service in [
        "_xmpp-server._tcp.xn--bcher-kva.example.",
        "_xmpps-server._tcp.xn--bcher-kva.example.",
    ] {
        assert!(
            queries
                .iter()
                .any(|(name, kind)| name == service && *kind == RecordType::SRV)
        );
    }
    Ok(())
}

#[test]
fn srv_and_static_endpoints_deduplicate_and_cap_at_sixteen() -> TestResult {
    let server = Server::start(|q| {
        if q.queries[0].query_type() == RecordType::SRV {
            return vec![srv(q, "target.example.", 5270)];
        }
        if q.queries[0].query_type() == RecordType::AAAA {
            return vec![response(q, ResponseCode::NoError, vec![])];
        }
        let mut records = Vec::new();
        for last in 1..=20 {
            let value = record(
                "target.example.",
                RData::A(A(Ipv4Addr::new(192, 0, 2, last))),
            );
            records.extend([value.clone(), value]);
        }
        vec![response(q, ResponseCode::NoError, records)]
    })?;
    let mut resolver = server.resolver()?;
    let result = resolve(&resolver, "remote.example").unwrap();
    assert_eq!(result.via, ResolvedVia::Srv);
    let expected: Vec<_> = (1..=16)
        .map(|last| starttls_endpoint(SocketAddr::from(([192, 0, 2, last], 5270))))
        .collect();
    assert_eq!(result.endpoints, expected);
    resolver.routes.insert(
        "static.example".into(),
        (1..=20)
            .map(|last| {
                crate::config::S2sRouteEndpoint::from(SocketAddr::from(([192, 0, 2, last], 5270)))
            })
            .collect(),
    );
    let result = resolve(&resolver, "static.example").unwrap();
    assert_eq!(result.endpoints, expected);
    assert_eq!(result.via, ResolvedVia::Static);
    Ok(())
}

#[test]
fn first_nameserver_timeout_uses_second() -> TestResult {
    let silent = Server::start(|_| vec![])?;
    let server = Server::start(|q| {
        vec![if q.queries[0].query_type() == RecordType::SRV {
            response(q, ResponseCode::NXDomain, vec![])
        } else {
            address(q)
        }]
    })?;
    let mut resolver = server.resolver()?;
    resolver.nameservers.insert(0, silent.address);
    resolver.timeout = Duration::from_secs(1);
    assert_endpoints(
        resolve(&resolver, "remote.example").unwrap(),
        ResolvedVia::Fallback,
        5269,
    );
    assert_eq!(silent.queries().len(), 4);
    Ok(())
}

#[test]
fn mismatched_id_qr_name_type_and_class_are_ignored() -> TestResult {
    let server = Server::start(|q| {
        let good = if q.queries[0].query_type() == RecordType::SRV {
            response(q, ResponseCode::NXDomain, vec![])
        } else {
            address(q)
        };
        let mut replies = Vec::new();
        let mut bad = good.clone();
        bad.metadata.id ^= 1;
        replies.push(bad);
        let mut bad = good.clone();
        bad.metadata.message_type = MessageType::Query;
        replies.push(bad);
        let mut bad = good.clone();
        bad.queries[0].set_name(Name::from_ascii("wrong.example.").unwrap());
        replies.push(bad);
        let mut bad = good.clone();
        bad.queries[0].set_query_type(RecordType::TXT);
        replies.push(bad);
        let mut bad = good.clone();
        bad.queries[0].set_query_class(DNSClass::CH);
        replies.push(bad);
        let mut good = good;
        let uppercase = Name::from_ascii(good.queries[0].name().to_ascii().to_uppercase()).unwrap();
        good.queries[0].set_name(uppercase);
        replies.push(good);
        replies
    })?;
    assert_endpoints(
        resolve(&server.resolver()?, "remote.example").unwrap(),
        ResolvedVia::Fallback,
        5269,
    );
    Ok(())
}

#[test]
fn truncated_udp_retries_same_nameserver_over_tcp() -> TestResult {
    let (listener, udp) = bind_dns_sockets()?;
    udp.set_read_timeout(Some(Duration::from_secs(2)))?;
    let address = udp.local_addr()?;
    let worker = thread::spawn(move || -> io::Result<()> {
        Runtime::new()?
            .block_on(compio::time::timeout(Duration::from_secs(2), async move {
                let udp = UdpSocket::from_std(udp)?;
                let listener = compio::net::TcpListener::from_std(listener)?;
                for _ in 0..2 {
                    let BufResult(received, bytes) = udp.recv_from(vec![0; 65535]).await;
                    let (length, peer) = received?;
                    let request = Message::from_vec(&bytes[..length]).map_err(io::Error::other)?;
                    let mut truncated = response(&request, ResponseCode::NoError, vec![]);
                    truncated.metadata.truncation = true;
                    udp.send_to(truncated.to_vec().map_err(io::Error::other)?, peer)
                        .await
                        .0?;
                    let (mut stream, _) = listener.accept().await?;
                    let BufResult(read, length) = stream.read_exact([0; 2]).await;
                    read?;
                    let length = usize::from(u16::from_be_bytes(length));
                    let BufResult(read, bytes) = stream.read_exact(bytes.slice(..length)).await;
                    read?;
                    let tcp = Message::from_vec(&bytes.into_inner()[..length])
                        .map_err(io::Error::other)?;
                    assert_eq!(tcp.metadata.id, request.metadata.id);
                    assert_eq!(tcp.queries, request.queries);
                    let reply = srv(&tcp, ".", 0).to_vec().map_err(io::Error::other)?;
                    stream
                        .write_all(
                            u16::try_from(reply.len())
                                .map_err(io::Error::other)?
                                .to_be_bytes(),
                        )
                        .await
                        .0?;
                    stream.write_all(reply).await.0?;
                }
                Ok(())
            }))
            .map_err(io::Error::other)?
    });
    let mut config = crate::config::S2sConfig::default();
    config.dns.nameservers.push(address);
    let result = resolve(&Resolver::new(&config)?, "remote.example");
    worker.join().unwrap()?;
    assert_eq!(result.unwrap_err(), ResolveError::NoService);
    Ok(())
}

#[test]
fn cname_hop_limit_loops_and_owner_class_are_bounded() {
    let name = Name::from_ascii("n0.example.").unwrap();
    for hops in [8, 9] {
        let mut reply = Message::response(1, OpCode::Query);
        for index in 0..hops {
            reply.answers.push(record(
                &format!("n{index}.example."),
                RData::CNAME(CNAME(
                    Name::from_ascii(format!("n{}.example.", index + 1)).unwrap(),
                )),
            ));
        }
        reply.answers.push(record(
            &format!("n{hops}.example."),
            RData::A(A(Ipv4Addr::LOCALHOST)),
        ));
        let result = answer_records(reply, &name, RecordType::A);
        if hops == 8 {
            assert_eq!(
                result.unwrap().records,
                vec![RData::A(A(Ipv4Addr::LOCALHOST))]
            );
        } else {
            assert!(matches!(result, Err(QueryError::Unavailable)));
        }
    }
    let mut reply = Message::response(1, OpCode::Query);
    reply
        .answers
        .push(record("n0.example.", RData::CNAME(CNAME(name.clone()))));
    assert!(matches!(
        answer_records(reply, &name, RecordType::A),
        Err(QueryError::Unavailable)
    ));
}

#[test]
fn service_and_address_queries_are_concurrent() -> TestResult {
    let socket = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    let address = socket.local_addr()?;
    let worker = thread::spawn(move || -> io::Result<()> {
        let mut buffer = [0; 65535];
        let mut services = Vec::new();
        for _ in 0..2 {
            let (length, peer) = socket.recv_from(&mut buffer)?;
            let query = Message::from_vec(&buffer[..length]).map_err(io::Error::other)?;
            assert_eq!(query.queries[0].query_type(), RecordType::SRV);
            services.push((query, peer));
        }
        let mut names: Vec<_> = services
            .iter()
            .map(|(query, _)| query.queries[0].name().to_ascii())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "_xmpp-server._tcp.remote.example.",
                "_xmpps-server._tcp.remote.example."
            ]
        );
        for (query, peer) in services.into_iter().rev() {
            socket.send_to(
                &response(&query, ResponseCode::NoError, vec![])
                    .to_vec()
                    .map_err(io::Error::other)?,
                peer,
            )?;
        }
        let mut waiting = Vec::with_capacity(2);
        for _ in 0..2 {
            let (length, peer) = socket.recv_from(&mut buffer)?;
            waiting.push((
                Message::from_vec(&buffer[..length]).map_err(io::Error::other)?,
                peer,
            ));
        }
        let mut kinds: Vec<_> = waiting
            .iter()
            .map(|(query, _)| query.queries[0].query_type())
            .collect();
        kinds.sort();
        assert_eq!(kinds, vec![RecordType::A, RecordType::AAAA]);
        for (query, peer) in waiting {
            socket.send_to(
                &super::tests::address(&query)
                    .to_vec()
                    .map_err(io::Error::other)?,
                peer,
            )?;
        }
        Ok(())
    });
    let mut config = crate::config::S2sConfig::default();
    config.dns.nameservers.push(address);
    let result = resolve(&Resolver::new(&config)?, "remote.example");
    worker.join().unwrap()?;
    assert_endpoints(result.unwrap(), ResolvedVia::Fallback, 5269);
    Ok(())
}

#[test]
fn mismatch_bound_moves_to_next_nameserver() -> TestResult {
    let wrong = Server::start(|q| {
        let mut bad = response(q, ResponseCode::NoError, vec![]);
        bad.metadata.id ^= 1;
        vec![bad; 17]
    })?;
    let server = Server::start(|q| vec![srv(q, ".", 0)])?;
    let mut resolver = server.resolver()?;
    resolver.nameservers.insert(0, wrong.address);
    assert_eq!(
        resolve(&resolver, "remote.example").unwrap_err(),
        ResolveError::NoService
    );
    assert_eq!(wrong.queries().len(), 2);
    assert_eq!(server.queries().len(), 1);
    Ok(())
}

#[test]
fn malformed_datagram_moves_to_next_nameserver() -> TestResult {
    let socket = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    let address = socket.local_addr()?;
    let worker = thread::spawn(move || -> io::Result<()> {
        let mut buffer = [0; 1232];
        let (_, peer) = socket.recv_from(&mut buffer)?;
        socket.send_to(&[0], peer)?;
        Ok(())
    });
    let server = Server::start(|q| vec![srv(q, ".", 0)])?;
    let mut resolver = server.resolver()?;
    resolver.nameservers.insert(0, address);
    let result = resolve(&resolver, "remote.example");
    worker.join().unwrap()?;
    assert_eq!(result.unwrap_err(), ResolveError::NoService);
    Ok(())
}

#[test]
fn tcp_partial_frame_is_bounded_by_whole_attempt_deadline() -> TestResult {
    let (listener, udp) = bind_dns_sockets()?;
    let address = udp.local_addr()?;
    let (release, wait) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || -> io::Result<()> {
        Runtime::new()?
            .block_on(compio::time::timeout(Duration::from_secs(2), async move {
                let udp = UdpSocket::from_std(udp)?;
                let listener = compio::net::TcpListener::from_std(listener)?;
                let BufResult(received, bytes) = udp.recv_from(vec![0; 1232]).await;
                let (length, peer) = received?;
                let query = Message::from_vec(&bytes[..length]).map_err(io::Error::other)?;
                let mut reply = response(&query, ResponseCode::NoError, vec![]);
                reply.metadata.truncation = true;
                udp.send_to(reply.to_vec().map_err(io::Error::other)?, peer)
                    .await
                    .0?;
                let (mut stream, _) = listener.accept().await?;
                let BufResult(read, length) = stream.read_exact([0; 2]).await;
                read?;
                let length = usize::from(u16::from_be_bytes(length));
                stream.read_exact(vec![0; length]).await.0?;
                stream.write_all([0, 20, 0]).await.0?;
                wait.recv_timeout(Duration::from_secs(2))
                    .map_err(io::Error::other)?;
                Ok(())
            }))
            .map_err(io::Error::other)?
    });
    let mut config = crate::config::S2sConfig::default();
    config.dns.nameservers.push(address);
    let mut resolver = Resolver::new(&config)?;
    resolver.timeout = Duration::from_secs(1);
    let result = Runtime::new()?
        .block_on(resolver.query(&Name::from_ascii("remote.example.")?, RecordType::A));
    release.send(())?;
    worker.join().unwrap()?;
    assert!(matches!(result, Err(QueryError::Unavailable)));
    Ok(())
}

#[test]
fn unrelated_and_wrong_class_answers_are_excluded() {
    let name = Name::from_ascii("remote.example.").unwrap();
    let mut reply = Message::response(0, OpCode::Query);
    let mut wrong_class = record("remote.example.", RData::A(A(Ipv4Addr::LOCALHOST)));
    wrong_class.dns_class = DNSClass::CH;
    reply.answers = vec![
        wrong_class,
        record("unrelated.example.", RData::A(A(Ipv4Addr::LOCALHOST))),
    ];
    assert!(
        answer_records(reply, &name, RecordType::A)
            .unwrap()
            .records
            .is_empty()
    );
}

#[test]
fn host_resolution_bypasses_routes_and_srv_and_keeps_address_order() -> TestResult {
    let server = Server::start(|query| vec![address(query)])?;
    let mut resolver = server.resolver()?;
    resolver
        .routes
        .insert("ca.example".into(), vec!["192.0.2.1:99".parse()?]);
    let runtime = Runtime::new()?;
    for text in ["127.0.0.1", "::1", "[::1]"] {
        let result = runtime
            .block_on(resolver.resolve_host(text))
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            result,
            vec![text.trim_matches(['[', ']']).parse::<IpAddr>()?]
        );
    }
    assert!(server.queries().is_empty());
    assert_eq!(
        runtime
            .block_on(resolver.resolve_host("ca.example"))
            .map_err(|error| format!("{error:?}"))?,
        vec![
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        ]
    );
    let queries = server.queries();
    assert_eq!(queries.len(), 2);
    assert!(
        queries.iter().all(|(name, kind)| name == "ca.example."
            && matches!(kind, RecordType::A | RecordType::AAAA))
    );
    Ok(())
}

#[test]
fn host_resolution_distinguishes_empty_answers_failures_and_invalid_names() -> TestResult {
    for (code, expected) in [
        (ResponseCode::NXDomain, ResolveError::NotFound),
        (ResponseCode::ServFail, ResolveError::Unavailable),
    ] {
        let server = Server::start(move |query| vec![response(query, code, Vec::new())])?;
        let resolver = server.resolver()?;
        assert_eq!(
            Runtime::new()?.block_on(resolver.resolve_host("ca.example")),
            Err(expected)
        );
        assert_eq!(
            Runtime::new()?.block_on(resolver.resolve_host("bad name")),
            Err(ResolveError::InvalidDomain)
        );
    }
    Ok(())
}

#[test]
fn typed_candidates_deduplicate_by_mode_and_share_the_cap() {
    let candidates = (1..=10).flat_map(|last| {
        let address = SocketAddr::from(([192, 0, 2, last], 5270));
        let starttls = Endpoint {
            address,
            tls_mode: TlsMode::StartTls,
        };
        let direct = Endpoint {
            address,
            tls_mode: TlsMode::Direct,
        };
        [starttls, starttls, direct, direct]
    });
    let mut endpoints = Vec::new();
    append_unique(&mut endpoints, candidates);
    let expected: Vec<_> = (1..=8)
        .flat_map(|last| {
            let address = SocketAddr::from(([192, 0, 2, last], 5270));
            [
                Endpoint {
                    address,
                    tls_mode: TlsMode::StartTls,
                },
                Endpoint {
                    address,
                    tls_mode: TlsMode::Direct,
                },
            ]
        })
        .collect();
    assert_eq!(endpoints, expected);
}

#[test]
fn address_expansion_preserves_target_mode_and_family_order() {
    let mut endpoints = Vec::new();
    let ipv6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let ipv4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    for tls_mode in [TlsMode::StartTls, TlsMode::Direct] {
        append_addresses(
            &mut endpoints,
            Ok(Answer {
                records: vec![RData::AAAA(AAAA(Ipv6Addr::LOCALHOST))],
            }),
            5270,
            tls_mode,
        );
        append_addresses(
            &mut endpoints,
            Ok(Answer {
                records: vec![RData::A(A(Ipv4Addr::LOCALHOST))],
            }),
            5270,
            tls_mode,
        );
    }
    assert_eq!(
        endpoints,
        [TlsMode::StartTls, TlsMode::Direct]
            .into_iter()
            .flat_map(|tls_mode| {
                [ipv6, ipv4].map(|ip| Endpoint {
                    address: SocketAddr::new(ip, 5270),
                    tls_mode,
                })
            })
            .collect::<Vec<_>>()
    );
}

#[derive(Clone, Copy, Debug)]
enum ServiceReply {
    NxDomain,
    NoData,
    ServFail,
    Refused,
    Dot,
    MixedDot,
    ZeroPort,
    Usable,
}

fn service_reply(query: &Message, reply: ServiceReply, mode: TlsMode) -> Vec<Message> {
    let target = if mode == TlsMode::Direct {
        "direct.example."
    } else {
        "start.example."
    };
    match reply {
        ServiceReply::NxDomain => vec![response(query, ResponseCode::NXDomain, vec![])],
        ServiceReply::NoData => vec![response(query, ResponseCode::NoError, vec![])],
        ServiceReply::ServFail => vec![response(query, ResponseCode::ServFail, vec![])],
        ServiceReply::Refused => vec![response(query, ResponseCode::Refused, vec![])],
        ServiceReply::Dot => vec![srv(query, ".", 0)],
        ServiceReply::ZeroPort => vec![srv(query, target, 0)],
        ServiceReply::Usable => vec![srv(query, target, 5270)],
        ServiceReply::MixedDot => {
            let mut reply = srv(query, ".", 0);
            reply.answers.extend(srv(query, target, 5270).answers);
            vec![reply]
        }
    }
}

fn service_mode(query: &Message) -> TlsMode {
    if query.queries[0]
        .name()
        .to_ascii()
        .starts_with("_xmpps-server.")
    {
        TlsMode::Direct
    } else {
        TlsMode::StartTls
    }
}

fn assert_both_services(queries: &[(String, RecordType)]) {
    for service in [
        "_xmpp-server._tcp.remote.example.",
        "_xmpps-server._tcp.remote.example.",
    ] {
        assert_eq!(
            queries
                .iter()
                .filter(|(name, kind)| name == service && *kind == RecordType::SRV)
                .count(),
            1,
            "{queries:?}"
        );
    }
}

#[test]
fn one_usable_service_survives_other_absent_unavailable_disabled_or_malformed() -> TestResult {
    for reply in [
        ServiceReply::NxDomain,
        ServiceReply::NoData,
        ServiceReply::ServFail,
        ServiceReply::Refused,
        ServiceReply::Dot,
        ServiceReply::MixedDot,
        ServiceReply::ZeroPort,
    ] {
        for usable in [TlsMode::StartTls, TlsMode::Direct] {
            let server = Server::with_services(move |query| {
                if query.queries[0].query_type() == RecordType::SRV {
                    let mode = service_mode(query);
                    service_reply(
                        query,
                        if mode == usable {
                            ServiceReply::Usable
                        } else {
                            reply
                        },
                        mode,
                    )
                } else {
                    vec![address(query)]
                }
            })?;
            let resolver = server.resolver()?;
            let result = resolve(&resolver, "remote.example").unwrap();
            assert_eq!(result.via, ResolvedVia::Srv);
            assert_eq!(
                result.endpoints,
                [Ipv6Addr::LOCALHOST.into(), Ipv4Addr::LOCALHOST.into()].map(|ip| Endpoint {
                    address: SocketAddr::new(ip, 5270),
                    tls_mode: usable
                })
            );
            let queries = server.queries();
            assert_both_services(&queries);
            let target = if usable == TlsMode::Direct {
                "direct.example."
            } else {
                "start.example."
            };
            assert_eq!(queries.len(), 4);
            assert!(
                queries
                    .iter()
                    .all(|(name, kind)| *kind == RecordType::SRV || name == target),
                "{reply:?} {usable:?}: {queries:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn both_unadvertised_services_fall_back_to_origin_starttls() -> TestResult {
    let replies = [
        ServiceReply::NxDomain,
        ServiceReply::NoData,
        ServiceReply::ServFail,
        ServiceReply::Refused,
    ];
    for starttls in replies {
        for direct in replies {
            let server = Server::with_services(move |query| {
                if query.queries[0].query_type() == RecordType::SRV {
                    let mode = service_mode(query);
                    service_reply(
                        query,
                        if mode == TlsMode::Direct {
                            direct
                        } else {
                            starttls
                        },
                        mode,
                    )
                } else {
                    vec![address(query)]
                }
            })?;
            let resolver = server.resolver()?;
            assert_endpoints(
                resolve(&resolver, "remote.example").unwrap(),
                ResolvedVia::Fallback,
                5269,
            );
            let queries = server.queries();
            assert_both_services(&queries);
            assert_eq!(queries.len(), 4);
            assert!(
                queries
                    .iter()
                    .all(|(name, kind)| *kind == RecordType::SRV || name == "remote.example.")
            );
        }
    }
    Ok(())
}

#[test]
fn dot_without_usable_other_service_never_queries_origin() -> TestResult {
    for (other, expected) in [
        (ServiceReply::NxDomain, ResolveError::NoService),
        (ServiceReply::NoData, ResolveError::NoService),
        (ServiceReply::Dot, ResolveError::NoService),
        (ServiceReply::ServFail, ResolveError::Unavailable),
        (ServiceReply::Refused, ResolveError::Unavailable),
    ] {
        for disabled in [TlsMode::StartTls, TlsMode::Direct] {
            let server = Server::with_services(move |query| {
                let mode = service_mode(query);
                assert_eq!(query.queries[0].query_type(), RecordType::SRV);
                service_reply(
                    query,
                    if mode == disabled {
                        ServiceReply::Dot
                    } else {
                        other
                    },
                    mode,
                )
            })?;
            let resolver = server.resolver()?;
            assert_eq!(resolve(&resolver, "remote.example").unwrap_err(), expected);
            assert_both_services(&server.queries());
            assert_eq!(server.queries().len(), 2);
        }
    }
    Ok(())
}

#[test]
fn malformed_and_zero_port_advertisements_never_query_targets_or_origin() -> TestResult {
    for invalid in [ServiceReply::MixedDot, ServiceReply::ZeroPort] {
        for mode in [TlsMode::StartTls, TlsMode::Direct] {
            let server = Server::with_services(move |query| {
                assert_eq!(query.queries[0].query_type(), RecordType::SRV);
                let selected = service_mode(query);
                service_reply(
                    query,
                    if selected == mode {
                        invalid
                    } else {
                        ServiceReply::NxDomain
                    },
                    selected,
                )
            })?;
            assert_eq!(
                resolve(&server.resolver()?, "remote.example").unwrap_err(),
                ResolveError::NotFound
            );
            assert_both_services(&server.queries());
            assert_eq!(server.queries().len(), 2);
        }
    }
    Ok(())
}

#[test]
fn advertised_targets_with_empty_or_failed_addresses_never_fall_back() -> TestResult {
    for failure in [
        ResponseCode::NoError,
        ResponseCode::NXDomain,
        ResponseCode::ServFail,
        ResponseCode::Refused,
    ] {
        for mode in [TlsMode::StartTls, TlsMode::Direct] {
            let server = Server::with_services(move |query| {
                if query.queries[0].query_type() == RecordType::SRV {
                    let selected = service_mode(query);
                    service_reply(
                        query,
                        if selected == mode {
                            ServiceReply::Usable
                        } else {
                            ServiceReply::NoData
                        },
                        selected,
                    )
                } else {
                    vec![response(query, failure, vec![])]
                }
            })?;
            let resolver = server.resolver()?;
            assert_eq!(
                resolve(&resolver, "remote.example").unwrap_err(),
                ResolveError::NotFound
            );
            let queries = server.queries();
            assert_both_services(&queries);
            let target = if mode == TlsMode::Direct {
                "direct.example."
            } else {
                "start.example."
            };
            assert!(
                queries
                    .iter()
                    .all(|(name, kind)| *kind == RecordType::SRV || name == target)
            );
            assert_eq!(queries.len(), 4);
        }
    }
    Ok(())
}

fn weighted_srv(query: &Message, priority: u16, weight: u16, port: u16, target: &str) -> Record {
    record(
        &query.queries[0].name().to_ascii(),
        RData::SRV(SRV::new(
            priority,
            weight,
            port,
            Name::from_ascii(target).unwrap(),
        )),
    )
}

#[test]
fn mixed_service_priorities_interleave_in_either_transport_order() -> TestResult {
    for first in [TlsMode::StartTls, TlsMode::Direct] {
        let server = Server::with_services(move |query| {
            if query.queries[0].query_type() != RecordType::SRV {
                return vec![address(query)];
            }
            let base = if service_mode(query) == first { 0 } else { 10 };
            vec![response(
                query,
                ResponseCode::NoError,
                vec![
                    weighted_srv(query, base, 0, 5270 + base, "target.example."),
                    weighted_srv(query, base + 20, 0, 5290 + base, "target.example."),
                ],
            )]
        })?;
        let result = resolve(&server.resolver()?, "remote.example").unwrap();
        let second = if first == TlsMode::Direct {
            TlsMode::StartTls
        } else {
            TlsMode::Direct
        };
        let expected: Vec<_> = [(5270, first), (5280, second), (5290, first), (5300, second)]
            .into_iter()
            .flat_map(|(port, tls_mode)| {
                [Ipv6Addr::LOCALHOST.into(), Ipv4Addr::LOCALHOST.into()].map(|ip| Endpoint {
                    address: SocketAddr::new(ip, port),
                    tls_mode,
                })
            })
            .collect();
        assert_eq!(result.endpoints, expected);
        assert_eq!(result.via, ResolvedVia::Srv);
        assert_both_services(&server.queries());
    }
    Ok(())
}

#[test]
fn mixed_weights_share_inclusive_zero_boundary_and_random_failures() {
    let answer = |records| Ok(Answer { records });
    let records = merge_srv([
        classify_srv(
            answer(vec![
                RData::SRV(SRV::new(
                    0,
                    5,
                    5270,
                    Name::from_ascii("start-five.").unwrap(),
                )),
                RData::SRV(SRV::new(
                    0,
                    0,
                    5270,
                    Name::from_ascii("start-zero.").unwrap(),
                )),
            ]),
            TlsMode::StartTls,
        ),
        classify_srv(
            answer(vec![
                RData::SRV(SRV::new(
                    0,
                    3,
                    5270,
                    Name::from_ascii("direct-three.").unwrap(),
                )),
                RData::SRV(SRV::new(
                    0,
                    0,
                    5270,
                    Name::from_ascii("direct-zero.").unwrap(),
                )),
            ]),
            TlsMode::Direct,
        ),
    ])
    .unwrap()
    .unwrap();
    let mut choices = [(8, 0), (8, 0), (8, 8), (5, 5)].into_iter();
    let ordered = order_srv(records, &mut |total| {
        let (expected, value) = choices.next().unwrap();
        assert_eq!(total, expected);
        Ok(value)
    })
    .unwrap();
    assert_eq!(
        ordered
            .iter()
            .map(|target| (target.name.as_ref(), target.tls_mode))
            .collect::<Vec<_>>(),
        [
            ("start-zero.", TlsMode::StartTls),
            ("direct-zero.", TlsMode::Direct),
            ("direct-three.", TlsMode::Direct),
            ("start-five.", TlsMode::StartTls)
        ]
    );
    assert!(choices.next().is_none());
    let records = vec![
        (
            0,
            0,
            SrvTarget {
                name: "start.".into(),
                port: 5270,
                tls_mode: TlsMode::StartTls,
            },
        ),
        (
            0,
            0,
            SrvTarget {
                name: "direct.".into(),
                port: 5270,
                tls_mode: TlsMode::Direct,
            },
        ),
    ];
    let ordered = order_srv(records, &mut |total| {
        assert_eq!(total, 0);
        Ok(0)
    })
    .unwrap();
    assert_eq!(
        ordered
            .iter()
            .map(|target| target.tls_mode)
            .collect::<Vec<_>>(),
        [TlsMode::StartTls, TlsMode::Direct]
    );
    let records = vec![(
        0,
        0,
        SrvTarget {
            name: "direct.".into(),
            port: 5270,
            tls_mode: TlsMode::Direct,
        },
    )];
    assert!(matches!(
        order_srv(records, &mut |_| Err(ResolveError::Unavailable)),
        Err(ResolveError::Unavailable)
    ));
}

#[test]
fn mixed_service_endpoints_deduplicate_pairs_with_one_shared_cap() -> TestResult {
    let server = Server::with_services(|query| {
        if query.queries[0].query_type() == RecordType::SRV {
            let offset = u16::from(service_mode(query) == TlsMode::Direct);
            let records = (1..=12)
                .flat_map(|last| {
                    let value = weighted_srv(
                        query,
                        (last - 1) * 2 + offset,
                        0,
                        5270,
                        &format!("t{last}.example."),
                    );
                    [value.clone(), value]
                })
                .collect();
            return vec![response(query, ResponseCode::NoError, records)];
        }
        let records = if query.queries[0].query_type() == RecordType::A {
            let name = query.queries[0].name().to_ascii();
            let last: u8 = name
                .strip_prefix('t')
                .unwrap()
                .split('.')
                .next()
                .unwrap()
                .parse()
                .unwrap();
            let value = record(&name, RData::A(A(Ipv4Addr::new(192, 0, 2, last))));
            vec![value.clone(), value]
        } else {
            vec![]
        };
        vec![response(query, ResponseCode::NoError, records)]
    })?;
    let result = resolve(&server.resolver()?, "remote.example").unwrap();
    let expected: Vec<_> = (1..=8)
        .flat_map(|last| {
            [TlsMode::StartTls, TlsMode::Direct].map(|tls_mode| Endpoint {
                address: SocketAddr::from(([192, 0, 2, last], 5270)),
                tls_mode,
            })
        })
        .collect();
    assert_eq!(result.endpoints, expected);
    assert_both_services(&server.queries());
    assert!(
        !server
            .queries()
            .iter()
            .any(|(name, _)| name == "t9.example.")
    );
    Ok(())
}

#[test]
fn either_service_preserves_ipv6_only_and_ipv4_only_targets() -> TestResult {
    for mode in [TlsMode::StartTls, TlsMode::Direct] {
        for family in [RecordType::AAAA, RecordType::A] {
            let server = Server::with_services(move |query| {
                let kind = query.queries[0].query_type();
                if kind == RecordType::SRV {
                    let selected = service_mode(query);
                    service_reply(
                        query,
                        if selected == mode {
                            ServiceReply::Usable
                        } else {
                            ServiceReply::NoData
                        },
                        selected,
                    )
                } else if kind == family {
                    vec![address(query)]
                } else {
                    vec![response(query, ResponseCode::NoError, vec![])]
                }
            })?;
            let result = resolve(&server.resolver()?, "remote.example").unwrap();
            let ip = if family == RecordType::AAAA {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            } else {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            };
            assert_eq!(
                result.endpoints,
                [Endpoint {
                    address: SocketAddr::new(ip, 5270),
                    tls_mode: mode
                }]
            );
            assert_eq!(result.via, ResolvedVia::Srv);
            assert_both_services(&server.queries());
        }
    }
    Ok(())
}
