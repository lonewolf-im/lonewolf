// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;

use compio::buf::{BufResult, IntoInner, IoBuf};
use compio::io::{AsyncReadExt, AsyncWriteExt};
use compio::net::{TcpStream, UdpSocket};
use futures_util::future::join;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};

const ENDPOINT_LIMIT: usize = 16;

pub(crate) struct Resolver {
    nameservers: Vec<SocketAddr>,
    timeout: Duration,
    routes: BTreeMap<String, Vec<SocketAddr>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResolveError {
    NoService,
    NotFound,
    Unavailable,
    InvalidDomain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResolvedVia {
    Srv,
    Fallback,
    Static,
    Literal,
}

#[derive(Debug)]
pub(crate) struct Resolved {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) endpoints: Vec<SocketAddr>,
    pub(crate) via: ResolvedVia,
}

pub(crate) struct SrvTarget {
    pub(crate) name: Box<str>,
    pub(crate) port: u16,
}

#[derive(Debug, Eq, PartialEq)]
enum QueryError {
    Unavailable,
}

struct Answer {
    records: Vec<RData>,
}

impl Resolver {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new(config: &crate::config::S2sConfig) -> io::Result<Self> {
        let nameservers = if config.dns.nameservers.is_empty() {
            parse_resolv_conf(&std::fs::read_to_string("/etc/resolv.conf")?)
        } else {
            config.dns.nameservers.clone()
        };
        Ok(Self {
            nameservers,
            timeout: Duration::from_secs(config.dns.timeout_secs.get()),
            routes: config.routes.clone(),
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn resolve(&self, domain: &str) -> Result<Resolved, ResolveError> {
        let result = self.resolve_inner(domain).await;
        let outcome = match &result {
            Ok(result) => match result.via {
                ResolvedVia::Srv => "srv",
                ResolvedVia::Fallback => "fallback",
                ResolvedVia::Static | ResolvedVia::Literal => "static",
            },
            Err(ResolveError::NoService) => "no_service",
            Err(ResolveError::NotFound | ResolveError::InvalidDomain) => "not_found",
            Err(ResolveError::Unavailable) => "unavailable",
        };
        let remote_domain = if domain.parse::<IpAddr>().is_ok()
            || result
                .as_ref()
                .is_ok_and(|value| value.via == ResolvedVia::Literal)
        {
            Cow::Borrowed("<literal>")
        } else if domain.len() <= 253 && !domain.chars().any(char::is_control) {
            Cow::Borrowed(domain)
        } else {
            Cow::Owned(
                domain
                    .chars()
                    .take(253)
                    .map(|c| if c.is_control() { '?' } else { c })
                    .collect::<String>(),
            )
        };
        tracing::debug!(remote_domain = %remote_domain, outcome, "s2s DNS resolution completed");
        result
    }

    async fn resolve_inner(&self, domain: &str) -> Result<Resolved, ResolveError> {
        let literal = domain.parse::<Ipv4Addr>().map(IpAddr::V4).ok().or_else(|| {
            domain
                .strip_prefix('[')?
                .strip_suffix(']')?
                .parse::<Ipv6Addr>()
                .ok()
                .map(IpAddr::V6)
        });
        if let Some(ip) = literal {
            return Ok(Resolved {
                endpoints: vec![SocketAddr::new(ip, 5269)],
                via: ResolvedVia::Literal,
            });
        }
        if let Some(route) = self.routes.get(domain) {
            let mut endpoints = Vec::with_capacity(route.len().min(ENDPOINT_LIMIT));
            append_unique(&mut endpoints, route.iter().copied());
            return Ok(Resolved {
                endpoints,
                via: ResolvedVia::Static,
            });
        }
        let ascii =
            idna::domain_to_ascii_strict(domain).map_err(|_| ResolveError::InvalidDomain)?;
        let mut name = Name::from_ascii(&ascii).map_err(|_| ResolveError::InvalidDomain)?;
        name.set_fqdn(true);
        let ascii = ascii.trim_end_matches('.');
        let srv_name = Name::from_ascii(format!("_xmpp-server._tcp.{ascii}."))
            .map_err(|_| ResolveError::InvalidDomain)?;
        let srv = self.query(&srv_name, RecordType::SRV).await;
        let records: Vec<_> = srv
            .into_iter()
            .flat_map(|answer| answer.records)
            .filter_map(|data| {
                if let RData::SRV(srv) = data {
                    Some((
                        srv.priority,
                        srv.weight,
                        SrvTarget {
                            name: srv.target.to_ascii().into_boxed_str(),
                            port: srv.port,
                        },
                    ))
                } else {
                    None
                }
            })
            .collect();
        if records.len() == 1 && records[0].2.name.as_ref() == "." {
            return Err(ResolveError::NoService);
        }
        if !records.is_empty() {
            let mut random_failed = false;
            let targets = order_srv(records, &mut |total| match random_inclusive(total) {
                Ok(value) => value,
                Err(_) => {
                    random_failed = true;
                    0
                }
            });
            if random_failed {
                return Err(ResolveError::Unavailable);
            }
            let mut endpoints = Vec::with_capacity(ENDPOINT_LIMIT);
            for target in targets {
                let Ok(name) = Name::from_ascii(&target.name) else {
                    continue;
                };
                let (aaaa, a) = self.addresses(&name).await;
                append_addresses(&mut endpoints, aaaa, target.port);
                append_addresses(&mut endpoints, a, target.port);
                if endpoints.len() == ENDPOINT_LIMIT {
                    break;
                }
            }
            return if endpoints.is_empty() {
                Err(ResolveError::NotFound)
            } else {
                Ok(Resolved {
                    endpoints,
                    via: ResolvedVia::Srv,
                })
            };
        }
        let (aaaa, a) = self.addresses(&name).await;
        let negative = aaaa.is_ok() && a.is_ok();
        let mut endpoints = Vec::with_capacity(ENDPOINT_LIMIT);
        append_addresses(&mut endpoints, aaaa, 5269);
        append_addresses(&mut endpoints, a, 5269);
        if endpoints.is_empty() {
            Err(if negative {
                ResolveError::NotFound
            } else {
                ResolveError::Unavailable
            })
        } else {
            Ok(Resolved {
                endpoints,
                via: ResolvedVia::Fallback,
            })
        }
    }

    async fn addresses(
        &self,
        name: &Name,
    ) -> (Result<Answer, QueryError>, Result<Answer, QueryError>) {
        join(
            self.query(name, RecordType::AAAA),
            self.query(name, RecordType::A),
        )
        .await
    }

    async fn query(&self, name: &Name, record_type: RecordType) -> Result<Answer, QueryError> {
        let mut id = [0; 2];
        graviola::random::fill(&mut id).map_err(|_| QueryError::Unavailable)?;
        let mut message = Message::new(u16::from_ne_bytes(id), MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message
            .queries
            .push(Query::query(name.clone(), record_type));
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        message.edns = Some(edns);
        let wire = Rc::new(message.to_vec().map_err(|_| QueryError::Unavailable)?);
        for &nameserver in &self.nameservers {
            if let Ok(Ok(response)) =
                compio::time::timeout(self.timeout, exchange(nameserver, &message, &wire)).await
            {
                match response.metadata.response_code {
                    ResponseCode::NXDomain => {
                        return Ok(Answer {
                            records: Vec::new(),
                        });
                    }
                    ResponseCode::NoError => {
                        if let Ok(answer) = answer_records(response, name, record_type) {
                            return Ok(answer);
                        }
                    }
                    _ => {}
                }
            }
        }
        Err(QueryError::Unavailable)
    }
}

fn append_unique(endpoints: &mut Vec<SocketAddr>, values: impl IntoIterator<Item = SocketAddr>) {
    for address in values {
        if endpoints.len() == ENDPOINT_LIMIT {
            break;
        }
        if !endpoints.contains(&address) {
            endpoints.push(address);
        }
    }
}

fn append_addresses(
    endpoints: &mut Vec<SocketAddr>,
    answer: Result<Answer, QueryError>,
    port: u16,
) {
    if let Ok(answer) = answer {
        append_unique(
            endpoints,
            answer.records.into_iter().filter_map(|data| match data {
                RData::AAAA(address) => Some(SocketAddr::new(IpAddr::V6(address.0), port)),
                RData::A(address) => Some(SocketAddr::new(IpAddr::V4(address.0), port)),
                _ => None,
            }),
        );
    }
}

fn matches(response: &Message, request: &Message) -> bool {
    response.metadata.id == request.metadata.id
        && response.metadata.message_type == MessageType::Response
        && response.metadata.op_code == request.metadata.op_code
        && response.queries == request.queries
}

async fn exchange(
    nameserver: SocketAddr,
    request: &Message,
    wire: &Rc<Vec<u8>>,
) -> io::Result<Message> {
    let bind = SocketAddr::new(
        if nameserver.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        },
        0,
    );
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(nameserver).await?;
    let BufResult(sent, _) = socket.send(Rc::clone(wire)).await;
    if sent? != wire.len() {
        return Err(io::ErrorKind::WriteZero.into());
    }
    let mut buffer = vec![0; 65535];
    for _ in 0..=16 {
        let BufResult(received, returned) = socket.recv(buffer).await;
        buffer = returned;
        let response = Message::from_vec(&buffer[..received?]).map_err(io::Error::other)?;
        if !matches(&response, request) {
            continue;
        }
        if !response.metadata.truncation {
            return Ok(response);
        }
        let mut stream = TcpStream::connect(nameserver).await?;
        let length = u16::try_from(wire.len())
            .map_err(io::Error::other)?
            .to_be_bytes();
        let BufResult(written, _) = stream.write_all(length).await;
        written?;
        let BufResult(written, _) = stream.write_all(Rc::clone(wire)).await;
        written?;
        let BufResult(read, length) = stream.read_exact([0; 2]).await;
        read?;
        let length = usize::from(u16::from_be_bytes(length));
        let BufResult(read, buffer) = stream.read_exact(buffer.slice(..length)).await;
        read?;
        let buffer = buffer.into_inner();
        let response = Message::from_vec(&buffer[..length]).map_err(io::Error::other)?;
        if matches(&response, request) && !response.metadata.truncation {
            return Ok(response);
        }
        return Err(io::ErrorKind::InvalidData.into());
    }
    Err(io::ErrorKind::InvalidData.into())
}

fn answer_records(message: Message, query: &Name, kind: RecordType) -> Result<Answer, QueryError> {
    let mut name = query;
    let mut visited = [None; 9];
    for hop in 0..=8 {
        if visited[..hop].contains(&Some(name)) {
            return Err(QueryError::Unavailable);
        }
        visited[hop] = Some(name);
        let target = message.answers.iter().find_map(|record| {
            if record.name == *name
                && record.dns_class == DNSClass::IN
                && let RData::CNAME(target) = &record.data
            {
                return Some(&target.0);
            }
            None
        });
        if let Some(target) = target {
            name = target;
        } else {
            let final_name = name.clone();
            return Ok(Answer {
                records: message
                    .answers
                    .into_iter()
                    .filter(|record| {
                        record.name == final_name
                            && record.dns_class == DNSClass::IN
                            && record.data.record_type() == kind
                    })
                    .map(|record| record.data)
                    .collect(),
            });
        }
    }
    Err(QueryError::Unavailable)
}

pub(crate) fn order_srv(
    mut records: Vec<(u16, u16, SrvTarget)>,
    random: &mut impl FnMut(u32) -> u32,
) -> Vec<SrvTarget> {
    records.sort_by_key(|(priority, weight, _)| (*priority, *weight != 0));
    let mut ordered = Vec::with_capacity(records.len());
    while !records.is_empty() {
        let priority = records[0].0;
        let end = records
            .iter()
            .position(|record| record.0 != priority)
            .unwrap_or(records.len());
        let total = records[..end]
            .iter()
            .map(|record| u32::from(record.1))
            .sum();
        let chosen = random(total);
        let mut sum = 0;
        let index = records[..end]
            .iter()
            .position(|record| {
                sum += u32::from(record.1);
                sum >= chosen
            })
            .unwrap_or(end - 1);
        ordered.push(records.remove(index).2);
    }
    ordered
}

fn random_inclusive(total: u32) -> Result<u32, graviola::Error> {
    let range = u64::from(total) + 1;
    let ceiling = (1_u64 << 32) / range * range;
    loop {
        let mut bytes = [0; 4];
        graviola::random::fill(&mut bytes)?;
        let value = u32::from_ne_bytes(bytes);
        if u64::from(value) < ceiling {
            return Ok((u64::from(value) % range) as u32);
        }
    }
}

pub(crate) fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    let mut nameservers = Vec::with_capacity(3);
    for line in text.lines() {
        let mut fields = line
            .split(['#', ';'])
            .next()
            .unwrap_or_default()
            .split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        if let Some(ip) = fields.next().and_then(|field| field.parse::<IpAddr>().ok()) {
            nameservers.push(SocketAddr::new(ip, 53));
            if nameservers.len() == 3 {
                break;
            }
        }
    }
    if nameservers.is_empty() {
        nameservers.push(SocketAddr::from(([127, 0, 0, 1], 53)));
    }
    nameservers
}

#[cfg(test)]
mod tests;
