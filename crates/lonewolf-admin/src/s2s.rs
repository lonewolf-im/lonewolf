// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use axum::response::Response;
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::{Jid, JidError, MAX_PART_LEN};
use serde::{Serialize, Serializer};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::api::{ApiError, DEFAULT_PAGE, MAX_PAGE, decode, response};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum S2sDirection {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum S2sTlsMode {
    StartTls,
    Direct,
}

#[derive(Clone, Debug)]
pub struct S2sConnection {
    pub connection_id: u64,
    pub direction: S2sDirection,
    pub bidirectional: bool,
    pub local_domain: Arc<str>,
    pub remote_domain: Arc<str>,
    pub remote_address: Option<SocketAddr>,
    pub tls_mode: S2sTlsMode,
    pub tls_version: &'static str,
    pub cipher_suite: &'static str,
    pub established_at: SystemTime,
    pub uptime: Duration,
    pub certificate_expires_at: SystemTime,
    pub bytes_received: u64,
    pub bytes_sent: u64,
}

pub trait S2sConnections: Send + Sync {
    /// Returns at most `limit` authenticated connections in ascending ID order, with
    /// IDs greater than `after` and an exact `remote_domain` match when supplied.
    /// Callers rely on this method returning without blocking I/O.
    fn connections(
        &self,
        after: Option<u64>,
        remote_domain: Option<&str>,
        limit: NonZeroUsize,
    ) -> Vec<S2sConnection>;
}

pub(crate) fn list(
    source: Option<&dyn S2sConnections>,
    query: Option<&str>,
) -> Result<Response, ApiError> {
    let ListParameters {
        after,
        limit,
        remote_domain,
    } = list_parameters(query)?;
    let mut arena;
    let domain = if let Some(domain) = remote_domain {
        if domain.len() > MAX_PART_LEN {
            return Err(invalid_domain());
        }
        arena = Arena::try_new(ArenaConfig::default()).map_err(|_| ApiError::internal())?;
        Some(prepare_domain(&domain, &mut arena)?)
    } else {
        None
    };
    let source = source.ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "s2s_inactive"))?;

    let lookahead = NonZeroUsize::MIN.saturating_add(limit);
    let mut page = source.connections(after, domain, lookahead);
    let has_more = page.len() > limit;
    page.truncate(limit);
    let cursor = page
        .last()
        .filter(|_| has_more)
        .map(|connection| connection.connection_id);

    let mut bytes = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"{\"connections\":[");
    for (index, connection) in page.iter().enumerate() {
        if index > 0 {
            bytes.push(b',');
        }
        serde_json::to_writer(&mut bytes, &ConnectionView::from(connection))
            .map_err(|_| ApiError::internal())?;
    }
    bytes.extend_from_slice(b"],\"next_cursor\":");
    serde_json::to_writer(&mut bytes, &cursor).map_err(|_| ApiError::internal())?;
    bytes.push(b'}');
    Ok(response(StatusCode::OK, bytes.into()))
}

struct ListParameters<'a> {
    after: Option<u64>,
    limit: usize,
    remote_domain: Option<Cow<'a, str>>,
}

fn list_parameters(query: Option<&str>) -> Result<ListParameters<'_>, ApiError> {
    let mut after = None;
    let mut limit = None;
    let mut remote_domain = None;
    if let Some(query) = query {
        for parameter in query.split('&') {
            let (name, value) = parameter
                .split_once('=')
                .ok_or_else(ApiError::bad_request)?;
            match name {
                "after" if after.is_none() => {
                    after = Some(value.parse::<u64>().map_err(|_| ApiError::bad_request())?);
                }
                "limit" if limit.is_none() => {
                    let value = value
                        .parse::<usize>()
                        .map_err(|_| ApiError::bad_request())?;
                    if !(1..=MAX_PAGE).contains(&value) {
                        return Err(ApiError::bad_request());
                    }
                    limit = Some(value);
                }
                "remote_domain" if remote_domain.is_none() => remote_domain = Some(decode(value)?),
                _ => return Err(ApiError::bad_request()),
            }
        }
    }
    Ok(ListParameters {
        after,
        limit: limit.unwrap_or(DEFAULT_PAGE),
        remote_domain,
    })
}

fn prepare_domain<'a>(domain: &str, arena: &'a mut Arena) -> Result<&'a str, ApiError> {
    let jid = Jid::parse_in(domain, arena).map_err(|error| match error {
        JidError::AllocationFailed(_) | JidError::AccessFailed(_) => ApiError::internal(),
        _ => invalid_domain(),
    })?;
    let jid = jid.resolve(arena).map_err(|_| ApiError::internal())?;
    if jid.localpart().is_some() || jid.resourcepart().is_some() {
        return Err(invalid_domain());
    }
    Ok(jid.domainpart())
}

fn invalid_domain() -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "invalid_domain")
}

#[derive(Serialize)]
struct ConnectionView<'a> {
    connection_id: u64,
    direction: &'static str,
    bidirectional: bool,
    local_domain: &'a str,
    remote_domain: &'a str,
    remote_address: Option<SocketAddr>,
    tls_mode: &'static str,
    tls_version: &'static str,
    cipher_suite: &'static str,
    established_at: Timestamp,
    uptime_secs: u64,
    certificate_expires_at: Timestamp,
    bytes_received: u64,
    bytes_sent: u64,
}

impl<'a> From<&'a S2sConnection> for ConnectionView<'a> {
    fn from(connection: &'a S2sConnection) -> Self {
        Self {
            connection_id: connection.connection_id,
            direction: match connection.direction {
                S2sDirection::Inbound => "inbound",
                S2sDirection::Outbound => "outbound",
            },
            bidirectional: connection.bidirectional,
            local_domain: &connection.local_domain,
            remote_domain: &connection.remote_domain,
            remote_address: connection.remote_address,
            tls_mode: match connection.tls_mode {
                S2sTlsMode::StartTls => "starttls",
                S2sTlsMode::Direct => "direct",
            },
            tls_version: connection.tls_version,
            cipher_suite: connection.cipher_suite,
            established_at: Timestamp(connection.established_at),
            uptime_secs: connection.uptime.as_secs(),
            certificate_expires_at: Timestamp(connection.certificate_expires_at),
            bytes_received: connection.bytes_received,
            bytes_sent: connection.bytes_sent,
        }
    }
}

struct Timestamp(SystemTime);

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let seconds = self
            .0
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut buffer = [0u8; 32];
        let timestamp = i64::try_from(seconds)
            .ok()
            .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
            .and_then(|timestamp| {
                timestamp
                    .format_into(&mut buffer.as_mut_slice(), &Rfc3339)
                    .ok()
            })
            .and_then(|length| std::str::from_utf8(&buffer[..length]).ok());
        match timestamp {
            Some(timestamp) => serializer.serialize_str(timestamp),
            None => serializer.serialize_none(),
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Bytes;
    use axum::response::IntoResponse;
    use futures_util::FutureExt;
    use http_body_util::BodyExt;
    use parking_lot::Mutex as PlMutex;
    use serde_json::{Value, json};

    use super::*;

    type Request = (Option<u64>, Option<String>, usize);

    #[derive(Default)]
    struct Source {
        entries: Vec<S2sConnection>,
        last_request: PlMutex<Option<Request>>,
    }

    impl S2sConnections for Source {
        fn connections(
            &self,
            after: Option<u64>,
            remote_domain: Option<&str>,
            limit: NonZeroUsize,
        ) -> Vec<S2sConnection> {
            *self.last_request.lock() =
                Some((after, remote_domain.map(str::to_owned), limit.get()));
            self.entries
                .iter()
                .filter(|entry| after.is_none_or(|after| entry.connection_id > after))
                .filter(|entry| remote_domain.is_none_or(|domain| domain == &*entry.remote_domain))
                .take(limit.get())
                .cloned()
                .collect()
        }
    }

    fn connection(connection_id: u64) -> S2sConnection {
        S2sConnection {
            connection_id,
            direction: S2sDirection::Outbound,
            bidirectional: true,
            local_domain: Arc::from("example.com"),
            remote_domain: Arc::from("example.org"),
            remote_address: Some("[2001:db8::1]:5269".parse().unwrap()),
            tls_mode: S2sTlsMode::StartTls,
            tls_version: "TLSv1.3",
            cipher_suite: "TLS13_AES_256_GCM_SHA384",
            established_at: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            uptime: Duration::new(3725, 900_000_000),
            certificate_expires_at: UNIX_EPOCH + Duration::from_secs(1_700_000_001),
            bytes_received: 18_234,
            bytes_sent: 40_211,
        }
    }

    fn body(response: Response) -> Bytes {
        response
            .into_body()
            .collect()
            .now_or_never()
            .unwrap()
            .unwrap()
            .to_bytes()
    }

    #[test]
    fn listing_without_a_source_answers_s2s_inactive() {
        let response = list(None, None).unwrap_or_else(IntoResponse::into_response);
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(body(response), r#"{"error":{"code":"s2s_inactive"}}"#);
    }

    #[test]
    fn listing_requests_one_extra_connection_to_report_next_cursor() {
        for (stored, cursor) in [(0, Value::Null), (2, Value::Null), (3, json!(18))] {
            let source = Source {
                entries: (17..17 + stored).map(connection).collect(),
                ..Source::default()
            };
            let response =
                list(Some(&source), Some("limit=2")).unwrap_or_else(IntoResponse::into_response);
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(*source.last_request.lock(), Some((None, None, 3)));
            let body: Value = serde_json::from_slice(&body(response)).unwrap();
            let ids: Vec<_> = body["connections"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["connection_id"].as_u64().unwrap())
                .collect();
            assert_eq!(ids, (17..17 + stored.min(2)).collect::<Vec<_>>());
            assert_eq!(body["next_cursor"], cursor);
        }
    }

    #[test]
    fn listing_forwards_cursor_and_prepared_domain() {
        let source = Source::default();
        let response = list(Some(&source), Some("after=17&remote_domain=EXAMPLE.org"))
            .unwrap_or_else(IntoResponse::into_response);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            *source.last_request.lock(),
            Some((Some(17), Some("example.org".to_owned()), 51))
        );
    }

    #[test]
    fn listing_serializes_every_field_in_contract_order() {
        let source = Source {
            entries: vec![
                connection(17),
                S2sConnection {
                    direction: S2sDirection::Inbound,
                    bidirectional: false,
                    remote_address: None,
                    tls_mode: S2sTlsMode::Direct,
                    ..connection(18)
                },
            ],
            ..Source::default()
        };
        let response = list(Some(&source), None).unwrap_or_else(IntoResponse::into_response);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body(response),
            concat!(
                r#"{"connections":[{"connection_id":17,"direction":"outbound","bidirectional":true,"#,
                r#""local_domain":"example.com","remote_domain":"example.org","remote_address":"[2001:db8::1]:5269","#,
                r#""tls_mode":"starttls","tls_version":"TLSv1.3","cipher_suite":"TLS13_AES_256_GCM_SHA384","#,
                r#""established_at":"2023-11-14T22:13:20Z","uptime_secs":3725,"#,
                r#""certificate_expires_at":"2023-11-14T22:13:21Z","bytes_received":18234,"bytes_sent":40211},"#,
                r#"{"connection_id":18,"direction":"inbound","bidirectional":false,"#,
                r#""local_domain":"example.com","remote_domain":"example.org","remote_address":null,"#,
                r#""tls_mode":"direct","tls_version":"TLSv1.3","cipher_suite":"TLS13_AES_256_GCM_SHA384","#,
                r#""established_at":"2023-11-14T22:13:20Z","uptime_secs":3725,"#,
                r#""certificate_expires_at":"2023-11-14T22:13:21Z","bytes_received":18234,"bytes_sent":40211}],"#,
                r#""next_cursor":null}"#,
            )
        );
    }

    #[test]
    fn invalid_listing_queries_are_rejected() {
        let oversized = format!("remote_domain={}", "a".repeat(MAX_PART_LEN + 1));
        let source = Source::default();
        for (query, code) in [
            ("limit=0", "invalid_request"),
            ("limit=101", "invalid_request"),
            ("limit=x", "invalid_request"),
            ("after=x", "invalid_request"),
            ("after=-1", "invalid_request"),
            ("after=1&after=2", "invalid_request"),
            ("foo=1", "invalid_request"),
            ("after", "invalid_request"),
            ("remote_domain=%zz", "invalid_request"),
            (
                "remote_domain=example.org&remote_domain=example.com",
                "invalid_request",
            ),
            ("remote_domain=user%40example.org", "invalid_domain"),
            ("remote_domain=example.org%2Fres", "invalid_domain"),
            (&oversized, "invalid_domain"),
        ] {
            let response =
                list(Some(&source), Some(query)).unwrap_or_else(IntoResponse::into_response);
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
            assert_eq!(
                body(response),
                format!(r#"{{"error":{{"code":"{code}"}}}}"#).as_str(),
                "{query}"
            );
        }
        assert!(source.last_request.lock().is_none());
    }

    #[test]
    fn timestamps_serialize_as_utc_whole_seconds() -> Result<(), serde_json::Error> {
        for (timestamp, expected) in [
            (
                UNIX_EPOCH + Duration::new(1_700_000_000, 900_000_000),
                r#""2023-11-14T22:13:20Z""#,
            ),
            (
                UNIX_EPOCH - Duration::from_secs(1),
                r#""1970-01-01T00:00:00Z""#,
            ),
            (UNIX_EPOCH + Duration::from_secs(253_402_300_800), "null"),
        ] {
            assert_eq!(serde_json::to_string(&Timestamp(timestamp))?, expected);
        }
        Ok(())
    }
}
