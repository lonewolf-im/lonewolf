// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::convert::Infallible;
use std::num::NonZeroUsize;
use std::pin::pin;
use std::time::Instant;

use futures_util::StreamExt;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE};
use hyper::{Method, Request, Response, StatusCode};
use lonewolf_auth::scram::{
    ScramCredentials, ScramError, ScramHash, ScramIterations, ScramVerifier,
};
use lonewolf_storage::StorageErrorKind;
use lonewolf_storage::account::{AccountError, AccountKey, AccountRepository, NewAccount};
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_util::blocking::BlockingExecutor;
use lonewolf_xmpp::jid::{Jid, JidError, MAX_PART_LEN};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const MAX_BODY: usize = 16 * 1024;
const MAX_PAGE: usize = 100;
const DEFAULT_PAGE: usize = 50;

type HttpResponse = Response<Full<Bytes>>;

pub(crate) struct Api<R> {
    accounts: R,
    passwords: BlockingExecutor,
}

impl<R: AccountRepository> Api<R> {
    pub(crate) fn new(accounts: R) -> Self {
        Self {
            accounts,
            passwords: BlockingExecutor::new(const { NonZeroUsize::new(2).unwrap() }),
        }
    }

    pub(crate) async fn handle(
        &self,
        request: Request<Incoming>,
    ) -> Result<HttpResponse, Infallible> {
        let started = Instant::now();
        let response = match self.route(request).await {
            Ok(response) => response,
            Err(error) => error.response(),
        };
        tracing::debug!(
            status = response.status().as_u16(),
            latency_ms = started.elapsed().as_millis(),
            "admin request completed"
        );
        Ok(response)
    }

    async fn route(&self, request: Request<Incoming>) -> Result<HttpResponse, ApiError> {
        let (parts, body) = request.into_parts();
        let path = parts.uri.path();
        if path == "/v1/accounts" {
            return match parts.method {
                Method::GET => self.list(parts.uri.query()).await,
                Method::POST if parts.uri.query().is_none() => {
                    let input: CreateAccount = read_json(&parts.headers, body).await?;
                    let key = account_key(&input.jid)?;
                    let response = json(StatusCode::CREATED, &AccountView { jid: key.as_str() })?;
                    let credentials = self.credentials(input.password).await?;
                    self.accounts
                        .create(NewAccount { key, credentials })
                        .await?;
                    Ok(response)
                }
                Method::POST => Err(ApiError::bad_request()),
                _ => Err(ApiError::method_not_allowed("GET, POST")),
            };
        }
        let Some(account_path) = path.strip_prefix("/v1/accounts/") else {
            return Err(ApiError::not_found());
        };
        if parts.uri.query().is_some() {
            return Err(ApiError::bad_request());
        }
        let (encoded_key, password) = match account_path.strip_suffix("/password") {
            Some(key) => (key, true),
            None => (account_path, false),
        };
        if encoded_key.is_empty() || encoded_key.contains('/') {
            return Err(ApiError::not_found());
        }
        let key = account_key(&decode(encoded_key)?)?;
        if password {
            if parts.method != Method::PUT {
                return Err(ApiError::method_not_allowed("PUT"));
            }
            let input: ChangePassword = read_json(&parts.headers, body).await?;
            let credentials = self.credentials(input.password).await?;
            self.accounts.replace_credentials(&key, credentials).await?;
            return Ok(empty());
        }
        match parts.method {
            Method::GET => {
                let account = self
                    .accounts
                    .get(&key)
                    .await?
                    .ok_or_else(ApiError::not_found)?;
                json(
                    StatusCode::OK,
                    &AccountView {
                        jid: account.key.as_str(),
                    },
                )
            }
            Method::DELETE => {
                self.accounts.delete(&key).await?;
                Ok(empty())
            }
            _ => Err(ApiError::method_not_allowed("GET, DELETE")),
        }
    }

    async fn list(&self, query: Option<&str>) -> Result<HttpResponse, ApiError> {
        let (after, limit) = list_parameters(query)?;
        let mut stream = pin!(self.accounts.list(after));
        let mut bytes = Vec::with_capacity(1024);
        bytes.extend_from_slice(b"{\"accounts\":[");
        let mut last_key = None;
        let mut count = 0;
        while count < limit {
            let Some(account) = stream.next().await else {
                break;
            };
            let account = account?;
            if count > 0 {
                bytes.push(b',');
            }
            serde_json::to_writer(
                &mut bytes,
                &AccountView {
                    jid: account.key.as_str(),
                },
            )
            .map_err(|_| ApiError::internal())?;
            last_key = Some(account.key);
            count += 1;
        }
        let has_more = count == limit && stream.next().await.transpose()?.is_some();
        bytes.extend_from_slice(b"],\"next_cursor\":");
        let cursor = last_key
            .as_ref()
            .filter(|_| has_more)
            .map(AccountKey::as_str);
        serde_json::to_writer(&mut bytes, &cursor).map_err(|_| ApiError::internal())?;
        bytes.push(b'}');
        Ok(response(StatusCode::OK, bytes.into()))
    }

    async fn credentials(&self, password: Password) -> Result<ScramCredentials, ApiError> {
        self.passwords
            .run(move || {
                let iterations = ScramIterations::new(100_000)?;
                let sha1 = ScramVerifier::generate(ScramHash::Sha1, &password.0, iterations)?;
                let sha256 = ScramVerifier::generate(ScramHash::Sha256, &password.0, iterations)?;
                match (sha1, sha256) {
                    (ScramVerifier::Sha1(sha1), ScramVerifier::Sha256(sha256)) => {
                        Ok(ScramCredentials::both(sha1, sha256))
                    }
                    _ => Err(ScramError::DerivationFailed),
                }
            })
            .await
            .map_err(|error| match error {
                ScramError::InvalidPassword => {
                    ApiError::new(StatusCode::BAD_REQUEST, "invalid_password")
                }
                _ => {
                    tracing::error!("admin password derivation failed");
                    ApiError::internal()
                }
            })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateAccount {
    jid: String,
    password: Password,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangePassword {
    password: Password,
}

#[derive(Deserialize)]
#[serde(transparent)]
struct Password(String);

impl Drop for Password {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Serialize)]
struct AccountView<'a> {
    jid: &'a str,
}

async fn read_json<T: serde::de::DeserializeOwned>(
    headers: &hyper::HeaderMap,
    mut body: Incoming,
) -> Result<T, ApiError> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("application/json")
    {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
        ));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| ApiError::bad_request())?;
        if let Ok(data) = frame.into_data() {
            if data.len() > MAX_BODY - bytes.len() {
                return Err(ApiError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "body_too_large",
                ));
            }
            bytes.extend_from_slice(&data);
        }
    }
    serde_json::from_slice(&bytes).map_err(|_| ApiError::bad_request())
}

fn account_key(text: &str) -> Result<AccountKey, ApiError> {
    if text.len() > MAX_PART_LEN * 2 + 1 {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_jid"));
    }
    let mut arena = Arena::try_new(ArenaConfig::default()).map_err(|_| ApiError::internal())?;
    let jid = Jid::parse_in(text, &mut arena).map_err(|error| match error {
        JidError::AllocationFailed(_) | JidError::AccessFailed(_) => ApiError::internal(),
        _ => ApiError::new(StatusCode::BAD_REQUEST, "invalid_jid"),
    })?;
    let jid = jid.resolve(&arena).map_err(|_| ApiError::internal())?;
    AccountKey::try_from(jid).map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_jid"))
}

fn decode(value: &str) -> Result<Cow<'_, str>, ApiError> {
    for (i, byte) in value.bytes().enumerate() {
        if byte == b'%'
            && !value
                .as_bytes()
                .get(i + 1..i + 3)
                .is_some_and(|pair| pair.iter().all(u8::is_ascii_hexdigit))
        {
            return Err(ApiError::bad_request());
        }
    }
    percent_decode_str(value)
        .decode_utf8()
        .map_err(|_| ApiError::bad_request())
}

fn list_parameters(query: Option<&str>) -> Result<(Option<AccountKey>, usize), ApiError> {
    let mut after = None;
    let mut limit = None;
    if let Some(query) = query {
        for parameter in query.split('&') {
            let (name, value) = parameter
                .split_once('=')
                .ok_or_else(ApiError::bad_request)?;
            match name {
                "after" if after.is_none() => after = Some(account_key(&decode(value)?)?),
                "limit" if limit.is_none() => {
                    let value = value
                        .parse::<usize>()
                        .map_err(|_| ApiError::bad_request())?;
                    if !(1..=MAX_PAGE).contains(&value) {
                        return Err(ApiError::bad_request());
                    }
                    limit = Some(value);
                }
                _ => return Err(ApiError::bad_request()),
            }
        }
    }
    Ok((after, limit.unwrap_or(DEFAULT_PAGE)))
}

fn json(status: StatusCode, value: &impl Serialize) -> Result<HttpResponse, ApiError> {
    serde_json::to_vec(value)
        .map(|bytes| response(status, bytes.into()))
        .map_err(|_| ApiError::internal())
}

fn response(status: StatusCode, body: Bytes) -> HttpResponse {
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("no-store"),
    );
    response
}

fn empty() -> HttpResponse {
    response(StatusCode::NO_CONTENT, Bytes::new())
}

struct ApiError {
    status: StatusCode,
    code: &'static str,
    allow: Option<&'static str>,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str) -> Self {
        Self {
            status,
            code,
            allow: None,
        }
    }
    fn bad_request() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request")
    }
    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found")
    }
    fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
    }
    fn method_not_allowed(allow: &'static str) -> Self {
        Self {
            allow: Some(allow),
            ..Self::new(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed")
        }
    }
    fn response(self) -> HttpResponse {
        let mut response = response(
            self.status,
            format!("{{\"error\":{{\"code\":\"{}\"}}}}", self.code).into(),
        );
        if let Some(allow) = self.allow {
            response.headers_mut().insert(
                hyper::header::ALLOW,
                hyper::header::HeaderValue::from_static(allow),
            );
        }
        response
    }
}

impl From<AccountError> for ApiError {
    fn from(error: AccountError) -> Self {
        match error {
            AccountError::AlreadyExists => Self::new(StatusCode::CONFLICT, "account_exists"),
            AccountError::NotFound => Self::not_found(),
            AccountError::Storage(error) => {
                tracing::error!(kind = ?error.kind(), "admin storage operation failed");
                match error.kind() {
                    StorageErrorKind::Unavailable => {
                        Self::new(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable")
                    }
                    StorageErrorKind::CommitUnknown => {
                        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "commit_unknown")
                    }
                    _ => Self::internal(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use futures_util::Stream;
    use lonewolf_storage::StorageError;
    use lonewolf_storage::account::Account;

    use super::*;

    struct Repository {
        reads: Cell<usize>,
        active: Cell<bool>,
        fail_at: Option<usize>,
    }

    struct Entries<'a>(&'a Repository);

    impl Stream for Entries<'_> {
        type Item = Result<Account, AccountError>;

        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let index = self.0.reads.get();
            self.0.reads.set(index + 1);
            let account = if self.0.fail_at == Some(index) {
                Err(StorageError::with_source(
                    StorageErrorKind::CorruptData,
                    std::io::Error::other("secret backend details"),
                )
                .into())
            } else {
                account_key(&format!("user{index:05}@example.org"))
                    .map(|key| Account { key })
                    .map_err(|_| StorageError::new(StorageErrorKind::Other).into())
            };
            Poll::Ready(Some(account))
        }
    }

    impl Drop for Entries<'_> {
        fn drop(&mut self) {
            self.0.active.set(false);
        }
    }

    impl AccountRepository for Repository {
        async fn create(&self, _: NewAccount) -> Result<(), AccountError> {
            unreachable!()
        }
        async fn get(&self, _: &AccountKey) -> Result<Option<Account>, AccountError> {
            unreachable!()
        }
        fn list(&self, _: Option<AccountKey>) -> impl Stream<Item = Result<Account, AccountError>> {
            self.active.set(true);
            Entries(self)
        }
        async fn delete(&self, _: &AccountKey) -> Result<(), AccountError> {
            unreachable!()
        }
        async fn get_scram(
            &self,
            _: &AccountKey,
            _: ScramHash,
        ) -> Result<Option<ScramVerifier>, AccountError> {
            unreachable!()
        }
        async fn replace_credentials(
            &self,
            _: &AccountKey,
            _: ScramCredentials,
        ) -> Result<(), AccountError> {
            unreachable!()
        }
    }

    #[test]
    fn listing_reads_only_the_page_and_lookahead_and_releases_the_stream()
    -> Result<(), Box<dyn std::error::Error>> {
        compio::runtime::Runtime::new()?.block_on(async {
            let api = Api::new(Repository {
                reads: Cell::new(0),
                active: Cell::new(false),
                fail_at: Some(3),
            });
            let response = api
                .list(Some("limit=2"))
                .await
                .map_err(|_| "listing failed")?;
            assert_eq!(api.accounts.reads.get(), 3);
            assert!(!api.accounts.active.get());
            let bytes = response.into_body().collect().await?.to_bytes();
            let body: serde_json::Value = serde_json::from_slice(&bytes)?;
            assert_eq!(body["next_cursor"], "user00001@example.org");
            Ok(())
        })
    }

    #[test]
    fn listing_errors_discard_partial_results_and_release_the_stream()
    -> Result<(), Box<dyn std::error::Error>> {
        compio::runtime::Runtime::new()?.block_on(async {
            for fail_at in [1, 2] {
                let api = Api::new(Repository {
                    reads: Cell::new(0),
                    active: Cell::new(false),
                    fail_at: Some(fail_at),
                });
                let error = match api.list(Some("limit=2")).await {
                    Err(error) => error,
                    Ok(_) => return Err("listing should fail".into()),
                };
                assert!(!api.accounts.active.get());
                let response = error.response();
                assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
                let bytes = response.into_body().collect().await?.to_bytes();
                assert_eq!(&bytes[..], b"{\"error\":{\"code\":\"internal_error\"}}");
            }
            Ok(())
        })
    }

    #[test]
    fn unknown_commits_are_distinct_from_unavailable_storage() {
        let unknown = ApiError::from(AccountError::Storage(StorageError::new(
            StorageErrorKind::CommitUnknown,
        )));
        assert_eq!(unknown.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(unknown.code, "commit_unknown");
        let unavailable = ApiError::from(AccountError::Storage(StorageError::new(
            StorageErrorKind::Unavailable,
        )));
        assert_eq!(unavailable.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(unavailable.code, "storage_unavailable");
    }
}
