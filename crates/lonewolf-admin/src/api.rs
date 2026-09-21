// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::num::NonZeroUsize;
use std::pin::pin;
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{FromRequest, FromRequestParts, MatchedPath, Path, Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode, Uri, request::Parts};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use futures_util::StreamExt;
use http_body_util::BodyExt;
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

pub(crate) fn router<R: AccountRepository + 'static>(accounts: R) -> Router {
    Router::new()
        .route(
            "/v1/accounts",
            get(list_accounts::<R>).post(create_account::<R>),
        )
        .route(
            "/v1/accounts/{jid}",
            get(get_account::<R>).delete(delete_account::<R>),
        )
        .route("/v1/accounts/{jid}/password", put(change_password::<R>))
        .fallback(|| async { ApiError::not_found() })
        .method_not_allowed_fallback(|| async {
            ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed")
        })
        .layer(middleware::from_fn(log_request))
        .with_state(Arc::new(Api::new(accounts)))
}

async fn log_request(route: Option<MatchedPath>, request: Request, next: Next) -> Response {
    let started = Instant::now();
    let response = next.run(request).await;
    tracing::debug!(
        route = route.as_ref().map_or("unmatched", MatchedPath::as_str),
        status = response.status().as_u16(),
        latency_ms = started.elapsed().as_millis(),
        "admin request completed"
    );
    response
}

async fn list_accounts<R: AccountRepository>(
    State(api): State<Arc<Api<R>>>,
    uri: Uri,
) -> Result<Response, ApiError> {
    api.list(uri.query()).await
}

async fn create_account<R: AccountRepository>(
    State(api): State<Arc<Api<R>>>,
    SensitiveJson(input): SensitiveJson<CreateAccount>,
) -> Result<Response, ApiError> {
    let key = account_key(&input.jid)?;
    let response = json(StatusCode::CREATED, &AccountView { jid: key.as_str() })?;
    let credentials = api.credentials(input.password).await?;
    api.accounts.create(NewAccount { key, credentials }).await?;
    Ok(response)
}

async fn get_account<R: AccountRepository>(
    State(api): State<Arc<Api<R>>>,
    AccountPath(key): AccountPath,
) -> Result<Response, ApiError> {
    let account = api
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

async fn delete_account<R: AccountRepository>(
    State(api): State<Arc<Api<R>>>,
    AccountPath(key): AccountPath,
) -> Result<Response, ApiError> {
    api.accounts.delete(&key).await?;
    Ok(empty())
}

async fn change_password<R: AccountRepository>(
    State(api): State<Arc<Api<R>>>,
    AccountPath(key): AccountPath,
    SensitiveJson(input): SensitiveJson<ChangePassword>,
) -> Result<Response, ApiError> {
    let credentials = api.credentials(input.password).await?;
    api.accounts.replace_credentials(&key, credentials).await?;
    Ok(empty())
}

struct AccountPath(AccountKey);

impl<S: Send + Sync> FromRequestParts<S> for AccountPath {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if parts.uri.query().is_some() {
            return Err(ApiError::bad_request());
        }
        validate_percent_encoding(parts.uri.path())?;
        let Path(jid) = Path::<String>::from_request_parts(parts, state)
            .await
            .map_err(|_| ApiError::bad_request())?;
        account_key(&jid).map(Self)
    }
}

struct SensitiveJson<T>(T);

impl<S, T> FromRequest<S> for SensitiveJson<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, _: &S) -> Result<Self, Self::Rejection> {
        let (parts, body) = request.into_parts();
        if parts.uri.query().is_some() {
            return Err(ApiError::bad_request());
        }
        read_json(&parts.headers, body).await.map(Self)
    }
}

struct Api<R> {
    accounts: R,
    passwords: BlockingExecutor,
}

impl<R: AccountRepository> Api<R> {
    fn new(accounts: R) -> Self {
        Self {
            accounts,
            passwords: BlockingExecutor::new(const { NonZeroUsize::new(2).unwrap() }),
        }
    }

    async fn list(&self, query: Option<&str>) -> Result<Response, ApiError> {
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
    headers: &axum::http::HeaderMap,
    mut body: Body,
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

fn validate_percent_encoding(value: &str) -> Result<(), ApiError> {
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
    Ok(())
}

fn decode(value: &str) -> Result<Cow<'_, str>, ApiError> {
    validate_percent_encoding(value)?;
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

fn json(status: StatusCode, value: &impl Serialize) -> Result<Response, ApiError> {
    serde_json::to_vec(value)
        .map(|bytes| response(status, bytes.into()))
        .map_err(|_| ApiError::internal())
}

fn response(status: StatusCode, body: Bytes) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn empty() -> Response {
    response(StatusCode::NO_CONTENT, Bytes::new())
}

struct ApiError {
    status: StatusCode,
    code: &'static str,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str) -> Self {
        Self { status, code }
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
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        response(
            self.status,
            format!("{{\"error\":{{\"code\":\"{}\"}}}}", self.code).into(),
        )
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
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    use futures_util::Stream;
    use lonewolf_storage::StorageError;
    use lonewolf_storage::account::Account;

    use super::*;

    struct Repository {
        reads: AtomicUsize,
        active: AtomicBool,
        fail_at: Option<usize>,
    }

    struct Entries<'a>(&'a Repository);

    impl Stream for Entries<'_> {
        type Item = Result<Account, AccountError>;

        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let index = self.0.reads.fetch_add(1, Ordering::Relaxed);
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
            self.0.active.store(false, Ordering::Relaxed);
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
            self.active.store(true, Ordering::Relaxed);
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
                reads: AtomicUsize::new(0),
                active: AtomicBool::new(false),
                fail_at: Some(3),
            });
            let response = api
                .list(Some("limit=2"))
                .await
                .map_err(|_| "listing failed")?;
            assert_eq!(api.accounts.reads.load(Ordering::Relaxed), 3);
            assert!(!api.accounts.active.load(Ordering::Relaxed));
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
                    reads: AtomicUsize::new(0),
                    active: AtomicBool::new(false),
                    fail_at: Some(fail_at),
                });
                let error = match api.list(Some("limit=2")).await {
                    Err(error) => error,
                    Ok(_) => return Err("listing should fail".into()),
                };
                assert!(!api.accounts.active.load(Ordering::Relaxed));
                let response = error.into_response();
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
