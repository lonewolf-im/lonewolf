// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::future::Future;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{FromRequest, FromRequestParts, MatchedPath, Path, Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderValue, Method, StatusCode, Uri, request::Parts};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use futures_channel::oneshot;
use http_body_util::BodyExt;
use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramError, ScramHash, ScramIterations,
    ScramVerifier,
};
use lonewolf_storage::account::{
    AccountError, AccountKey, AccountReads, AccountWrites, NewAccount,
};
use lonewolf_storage::{Storage, StorageError, StorageErrorKind, WriteTransaction};

use crate::observer::AccountDeleter;
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_util::blocking::BlockingExecutor;
use lonewolf_xmpp::jid::{Jid, JidError, MAX_PART_LEN};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const MAX_BODY: usize = 16 * 1024;
const MAX_PAGE: usize = 100;
const DEFAULT_PAGE: usize = 50;

pub(crate) fn router<S: Storage>(storage: S, deleter: Arc<dyn AccountDeleter>) -> Router {
    Router::new()
        .route(
            "/v1/accounts",
            get(list_accounts::<S>).post(create_account::<S>),
        )
        .route(
            "/v1/accounts/{jid}",
            get(get_account::<S>).delete(delete_account::<S>),
        )
        .route("/v1/accounts/{jid}/password", put(change_password::<S>))
        .fallback(|| async { ApiError::not_found() })
        .method_not_allowed_fallback(|| async {
            ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed")
        })
        .layer(middleware::from_fn(log_request))
        .with_state(Arc::new(Api::new(storage, deleter)))
}

async fn log_request(route: Option<MatchedPath>, request: Request, next: Next) -> Response {
    let command = admin_command(request.method(), route.as_ref());
    let started = Instant::now();
    let response = next.run(request).await;
    if let Some(command) = command {
        tracing::info!(
            command,
            status = response.status().as_u16(),
            latency_ms = started.elapsed().as_millis(),
            "admin command handled"
        );
    } else {
        // Concrete paths and queries can contain account identities or secrets.
        tracing::debug!(
            route = route.as_ref().map_or("unmatched", MatchedPath::as_str),
            status = response.status().as_u16(),
            latency_ms = started.elapsed().as_millis(),
            "admin request completed"
        );
    }
    response
}

fn admin_command(method: &Method, route: Option<&MatchedPath>) -> Option<&'static str> {
    match (method.as_str(), route.map(MatchedPath::as_str)) {
        ("GET", Some("/v1/accounts")) => Some("account_list"),
        ("POST", Some("/v1/accounts")) => Some("account_create"),
        ("GET", Some("/v1/accounts/{jid}")) => Some("account_get"),
        ("DELETE", Some("/v1/accounts/{jid}")) => Some("account_delete"),
        ("PUT", Some("/v1/accounts/{jid}/password")) => Some("account_password"),
        _ => None,
    }
}

async fn list_accounts<S: Storage>(
    State(api): State<Arc<Api<S>>>,
    uri: Uri,
) -> Result<Response, ApiError> {
    api.list(uri.query()).await
}

async fn create_account<S: Storage>(
    State(api): State<Arc<Api<S>>>,
    SensitiveJson(input): SensitiveJson<CreateAccount>,
) -> Result<Response, ApiError> {
    api.create(account_key(&input.jid)?, input.password).await
}

async fn get_account<S: Storage>(
    State(api): State<Arc<Api<S>>>,
    AccountPath(key): AccountPath,
) -> Result<Response, ApiError> {
    let account = api
        .storage
        .begin_read()
        .await?
        .account(&key)
        .await?
        .ok_or_else(ApiError::not_found)?;
    json(
        StatusCode::OK,
        &AccountView {
            jid: account.key.as_str(),
        },
    )
}

async fn delete_account<S: Storage>(
    State(api): State<Arc<Api<S>>>,
    AccountPath(key): AccountPath,
) -> Result<Response, ApiError> {
    api.delete(key).await
}

async fn change_password<S: Storage>(
    State(api): State<Arc<Api<S>>>,
    AccountPath(key): AccountPath,
    SensitiveJson(input): SensitiveJson<ChangePassword>,
) -> Result<Response, ApiError> {
    let credentials = api.credentials(input.password).await?;
    let mut write = api.storage.begin_write().await?;
    write.replace_credentials(&key, credentials).await?;
    write.commit().await?;
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

struct Api<S> {
    storage: S,
    deleter: Arc<dyn AccountDeleter>,
    passwords: BlockingExecutor,
}

impl<S: Storage> Api<S> {
    fn new(storage: S, deleter: Arc<dyn AccountDeleter>) -> Self {
        Self {
            storage,
            deleter,
            passwords: BlockingExecutor::new(const { NonZeroUsize::new(2).unwrap() }),
        }
    }

    async fn create(&self, key: AccountKey, password: Password) -> Result<Response, ApiError> {
        let response = json(StatusCode::CREATED, &AccountView { jid: key.as_str() })?;
        let credentials = self.credentials(password).await?;
        let mut write = self.storage.begin_write().await?;
        write
            .create_account(NewAccount { key, credentials })
            .await?;
        write.commit().await?;
        Ok(response)
    }

    async fn delete(self: &Arc<Self>, key: AccountKey) -> Result<Response, ApiError> {
        let existed = self
            .run_to_completion(key, |api, key| async move {
                api.deleter.delete(&key).await.map_err(|error| {
                    tracing::error!(error = %error, "account deletion failed");
                    ApiError::internal()
                })
            })
            .await?;
        if existed {
            Ok(empty())
        } else {
            Err(ApiError::not_found())
        }
    }

    /// Runs a deletion in a task of its own, so a request abandoned by the connection
    /// deadline still delivers the notifications and ends the sessions that follow the
    /// commit.
    async fn run_to_completion<T, Fut>(
        self: &Arc<Self>,
        key: AccountKey,
        operation: impl FnOnce(Arc<Self>, AccountKey) -> Fut + 'static,
    ) -> Result<T, ApiError>
    where
        Fut: Future<Output = Result<T, ApiError>> + 'static,
        T: 'static,
    {
        let (done, completed) = oneshot::channel();
        let api = Arc::clone(self);
        compio::runtime::spawn(async move {
            let result = operation(api, key).await;
            let _ = done.send(result);
        })
        .detach();
        completed
            .await
            .unwrap_or_else(|_| Err(ApiError::internal()))
    }

    async fn list(&self, query: Option<&str>) -> Result<Response, ApiError> {
        let (after, limit) = list_parameters(query)?;
        let lookahead = NonZeroUsize::MIN.saturating_add(limit);
        let mut page = self
            .storage
            .begin_read()
            .await?
            .accounts_after(after.as_ref(), lookahead)
            .await?;
        let has_more = page.len() > limit;
        page.truncate(limit);
        let mut bytes = Vec::with_capacity(1024);
        bytes.extend_from_slice(b"{\"accounts\":[");
        for (index, account) in page.iter().enumerate() {
            if index > 0 {
                bytes.push(b',');
            }
            serde_json::to_writer(
                &mut bytes,
                &AccountView {
                    jid: account.key.as_str(),
                },
            )
            .map_err(|_| ApiError::internal())?;
        }
        bytes.extend_from_slice(b"],\"next_cursor\":");
        let cursor = page
            .last()
            .filter(|_| has_more)
            .map(|account| account.key.as_str());
        serde_json::to_writer(&mut bytes, &cursor).map_err(|_| ApiError::internal())?;
        bytes.push(b'}');
        Ok(response(StatusCode::OK, bytes.into()))
    }

    async fn credentials(&self, password: Password) -> Result<ScramCredentials, ApiError> {
        self.passwords
            .run(move || {
                let iterations = ScramIterations::new(SCRAM_POLICY_ITERATIONS.get())?;
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

// The percent decoder preserves malformed escapes instead of rejecting them.
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
            AccountError::UnsupportedIterations => {
                tracing::error!("admin generated unsupported SCRAM iterations");
                Self::internal()
            }
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

impl From<StorageError> for ApiError {
    fn from(error: StorageError) -> Self {
        Self::from(AccountError::Storage(error))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::ops::Bound;
    use std::pin::{Pin, pin};
    use std::sync::PoisonError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use async_lock::{Mutex, MutexGuardArc};
    use compio::time::{sleep, timeout};
    use lonewolf_auth::server::ScramDecoy;
    use lonewolf_storage::ReadTransaction;
    use lonewolf_storage::account::Account;
    use lonewolf_storage::roster::{self, RosterReads, RosterWrites};
    use serde_json::{Value, json};

    use super::*;
    use crate::observer::{DeleterError, RecordDeleter};

    type TestError = Box<dyn std::error::Error + Send + Sync>;
    type TestResult = Result<(), TestError>;

    /// Keeps accounts in memory with snapshot reads and staged, single-writer commits.
    #[derive(Clone)]
    struct MemoryStorage {
        inner: Arc<MemoryInner>,
    }

    struct MemoryInner {
        state: std::sync::Mutex<MemoryState>,
        writer: Arc<Mutex<()>>,
        decoy: ScramDecoy,
    }

    #[derive(Default)]
    struct MemoryState {
        accounts: BTreeSet<AccountKey>,
        listing_failure: Option<StorageErrorKind>,
        last_listing: Option<(Option<AccountKey>, NonZeroUsize)>,
    }

    struct MemoryTransaction {
        storage: MemoryStorage,
        accounts: BTreeSet<AccountKey>,
        _writer: Option<MutexGuardArc<()>>,
    }

    impl MemoryStorage {
        fn new(keys: impl IntoIterator<Item = AccountKey>) -> Self {
            Self {
                inner: Arc::new(MemoryInner {
                    state: std::sync::Mutex::new(MemoryState {
                        accounts: keys.into_iter().collect(),
                        ..MemoryState::default()
                    }),
                    writer: Arc::new(Mutex::new(())),
                    decoy: ScramDecoy::from_secret([0; 32]),
                }),
            }
        }

        fn state(&self) -> std::sync::MutexGuard<'_, MemoryState> {
            self.inner
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
        }

        fn fail_listing(&self, kind: StorageErrorKind) {
            self.state().listing_failure = Some(kind);
        }

        fn last_listing(&self) -> Option<(Option<AccountKey>, NonZeroUsize)> {
            self.state().last_listing.take()
        }

        fn transaction(&self, writer: Option<MutexGuardArc<()>>) -> MemoryTransaction {
            MemoryTransaction {
                storage: self.clone(),
                accounts: self.state().accounts.clone(),
                _writer: writer,
            }
        }
    }

    impl Storage for MemoryStorage {
        type Read = MemoryTransaction;
        type Write = MemoryTransaction;

        async fn begin_read(&self) -> Result<MemoryTransaction, StorageError> {
            Ok(self.transaction(None))
        }

        async fn begin_write(&self) -> Result<MemoryTransaction, StorageError> {
            let writer = Arc::clone(&self.inner.writer).lock_arc().await;
            Ok(self.transaction(Some(writer)))
        }

        fn scram_decoy(&self) -> &ScramDecoy {
            &self.inner.decoy
        }
    }

    impl ReadTransaction for MemoryTransaction {}

    impl WriteTransaction for MemoryTransaction {
        async fn commit(self) -> Result<(), StorageError> {
            self.storage.state().accounts = self.accounts;
            Ok(())
        }
    }

    impl AccountReads for MemoryTransaction {
        async fn account(&self, key: &AccountKey) -> Result<Option<Account>, AccountError> {
            Ok(self
                .accounts
                .contains(key)
                .then(|| Account { key: key.clone() }))
        }

        async fn scram(
            &self,
            _: &AccountKey,
            _: ScramHash,
        ) -> Result<Option<ScramVerifier>, AccountError> {
            Ok(None)
        }

        async fn accounts_after(
            &self,
            after: Option<&AccountKey>,
            limit: NonZeroUsize,
        ) -> Result<Vec<Account>, AccountError> {
            let mut state = self.storage.state();
            state.last_listing = Some((after.cloned(), limit));
            if let Some(kind) = state.listing_failure {
                return Err(StorageError::with_source(
                    kind,
                    std::io::Error::other("secret backend details"),
                )
                .into());
            }
            Ok(self
                .accounts
                .range((
                    after.map_or(Bound::Unbounded, Bound::Excluded),
                    Bound::Unbounded,
                ))
                .take(limit.get())
                .map(|key| Account { key: key.clone() })
                .collect())
        }
    }

    impl AccountWrites for MemoryTransaction {
        async fn create_account(&mut self, account: NewAccount) -> Result<(), AccountError> {
            self.accounts
                .insert(account.key)
                .then_some(())
                .ok_or(AccountError::AlreadyExists)
        }

        async fn delete_account(&mut self, key: &AccountKey) -> Result<(), AccountError> {
            self.accounts
                .remove(key)
                .then_some(())
                .ok_or(AccountError::NotFound)
        }

        async fn replace_credentials(
            &mut self,
            key: &AccountKey,
            _: ScramCredentials,
        ) -> Result<(), AccountError> {
            self.accounts
                .contains(key)
                .then_some(())
                .ok_or(AccountError::NotFound)
        }
    }

    impl RosterReads for MemoryTransaction {
        async fn roster(
            &self,
            _: &AccountKey,
        ) -> Result<roster::RosterSnapshot, roster::RosterError> {
            unreachable!()
        }

        async fn roster_item(
            &self,
            _: &AccountKey,
            _: &roster::RosterJid,
        ) -> Result<Option<roster::RosterItem>, roster::RosterError> {
            unreachable!()
        }

        async fn pending_requests(
            &self,
            _: &AccountKey,
        ) -> Result<Vec<roster::PendingSubscription>, roster::RosterError> {
            unreachable!()
        }

        async fn pending_request(
            &self,
            _: &AccountKey,
            _: &roster::RosterJid,
        ) -> Result<Option<roster::PendingSubscription>, roster::RosterError> {
            unreachable!()
        }
    }

    impl RosterWrites for MemoryTransaction {
        async fn put_roster_item(
            &mut self,
            _: &AccountKey,
            _: &roster::RosterItem,
        ) -> Result<roster::RosterVersion, roster::RosterError> {
            unreachable!()
        }
        async fn remove_roster_item(
            &mut self,
            _: &AccountKey,
            _: &roster::RosterJid,
        ) -> Result<Option<roster::RosterMutation<roster::RosterItem>>, roster::RosterError>
        {
            unreachable!()
        }
        async fn put_pending_request(
            &mut self,
            _: &AccountKey,
            _: roster::PendingSubscription,
        ) -> Result<(), roster::RosterError> {
            unreachable!()
        }
        async fn remove_pending_request(
            &mut self,
            _: &AccountKey,
            _: &roster::RosterJid,
        ) -> Result<bool, roster::RosterError> {
            unreachable!()
        }
        async fn clear_roster(&mut self, _: &AccountKey) -> Result<(), roster::RosterError> {
            unreachable!()
        }
    }

    /// Removes the record through the wrapped storage, counts calls, optionally reports
    /// when a deletion starts and holds it until released, and fails the first `failures`
    /// calls before touching storage.
    struct GatedDeleter {
        storage: MemoryStorage,
        started: std::sync::Mutex<Option<oneshot::Sender<()>>>,
        release: std::sync::Mutex<Option<oneshot::Receiver<()>>>,
        failures: AtomicUsize,
        calls: AtomicUsize,
    }

    impl GatedDeleter {
        fn new(
            storage: MemoryStorage,
            started: Option<oneshot::Sender<()>>,
            release: Option<oneshot::Receiver<()>>,
            failures: usize,
        ) -> Arc<Self> {
            Arc::new(Self {
                storage,
                started: std::sync::Mutex::new(started),
                release: std::sync::Mutex::new(release),
                failures: AtomicUsize::new(failures),
                calls: AtomicUsize::new(0),
            })
        }

        fn counting(storage: MemoryStorage) -> Arc<Self> {
            Self::new(storage, None, None, 0)
        }

        fn failing_once(storage: MemoryStorage) -> Arc<Self> {
            Self::new(storage, None, None, 1)
        }

        fn gated(
            storage: MemoryStorage,
        ) -> (Arc<Self>, oneshot::Receiver<()>, oneshot::Sender<()>) {
            let (started, deletion_started) = oneshot::channel();
            let (release, released) = oneshot::channel();
            (
                Self::new(storage, Some(started), Some(released), 0),
                deletion_started,
                release,
            )
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl AccountDeleter for GatedDeleter {
        fn delete<'a>(
            &'a self,
            account: &'a AccountKey,
        ) -> Pin<Box<dyn Future<Output = Result<bool, DeleterError>> + Send + 'a>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let started = self
                .started
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            let release = self
                .release
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            let fails = self
                .failures
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                    left.checked_sub(1)
                })
                .is_ok();
            Box::pin(async move {
                if let Some(started) = started {
                    let _ = started.send(());
                }
                if let Some(release) = release {
                    let _ = release.await;
                }
                if fails {
                    return Err("deletion failed".into());
                }
                let mut transaction = self.storage.begin_write().await?;
                let existed = match transaction.delete_account(account).await {
                    Ok(()) => true,
                    Err(AccountError::NotFound) => false,
                    Err(error) => return Err(error.into()),
                };
                transaction.commit().await?;
                Ok(existed)
            })
        }
    }

    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    fn user_keys(count: usize) -> Result<Vec<AccountKey>, &'static str> {
        (0..count)
            .map(|index| account_key(&format!("user{index:05}@example.org")))
            .collect::<Result<_, _>>()
            .map_err(|error| error.code)
    }

    async fn list_body(api: &Api<MemoryStorage>, query: &str) -> Result<Value, TestError> {
        let response = api.list(Some(query)).await.map_err(|error| error.code)?;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await?.to_bytes();
        Ok(serde_json::from_slice(&bytes)?)
    }

    async fn stored(storage: &MemoryStorage, key: &AccountKey) -> Result<bool, TestError> {
        Ok(storage.begin_read().await?.account(key).await?.is_some())
    }

    async fn wait_until_absent(storage: &MemoryStorage, key: &AccountKey) -> TestResult {
        let settled = async {
            while stored(storage, key).await? {
                sleep(Duration::from_millis(1)).await;
            }
            Ok(())
        };
        timeout(Duration::from_secs(5), settled)
            .await
            .map_err(|_| "the record was not removed")?
    }

    async fn expect_error(
        result: Result<Response, ApiError>,
        status: StatusCode,
        code: &str,
    ) -> TestResult {
        let response = match result {
            Err(error) => error.into_response(),
            Ok(_) => return Err("request should fail".into()),
        };
        assert_eq!(response.status(), status);
        let bytes = response.into_body().collect().await?.to_bytes();
        assert_eq!(
            &bytes[..],
            format!("{{\"error\":{{\"code\":\"{code}\"}}}}").as_bytes()
        );
        Ok(())
    }

    #[test]
    fn deletion_answers_no_content_and_removes_the_record() -> TestResult {
        compio::runtime::Runtime::new()?.block_on(async {
            let key = account_key("alice@example.org").map_err(|error| error.code)?;
            let storage = MemoryStorage::new([key.clone()]);
            let deleter = GatedDeleter::counting(storage.clone());
            let api = Arc::new(Api::new(storage.clone(), deleter.clone()));

            let response = api.delete(key.clone()).await.map_err(|error| error.code)?;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert!(!stored(&storage, &key).await?);
            assert_eq!(deleter.calls(), 1);
            Ok(())
        })
    }

    #[test]
    fn deleting_an_absent_account_answers_not_found() -> TestResult {
        compio::runtime::Runtime::new()?.block_on(async {
            let key = account_key("alice@example.org").map_err(|error| error.code)?;
            let storage = MemoryStorage::new([]);
            let deleter = GatedDeleter::counting(storage.clone());
            let api = Arc::new(Api::new(storage.clone(), deleter.clone()));

            let result = api.delete(key.clone()).await;
            expect_error(result, StatusCode::NOT_FOUND, "not_found").await?;
            assert_eq!(deleter.calls(), 1);
            Ok(())
        })
    }

    #[test]
    fn failed_deletion_answers_internal_error_and_changes_nothing() -> TestResult {
        compio::runtime::Runtime::new()?.block_on(async {
            let key = account_key("alice@example.org").map_err(|error| error.code)?;
            let storage = MemoryStorage::new([key.clone()]);
            let deleter = GatedDeleter::failing_once(storage.clone());
            let api = Arc::new(Api::new(storage.clone(), deleter.clone()));

            let failed = api.delete(key.clone()).await;
            expect_error(failed, StatusCode::INTERNAL_SERVER_ERROR, "internal_error").await?;
            assert!(stored(&storage, &key).await?);
            assert_eq!(deleter.calls(), 1);

            let response = api.delete(key.clone()).await.map_err(|error| error.code)?;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert!(!stored(&storage, &key).await?);
            assert_eq!(deleter.calls(), 2);
            Ok(())
        })
    }

    #[test]
    fn abandoned_deletion_still_completes() -> TestResult {
        compio::runtime::Runtime::new()?.block_on(async {
            let key = account_key("alice@example.org").map_err(|error| error.code)?;
            let storage = MemoryStorage::new([key.clone()]);
            let (deleter, deletion_started, release) = GatedDeleter::gated(storage.clone());
            let api = Arc::new(Api::new(storage.clone(), deleter.clone()));
            {
                let mut delete = pin!(api.delete(key.clone()));
                assert!(poll_once(delete.as_mut()).is_pending());
            }
            deletion_started.await?;
            assert!(stored(&storage, &key).await?);

            release.send(()).map_err(|_| "deletion is not waiting")?;
            wait_until_absent(&storage, &key).await?;
            assert_eq!(deleter.calls(), 1);
            Ok(())
        })
    }

    #[test]
    fn recreation_after_deletion_succeeds() -> TestResult {
        compio::runtime::Runtime::new()?.block_on(async {
            let key = account_key("alice@example.org").map_err(|error| error.code)?;
            let storage = MemoryStorage::new([key.clone()]);
            let deleter = GatedDeleter::counting(storage.clone());
            let api = Arc::new(Api::new(storage.clone(), deleter.clone()));

            let response = api.delete(key.clone()).await.map_err(|error| error.code)?;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert!(!stored(&storage, &key).await?);

            let response = api
                .create(key.clone(), Password("secret".into()))
                .await
                .map_err(|error| error.code)?;
            assert_eq!(response.status(), StatusCode::CREATED);
            assert!(stored(&storage, &key).await?);
            Ok(())
        })
    }

    #[test]
    fn record_deleter_removes_the_record_and_reports_whether_it_existed() -> TestResult {
        compio::runtime::Runtime::new()?.block_on(async {
            let key = account_key("alice@example.org").map_err(|error| error.code)?;
            let storage = MemoryStorage::new([key.clone()]);
            let deleter = RecordDeleter::new(storage.clone());

            assert!(deleter.delete(&key).await?);
            assert!(!stored(&storage, &key).await?);
            assert!(!deleter.delete(&key).await?);
            assert!(!stored(&storage, &key).await?);
            Ok(())
        })
    }

    #[test]
    fn listing_requests_one_extra_entry_to_report_has_more() -> TestResult {
        compio::runtime::Runtime::new()?.block_on(async {
            let keys = user_keys(3)?;
            let lookahead = const { NonZeroUsize::new(3).unwrap() };
            for (stored, cursor) in [
                (0, Value::Null),
                (1, Value::Null),
                (2, Value::Null),
                (3, Value::from("user00001@example.org")),
            ] {
                let storage = MemoryStorage::new(keys.iter().take(stored).cloned());
                let api = Api::new(
                    storage.clone(),
                    Arc::new(RecordDeleter::new(storage.clone())),
                );
                let body = list_body(&api, "limit=2").await?;
                assert_eq!(
                    storage.last_listing(),
                    Some((None, lookahead)),
                    "stored {stored}"
                );
                assert_eq!(
                    body["accounts"].as_array().map(Vec::len),
                    Some(stored.min(2)),
                    "stored {stored}"
                );
                assert_eq!(body["next_cursor"], cursor, "stored {stored}");
            }

            let storage = MemoryStorage::new(keys.iter().cloned());
            let api = Api::new(
                storage.clone(),
                Arc::new(RecordDeleter::new(storage.clone())),
            );
            let body = list_body(&api, "after=user00000%40example.org&limit=2").await?;
            assert_eq!(
                storage.last_listing(),
                Some((Some(keys[0].clone()), lookahead))
            );
            assert_eq!(
                body["accounts"],
                json!([{"jid": "user00001@example.org"}, {"jid": "user00002@example.org"}])
            );
            assert_eq!(body["next_cursor"], Value::Null);
            Ok(())
        })
    }

    #[test]
    fn listing_failures_yield_the_mapped_error_without_partial_output() -> TestResult {
        compio::runtime::Runtime::new()?.block_on(async {
            let keys = user_keys(3)?;
            for (kind, status, code) in [
                (
                    StorageErrorKind::CorruptData,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                ),
                (
                    StorageErrorKind::Unavailable,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "storage_unavailable",
                ),
            ] {
                let storage = MemoryStorage::new(keys.iter().cloned());
                storage.fail_listing(kind);
                let api = Api::new(
                    storage.clone(),
                    Arc::new(RecordDeleter::new(storage.clone())),
                );
                let error = match api.list(Some("limit=2")).await {
                    Err(error) => error,
                    Ok(_) => return Err("listing should fail".into()),
                };
                let response = error.into_response();
                assert_eq!(response.status(), status);
                let bytes = response.into_body().collect().await?.to_bytes();
                assert_eq!(
                    &bytes[..],
                    format!("{{\"error\":{{\"code\":\"{code}\"}}}}").as_bytes()
                );
            }
            Ok(())
        })
    }

    #[test]
    fn unknown_commits_are_distinct_from_unavailable_storage() {
        let unknown = ApiError::from(StorageError::new(StorageErrorKind::CommitUnknown));
        assert_eq!(unknown.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(unknown.code, "commit_unknown");
        let unavailable = ApiError::from(AccountError::Storage(StorageError::new(
            StorageErrorKind::Unavailable,
        )));
        assert_eq!(unavailable.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(unavailable.code, "storage_unavailable");
    }
}
