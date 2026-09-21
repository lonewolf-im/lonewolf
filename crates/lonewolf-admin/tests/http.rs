// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use std::error::Error;
use std::fs;
use std::future::Future;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::time::Duration;

use compio::io::{AsyncReadExt, AsyncWriteExt};
use compio::net::UnixStream;
use compio::runtime::Runtime;
use futures_channel::oneshot;
use futures_util::future::join;
use lonewolf_admin::Server;
use lonewolf_auth::scram::{ScramCredentials, ScramHash, ScramIterations, ScramVerifier};
use lonewolf_storage::RedbDatabase;
use lonewolf_storage::account::redb::RedbAccountRepository;
use lonewolf_storage::account::{AccountKey, AccountRepository, NewAccount};
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::Jid;
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn Error>>;

fn with_server<F, Fut>(test: F) -> TestResult
where
    F: FnOnce(PathBuf, RedbAccountRepository) -> Fut,
    Fut: Future<Output = TestResult>,
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("private/admin.sock");
    let database = RedbDatabase::open(directory.path().join("accounts.redb"))?;
    let accounts = RedbAccountRepository::from_database(database.clone())?;
    Runtime::new()?.block_on(async {
        let server = Server::bind(
            &path,
            RedbAccountRepository::from_database(database.clone())?,
        )?;
        let (stop, stopped) = oneshot::channel();
        let client = async {
            let result = test(path.clone(), accounts).await;
            let _ = stop.send(());
            result
        };
        let (server_result, test_result) = compio::time::timeout(
            Duration::from_secs(60),
            join(
                server.run(async { stopped.await.map_err(io::Error::other) }),
                client,
            ),
        )
        .await?;
        server_result?;
        test_result?;
        assert!(!path.exists());
        Ok(())
    })
}

struct Reply {
    status: u16,
    headers: String,
    body: Value,
}

async fn raw(path: &Path, request: String) -> Result<Reply, Box<dyn Error>> {
    let mut stream = UnixStream::connect(path).await?;
    stream.write_all(request).await.0?;
    read_reply(stream).await
}

async fn read_reply(mut stream: UnixStream) -> Result<Reply, Box<dyn Error>> {
    let compio::BufResult(result, bytes) = stream.read_to_end(Vec::new()).await;
    result?;
    let response = std::str::from_utf8(&bytes)?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or("missing HTTP headers")?;
    let status = headers
        .split_whitespace()
        .nth(1)
        .ok_or("missing status")?
        .parse()?;
    let body = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(body)?
    };
    Ok(Reply {
        status,
        headers: headers.to_owned(),
        body,
    })
}

async fn request(
    path: &Path,
    method: &str,
    target: &str,
    body: Option<Value>,
) -> Result<Reply, Box<dyn Error>> {
    let body = body.map(|body| body.to_string()).unwrap_or_default();
    raw(path, format!("{method} {target} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len())).await
}

fn key(text: &str) -> Result<AccountKey, Box<dyn Error>> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in(text, &mut arena)?;
    Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
}

async fn seed(accounts: &RedbAccountRepository, text: &str) -> TestResult {
    let verifier = ScramVerifier::derive(
        ScramHash::Sha256,
        "initial",
        [1; 16],
        ScramIterations::new(4096)?,
    )?;
    accounts
        .create(NewAccount {
            key: key(text)?,
            credentials: ScramCredentials::new(verifier),
        })
        .await?;
    Ok(())
}

async fn assert_password(accounts: &RedbAccountRepository, password: &str) -> TestResult {
    for hash in [ScramHash::Sha1, ScramHash::Sha256] {
        let verifier = accounts
            .get_scram(&key("alice@example.org")?, hash)
            .await?
            .ok_or("missing credentials")?;
        let (salt, iterations) = match &verifier {
            ScramVerifier::Sha1(v) => (*v.salt(), v.iterations()),
            ScramVerifier::Sha256(v) => (*v.salt(), v.iterations()),
        };
        let expected = ScramVerifier::derive(
            hash,
            password,
            salt,
            ScramIterations::new(iterations.get())?,
        )?;
        match (verifier, expected) {
            (ScramVerifier::Sha1(actual), ScramVerifier::Sha1(expected)) => {
                assert_eq!(actual.stored_key(), expected.stored_key());
                assert_eq!(actual.server_key(), expected.server_key());
            }
            (ScramVerifier::Sha256(actual), ScramVerifier::Sha256(expected)) => {
                assert_eq!(actual.stored_key(), expected.stored_key());
                assert_eq!(actual.server_key(), expected.server_key());
            }
            _ => return Err("unexpected verifier".into()),
        }
    }
    Ok(())
}

#[test]
fn account_lifecycle_uses_canonical_jids_and_never_returns_credentials() -> TestResult {
    with_server(|path, accounts| async move {
        let input = json!({"jid":"Alice@EXAMPLE.ORG", "password":"first password"});
        let reply = request(&path, "POST", "/v1/accounts", Some(input.clone())).await?;
        assert_eq!(reply.status, 201);
        assert_eq!(reply.body, json!({"jid":"alice@example.org"}));
        assert!(reply.headers.contains("cache-control: no-store"));
        assert_password(&accounts, "first password").await?;

        assert_eq!(
            request(&path, "POST", "/v1/accounts", Some(input))
                .await?
                .status,
            409
        );
        let reply = request(&path, "GET", "/v1/accounts/ALICE%40example.org", None).await?;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, json!({"jid":"alice@example.org"}));

        let reply = request(
            &path,
            "PUT",
            "/v1/accounts/alice%40example.org/password",
            Some(json!({"password":"replacement"})),
        )
        .await?;
        assert_eq!(reply.status, 204);
        assert_eq!(reply.body, Value::Null);
        assert_password(&accounts, "replacement").await?;

        assert_eq!(
            request(&path, "DELETE", "/v1/accounts/alice%40example.org", None)
                .await?
                .status,
            204
        );
        assert_eq!(
            request(&path, "GET", "/v1/accounts/alice%40example.org", None)
                .await?
                .status,
            404
        );
        assert_eq!(
            request(&path, "DELETE", "/v1/accounts/alice%40example.org", None)
                .await?
                .status,
            404
        );
        for hash in [ScramHash::Sha1, ScramHash::Sha256] {
            assert!(
                accounts
                    .get_scram(&key("alice@example.org")?, hash)
                    .await?
                    .is_none()
            );
        }
        Ok(())
    })
}

#[test]
fn pagination_handles_empty_exact_and_partial_pages_and_deleted_cursors() -> TestResult {
    with_server(|path, accounts| async move {
        let reply = request(&path, "GET", "/v1/accounts", None).await?;
        assert_eq!(reply.body, json!({"accounts":[],"next_cursor":null}));
        for jid in [
            "charlie@example.org",
            "alice@example.org",
            "bob@example.org",
        ] {
            seed(&accounts, jid).await?;
        }
        let reply = request(&path, "GET", "/v1/accounts?limit=2", None).await?;
        assert_eq!(
            reply.body,
            json!({"accounts":[{"jid":"alice@example.org"},{"jid":"bob@example.org"}],"next_cursor":"bob@example.org"})
        );
        accounts.delete(&key("bob@example.org")?).await?;
        let reply = request(
            &path,
            "GET",
            "/v1/accounts?limit=2&after=bob%40example.org",
            None,
        )
        .await?;
        assert_eq!(
            reply.body,
            json!({"accounts":[{"jid":"charlie@example.org"}],"next_cursor":null})
        );
        let reply = request(&path, "GET", "/v1/accounts?limit=2", None).await?;
        assert_eq!(
            reply.body["accounts"]
                .as_array()
                .ok_or("missing accounts")?
                .len(),
            2
        );
        assert_eq!(reply.body["next_cursor"], Value::Null);
        Ok(())
    })
}

#[test]
fn rejects_invalid_routes_keys_queries_and_json() -> TestResult {
    with_server(|path, _| async move {
        for target in [
            "/v1/accounts?limit=0",
            "/v1/accounts?limit=101",
            "/v1/accounts?limit=no",
            "/v1/accounts?limit=1&limit=2",
            "/v1/accounts?unknown=1",
            "/v1/accounts?after=a%40example.org&after=b%40example.org",
            "/v1/accounts?after=%GG",
            "/v1/accounts?after=%FF",
            "/v1/accounts?after=example.org",
            "/v1/accounts/a%40example.org%2Fresource",
            "/v1/accounts/a%40example.org?limit=1",
            "/v1/accounts/bad%",
        ] {
            assert_eq!(
                request(&path, "GET", target, None).await?.status,
                400,
                "{target}"
            );
        }
        assert_eq!(request(&path, "GET", "/unknown", None).await?.status, 404);
        let reply = request(&path, "PATCH", "/v1/accounts", None).await?;
        assert_eq!(reply.status, 405);
        assert!(reply.headers.contains("allow: GET, POST"));
        for input in [
            json!({"jid":"example.org","password":"valid"}),
            json!({"jid":"a@example.org/resource","password":"valid"}),
            json!({"jid":"a@example.org","password":""}),
            json!({"jid":"a@example.org","password":"valid","extra":true}),
            json!({"jid":"a@example.org"}),
        ] {
            assert_eq!(
                request(&path, "POST", "/v1/accounts", Some(input))
                    .await?
                    .status,
                400
            );
        }
        assert_eq!(
            raw(
                &path,
                "POST /v1/accounts HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}"
                    .into()
            )
            .await?
            .status,
            415
        );
        assert_eq!(raw(&path, "POST /v1/accounts HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 1\r\n\r\n{".into()).await?.status, 400);
        Ok(())
    })
}

#[test]
fn limits_fixed_length_and_chunked_request_bodies() -> TestResult {
    with_server(|path, _| async move {
        let oversized = "x".repeat(17 * 1024);
        assert_eq!(
            request(
                &path,
                "POST",
                "/v1/accounts",
                Some(json!({"jid":"a@example.org","password":oversized}))
            )
            .await?
            .status,
            413
        );
        let reply = raw(&path, format!("POST /v1/accounts HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{:X}\r\n{}\r\n0\r\n\r\n", oversized.len(), oversized)).await?;
        assert_eq!(reply.status, 413);
        Ok(())
    })
}

#[test]
fn slow_client_does_not_block_other_connections() -> TestResult {
    with_server(|path, _| async move {
        let mut slow = UnixStream::connect(&path).await?;
        slow.write_all("POST /v1/accounts HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\nContent-Type: application/json\r\n\r\n{").await.0?;
        let reply = compio::time::timeout(
            Duration::from_secs(2),
            request(&path, "GET", "/v1/accounts", None),
        )
        .await??;
        assert_eq!(reply.status, 200);
        drop(slow);
        Ok(())
    })
}

#[test]
fn socket_permissions_and_existing_paths_are_preserved() -> TestResult {
    let directory = tempfile::tempdir()?;
    let database = RedbDatabase::open(directory.path().join("accounts.redb"))?;
    let accounts = || RedbAccountRepository::from_database(database.clone());
    Runtime::new()?.block_on(async {
        let path = directory.path().join("private/admin.sock");
        let server = Server::bind(&path, accounts()?)?;
        assert_eq!(
            fs::metadata(path.parent().ok_or("missing parent")?)?.mode() & 0o777,
            0o700
        );
        assert_eq!(fs::metadata(&path)?.mode() & 0o777, 0o600);
        assert!(Server::bind(&path, accounts()?).is_err());
        drop(server);
        assert!(!path.exists());

        let stale = std::os::unix::net::UnixListener::bind(&path)?;
        drop(stale);
        assert!(Server::bind(&path, accounts()?).is_err());
        assert!(path.exists());
        fs::remove_file(&path)?;

        fs::write(&path, "keep")?;
        assert!(Server::bind(&path, accounts()?).is_err());
        assert_eq!(fs::read_to_string(&path)?, "keep");
        fs::remove_file(&path)?;
        symlink(directory.path().join("target"), &path)?;
        assert!(Server::bind(&path, accounts()?).is_err());
        assert!(fs::symlink_metadata(&path)?.file_type().is_symlink());
        fs::remove_file(&path)?;

        let server = Server::bind(&path, accounts()?)?;
        fs::remove_file(&path)?;
        fs::write(&path, "replacement")?;
        drop(server);
        assert_eq!(fs::read_to_string(&path)?, "replacement");

        let public = directory.path().join("public");
        fs::create_dir(&public)?;
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755))?;
        assert!(Server::bind(&public.join("admin.sock"), accounts()?).is_err());
        Ok(())
    })
}

#[test]
fn shutdown_drains_an_accepted_request_and_removes_the_socket() -> TestResult {
    let directory = tempfile::tempdir()?;
    let database = RedbDatabase::open(directory.path().join("accounts.redb"))?;
    let accounts = RedbAccountRepository::from_database(database.clone())?;
    let path = directory.path().join("private/admin.sock");
    Runtime::new()?.block_on(async {
        let server = Server::bind(&path, accounts)?;
        let (stop, stopped) = oneshot::channel();
        let client = async {
            let body = r#"{"jid":"alice@example.org","password":"password"}"#;
            let mut stream = UnixStream::connect(&path).await?;
            stream.write_all(format!("POST /v1/accounts HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{{", body.len())).await.0?;
            assert_eq!(request(&path, "GET", "/v1/accounts", None).await?.status, 200);
            stop.send(()).map_err(|_| "server stopped early")?;
            stream.write_all(body[1..].to_owned()).await.0?;
            assert_eq!(read_reply(stream).await?.status, 201);
            TestResult::Ok(())
        };
        let (server_result, client_result) = compio::time::timeout(Duration::from_secs(30), join(
            server.run(async { stopped.await.map_err(io::Error::other) }), client,
        )).await?;
        server_result?;
        client_result?;
        assert!(!path.exists());
        let accounts = RedbAccountRepository::from_database(database)?;
        assert!(accounts.get(&key("alice@example.org")?).await?.is_some());
        Ok(())
    })
}
