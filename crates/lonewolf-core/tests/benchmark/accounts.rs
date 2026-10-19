// SPDX-License-Identifier: Apache-2.0

use lonewolf_bench::accounts::{
    CredentialSet, ProvisionSummary, generate_credentials, provision_accounts,
};
use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixListener,
    path::Path,
    process::{Command, Output},
    thread,
    time::Duration,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn cli(args: &[&std::ffi::OsStr]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_lonewolf-bench"))
        .args(args)
        .output()
}

fn read_request(stream: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut request = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Err(std::io::Error::other("request ended early"));
        }
        request.extend_from_slice(&chunk[..count]);
        if request.len() > 20000 {
            return Err(std::io::Error::other("request too large"));
        }
        if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&request[..end]).map_err(std::io::Error::other)?;
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                        .map(|(_, value)| value.trim().parse::<usize>())
                })
                .ok_or_else(|| std::io::Error::other("missing length"))?
                .map_err(std::io::Error::other)?;
            if request.len() >= end + 4 + length {
                return Ok(request);
            }
        }
    }
}

fn reply(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn mock(
    socket: &Path,
    replies: Vec<Vec<u8>>,
) -> std::io::Result<thread::JoinHandle<std::io::Result<Vec<Vec<u8>>>>> {
    let listener = UnixListener::bind(socket)?;
    listener.set_nonblocking(true)?;
    Ok(thread::spawn(move || {
        let mut requests = Vec::new();
        for reply in replies {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => return Err(error),
                }
            };
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            requests.push(read_request(&mut stream)?);
            let _ = stream.write_all(&reply);
        }
        Ok(requests)
    }))
}

#[test]
fn generated_cli_manifest_is_provisioned_in_file_order_over_explicit_uds() -> TestResult {
    let directory = tempfile::tempdir()?;
    let credentials = directory.path().join("credentials.json");
    let socket = directory.path().join("admin.sock");
    let output = cli(&[
        "accounts".as_ref(),
        "generate".as_ref(),
        "--domain".as_ref(),
        "localhost".as_ref(),
        "--prefix".as_ref(),
        "bench".as_ref(),
        "--count".as_ref(),
        "2".as_ref(),
        "--output".as_ref(),
        credentials.as_os_str(),
    ])?;
    assert!(output.status.success());
    let original = fs::read(&credentials)?;
    let server = mock(
        &socket,
        vec![reply("201 Created", "{}"), reply("201 Created", "{}")],
    )?;
    let output = cli(&[
        "accounts".as_ref(),
        "provision".as_ref(),
        "--socket".as_ref(),
        socket.as_os_str(),
        "--credentials".as_ref(),
        credentials.as_os_str(),
    ])?;
    let requests = server.join().map_err(|_| "mock panicked")??;
    assert!(output.status.success());
    assert_eq!(
        std::str::from_utf8(&output.stdout)?,
        "confirmed_created=2; uncertain_last_create=false\n"
    );
    assert!(std::str::from_utf8(&requests[0])?.contains("bench-000000@localhost"));
    assert!(std::str::from_utf8(&requests[1])?.contains("bench-000001@localhost"));
    assert_eq!(fs::read(&credentials)?, original);
    assert!(
        cli(&[
            "accounts".as_ref(),
            "generate".as_ref(),
            "--domain".as_ref(),
            "localhost".as_ref(),
            "--prefix".as_ref(),
            "bench".as_ref(),
            "--count".as_ref(),
            "2".as_ref(),
            "--output".as_ref(),
            credentials.as_os_str()
        ])?
        .status
        .code()
        .is_some_and(|code| code != 0)
    );
    assert_eq!(fs::read(&credentials)?, original);
    Ok(())
}

#[tokio::test]
async fn provisioning_stops_on_conflict_and_preserves_confirmed_prefix() -> TestResult {
    let directory = tempfile::tempdir()?;
    let credentials = directory.path().join("credentials.json");
    let socket = directory.path().join("admin.sock");
    generate_credentials("localhost", "bench", 3, &credentials)?;
    let credentials = CredentialSet::read(&credentials, None, None)?;
    let server = mock(
        &socket,
        vec![
            reply("201 Created", "{}"),
            reply("409 Conflict", r#"{"error":{"code":"account_exists"}}"#),
        ],
    )?;
    let error = provision_accounts(&socket, &credentials)
        .await
        .err()
        .ok_or("expected conflict")?;
    assert_eq!(
        error.provision_summary(),
        Some(ProvisionSummary {
            confirmed_created: 1,
            uncertain_last_create: false
        })
    );
    assert_eq!(server.join().map_err(|_| "mock panicked")??.len(), 2);
    assert!(!error.to_string().contains("bench-"));
    Ok(())
}

#[tokio::test]
async fn acknowledgment_and_uncertainty_survive_partial_and_invalid_responses() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("credentials.json");
    generate_credentials("localhost", "bench", 2, &path)?;
    let credentials = CredentialSet::read(&path, None, None)?;
    let cases = [
        (
            b"HTTP/1.1 201 Created\r\ncontent-length: 100\r\n\r\n{".to_vec(),
            1,
            false,
        ),
        (
            b"HTTP/1.1 409 Conflict\r\ncontent-length: 100\r\n\r\n{".to_vec(),
            0,
            true,
        ),
        (reply("409 Conflict", "secret-invalid-json"), 0, true),
        (
            reply(
                "409 Conflict",
                r#"{"error":{"code":"account\u005fexists"}}"#,
            ),
            0,
            false,
        ),
        (
            reply(
                "500 Internal Server Error",
                r#"{"error":{"code":"commit_unknown"}}"#,
            ),
            0,
            true,
        ),
        (reply("200 OK", "{}"), 0, true),
        (
            reply("400 Bad Request", r#"{"error":{"code":"weak_password"}}"#),
            0,
            false,
        ),
        (Vec::new(), 0, true),
        (reply("201 Created", &"s".repeat(1024 * 1024 + 1)), 1, false),
        (reply("409 Conflict", &"s".repeat(1024 * 1024 + 1)), 0, true),
    ];
    for (index, (response, confirmed_created, uncertain_last_create)) in
        cases.into_iter().enumerate()
    {
        let socket = directory.path().join(format!("admin-{index}.sock"));
        let server = mock(&socket, vec![response])?;
        let error = provision_accounts(&socket, &credentials)
            .await
            .err()
            .ok_or("expected failure")?;
        assert_eq!(
            error.provision_summary(),
            Some(ProvisionSummary {
                confirmed_created,
                uncertain_last_create
            })
        );
        assert_eq!(server.join().map_err(|_| "mock panicked")??.len(), 1);
        assert!(!error.to_string().contains("secret"));
    }
    let error = provision_accounts(&directory.path().join("absent"), &credentials)
        .await
        .err()
        .ok_or("connect failure")?;
    assert_eq!(error.provision_summary(), Some(ProvisionSummary::default()));
    Ok(())
}

#[test]
fn cli_preparation_errors_include_zero_effect_evidence_without_secret_echo() -> TestResult {
    let output = cli(&[
        "accounts".as_ref(),
        "provision".as_ref(),
        "--socket".as_ref(),
        "/absent-local-socket".as_ref(),
        "--credentials".as_ref(),
        "/absent-credentials".as_ref(),
    ])?;
    assert!(!output.status.success());
    assert!(
        std::str::from_utf8(&output.stderr)?
            .contains("confirmed_created=0; uncertain_last_create=false")
    );
    Ok(())
}

#[tokio::test]
async fn request_timeout_retains_uncertain_create_and_closes_driver() -> TestResult {
    use tokio::io::AsyncReadExt;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("credentials.json");
    let socket = directory.path().join("admin.sock");
    generate_credentials("localhost", "bench", 1, &path)?;
    let credentials = CredentialSet::read(&path, None, None)?;
    let listener = tokio::net::UnixListener::bind(&socket)?;
    let request = tokio::spawn(async move { provision_accounts(&socket, &credentials).await });
    let (mut connection, _) = listener.accept().await?;
    let mut bytes = [0; 4096];
    assert!(connection.read(&mut bytes).await? > 0);
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(36)).await;
    let error = request.await?.err().ok_or("expected timeout")?;
    assert_eq!(error.context(), "provision_timeout");
    assert_eq!(
        error.provision_summary(),
        Some(ProvisionSummary {
            confirmed_created: 0,
            uncertain_last_create: true
        })
    );
    assert_eq!(connection.read(&mut bytes).await?, 0);
    Ok(())
}

#[tokio::test]
async fn cancelled_provisioning_aborts_http_driver_without_claiming_an_outcome() -> TestResult {
    use tokio::io::AsyncReadExt;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("credentials.json");
    let socket = directory.path().join("admin.sock");
    generate_credentials("localhost", "bench", 1, &path)?;
    let credentials = CredentialSet::read(&path, None, None)?;
    let listener = tokio::net::UnixListener::bind(&socket)?;
    let request = tokio::spawn(async move { provision_accounts(&socket, &credentials).await });
    let (mut connection, _) = listener.accept().await?;
    let mut bytes = [0; 4096];
    assert!(connection.read(&mut bytes).await? > 0);
    request.abort();
    assert!(request.await.is_err_and(|error| error.is_cancelled()));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), connection.read(&mut bytes)).await??,
        0
    );
    Ok(())
}

#[test]
fn provision_cli_reports_partial_conflicting_and_uncertain_creates() -> TestResult {
    let directory = tempfile::tempdir()?;
    let credentials = directory.path().join("credentials.json");
    generate_credentials("localhost", "bench", 3, &credentials)?;
    let original = fs::read(&credentials)?;
    let cases = [
        (
            vec![
                reply("201 Created", "{}"),
                reply("409 Conflict", r#"{"error":{"code":"account_exists"}}"#),
            ],
            1,
            false,
        ),
        (
            vec![b"HTTP/1.1 201 Created\r\ncontent-length: 100\r\n\r\n{".to_vec()],
            1,
            false,
        ),
        (
            vec![reply(
                "500 Internal Server Error",
                r#"{"error":{"code":"commit_unknown"}}"#,
            )],
            0,
            true,
        ),
    ];
    for (index, (responses, confirmed, uncertain)) in cases.into_iter().enumerate() {
        let socket = directory.path().join(format!("cli-{index}.sock"));
        let expected_requests = responses.len();
        let server = mock(&socket, responses)?;
        let output = cli(&[
            "accounts".as_ref(),
            "provision".as_ref(),
            "--socket".as_ref(),
            socket.as_os_str(),
            "--credentials".as_ref(),
            credentials.as_os_str(),
        ])?;
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error = std::str::from_utf8(&output.stderr)?;
        assert!(error.contains(&format!(
            "confirmed_created={confirmed}; uncertain_last_create={uncertain}"
        )));
        assert!(!error.contains("bench-"));
        assert_eq!(
            server.join().map_err(|_| "mock panicked")??.len(),
            expected_requests
        );
        assert_eq!(fs::read(&credentials)?, original);
    }
    Ok(())
}
