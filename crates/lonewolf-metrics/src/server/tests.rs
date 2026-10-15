// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use compio::runtime::Runtime;
use compio::time::timeout;
use futures_channel::oneshot;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::registry::Registry;

use super::MetricsServer;

type TestResult = Result<(), Box<dyn Error>>;

async fn request(address: SocketAddr, request: &'static str) -> io::Result<String> {
    blocking::unblock(move || {
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        stream.write_all(request.as_bytes())?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    })
    .await
}

async fn with_server(
    registry: Arc<Registry>,
    check: impl AsyncFnOnce(SocketAddr) -> TestResult,
) -> TestResult {
    let server = MetricsServer::bind("127.0.0.1:0".parse()?).await?;
    let address = server.local_addr()?;
    let (stop, stopped) = oneshot::channel();
    let task = compio::runtime::spawn(server.run(registry, async move {
        let _ = stopped.await;
    }));
    let result = check(address).await;
    stop.send(())
        .map_err(|_| "server stopped before shutdown")?;
    assert!(timeout(Duration::from_secs(5), task).await?.is_ok());
    result
}

fn registry_with_counter() -> (Arc<Registry>, Counter) {
    let mut registry = Registry::default();
    let counter = Counter::default();
    registry.register("requests", "Handled requests", counter.clone());
    (Arc::new(registry), counter)
}

#[test]
fn get_metrics_returns_openmetrics_text() -> TestResult {
    let (registry, counter) = registry_with_counter();
    counter.inc();
    Runtime::new()?.block_on(with_server(registry, async |address| {
        let response = request(address, "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await?;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        let (headers, body) = response.split_once("\r\n\r\n").ok_or("missing headers")?;
        let headers = headers.to_ascii_lowercase();
        assert!(
            headers.contains(
                "content-type: application/openmetrics-text; version=1.0.0; charset=utf-8"
            )
        );
        assert!(headers.contains("cache-control: no-store"));
        assert!(body.lines().any(|line| line == "requests_total 1"));
        assert!(body.ends_with("# EOF\n"));
        Ok(())
    }))
}

#[test]
fn repeated_scrapes_render_current_values() -> TestResult {
    let (registry, counter) = registry_with_counter();
    counter.inc();
    Runtime::new()?.block_on(with_server(registry, async |address| {
        let first = request(address, "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await?;
        assert!(first.lines().any(|line| line == "requests_total 1"));
        counter.inc();
        let second = request(address, "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await?;
        assert!(second.lines().any(|line| line == "requests_total 2"));
        assert!(!second.lines().any(|line| line == "requests_total 1"));
        Ok(())
    }))
}

#[test]
fn head_metrics_returns_headers_without_a_body() -> TestResult {
    Runtime::new()?.block_on(with_server(
        Arc::new(Registry::default()),
        async |address| {
            let response =
                request(address, "HEAD /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await?;
            assert!(response.starts_with("HTTP/1.1 200 OK"));
            let (headers, body) = response.split_once("\r\n\r\n").ok_or("missing headers")?;
            let headers = headers.to_ascii_lowercase();
            assert!(headers.contains(
                "content-type: application/openmetrics-text; version=1.0.0; charset=utf-8"
            ));
            assert!(headers.contains("cache-control: no-store"));
            assert!(body.is_empty());
            Ok(())
        },
    ))
}

#[test]
fn unknown_paths_and_methods_are_rejected() -> TestResult {
    Runtime::new()?.block_on(with_server(
        Arc::new(Registry::default()),
        async |address| {
            let response =
                request(address, "GET /other HTTP/1.1\r\nHost: localhost\r\n\r\n").await?;
            assert!(response.starts_with("HTTP/1.1 404"));
            let response = request(
                address,
                "POST /metrics HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
            )
            .await?;
            assert!(response.starts_with("HTTP/1.1 405"));
            Ok(())
        },
    ))
}

#[test]
fn shutdown_drains_connections_and_releases_the_port() -> TestResult {
    Runtime::new()?.block_on(async {
        let server = MetricsServer::bind("127.0.0.1:0".parse()?).await?;
        let address = server.local_addr()?;
        let (stop, stopped) = oneshot::channel();
        let mut task =
            compio::runtime::spawn(server.run(Arc::new(Registry::default()), async move {
                let _ = stopped.await;
            }));
        let stream = blocking::unblock(move || -> io::Result<TcpStream> {
            let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            stream.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n")?;
            Ok(stream)
        })
        .await?;
        let response = request(address, "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await?;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        stop.send(())
            .map_err(|_| "server stopped before shutdown")?;
        assert!(timeout(Duration::from_millis(20), &mut task).await.is_err());
        let response = blocking::unblock(move || -> io::Result<String> {
            let mut stream = stream;
            stream.write_all(b"\r\n")?;
            let mut response = String::new();
            stream.read_to_string(&mut response)?;
            Ok(response)
        })
        .await?;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(timeout(Duration::from_secs(5), task).await?.is_ok());
        let _listener = TcpListener::bind(address)?;
        Ok(())
    })
}

#[test]
fn occupied_address_fails_to_bind() -> TestResult {
    Runtime::new()?.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let error = MetricsServer::bind(listener.local_addr()?)
            .await
            .err()
            .ok_or("accepted occupied address")?;
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        Ok(())
    })
}
