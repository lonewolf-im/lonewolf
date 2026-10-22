// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Buf;
use hyper::client::conn::http1;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::net::UnixStream;
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::CtlError;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(35);
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

pub(crate) struct Client {
    socket: PathBuf,
}

pub(crate) struct Reply {
    pub(crate) status: StatusCode,
    pub(crate) body: Vec<u8>,
}

struct SensitiveBytes {
    data: Zeroizing<Vec<u8>>,
    offset: usize,
}

impl Buf for SensitiveBytes {
    fn remaining(&self) -> usize {
        self.data.len() - self.offset
    }

    fn chunk(&self) -> &[u8] {
        &self.data[self.offset..]
    }

    fn advance(&mut self, count: usize) {
        assert!(count <= self.remaining());
        self.offset += count;
    }
}

impl Client {
    pub(crate) fn new(socket: PathBuf) -> Self {
        Self { socket }
    }

    pub(crate) async fn request(
        &self,
        method: Method,
        uri: &str,
        body: Vec<u8>,
    ) -> Result<Reply, CtlError> {
        timeout(REQUEST_TIMEOUT, self.request_inner(method, uri, body))
            .await
            .map_err(|_| CtlError::new("request_timeout", "admin request timed out"))?
    }

    async fn request_inner(
        &self,
        method: Method,
        uri: &str,
        body: Vec<u8>,
    ) -> Result<Reply, CtlError> {
        let stream = UnixStream::connect(&self.socket).await.map_err(|error| {
            CtlError::new(
                "connection_failed",
                format!(
                    "cannot connect to admin socket {}: {error}",
                    self.socket.display()
                ),
            )
        })?;
        let (mut sender, connection) =
            http1::handshake::<_, Full<SensitiveBytes>>(TokioIo::new(stream))
                .await
                .map_err(|_| CtlError::invalid_response())?;
        let driver = tokio::spawn(connection);
        let result = async {
            let request = Request::builder()
                .method(method)
                .uri(uri)
                .header("host", "localhost")
                .header("content-type", "application/json")
                .body(Full::new(SensitiveBytes {
                    data: Zeroizing::new(body),
                    offset: 0,
                }))
                .map_err(|_| CtlError::new("invalid_request", "cannot build admin request"))?;
            let response = sender
                .send_request(request)
                .await
                .map_err(|_| CtlError::new("request_failed", "admin request failed"))?;
            let status = response.status();
            let mut incoming = response.into_body();
            let mut body = Vec::new();
            while let Some(frame) = incoming.frame().await {
                let frame = frame.map_err(|_| CtlError::invalid_response())?;
                if let Ok(data) = frame.into_data() {
                    if data.len() > MAX_RESPONSE_BYTES.saturating_sub(body.len()) {
                        return Err(CtlError::invalid_response());
                    }
                    body.extend_from_slice(&data);
                }
            }
            Ok(Reply { status, body })
        }
        .await;
        driver.abort();
        result
    }
}

#[derive(Deserialize)]
struct ApiErrorResponse {
    error: ApiErrorCode,
}

#[derive(Deserialize)]
struct ApiErrorCode {
    code: String,
}

impl Reply {
    pub(crate) fn expect_status(self, expected: StatusCode) -> Result<Vec<u8>, CtlError> {
        if self.status == expected {
            return Ok(self.body);
        }
        if self.status.is_success() {
            return Err(CtlError::invalid_response());
        }
        let code = serde_json::from_slice::<ApiErrorResponse>(&self.body)
            .ok()
            .map(|response| response.error.code);
        Err(CtlError::api(code.as_deref()))
    }
}

#[cfg(test)]
mod tests {
    use std::future::{Future, poll_fn};
    use std::pin::Pin;
    use std::task::Poll;

    use super::*;

    #[test]
    fn expected_status_preserves_the_response_body() {
        for status in [StatusCode::OK, StatusCode::CREATED, StatusCode::NO_CONTENT] {
            let body = b"opaque response bytes\0\xff";
            let reply = Reply {
                status,
                body: body.to_vec(),
            };
            let actual = reply
                .expect_status(status)
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(actual, body);
        }
    }

    #[test]
    fn unexpected_success_status_is_an_invalid_response() {
        for status in [
            StatusCode::CREATED,
            StatusCode::ACCEPTED,
            StatusCode::NO_CONTENT,
        ] {
            let reply = Reply {
                status,
                body: br#"{"error":{"code":"not_found"}}"#.to_vec(),
            };
            let Err(error) = reply.expect_status(StatusCode::OK) else {
                panic!("accepted unexpected success status {status}");
            };
            assert_eq!(error.code, "invalid_response");
            assert_eq!(
                error.to_string(),
                "admin service returned an invalid response"
            );
        }
    }

    #[test]
    fn failed_statuses_preserve_valid_api_codes() {
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::NOT_FOUND,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let reply = Reply {
                status,
                body: br#"{"error":{"code":"not_found"}}"#.to_vec(),
            };
            let Err(error) = reply.expect_status(StatusCode::OK) else {
                panic!("accepted failed status {status}");
            };
            assert_eq!(error.code, "not_found");
            assert_eq!(error.to_string(), "account not found");
        }
    }

    #[test]
    fn failed_statuses_without_valid_error_json_use_server_error() {
        for body in [
            "",
            "not JSON",
            r#"{"error":{"code":"not_found"}"#,
            "null",
            "[]",
            "{}",
            r#"{"error":null}"#,
            r#"{"error":{"code":42}}"#,
        ] {
            let reply = Reply {
                status: StatusCode::BAD_REQUEST,
                body: body.as_bytes().to_vec(),
            };
            let Err(error) = reply.expect_status(StatusCode::OK) else {
                panic!("accepted failed reply {body:?}");
            };
            assert_eq!(error.code, "server_error", "{body:?}");
            assert_eq!(error.to_string(), "admin service returned an error");
        }
    }

    #[test]
    fn admitted_request_times_out_without_a_server_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let directory = tempfile::tempdir()?;
            let socket = directory.path().join("timeout.sock");
            let listener = tokio::net::UnixListener::bind(&socket)?;
            let (admitted, admission) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await?;
                let mut request = Vec::new();
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    stream.readable().await?;
                    let mut buffer = [0; 1024];
                    match stream.try_read(&mut buffer) {
                        Ok(0) => return Err(std::io::Error::other("request ended before headers")),
                        Ok(read) => request.extend_from_slice(&buffer[..read]),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(error) => return Err(error),
                    }
                }
                assert!(request.starts_with(b"GET /v1/accounts HTTP/1.1\r\n"));
                admitted
                    .send(())
                    .map_err(|_| std::io::Error::other("admission cancelled"))?;
                std::future::pending::<()>().await;
                drop(stream);
                Ok(())
            });
            let mut request = tokio::spawn(async move {
                Client::new(socket)
                    .request(Method::GET, "/v1/accounts", Vec::new())
                    .await
            });
            tokio::time::timeout(Duration::from_secs(5), admission).await??;
            assert!(
                poll_fn(|context| Poll::Ready(Pin::new(&mut request).poll(context)))
                    .await
                    .is_pending()
            );
            tokio::time::pause();
            tokio::time::advance(REQUEST_TIMEOUT).await;
            let Err(error) = tokio::time::timeout(Duration::from_secs(1), request).await?? else {
                return Err("accepted unanswered request".into());
            };
            assert_eq!(error.code, "request_timeout");
            assert_eq!(error.to_string(), "admin request timed out");
            server.abort();
            let cancelled = server.await.err().ok_or("server was not cancelled")?;
            assert!(cancelled.is_cancelled());
            Ok::<_, Box<dyn std::error::Error>>(())
        })
    }
}
