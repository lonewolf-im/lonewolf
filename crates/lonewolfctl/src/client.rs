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
