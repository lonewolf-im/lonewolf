// SPDX-License-Identifier: Apache-2.0

use super::{Credential, CredentialSet, ProvisionSummary, failure};
use crate::error::BenchResult;
use http_body_util::{BodyExt, Full};
use hyper::{Request, StatusCode, body::Buf, client::conn::http1};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, path::Path, time::Duration};
use tokio::{net::UnixStream, task::JoinHandle, time::timeout};
use zeroize::Zeroizing;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(35);
const MAX_RESPONSE: usize = 1024 * 1024;

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
        self.offset += count;
    }
}

struct Driver(JoinHandle<Result<(), hyper::Error>>);
impl Driver {
    async fn close(&mut self) {
        self.0.abort();
        let _ = (&mut self.0).await;
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub async fn provision_accounts(
    socket: &Path,
    credentials: &CredentialSet,
) -> BenchResult<ProvisionSummary> {
    let mut summary = ProvisionSummary::default();
    for account in &credentials.accounts {
        request(socket, account, &mut summary)
            .await
            .map_err(|error| error.with_provision_summary(summary))?;
    }
    Ok(summary)
}

async fn request(
    socket: &Path,
    account: &Credential,
    summary: &mut ProvisionSummary,
) -> BenchResult<()> {
    let mut driver = None;
    let result = timeout(REQUEST_TIMEOUT, async {
        let stream = UnixStream::connect(socket)
            .await
            .map_err(|_| failure("provision_connect"))?;
        let (mut sender, connection) =
            http1::handshake::<_, Full<SensitiveBytes>>(TokioIo::new(stream))
                .await
                .map_err(|_| failure("provision_handshake"))?;
        driver = Some(Driver(tokio::spawn(connection)));
        #[derive(Serialize)]
        struct Create<'a> {
            jid: &'a str,
            password: &'a str,
        }
        let mut data = Zeroizing::new(Vec::new());
        data.try_reserve_exact(64 + 6 * (account.jid.len() + account.password.len()))
            .map_err(|_| failure("provision_allocation"))?;
        serde_json::to_writer(
            &mut *data,
            &Create {
                jid: &account.jid,
                password: &account.password,
            },
        )
        .map_err(|_| failure("provision_encode"))?;
        let request = Request::builder()
            .method("POST")
            .uri("/v1/accounts")
            .header("host", "localhost")
            .header("content-type", "application/json")
            .body(Full::new(SensitiveBytes { data, offset: 0 }))
            .map_err(|_| failure("provision_request"))?;
        summary.uncertain_last_create = true;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| failure("provision_transport"))?;
        let status = response.status();
        if status == StatusCode::CREATED {
            summary.confirmed_created += 1;
            summary.uncertain_last_create = false;
        }
        let mut incoming = response.into_body();
        let mut body = Zeroizing::new(Vec::new());
        while let Some(frame) = incoming.frame().await {
            let frame = frame.map_err(|_| failure("provision_response"))?;
            if let Ok(data) = frame.into_data() {
                if data.len() > MAX_RESPONSE.saturating_sub(body.len()) {
                    return Err(failure("provision_response_size"));
                }
                body.try_reserve(data.len())
                    .map_err(|_| failure("provision_allocation"))?;
                body.extend_from_slice(&data);
            }
        }
        if status == StatusCode::CREATED {
            return Ok(());
        }
        let rejection = known_rejection(status, &body);
        if let Some(category) = rejection {
            summary.uncertain_last_create = false;
            return Err(failure(category));
        }
        Err(failure("provision_unacknowledged"))
    })
    .await
    .unwrap_or_else(|_| Err(failure("provision_timeout")));
    if let Some(driver) = &mut driver {
        driver.close().await;
    }
    result
}

fn known_rejection(status: StatusCode, body: &[u8]) -> Option<&'static str> {
    #[derive(Deserialize)]
    struct Reply<'a> {
        #[serde(borrow)]
        error: Code<'a>,
    }
    #[derive(Deserialize)]
    struct Code<'a> {
        #[serde(borrow)]
        code: Cow<'a, str>,
    }
    let reply: Reply<'_> = serde_json::from_slice(body).ok()?;
    match (status.as_u16(), reply.error.code.as_ref()) {
        (409, "account_exists") => Some("provision_account_exists"),
        (400, "invalid_request" | "invalid_jid" | "invalid_password" | "weak_password") => {
            Some("provision_rejected")
        }
        (413, "body_too_large") | (415, "unsupported_media_type") => Some("provision_rejected"),
        _ => None,
    }
}
