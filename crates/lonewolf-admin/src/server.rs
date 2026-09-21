// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, DirBuilder, Permissions};
use std::future::Future;
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::time::Duration;

use compio::net::{UnixListener, UnixStream};
use compio::time::timeout;
use compio_io::compat::AsyncStream;
use futures_util::future::{Either, select};
use futures_util::stream::{FuturesUnordered, StreamExt};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use lonewolf_storage::account::AccountRepository;
use tokio_util::compat::FuturesAsyncReadCompatExt;

use crate::api::Api;

const MAX_CONNECTIONS: usize = 32;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Server<R> {
    listener: UnixListener,
    socket: SocketFile,
    api: Api<R>,
}

impl<R: AccountRepository> Server<R> {
    /// Requires a private parent directory owned by the current user.
    /// Creates missing directories with mode 0700 and the socket with mode 0600.
    /// Refuses existing paths, including stale sockets.
    pub fn bind(path: &Path, accounts: R) -> io::Result<Self> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
        let parent_metadata = fs::metadata(parent)?;
        if parent_metadata.uid() != nix::unistd::geteuid().as_raw()
            || parent_metadata.mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "admin socket directory must be owned by the current user with mode 0700",
            ));
        }
        let listener = std::os::unix::net::UnixListener::bind(path)?;
        let metadata = fs::symlink_metadata(path)?;
        let socket = SocketFile {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        fs::set_permissions(path, Permissions::from_mode(0o600))?;
        Ok(Self {
            listener: UnixListener::from_std(listener)?,
            socket,
            api: Api::new(accounts),
        })
    }

    /// Stops accepting on shutdown, then drains connections within their deadlines.
    /// Each connection serves one request with a 30-second deadline.
    pub async fn run(self, shutdown: impl Future<Output = io::Result<()>>) -> io::Result<()> {
        let mut shutdown = pin!(shutdown);
        let mut connections = FuturesUnordered::new();
        tracing::info!(socket_path = ?self.socket.path, "admin service started");
        let result = loop {
            let event = {
                let progress = async {
                    if connections.len() >= MAX_CONNECTIONS {
                        connections.next().await;
                        return Ok(None);
                    }
                    if connections.is_empty() {
                        return self.listener.accept().await.map(Some);
                    }
                    match select(pin!(self.listener.accept()), pin!(connections.next())).await {
                        Either::Left((accepted, _)) => accepted.map(Some),
                        Either::Right(_) => Ok(None),
                    }
                };
                match select(shutdown.as_mut(), pin!(progress)).await {
                    Either::Left((result, _)) => Either::Left(result),
                    Either::Right((result, _)) => Either::Right(result),
                }
            };
            match event {
                Either::Left(result) => break result,
                Either::Right(Ok(Some((stream, _)))) => {
                    connections.push(serve_connection(stream, &self.api));
                }
                Either::Right(Ok(None)) => {}
                Either::Right(Err(error)) => break Err(error),
            }
        };
        drop(self.listener);
        while connections.next().await.is_some() {}
        tracing::info!("admin service stopped");
        result
    }
}

async fn serve_connection<R: AccountRepository>(stream: UnixStream, api: &Api<R>) {
    let io = TokioIo::new(Box::pin(AsyncStream::with_limits(4096, 16384, stream)).compat());
    let mut builder = http1::Builder::new();
    builder
        .keep_alive(false)
        .max_buf_size(16384)
        .max_headers(32);
    let connection = builder.serve_connection(io, service_fn(|request| api.handle(request)));
    match timeout(CONNECTION_TIMEOUT, connection).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => tracing::debug!(outcome = "connection_failed", "admin connection closed"),
        Err(_) => tracing::warn!(outcome = "timeout", "admin connection deadline exceeded"),
    }
}

struct SocketFile {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketFile {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
            && fs::remove_file(&self.path).is_err()
        {
            tracing::warn!("cannot remove admin socket");
        }
    }
}
