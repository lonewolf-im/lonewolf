// SPDX-License-Identifier: Apache-2.0

use std::io;
#[cfg(unix)]
use std::pin::pin;

#[cfg(unix)]
pub(crate) async fn wait() -> io::Result<()> {
    use futures_util::future::{Either, select};
    use nix::sys::signal::Signal;

    let interrupt = pin!(compio::signal::ctrl_c());
    let terminate = pin!(compio::signal::unix::signal(Signal::SIGTERM as i32));
    match select(interrupt, terminate).await {
        Either::Left((result, _)) | Either::Right((result, _)) => result,
    }
}

#[cfg(windows)]
pub(crate) async fn wait() -> io::Result<()> {
    compio::signal::ctrl_c().await
}
