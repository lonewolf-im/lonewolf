// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::pin::pin;

use futures_util::future::{Either, select};
use nix::sys::signal::Signal;

pub(crate) async fn wait() -> io::Result<()> {
    let interrupt = pin!(compio::signal::ctrl_c());
    let terminate = pin!(compio::signal::unix::signal(Signal::SIGTERM as i32));
    match select(interrupt, terminate).await {
        Either::Left((result, _)) | Either::Right((result, _)) => result,
    }
}
