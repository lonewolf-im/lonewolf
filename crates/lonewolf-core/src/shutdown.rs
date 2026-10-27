// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::pin::pin;
use std::task::Poll;

use futures_util::future::{Either, select};
use futures_util::poll;
use nix::sys::signal::Signal;

pub(crate) async fn wait() -> io::Result<()> {
    wait_after_registration(|| tracing::debug!("shutdown signal handlers registered")).await
}

async fn wait_after_registration(registered: impl FnOnce()) -> io::Result<()> {
    let interrupt = pin!(compio::signal::ctrl_c());
    let terminate = pin!(compio::signal::unix::signal(Signal::SIGTERM as i32));
    let mut stop = pin!(select(interrupt, terminate));
    // Signal handlers register on the first poll.
    let stopped = match poll!(stop.as_mut()) {
        Poll::Ready(result) => result,
        Poll::Pending => {
            registered();
            stop.await
        }
    };
    let result = match stopped {
        Either::Left((result, _)) | Either::Right((result, _)) => result,
    };
    if result.is_ok() {
        tracing::info!("received stop signal... gracefully shutting down...");
    }
    result
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::Duration;

    use nix::sys::signal::{Signal, raise};

    fn signal_at_registration(signal: Signal, test: &str) {
        const CHILD: &str = "LONEWOLF_TEST_STOP_AT_REGISTRATION";
        if std::env::var_os(CHILD).is_some() {
            compio::runtime::Runtime::new().unwrap().block_on(async {
                compio::time::timeout(
                    Duration::from_secs(2),
                    super::wait_after_registration(|| raise(signal).unwrap()),
                )
                .await
                .unwrap()
                .unwrap();
            });
            return;
        }
        let output = Command::new(std::env::current_exe().unwrap())
            .args([test, "--exact", "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"),
            "{signal:?}: {}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn sigint_at_registration_is_registered() {
        signal_at_registration(
            Signal::SIGINT,
            "shutdown::tests::sigint_at_registration_is_registered",
        );
    }

    #[test]
    fn sigterm_at_registration_is_registered() {
        signal_at_registration(
            Signal::SIGTERM,
            "shutdown::tests::sigterm_at_registration_is_registered",
        );
    }
}
