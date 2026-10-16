// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::pin::pin;
use std::task::Poll;

use futures_util::future::{Either, select};
use futures_util::poll;
use nix::sys::signal::Signal;

pub(crate) async fn wait() -> io::Result<()> {
    let interrupt = pin!(compio::signal::ctrl_c());
    let terminate = pin!(compio::signal::unix::signal(Signal::SIGTERM as i32));
    let mut stop = pin!(select(interrupt, terminate));
    // Signal handlers register on the first poll.
    let stopped = match poll!(stop.as_mut()) {
        Poll::Ready(result) => result,
        Poll::Pending => {
            tracing::info!("waiting for stop signal... (press Ctrl+C to stop the server)");
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
    use tracing::field::{Field, Visit};
    use tracing::{Event, Subscriber};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::{Context, SubscriberExt};

    struct SignalAtReadiness(Signal);

    impl<S: Subscriber> Layer<S> for SignalAtReadiness {
        fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
            struct Readiness(bool);
            impl Visit for Readiness {
                fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                    if field.name() == "message"
                        && format!("{value:?}").starts_with("waiting for stop signal")
                    {
                        self.0 = true;
                    }
                }
            }
            let mut readiness = Readiness(false);
            event.record(&mut readiness);
            if readiness.0 {
                raise(self.0).unwrap();
            }
        }
    }

    fn signal_at_readiness(signal: Signal, test: &str) {
        const CHILD: &str = "LONEWOLF_TEST_STOP_AT_READINESS";
        if std::env::var_os(CHILD).is_some() {
            let subscriber = tracing_subscriber::registry().with(SignalAtReadiness(signal));
            let _subscriber = tracing::subscriber::set_default(subscriber);
            compio::runtime::Runtime::new().unwrap().block_on(async {
                compio::time::timeout(Duration::from_secs(2), super::wait())
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
            output.status.success(),
            "{signal:?}: {}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn sigint_at_readiness_is_registered() {
        signal_at_readiness(
            Signal::SIGINT,
            "shutdown::tests::sigint_at_readiness_is_registered",
        );
    }

    #[test]
    fn sigterm_at_readiness_is_registered() {
        signal_at_readiness(
            Signal::SIGTERM,
            "shutdown::tests::sigterm_at_readiness_is_registered",
        );
    }
}
