// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fmt;
use std::io;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

const RETRY_WINDOW: Duration = Duration::from_secs(2);
const FIRST_DELAY: Duration = Duration::from_millis(10);
const MAX_DELAY: Duration = Duration::from_millis(200);

/// Spawns `command`, retrying while the operating system temporarily cannot create a process.
///
/// A shortage that outlasts a short window fails with the last spawn error as its source.
pub fn spawn_child(command: &mut Command) -> io::Result<Child> {
    let deadline = Instant::now() + RETRY_WINDOW;
    let mut delay = FIRST_DELAY;
    let mut attempts = 1;
    loop {
        match command.spawn() {
            // Process creation reports a transient kernel resource shortage as EAGAIN.
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(io::Error::new(
                        error.kind(),
                        Unavailable {
                            attempts,
                            source: error,
                        },
                    ));
                }
                thread::sleep(delay.min(deadline - now));
                delay = (delay * 2).min(MAX_DELAY);
                attempts += 1;
            }
            result => return result,
        }
    }
}

#[derive(Debug)]
struct Unavailable {
    attempts: u32,
    source: io::Error,
}

impl fmt::Display for Unavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "process creation stayed unavailable after {} attempts: {}",
            self.attempts, self.source
        )
    }
}

impl Error for Unavailable {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}
