// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::backtrace::{Backtrace, BacktraceStatus};
use std::env;
use std::io::{self, Write};
use std::panic;

use crate::BuildInfo;

pub(crate) fn init(build: &BuildInfo) {
    let BuildInfo {
        version,
        branch,
        commit,
    } = *build;

    // The default hook prints formatted panic messages, which can embed secrets.
    panic::set_hook(Box::new(move |info| {
        let backtrace = Backtrace::capture();
        let mut stderr = io::stderr().lock();
        let _ = writeln!(stderr, "Lonewolf encountered an unexpected panic.");
        let _ = writeln!(
            stderr,
            "version={version:?} branch={branch:?} commit={commit:?}"
        );
        let _ = writeln!(stderr, "platform={}/{}", env::consts::OS, env::consts::ARCH);
        if let Some(location) = info.location() {
            let _ = writeln!(stderr, "location={location}");
        }
        if let Some(message) = literal_message(info.payload()) {
            let _ = writeln!(stderr, "message={message:?}");
        }
        let _ = writeln!(
            stderr,
            "Report this at https://github.com/lonewolf-im/lonewolf/issues/new"
        );

        match backtrace.status() {
            BacktraceStatus::Captured => {
                let _ = writeln!(stderr, "Backtrace:\n{backtrace}");
            }
            BacktraceStatus::Disabled => {
                let _ = writeln!(stderr, "Set RUST_BACKTRACE=1 to include a backtrace.");
            }
            _ => {}
        }
    }));
}

/// Returns the message of a panic raised with a string literal, which cannot embed runtime data.
fn literal_message(payload: &(dyn Any + Send)) -> Option<&'static str> {
    payload.downcast_ref::<&'static str>().copied()
}

#[cfg(test)]
mod tests {
    use std::panic;

    use super::literal_message;

    #[test]
    fn literal_message_keeps_literal_panics() {
        let payload = panic::catch_unwind(|| panic!("invariant violated")).unwrap_err();

        assert_eq!(
            literal_message(payload.as_ref()),
            Some("invariant violated")
        );
    }

    #[test]
    fn literal_message_hides_formatted_panics() {
        let secret = String::from("hunter2");
        let payload = panic::catch_unwind(|| panic!("token {secret}")).unwrap_err();

        assert_eq!(literal_message(payload.as_ref()), None);
    }

    #[test]
    fn literal_message_hides_panics_with_runtime_arguments() {
        let payload =
            panic::catch_unwind(|| panic!("{}", String::from("seeded-secret"))).unwrap_err();

        assert_eq!(literal_message(payload.as_ref()), None);
    }
}
