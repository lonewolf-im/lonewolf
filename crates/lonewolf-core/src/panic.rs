// SPDX-License-Identifier: Apache-2.0

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

    // The default hook can expose secrets from the panic payload.
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
