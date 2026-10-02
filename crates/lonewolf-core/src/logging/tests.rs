// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::sync::Mutex;

pub(crate) struct Capture {
    _guard: tracing::subscriber::DefaultGuard,
    file: tempfile::NamedTempFile,
}

impl Capture {
    pub(crate) fn new() -> io::Result<Self> {
        let file = tempfile::NamedTempFile::new()?;
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .with_writer(Mutex::new(file.reopen()?))
            .finish();
        Ok(Self {
            _guard: tracing::subscriber::set_default(subscriber),
            file,
        })
    }

    pub(crate) fn read(&self) -> io::Result<String> {
        std::fs::read_to_string(self.file.path())
    }

    pub(crate) fn count(&self, event: &str) -> io::Result<usize> {
        Ok(self
            .read()?
            .lines()
            .filter(|line| line.contains(event))
            .count())
    }
}
