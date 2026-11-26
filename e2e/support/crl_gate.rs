// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};

use super::TestResult;

pub struct CrlReadGate {
    path: PathBuf,
    held: PathBuf,
    material: Vec<u8>,
    opened: Receiver<io::Result<File>>,
    worker: Option<JoinHandle<()>>,
    writer: Option<File>,
    _directory: tempfile::TempDir,
}

impl CrlReadGate {
    pub fn new(path: &Path) -> TestResult<Self> {
        let material = super::tls::block_crl_reads(path)?;
        let directory = tempfile::tempdir_in(path.parent().ok_or("CRL path has no parent")?)?;
        let held = directory.path().join("held");
        // Keep the FIFO reachable after the policy path is replaced.
        fs::hard_link(path, &held)?;
        let (sender, opened) = mpsc::sync_channel(1);
        let target = held.clone();
        let worker = thread::spawn(move || {
            let result = OpenOptions::new().write(true).open(target);
            let _ = sender.send(result);
        });
        Ok(Self {
            path: path.into(),
            held,
            material,
            opened,
            worker: Some(worker),
            writer: None,
            _directory: directory,
        })
    }

    pub fn captured(&mut self) -> TestResult {
        self.writer = Some(self.opened.recv_timeout(super::TIMEOUT)??);
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| "CRL rendezvous worker panicked")?;
        }
        Ok(())
    }

    pub fn replace_path(&self) -> TestResult {
        if self.writer.is_none() {
            return Err("CRL reader has not arrived".into());
        }
        self.restore()
    }

    pub fn release(&mut self) -> TestResult {
        let mut writer = self.writer.take().ok_or("CRL reader has not arrived")?;
        writer.write_all(&self.material)?;
        Ok(())
    }

    fn restore(&self) -> TestResult {
        let mut file =
            tempfile::NamedTempFile::new_in(self.path.parent().ok_or("CRL path has no parent")?)?;
        file.write_all(&self.material)?;
        file.persist(&self.path).map_err(|error| error.error)?;
        Ok(())
    }
}

impl Drop for CrlReadGate {
    fn drop(&mut self) {
        // A blocked writer cannot finish until a reader opens the FIFO.
        let unblock = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(&self.held);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        if self.writer.is_none() {
            self.writer = self.opened.try_recv().ok().and_then(Result::ok);
        }
        drop(self.writer.take());
        if fs::metadata(&self.path).is_ok_and(|metadata| metadata.file_type().is_fifo()) {
            let _ = self.restore();
        }
        drop(unblock);
    }
}
