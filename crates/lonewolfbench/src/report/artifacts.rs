// SPDX-License-Identifier: Apache-2.0

use crate::{
    config::validate_new_output,
    error::{BenchError, BenchResult, ErrorCode},
};
use serde::Serialize;
use std::{
    fs::{self, OpenOptions},
    io::{BufWriter, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

/// Writes artifacts into a new private directory and never replaces an existing file.
pub struct ArtifactWriter {
    output: PathBuf,
}

fn failure() -> BenchError {
    BenchError::new(ErrorCode::ArtifactFailure, "artifact_write_failed")
}

impl ArtifactWriter {
    pub fn create(output: &Path) -> BenchResult<Self> {
        validate_new_output(output)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(output)
            .map_err(|_| BenchError::new(ErrorCode::InvalidPath, "output_directory_create"))?;
        Ok(Self {
            output: output.to_owned(),
        })
    }

    pub fn write(&self, name: &str, bytes: &[u8]) -> BenchResult<()> {
        self.write_with(name, |writer| writer.write_all(bytes))
    }

    pub fn write_json(&self, name: &str, value: &impl Serialize) -> BenchResult<()> {
        self.write_with(name, |writer| {
            serde_json::to_writer_pretty(&mut *writer, value)?;
            writer.write_all(b"\n")
        })
    }

    fn write_with(
        &self,
        name: &str,
        write: impl FnOnce(&mut dyn Write) -> std::io::Result<()>,
    ) -> BenchResult<()> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.output.join(name))
            .map_err(|_| failure())?;
        let mut writer = BufWriter::new(file);
        write(&mut writer).map_err(|_| failure())?;
        writer.flush().map_err(|_| failure())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn writes_private_files_once_in_a_new_directory() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("run");
        let writer = ArtifactWriter::create(&output)?;
        writer.write("summary.md", b"text")?;
        writer.write_json("result.json", &serde_json::json!({"status": "passed"}))?;
        assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o777, 0o700);
        for name in ["summary.md", "result.json"] {
            assert_eq!(
                fs::metadata(output.join(name))?.permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(writer.write("summary.md", b"other").is_err());
        assert_eq!(fs::read(output.join("summary.md"))?, b"text");
        assert!(ArtifactWriter::create(&output).is_err());
        Ok(())
    }

    #[test]
    fn rejects_an_output_symlink() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(directory.path().join("missing"), &link)?;
        assert!(ArtifactWriter::create(&link).is_err());
        assert!(!directory.path().join("missing").exists());
        Ok(())
    }
}
