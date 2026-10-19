// SPDX-License-Identifier: Apache-2.0

use super::{ArtifactKind, ArtifactMetadata, RunReport, metadata::hash_bytes, summary};
use crate::{
    config::validate_new_output,
    error::{BenchError, BenchResult, ErrorCode},
};
use std::{
    fs::{self, OpenOptions},
    io::{self, BufWriter, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub const RESULT_LIMIT: usize = 32 * 1024 * 1024;
pub struct ArtifactWriter {
    output: PathBuf,
    #[cfg(test)]
    fault: Option<Fault>,
}
#[cfg(test)]
#[derive(Clone, Copy, PartialEq)]
enum Fault {
    Write,
    Flush,
    Sync,
    Link,
    Unlink,
    Marker,
}

fn failure() -> BenchError {
    BenchError::new(ErrorCode::ArtifactFailure, "artifact_publication_failed")
}

struct LimitedWriter<W> {
    inner: W,
    remaining: usize,
}
impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::other("result_limit"));
        }
        let written = self.inner.write(bytes)?;
        self.remaining -= written;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl ArtifactWriter {
    pub fn create(output: &Path) -> BenchResult<Self> {
        validate_new_output(output)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(output)
            .map_err(|_| BenchError::new(ErrorCode::InvalidPath, "output_directory_create"))?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(output.join(".incomplete"))
            .map_err(|_| failure())?;
        Ok(Self {
            output: output.to_owned(),
            #[cfg(test)]
            fault: None,
        })
    }
    pub fn prepare(
        &self,
        report: &mut RunReport,
        telemetry: &[u8],
        log: Option<&[u8]>,
    ) -> BenchResult<()> {
        self.prepare_data(report, telemetry, log)?;
        self.prepare_summary(report)
    }
    pub(crate) fn prepare_data(
        &self,
        report: &mut RunReport,
        telemetry: &[u8],
        log: Option<&[u8]>,
    ) -> BenchResult<()> {
        self.bytes(
            report,
            ArtifactKind::Telemetry,
            "telemetry.ndjson",
            telemetry,
        )?;
        if let Some(log) = log {
            self.bytes(report, ArtifactKind::ServerLog, "server.log", log)?;
        }
        Ok(())
    }
    pub(crate) fn prepare_summary(&self, report: &mut RunReport) -> BenchResult<()> {
        let summary = summary::render(report);
        self.bytes(
            report,
            ArtifactKind::Summary,
            "summary.md",
            summary.as_bytes(),
        )
    }
    fn bytes(
        &self,
        report: &mut RunReport,
        kind: ArtifactKind,
        name: &str,
        bytes: &[u8],
    ) -> BenchResult<()> {
        self.publish(name, |writer| {
            writer.write_all(bytes).map_err(|_| failure())
        })?;
        report.artifacts.insert(
            kind,
            ArtifactMetadata {
                bytes: bytes.len() as u64,
                sha256: hash_bytes(bytes),
            },
        );
        Ok(())
    }
    pub(crate) fn publish(
        &self,
        name: &str,
        write: impl FnOnce(&mut dyn Write) -> BenchResult<()>,
    ) -> BenchResult<()> {
        let staging = self.output.join(format!(".{name}.partial"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staging)
            .map_err(|_| failure())?;
        {
            let mut writer = BufWriter::new(&file);
            #[cfg(test)]
            self.inject(Fault::Write)?;
            write(&mut writer)?;
            #[cfg(test)]
            self.inject(Fault::Flush)?;
            writer.flush().map_err(|_| failure())?;
        }
        #[cfg(test)]
        self.inject(Fault::Sync)?;
        file.sync_all().map_err(|_| failure())?;
        drop(file);
        #[cfg(test)]
        self.inject(Fault::Link)?;
        fs::hard_link(&staging, self.output.join(name)).map_err(|_| failure())?;
        #[cfg(test)]
        self.inject(Fault::Unlink)?;
        fs::remove_file(staging).map_err(|_| failure())
    }
    #[cfg(test)]
    fn inject(&self, fault: Fault) -> BenchResult<()> {
        if self.fault == Some(fault) {
            Err(failure())
        } else {
            Ok(())
        }
    }
    pub fn finish(self, report: &RunReport) -> BenchResult<()> {
        if !report.artifacts.contains_key(&ArtifactKind::Summary)
            || !report.artifacts.contains_key(&ArtifactKind::Telemetry)
        {
            return Err(failure());
        }
        self.publish("result.json", |writer| {
            let mut writer = LimitedWriter {
                inner: writer,
                remaining: RESULT_LIMIT,
            };
            serde_json::to_writer_pretty(&mut writer, report).map_err(|_| failure())
        })?;
        #[cfg(test)]
        self.inject(Fault::Marker)?;
        fs::remove_file(self.output.join(".incomplete")).map_err(|_| failure())
    }

    pub(crate) fn finish_comparison(
        self,
        report: &crate::compare::ComparisonReport,
        markdown: &str,
    ) -> BenchResult<()> {
        if markdown.len() > RESULT_LIMIT {
            return Err(failure());
        }
        self.publish("comparison.md", |writer| {
            writer.write_all(markdown.as_bytes()).map_err(|_| failure())
        })?;
        self.publish("comparison.json", |writer| {
            let mut writer = LimitedWriter {
                inner: writer,
                remaining: RESULT_LIMIT,
            };
            serde_json::to_writer_pretty(&mut writer, report).map_err(|_| failure())
        })?;
        #[cfg(test)]
        self.inject(Fault::Marker)?;
        fs::remove_file(self.output.join(".incomplete")).map_err(|_| failure())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{RunStatus, tests::report_fixture};
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn report() -> Result<RunReport, Box<dyn std::error::Error>> {
        Ok(serde_json::from_value(report_fixture()?)?)
    }

    #[test]
    fn private_atomic_files_hashes_and_complete_unsuccessful_outcomes() -> TestResult {
        let directory = tempfile::tempdir()?;
        for status in [
            RunStatus::Passed,
            RunStatus::Failed,
            RunStatus::Invalid,
            RunStatus::Interrupted,
        ] {
            let output = directory.path().join(format!("{status:?}"));
            let writer = ArtifactWriter::create(&output)?;
            assert!(output.join(".incomplete").exists());
            assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o777, 0o700);
            let mut report = report()?;
            report.status = status;
            writer.prepare(&mut report, b"raw\n", Some(b"server_ready\n"))?;
            writer.finish(&report)?;
            assert!(!output.join(".incomplete").exists());
            for (kind, name) in [
                (ArtifactKind::Telemetry, "telemetry.ndjson"),
                (ArtifactKind::Summary, "summary.md"),
                (ArtifactKind::ServerLog, "server.log"),
            ] {
                let bytes = fs::read(output.join(name))?;
                assert_eq!(report.artifacts[&kind].sha256, hash_bytes(&bytes));
                assert_eq!(report.artifacts[&kind].bytes, bytes.len() as u64);
                assert_eq!(
                    fs::metadata(output.join(name))?.permissions().mode() & 0o777,
                    0o600
                );
                assert!(!output.join(format!(".{name}.partial")).exists());
            }
            assert_eq!(
                serde_json::from_slice::<RunReport>(&fs::read(output.join("result.json"))?)?,
                report
            );
            assert!(ArtifactWriter::create(&output).is_err());
        }
        Ok(())
    }
    #[test]
    fn existing_final_files_directories_symlinks_and_staging_are_untouched() -> TestResult {
        let directory = tempfile::tempdir()?;
        for kind in ["file", "directory", "symlink", "dangling", "staging"] {
            let output = directory.path().join(kind);
            let writer = ArtifactWriter::create(&output)?;
            let final_path = output.join("telemetry.ndjson");
            let victim = directory.path().join(format!("victim-{kind}"));
            fs::write(&victim, b"unchanged")?;
            match kind {
                "file" => fs::write(&final_path, b"unchanged")?,
                "directory" => fs::create_dir(&final_path)?,
                "symlink" => symlink(&victim, &final_path)?,
                "dangling" => symlink("absent", &final_path)?,
                _ => fs::write(output.join(".telemetry.ndjson.partial"), b"unchanged")?,
            }
            assert!(writer.prepare(&mut report()?, b"new", None).is_err());
            assert!(output.join(".incomplete").exists());
            assert_eq!(fs::read(&victim)?, b"unchanged");
            if kind == "file" {
                assert_eq!(fs::read(&final_path)?, b"unchanged");
            }
            if kind == "staging" {
                assert_eq!(
                    fs::read(output.join(".telemetry.ndjson.partial"))?,
                    b"unchanged"
                );
            }
            assert!(
                fs::symlink_metadata(if kind == "staging" {
                    output.join(".telemetry.ndjson.partial")
                } else {
                    final_path
                })
                .is_ok()
            );
        }
        Ok(())
    }
    #[test]
    fn every_io_failure_retains_marker_and_diagnostic_evidence() -> TestResult {
        let directory = tempfile::tempdir()?;
        for (i, fault) in [
            Fault::Write,
            Fault::Flush,
            Fault::Sync,
            Fault::Link,
            Fault::Unlink,
            Fault::Marker,
        ]
        .into_iter()
        .enumerate()
        {
            let output = directory.path().join(i.to_string());
            let mut writer = ArtifactWriter::create(&output)?;
            let mut report = report()?;
            if fault == Fault::Marker {
                writer.prepare(&mut report, b"raw", None)?;
                writer.fault = Some(fault);
                assert!(writer.finish(&report).is_err());
                assert!(output.join("result.json").exists());
            } else {
                writer.fault = Some(fault);
                assert!(writer.prepare(&mut report, b"raw", None).is_err());
                assert!(output.join(".telemetry.ndjson.partial").exists());
            }
            assert!(output.join(".incomplete").exists());
            if fault == Fault::Unlink {
                let staged = fs::metadata(output.join(".telemetry.ndjson.partial"))?;
                let published = fs::metadata(output.join("telemetry.ndjson"))?;
                assert_eq!(
                    (staged.dev(), staged.ino()),
                    (published.dev(), published.ino())
                );
                assert_eq!(fs::read(output.join("telemetry.ndjson"))?, b"raw");
            }
        }
        Ok(())
    }
    #[test]
    fn oversized_json_is_never_published_and_output_symlink_is_rejected() -> TestResult {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("output");
        let writer = ArtifactWriter::create(&output)?;
        let mut report = report()?;
        writer.prepare(&mut report, b"", None)?;
        report.driver.revision = "x".repeat(RESULT_LIMIT);
        assert!(writer.finish(&report).is_err());
        assert!(!output.join("result.json").exists());
        assert!(output.join(".incomplete").exists());
        let link = directory.path().join("link");
        symlink(&output, &link)?;
        assert!(ArtifactWriter::create(&link).is_err());
        Ok(())
    }
}

#[cfg(test)]
mod comparison_tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn compare_publication_faults_keep_marker_staging_and_completed_files() -> TestResult {
        let directory = tempfile::tempdir()?;
        let run: RunReport = serde_json::from_value(crate::report::tests::report_fixture()?)?;
        let comparison = crate::compare::compare_runs(&run, &run);
        for (index, fault) in [
            Fault::Write,
            Fault::Flush,
            Fault::Sync,
            Fault::Link,
            Fault::Unlink,
            Fault::Marker,
        ]
        .into_iter()
        .enumerate()
        {
            let output = directory.path().join(index.to_string());
            let mut writer = ArtifactWriter::create(&output)?;
            writer.fault = Some(fault);
            assert!(writer.finish_comparison(&comparison, "summary").is_err());
            assert!(output.join(".incomplete").exists());
            if fault == Fault::Marker {
                assert!(output.join("comparison.json").is_file());
            } else {
                assert!(output.join(".comparison.md.partial").is_file());
            }
        }
        for name in [
            "comparison.md",
            "comparison.json",
            ".comparison.md.partial",
            ".comparison.json.partial",
        ] {
            let output = directory.path().join(format!("existing-{name}"));
            let writer = ArtifactWriter::create(&output)?;
            fs::write(output.join(name), b"untouched")?;
            assert!(writer.finish_comparison(&comparison, "summary").is_err());
            assert_eq!(fs::read(output.join(name))?, b"untouched");
            assert!(output.join(".incomplete").exists());
        }
        Ok(())
    }
}
