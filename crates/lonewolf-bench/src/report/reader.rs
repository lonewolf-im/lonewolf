// SPDX-License-Identifier: Apache-2.0

use super::{ArtifactKind, ArtifactMetadata, RunReport, artifacts};
use crate::error::{BenchError, BenchResult, ErrorCode};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const LOG_LIMIT: u64 = 64 * 1024;
const ENTRIES: [(ArtifactKind, &str, u64); 3] = [
    (
        ArtifactKind::Summary,
        "summary.md",
        artifacts::RESULT_LIMIT as u64,
    ),
    (
        ArtifactKind::Telemetry,
        "telemetry.ndjson",
        crate::telemetry::RAW_CAPACITY as u64,
    ),
    (ArtifactKind::ServerLog, "server.log", LOG_LIMIT),
];

fn error(context: &'static str) -> BenchError {
    BenchError::new(ErrorCode::IncompatibleComparison, context)
}

struct CheckedFile {
    file: File,
    path: PathBuf,
    initial: Metadata,
}
impl CheckedFile {
    fn open(path: PathBuf, limit: u64, result: bool) -> BenchResult<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&path)
            .map_err(|_| {
                error(if result {
                    "result_open"
                } else {
                    "artifact_open"
                })
            })?;
        let initial = file.metadata().map_err(|_| {
            error(if result {
                "result_metadata"
            } else {
                "artifact_open"
            })
        })?;
        if !initial.is_file() || initial.len() > limit {
            return Err(error(if result {
                "result_size_or_type"
            } else {
                "artifact_size_or_type"
            }));
        }
        Ok(Self {
            file,
            path,
            initial,
        })
    }
    fn verify_unchanged(&self) -> BenchResult<()> {
        let descriptor = self.file.metadata().map_err(|_| error("input_changed"))?;
        let path = fs::symlink_metadata(&self.path).map_err(|_| error("input_changed"))?;
        if same_file(&self.initial, &descriptor) && same_file(&self.initial, &path) {
            Ok(())
        } else {
            Err(error("input_changed"))
        }
    }
    fn verify_digest(
        &mut self,
        declared: &ArtifactMetadata,
        buffer: &mut [u8; 65536],
    ) -> BenchResult<()> {
        if self.initial.len() != declared.bytes {
            return Err(error("artifact_size_or_type"));
        }
        let mut input = (&mut self.file).take(declared.bytes + 1);
        let mut count = 0;
        let mut digest = Sha256::new();
        loop {
            let read = input.read(buffer).map_err(|_| error("artifact_read"))?;
            if read == 0 {
                break;
            }
            count += read as u64;
            digest.update(&buffer[..read]);
        }
        if count != declared.bytes {
            return Err(error("artifact_size_or_type"));
        }
        let digest = digest.finalize();
        for (byte, pair) in digest
            .iter()
            .zip(declared.sha256.as_bytes().as_chunks::<2>().0)
        {
            let digit = |value: u8| {
                if value.is_ascii_digit() {
                    value - b'0'
                } else {
                    value.to_ascii_lowercase() - b'a' + 10
                }
            };
            if *byte != digit(pair[0]) * 16 + digit(pair[1]) {
                return Err(error("artifact_digest"));
            }
        }
        Ok(())
    }
}
fn same_file(a: &Metadata, b: &Metadata) -> bool {
    b.is_file()
        && a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}
fn marker_absent(directory: &Path) -> BenchResult<()> {
    match fs::symlink_metadata(directory.join(".incomplete")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(error("incomplete_publication")),
    }
}
fn declarations(report: &RunReport) -> BenchResult<()> {
    for required in [ArtifactKind::Summary, ArtifactKind::Telemetry] {
        if !report.artifacts.contains_key(&required) {
            return Err(error("artifact_required"));
        }
    }
    for (kind, _, limit) in ENTRIES {
        if let Some(declared) = report.artifacts.get(&kind)
            && (declared.bytes > limit
                || (kind == ArtifactKind::Summary && declared.bytes == 0)
                || declared.sha256.len() != 64
                || !declared.sha256.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(error("artifact_declaration"));
        }
    }
    Ok(())
}

pub(super) fn read(directory: &Path) -> BenchResult<RunReport> {
    marker_absent(directory)?;
    let mut result = CheckedFile::open(
        directory.join("result.json"),
        artifacts::RESULT_LIMIT as u64,
        true,
    )?;
    let mut bytes = Vec::new();
    (&mut result.file)
        .take(artifacts::RESULT_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| error("result_read"))?;
    if bytes.len() > artifacts::RESULT_LIMIT {
        return Err(error("result_size_or_type"));
    }
    let report: RunReport = serde_json::from_slice(&bytes).map_err(|_| error("result_schema"))?;
    drop(bytes);
    declarations(&report)?;
    let mut checked = [None, None, None];
    let mut buffer = [0; 65536];
    for (index, (kind, name, limit)) in ENTRIES.into_iter().enumerate() {
        if let Some(declared) = report.artifacts.get(&kind) {
            let mut file = CheckedFile::open(directory.join(name), limit, false)?;
            file.verify_digest(declared, &mut buffer)?;
            checked[index] = Some(file);
        }
    }
    result.verify_unchanged()?;
    for file in checked.iter().flatten() {
        file.verify_unchanged()?;
    }
    marker_absent(directory)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{RunStatus, metadata::hash_bytes, tests::report_fixture};
    use std::os::unix::fs::symlink;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn persisted(
        root: &Path,
        log: Option<&[u8]>,
        telemetry: &[u8],
    ) -> Result<RunReport, Box<dyn std::error::Error>> {
        let mut report: RunReport = serde_json::from_value(report_fixture()?)?;
        let writer = artifacts::ArtifactWriter::create(root)?;
        writer.prepare(&mut report, telemetry, log)?;
        writer.finish(&report)?;
        Ok(report)
    }
    fn rewrite(root: &Path, report: &RunReport) -> TestResult {
        fs::write(root.join("result.json"), serde_json::to_vec(report)?)?;
        Ok(())
    }
    #[test]
    fn mandatory_and_optional_artifacts_allow_empty_telemetry_and_unsuccessful_statuses()
    -> TestResult {
        let directory = tempfile::tempdir()?;
        for (index, status) in [
            RunStatus::Passed,
            RunStatus::Failed,
            RunStatus::Invalid,
            RunStatus::Interrupted,
        ]
        .into_iter()
        .enumerate()
        {
            let root = directory.path().join(index.to_string());
            let mut report = persisted(&root, if index % 2 == 0 { Some(b"") } else { None }, b"")?;
            report.status = status;
            for metadata in report.artifacts.values_mut() {
                metadata.sha256.make_ascii_uppercase();
            }
            rewrite(&root, &report)?;
            assert_eq!(read(&root)?, report);
            fs::write(root.join("telemetry.jsonl"), b"undeclared extra")?;
            assert!(read(&root).is_ok());
        }
        Ok(())
    }
    #[test]
    fn missing_declarations_files_and_malformed_or_wrong_hashes_refuse() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("run");
        let report = persisted(&root, Some(b"log"), b"telemetry")?;
        for kind in [ArtifactKind::Summary, ArtifactKind::Telemetry] {
            let mut changed = report.clone();
            changed.artifacts.remove(&kind);
            rewrite(&root, &changed)?;
            assert_eq!(
                read(&root).err().ok_or("accepted")?.context(),
                "artifact_required"
            );
        }
        for (kind, name, _) in ENTRIES {
            rewrite(&root, &report)?;
            let original = fs::read(root.join(name))?;
            fs::remove_file(root.join(name))?;
            assert!(read(&root).is_err());
            fs::write(root.join(name), &original)?;
            for hash in [
                "x".repeat(64),
                "0".repeat(63),
                "0".repeat(64),
                "é".repeat(32),
            ] {
                let mut changed = report.clone();
                changed.artifacts.get_mut(&kind).ok_or("entry")?.sha256 = hash;
                rewrite(&root, &changed)?;
                assert!(read(&root).is_err());
            }
            for contents in [
                vec![b'!'; original.len()],
                original[..original.len() - 1].to_vec(),
                [original.clone(), vec![b'!']].concat(),
            ] {
                rewrite(&root, &report)?;
                fs::write(root.join(name), contents)?;
                assert!(read(&root).is_err());
            }
            fs::write(root.join(name), original)?;
        }
        Ok(())
    }
    #[test]
    fn declaration_caps_are_checked_before_opens_and_oversized_files_refuse() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("run");
        let report = persisted(&root, Some(b"log"), b"")?;
        for (kind, name, limit) in ENTRIES {
            let original = fs::read(root.join(name))?;
            fs::remove_file(root.join(name))?;
            for count in [limit + 1, u64::MAX] {
                let mut changed = report.clone();
                changed.artifacts.get_mut(&kind).ok_or("entry")?.bytes = count;
                rewrite(&root, &changed)?;
                assert_eq!(
                    read(&root).err().ok_or("accepted")?.context(),
                    "artifact_declaration"
                );
            }
            fs::File::create(root.join(name))?.set_len(limit + 1)?;
            rewrite(&root, &report)?;
            assert!(read(&root).is_err());
            fs::write(root.join(name), original)?;
        }
        let mut changed = report;
        changed
            .artifacts
            .get_mut(&ArtifactKind::Summary)
            .ok_or("summary")?
            .bytes = 0;
        rewrite(&root, &changed)?;
        assert!(read(&root).is_err());
        fs::File::create(root.join("result.json"))?.set_len(artifacts::RESULT_LIMIT as u64 + 1)?;
        assert!(read(&root).is_err());
        Ok(())
    }
    #[test]
    fn symlinks_directories_fifos_and_sockets_are_rejected_without_blocking() -> TestResult {
        use nix::{sys::stat::Mode, unistd::mkfifo};
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("run");
        persisted(&root, Some(b"log"), b"raw")?;
        for name in [
            "result.json",
            "summary.md",
            "telemetry.ndjson",
            "server.log",
        ] {
            let path = root.join(name);
            let bytes = fs::read(&path)?;
            fs::remove_file(&path)?;
            fs::write(root.join("target"), &bytes)?;
            for target in ["absent", "../run", "target"] {
                symlink(target, &path)?;
                assert!(read(&root).is_err());
                fs::remove_file(&path)?;
            }
            fs::create_dir(&path)?;
            assert!(read(&root).is_err());
            fs::remove_dir(&path)?;
            mkfifo(&path, Mode::S_IRUSR | Mode::S_IWUSR)?;
            assert!(read(&root).is_err());
            fs::remove_file(&path)?;
            let socket = std::os::unix::net::UnixListener::bind(&path)?;
            assert!(read(&root).is_err());
            drop(socket);
            fs::remove_file(&path)?;
            fs::write(&path, bytes)?;
        }
        Ok(())
    }
    #[test]
    fn retained_handles_reject_mutation_replacement_and_marker_creation() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("input");
        fs::write(&path, b"same")?;
        let file = CheckedFile::open(path.clone(), 10, false)?;
        fs::write(&path, b"different")?;
        assert_eq!(
            file.verify_unchanged().err().ok_or("accepted")?.context(),
            "input_changed"
        );
        let file = CheckedFile::open(path.clone(), 10, false)?;
        file.file
            .set_times(std::fs::FileTimes::new().set_modified(std::time::SystemTime::UNIX_EPOCH))?;
        assert!(file.verify_unchanged().is_err());
        let file = CheckedFile::open(path.clone(), 10, false)?;
        fs::rename(&path, directory.path().join("old"))?;
        fs::write(&path, b"different")?;
        assert!(file.verify_unchanged().is_err());
        assert!(marker_absent(directory.path()).is_ok());
        symlink("absent", directory.path().join(".incomplete"))?;
        assert!(marker_absent(directory.path()).is_err());
        Ok(())
    }
    #[test]
    fn digest_checks_do_not_accept_size_only_or_changed_declarations() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("file");
        fs::write(&path, b"aaaa")?;
        let mut file = CheckedFile::open(path, 4, false)?;
        let mut buffer = [0; 65536];
        let declared = ArtifactMetadata {
            bytes: 4,
            sha256: hash_bytes(b"bbbb"),
        };
        assert_eq!(
            file.verify_digest(&declared, &mut buffer)
                .err()
                .ok_or("accepted")?
                .context(),
            "artifact_digest"
        );
        Ok(())
    }
}
