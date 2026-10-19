// SPDX-License-Identifier: Apache-2.0

use super::TestResult;
use lonewolf_bench::report::{RunReport, RunStatus};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

pub fn complete(directory: &Path, expected: RunStatus) -> TestResult<RunReport> {
    assert_eq!(fs::metadata(directory)?.permissions().mode() & 0o077, 0);
    assert!(!directory.join(".incomplete").exists());
    let report = RunReport::read(directory)?;
    assert_eq!(report.status, expected, "{:?}", report.reasons);
    for name in ["result.json", "summary.md", "telemetry.ndjson"] {
        let metadata = fs::metadata(directory.join(name))?;
        if expected == RunStatus::Passed || name != "telemetry.ndjson" {
            assert!(metadata.len() > 0);
        }
        assert_eq!(metadata.permissions().mode() & 0o077, 0);
    }
    Ok(report)
}

pub fn copy_run(source: &Path, target: &Path) -> TestResult {
    fs::create_dir(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        fs::copy(entry.path(), target.join(entry.file_name()))?;
    }
    Ok(())
}

pub fn edit_report(directory: &Path, edit: impl FnOnce(&mut serde_json::Value)) -> TestResult {
    let file = directory.join("result.json");
    let mut value = serde_json::from_slice(&fs::read(&file)?)?;
    edit(&mut value);
    fs::write(file, serde_json::to_vec(&value)?)?;
    Ok(())
}

pub fn contents(directory: &Path) -> TestResult<Vec<(std::ffi::OsString, Vec<u8>)>> {
    let mut contents = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        contents.push((entry.file_name(), fs::read(entry.path())?));
    }
    contents.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    Ok(contents)
}
