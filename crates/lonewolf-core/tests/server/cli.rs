// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::process::Command;

use lonewolf_core::config::DEFAULT_CONFIG_PATH;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn invalid_default_file_is_rejected() -> TestResult {
    let directory = tempfile::tempdir()?;
    fs::write(directory.path().join(DEFAULT_CONFIG_PATH), "[admni]")?;
    let output = Command::new(env!("CARGO_BIN_EXE_lonewolf"))
        .current_dir(directory.path())
        .output()?;

    assert_eq!(output.status.code(), Some(1));
    let stderr = std::str::from_utf8(&output.stderr)?;
    assert!(stderr.contains("invalid configuration file"));
    assert!(stderr.contains(DEFAULT_CONFIG_PATH));
    Ok(())
}

#[test]
fn explicit_path_overrides_default_file() -> TestResult {
    let directory = tempfile::tempdir()?;
    fs::write(directory.path().join(DEFAULT_CONFIG_PATH), "[admni]")?;
    fs::write(directory.path().join("custom.toml"), "[admni]")?;

    for flag in ["-c", "--config"] {
        let output = Command::new(env!("CARGO_BIN_EXE_lonewolf"))
            .current_dir(directory.path())
            .args([flag, "custom.toml"])
            .output()?;

        assert_eq!(output.status.code(), Some(1));
        let stderr = std::str::from_utf8(&output.stderr)?;
        assert!(stderr.contains("invalid configuration file 'custom.toml'"));
        assert!(!stderr.contains(DEFAULT_CONFIG_PATH));
    }
    Ok(())
}

#[test]
fn explicit_missing_default_path_does_not_fall_back() -> TestResult {
    let directory = tempfile::tempdir()?;
    let output = Command::new(env!("CARGO_BIN_EXE_lonewolf"))
        .current_dir(directory.path())
        .args(["--config", DEFAULT_CONFIG_PATH])
        .output()?;

    assert_eq!(output.status.code(), Some(1));
    let stderr = std::str::from_utf8(&output.stderr)?;
    assert!(stderr.contains("cannot read configuration file"));
    assert!(stderr.contains(DEFAULT_CONFIG_PATH));
    Ok(())
}

#[test]
fn unreadable_default_file_does_not_fall_back() -> TestResult {
    let directory = tempfile::tempdir()?;
    fs::create_dir(directory.path().join(DEFAULT_CONFIG_PATH))?;
    let output = Command::new(env!("CARGO_BIN_EXE_lonewolf"))
        .current_dir(directory.path())
        .output()?;

    assert_eq!(output.status.code(), Some(1));
    assert!(std::str::from_utf8(&output.stderr)?.contains("cannot read configuration file"));
    Ok(())
}

// macOS filesystems can reject non-UTF-8 filenames.
#[cfg(target_os = "linux")]
#[test]
fn config_file_with_non_utf8_path_is_loaded() -> TestResult {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let directory = tempfile::tempdir()?;
    let path = directory
        .path()
        .join(OsString::from_vec(b"config-\xff.toml".to_vec()));
    fs::write(&path, "[admni]")?;
    let output = Command::new(env!("CARGO_BIN_EXE_lonewolf"))
        .current_dir(directory.path())
        .arg("--config")
        .arg(&path)
        .output()?;

    assert_eq!(output.status.code(), Some(1));
    assert!(std::str::from_utf8(&output.stderr)?.contains("invalid configuration file"));
    Ok(())
}
