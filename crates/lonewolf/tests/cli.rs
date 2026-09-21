// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::process::Command;

use lonewolf::config::DEFAULT_CONFIG_PATH;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn help_and_version_succeed_without_loading_configuration() -> TestResult {
    let directory = tempfile::tempdir()?;
    for flag in ["--help", "--version"] {
        let output = Command::new(env!("CARGO_BIN_EXE_lonewolf"))
            .current_dir(directory.path())
            .args(["--config", "missing.conf", flag])
            .output()?;

        assert!(output.status.success());
        let stdout = std::str::from_utf8(&output.stdout)?;
        assert!(stdout.contains("lonewolf"));
        if flag == "--help" {
            assert!(stdout.contains("--config <PATH>"));
            assert!(stdout.contains("TOML configuration file"));
            assert!(stdout.contains(DEFAULT_CONFIG_PATH));
            assert!(stdout.starts_with("An XMPP messaging server\n"));
        }
        assert!(output.stderr.is_empty());
    }
    Ok(())
}

#[test]
fn invalid_arguments_return_usage_errors() -> TestResult {
    let directory = tempfile::tempdir()?;
    for argument in ["--config", "--unknown", "unexpected"] {
        let output = Command::new(env!("CARGO_BIN_EXE_lonewolf"))
            .current_dir(directory.path())
            .arg(argument)
            .output()?;

        assert_eq!(output.status.code(), Some(2));
        assert!(!output.stderr.is_empty());
    }
    Ok(())
}

#[test]
fn missing_default_file_uses_builtin_defaults() -> TestResult {
    let directory = tempfile::tempdir()?;
    let output = Command::new(env!("CARGO_BIN_EXE_lonewolf"))
        .current_dir(directory.path())
        .output()?;

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn default_file_is_loaded_and_invalid_settings_fail() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join(DEFAULT_CONFIG_PATH);

    for (contents, success) in [("[admin]\nenabled = false", true), ("[admni]", false)] {
        fs::write(&path, contents)?;
        let output = Command::new(env!("CARGO_BIN_EXE_lonewolf"))
            .current_dir(directory.path())
            .output()?;

        assert_eq!(output.status.success(), success);
        if !success {
            assert_eq!(output.status.code(), Some(1));
            let stderr = std::str::from_utf8(&output.stderr)?;
            assert!(stderr.contains("invalid configuration file"));
            assert!(stderr.contains(DEFAULT_CONFIG_PATH));
        }
    }
    Ok(())
}

#[test]
fn explicit_path_overrides_default_file() -> TestResult {
    let directory = tempfile::tempdir()?;
    fs::write(directory.path().join(DEFAULT_CONFIG_PATH), "[admni]")?;
    fs::write(
        directory.path().join("custom.toml"),
        "[admin]\nenabled = false",
    )?;

    for flag in ["-c", "--config"] {
        let output = Command::new(env!("CARGO_BIN_EXE_lonewolf"))
            .current_dir(directory.path())
            .args([flag, "custom.toml"])
            .output()?;

        assert!(output.status.success());
        assert!(output.stderr.is_empty());
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
    fs::write(&path, "[admin]\nenabled = false")?;
    let output = Command::new(env!("CARGO_BIN_EXE_lonewolf"))
        .current_dir(directory.path())
        .arg("--config")
        .arg(&path)
        .output()?;

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    Ok(())
}
