// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::process::Command;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn invalid_worker_counts_fail_before_opening_storage() -> TestResult {
    let directory = tempfile::tempdir()?;
    for value in [
        OsStr::new(""),
        OsStr::new("0"),
        OsStr::new("-1"),
        OsStr::new("1.5"),
        OsStr::new("one"),
        OsStr::new(" 1 "),
        OsStr::new("9999999999999999999999999999999999999999"),
        OsStr::from_bytes(b"\xff"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_lonewolf"))
            .current_dir(directory.path())
            .env("LONEWOLF_WORKER_COUNT", value)
            .output()?;

        assert_eq!(output.status.code(), Some(1));
        assert_eq!(
            std::str::from_utf8(&output.stderr)?,
            "cannot configure core workers: LONEWOLF_WORKER_COUNT must be a positive integer\n"
        );
        assert!(!directory.path().join("data").exists());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn worker_count_above_the_allowed_cpu_count_fails_startup() -> TestResult {
    let directory = tempfile::tempdir()?;
    let output = Command::new(env!("CARGO_BIN_EXE_lonewolf"))
        .current_dir(directory.path())
        .env("LONEWOLF_WORKER_COUNT", usize::MAX.to_string())
        .output()?;

    assert_eq!(output.status.code(), Some(1));
    assert!(
        std::str::from_utf8(&output.stderr)?
            .contains("cannot start core dispatcher: worker count exceeds the allowed CPU set")
    );
    assert!(!directory.path().join("data").exists());
    Ok(())
}

#[test]
fn storage_failure_stops_the_dispatcher_with_admin_disabled() -> TestResult {
    let directory = tempfile::tempdir()?;
    fs::write(directory.path().join("not-directory"), "keep")?;
    fs::write(
        directory.path().join("lonewolf.toml"),
        "[xmpp]\nstanza_pool_size_mib = 8\n[admin]\nenabled = false\n[storage.stores.primary]\nbackend = 'redb'\npath = 'not-directory/accounts.redb'\n",
    )?;
    let output = Command::new(env!("CARGO_BIN_EXE_lonewolf"))
        .current_dir(directory.path())
        .env("LONEWOLF_WORKER_COUNT", "1")
        .output()?;

    assert_eq!(output.status.code(), Some(1));
    let logs = std::str::from_utf8(&output.stderr)?;
    assert!(logs.contains("core dispatcher started"));
    assert!(logs.contains("core dispatcher stopped"));
    assert!(logs.contains("cannot create parent directory"));
    assert_eq!(
        fs::read_to_string(directory.path().join("not-directory"))?,
        "keep"
    );
    Ok(())
}
