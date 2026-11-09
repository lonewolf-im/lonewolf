// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn generation_is_private_indexed_and_never_overwrites() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("credentials.json");
    generate_credentials("localhost", "bench", 3, &path)?;
    assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    let original = fs::read(&path)?;
    let all = CredentialSet::read(&path, None, None)?;
    assert_eq!(all.len(), 3);
    assert_eq!(all.accounts[1].jid, "bench-000001@localhost");
    assert!(
        all.accounts
            .iter()
            .all(|account| account.password.len() == 32)
    );
    let selected = CredentialSet::read(&path, Some("localhost"), Some(2))?;
    assert_eq!(selected.len(), 2);
    assert_eq!(selected.into_prepared()?.len(), 2);
    assert!(CredentialSet::read(&path, Some("localhost"), Some(4)).is_err());
    assert!(CredentialSet::read(&path, Some("example.test"), Some(1)).is_err());
    assert!(generate_credentials("localhost", "bench", 1, &path).is_err());
    assert_eq!(fs::read(&path)?, original);
    Ok(())
}

#[test]
fn private_reads_refuse_symlinks_nonregular_files_and_public_modes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("credentials.json");
    generate_credentials("localhost", "bench", 1, &path)?;
    let link = directory.path().join("link");
    symlink(&path, &link)?;
    assert!(CredentialSet::read(&link, None, None).is_err());
    assert!(generate_credentials("localhost", "bench", 1, &link).is_err());
    assert!(CredentialSet::read(directory.path(), None, None).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
    assert!(CredentialSet::read(&path, None, None).is_err());
    Ok(())
}

#[test]
fn manifests_validate_all_entries_and_never_echo_passwords() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("credentials.json");
    for accounts in [
        r#"[{"jid":"a@localhost","password":"secret"},{"jid":"a@localhost","password":"secret"}]"#,
        r#"[{"jid":"a@localhost","password":"secret"},{"jid":"b@localhost/x","password":"secret"}]"#,
        r#"[{"jid":"A@localhost","password":"secret"}]"#,
        r#"[{"jid":"a@example.test","password":"secret"}]"#,
        r#"[{"jid":"a@localhost","password":"secret\u0007"}]"#,
        r#"[{"jid":"a@localhost","password":"secret","unknown":1}]"#,
    ] {
        fs::write(
            &path,
            format!(r#"{{"schema_version":1,"domain":"localhost","accounts":{accounts}}}"#),
        )?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        match CredentialSet::read(&path, Some("localhost"), Some(1)) {
            Ok(_) => panic!("invalid manifest was accepted"),
            Err(error) => {
                assert!(!error.to_string().contains("secret"));
                assert!(!format!("{error:?}").contains("secret"));
            }
        }
    }
    for prefix in [
        "",
        "A",
        "a.b",
        "1a",
        "a/b",
        "abcdefghijklmnopqrstuvwxyzabcdefg",
    ] {
        assert!(generated("localhost", prefix, 1).is_err());
    }
    Ok(())
}

#[test]
fn password_and_file_sizes_are_bounded() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("credentials.json");
    fs::write(
        &path,
        format!(
            r#"{{"schema_version":1,"domain":"localhost","accounts":[{{"jid":"a@localhost","password":"{}"}}]}}"#,
            "s".repeat(MAX_PASSWORD + 1)
        ),
    )?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    assert!(CredentialSet::read(&path, None, None).is_err());
    OpenOptions::new()
        .write(true)
        .open(&path)?
        .set_len(MAX_FILE as u64 + 1)?;
    assert!(CredentialSet::read(&path, None, None).is_err());
    Ok(())
}

#[test]
fn escaped_passwords_decode_directly_with_unicode_and_byte_bounds() -> TestResult {
    assert_eq!(
        &*decode_password(r#""secret\"\\\/\b\f\n\r\t\u00e9\ud834\udd1e""#)?,
        "secret\"\\/\u{8}\u{c}\n\r\té𝄞"
    );
    assert_eq!(
        decode_password(&format!("\"{}\"", "\\u0061".repeat(MAX_PASSWORD)))?.len(),
        MAX_PASSWORD
    );
    assert!(decode_password(&format!("\"{}\"", "\\u0061".repeat(MAX_PASSWORD + 1))).is_err());
    assert!(decode_password(&format!("\"{}\"", "\\u00e9".repeat(MAX_PASSWORD / 2 + 1))).is_err());
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("credentials.json");
    fs::write(
        &path,
        r#"{"schema_version":1,"domain":"localhost","accounts":[{"jid":"a@localhost","password":"str\u006fng-\"quoted\"-passw\u00f6rd"}]}"#,
    )?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let credentials = CredentialSet::read(&path, None, None)?;
    assert_eq!(
        &*credentials.accounts[0].password,
        "strong-\"quoted\"-passwörd"
    );
    Ok(())
}

#[test]
fn malformed_escaped_passwords_return_only_sanitized_errors() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("credentials.json");
    for password in [
        r#""secret\x""#,
        r#""secret\u""#,
        r#""secret\u123""#,
        r#""secret\uzzzz""#,
        r#""secret\ud800""#,
        r#""secret\ud800\u1234""#,
        r#""secret\ud800\ud800""#,
        r#""secret\udc00""#,
        r#""secret\ud800x""#,
        r#""secret"unescaped""#,
    ] {
        let error = decode_password(password)
            .err()
            .ok_or("decoder accepted invalid escape")?;
        assert!(!error.to_string().contains("secret"));
        fs::write(
            &path,
            format!(
                r#"{{"schema_version":1,"domain":"localhost","accounts":[{{"jid":"a@localhost","password":{password}}}]}}"#
            ),
        )?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        match CredentialSet::read(&path, None, None) {
            Ok(_) => return Err("manifest accepted invalid escape".into()),
            Err(error) => {
                assert!(!error.to_string().contains("secret"));
                assert!(!format!("{error:?}").contains("secret"));
            }
        }
    }
    Ok(())
}
