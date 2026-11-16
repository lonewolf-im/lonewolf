// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::io::Write;

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn one_lf_or_crlf_trailer_is_removed() -> TestResult {
    for (contents, expected) in [
        ("component-test-secret-0001\n", "component-test-secret-0001"),
        (
            "component-test-secret-0001\r\n",
            "component-test-secret-0001",
        ),
        (
            "component-test-secret-0001\n\n",
            "component-test-secret-0001\n",
        ),
        (
            "component-test-secret-0001\r",
            "component-test-secret-0001\r",
        ),
    ] {
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(contents.as_bytes())?;
        let config: ComponentsConfig = toml::from_str(&format!(
            "[domains.'muc.localhost']\nsecret_file={:?}",
            file.path()
        ))?;
        let secrets = load(&config)?;
        assert_eq!(
            secrets.get("muc.localhost"),
            Some(&ComponentSecret::new(expected)?)
        );
    }
    Ok(())
}

#[test]
fn unavailable_invalid_utf8_and_short_files_report_the_domain_without_contents() -> TestResult {
    let directory = tempfile::tempdir()?;
    for (name, contents, kind) in [
        ("missing", None, io::ErrorKind::NotFound),
        (
            "utf8",
            Some(&b"synthetic-secret\xff"[..]),
            io::ErrorKind::InvalidData,
        ),
        (
            "short",
            Some(&b"synthetic-short"[..]),
            io::ErrorKind::InvalidData,
        ),
    ] {
        let path = directory.path().join(name);
        if let Some(contents) = contents {
            fs::write(&path, contents)?;
        }
        let config: ComponentsConfig =
            toml::from_str(&format!("[domains.'muc.localhost']\nsecret_file={path:?}"))?;
        let error = load(&config).err().ok_or("expected credential failure")?;
        assert!(error.to_string().contains("muc.localhost"));
        assert!(!error.to_string().contains("synthetic"));
        assert!(!format!("{error:?}").contains("synthetic"));
        assert!(error.source().is_some());
        let RunError::ComponentSecret { domain, source } = error else {
            return Err("wrong error".into());
        };
        assert_eq!(domain, "muc.localhost");
        assert_eq!(source.kind(), kind);
        if name == "short" {
            assert_eq!(
                source.to_string(),
                "component secret must be 16 to 1024 bytes"
            );
        }
    }
    Ok(())
}
