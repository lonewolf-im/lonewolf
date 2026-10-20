// SPDX-License-Identifier: Apache-2.0

use std::{env, path::Path, process::Command};

fn output(program: &str, args: &[&str]) -> Option<String> {
    let result = Command::new(program).args(args).output().ok()?;
    if !result.status.success() {
        return None;
    }
    let value = String::from_utf8(result.stdout).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.replace('\n', " | "))
}

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    for name in ["HEAD", "refs", "packed-refs"] {
        if let Some(path) = output(
            "git",
            &["rev-parse", "--path-format=absolute", "--git-path", name],
        ) && Path::new(&path).exists()
        {
            println!("cargo::rerun-if-changed={path}");
        }
    }
    println!("cargo::rerun-if-env-changed=PROFILE");
    for (key, value) in [
        ("REVISION", output("git", &["rev-parse", "HEAD"])),
        ("PROFILE", env::var("PROFILE").ok()),
    ] {
        println!(
            "cargo::rustc-env=LONEWOLF_BENCH_{key}={}",
            value.as_deref().unwrap_or("unknown")
        );
    }
}
