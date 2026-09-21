// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo::rerun-if-changed=build.rs");

    for name in ["HEAD", "refs", "packed-refs"] {
        if let Some(path) = git(&["rev-parse", "--path-format=absolute", "--git-path", name])
            && Path::new(&path).exists()
        {
            println!("cargo::rerun-if-changed={path}");
        }
    }

    let commit = git(&["rev-parse", "--short", "HEAD"]);
    let branch = git(&["symbolic-ref", "--quiet", "--short", "HEAD"]);
    let branch = branch.as_deref().unwrap_or(if commit.is_some() {
        "detached"
    } else {
        "unknown"
    });
    println!("cargo::rustc-env=LONEWOLF_GIT_BRANCH={branch}");
    println!(
        "cargo::rustc-env=LONEWOLF_GIT_COMMIT={}",
        commit.as_deref().unwrap_or("unknown")
    );
}

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let mut value = String::from_utf8(output.stdout).ok()?;
    value.truncate(value.trim_end().len());
    if value.is_empty() {
        return None;
    }
    Some(value)
}
