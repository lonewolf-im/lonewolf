import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]


class RustDiffTest(unittest.TestCase):
    def test_checks_added_comments_and_event_arguments(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            def git(*args):
                subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)

            git("init", "-q")
            source = root / "example file.rs"
            source.write_text('// --- pre-existing\nfn example() {\n    info!(\n    );\n}\n')
            git("add", ".")
            git("-c", "user.name=Test", "-c", "user.email=test@example.org",
                "commit", "--no-gpg-sign", "--signoff", "-qm", "baseline")
            source.write_text('''// --- pre-existing
fn example() {
    info!(
        target: "api",
        safe_field = "{field value}",
        token = %credential,
        r#"request {id}"#,
    );
    let sample = r#"// FIXME — ... "#;
    tracing::debug!(safe = method("body"), "{{escaped}} \\u{2665}");
    /* This function narrates */
    // TODO #901
    // FIXME
    // ===
    /** Avoid an ellipsis… */
    // Now the external constraint holds.
}
#[cfg(test)]
mod unit {
    // Arrange
    // Here we check
    // Heading — detail
    fn run() {
        other_macro! { tracing::warn!(?payload, "failure {}"); }
    }
}
''')
            result = subprocess.run([sys.executable, SCRIPTS / "check-rust-diff.py", "HEAD"],
                                    cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            rows = [(int(line.split(":")[1]), line.split(":")[2].strip())
                    for line in result.stdout.splitlines() if line.startswith("example file.rs:")]
            self.assertEqual(rows, [(6, "warning"), (7, "error"), (11, "error"),
                                    (13, "error"), (14, "error"), (15, "error"),
                                    (20, "error"), (21, "error"), (22, "error"),
                                    (24, "error"), (24, "warning")])

            source.write_text('fn example() { tracing::info!(%token, "request"); }\n')
            result = subprocess.run([sys.executable, SCRIPTS / "check-rust-diff.py", "HEAD"],
                                    cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("warning: review log field token", result.stdout)


class NativeDependenciesTest(unittest.TestCase):
    def test_only_enabled_native_build_edges_and_links_fail(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            def package(name, manifest):
                directory = root / name
                (directory / "src").mkdir(parents=True)
                (directory / "src/lib.rs").touch()
                (directory / "Cargo.toml").write_text(
                    f'[package]\nname="{name}"\nversion="0.1.0"\nedition="2024"\n{manifest}'
                )
                return directory

            package("cc", "")
            package("linked", 'links="fixture"\n').joinpath("build.rs").write_text("fn main() {}")
            package("unused", '[build-dependencies]\ncc={path="../cc"}\n').joinpath("build.rs").touch()
            package("builder", '[target.\'cfg(target_os = "macos")\'.build-dependencies]\n'
                    'compiler={package="cc",path="../cc"}\n').joinpath("build.rs").write_text("fn main() {}")
            optional = package("optional", 'links="optional"\n[features]\nstd=[]\n')
            (optional / "build.rs").touch()
            package("weak", '[dependencies]\nbackend={package="optional",path="../optional",optional=true}\n'
                    '[features]\ndefault=["backend?/std"]\nenable=["dep:backend"]\n')
            app = package("app", '[workspace]\n[dependencies]\nbuilder={path="../builder"}\n'
                          'weak={path="../weak"}\n'
                          'linked={path="../linked"}\n[target.\'cfg(loom)\'.dependencies]\n'
                          'unused={path="../unused"}\n')
            (app / "deny.toml").write_text(
                '[graph]\ntargets=["x86_64-unknown-linux-gnu","aarch64-apple-darwin"]\n')
            subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=app, check=True,
                           capture_output=True)
            result = subprocess.run([sys.executable, SCRIPTS / "check-native-dependencies.py"],
                                    cwd=app, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            lines = result.stderr.splitlines()
            self.assertEqual(len(lines), 3, lines)
            self.assertTrue(any("aarch64-apple-darwin:" in s and "build tools=cc" in s for s in lines))
            self.assertEqual(sum("links='fixture'" in s for s in lines), 2)

            manifest = app / "Cargo.toml"
            manifest.write_text(manifest.read_text().replace('path="../weak"', 'path="../weak",features=["enable"]'))
            result = subprocess.run([sys.executable, SCRIPTS / "check-native-dependencies.py"],
                                    cwd=app, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr.count("links='optional'"), 2, result.stderr)
