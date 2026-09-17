# Global Agent Instructions

You are an expert AI software engineer. Whenever you modify code in this repository, you must strictly adhere to the following rules:

## 1. Memory Allocation and Idiomatic Rust Rule

- Minimize heap allocations whenever possible. Prefer stack allocation, borrowing, and in-place operations over creating new owned values.
- Avoid unnecessary `clone()`, `to_string()`, `to_vec()`, `unwrap()`, or `expect()` calls when a reference, slice, or proper error handling would suffice.
- Reuse buffers and collections instead of allocating new ones in hot paths.
- When allocations are unavoidable, prefer pre-allocated or pooled resources over per-request allocations.

## 2. Rust Formatting and Linting Gates

Whenever you modify, create, or delete Rust (`.rs`) files, you MUST follow this exact validation loop before considering your task complete and returning control to the user:

1. **Format:** Run `cargo fmt --all` to format the workspace. Do not ask for permission. Run it.
2. **Lint:** Run `cargo clippy --workspace --all-targets -- -D warnings` (or use `-p <package>` if scoped to a specific crate) to check for idiomatic code and errors.
3. **Self-correct:** If Clippy outputs any warnings or errors related to your changes:
   - Read the error output.
   - Apply the fixes suggested by Clippy.
   - You may use `cargo clippy --fix --allow-dirty --allow-staged` if it helps resolve the issues faster.
   - Re-run the `cargo clippy` command to verify the fix worked.
4. **Completion:** Do not report that you are finished until `cargo fmt` has been run and `cargo clippy` returns a clean, zero-exit-code run with no warnings.

## 3. Code Comments

- **Omit comments by default.** New code should carry no comments unless one of the exceptions below applies. Do not narrate what the code does — that is recoverable from the code itself. Never add a comment that restates the adjacent statement, labels an obvious block, or describes the change you just made.
- **Exception 1 — non-obvious "why".** Add a comment when it explains *why* the code does something a certain way and that rationale is not obvious from reading it: a subtle correctness or performance reason, a non-obvious invariant or constraint, a workaround, or a reference to an external requirement.
- **Exception 2 — the deliberate omission.** Add a comment when a casual reader would expect some action to happen here and it deliberately does not, so they don't "fix" it by adding it back. Explain why it was intentionally left out.
- **Exception 3 — godoc on non-obvious functions.** For a new method or function whose behaviour isn't obvious or that carries important invariants, a brief godoc-style doc comment is fine. Keep it short and focused on the contract/invariants, not a line-by-line description.
- **Keep comments self-contained.** Do not name specific symbols (functions, types, variables) or describe behaviour that lives far from the comment — those references silently go stale when the remote code changes. State the rationale in terms of the invariant or consequence itself, not by pointing at distant code that must be kept in sync.
- **Tests get the same treatment, usually less.** Do not write a doc comment above a test function narrating the scenario, and do not annotate steps inside a test body ("bring the DB up", "simulate a newer binary", "now assert…"). A precise test name plus readable setup and assertion messages already convey intent; a step comment that restates the next line is noise. Keep a comment only for a genuine non-obvious "why" (Exceptions 1–2) — e.g. why the test forces an otherwise-invalid state.
- **No decorative separators.** Never add divider/section comments (`// --- label ---`, `// === section ===`, trailing dashes). Group with blank lines or split the file instead.
- **Test:** if a comment could be deleted without losing information not already in the code, delete it.

## 4. License Header Rule

Every Rust (`.rs`) file MUST begin with a single-line SPDX license header as its first line:

```rust
// SPDX-License-Identifier: Apache-2.0
```

When you create a new `.rs` file, add this header before any other content. When you modify an existing `.rs` file that is missing the header, add it.

## 5. Commit Sign-off Rule

Every commit MUST be signed off. It must include a `Signed-off-by:` trailer that matches the committer identity. Always create commits with `git commit --signoff` or `git commit -s`. Do not author unsigned commits.

## 6. Pull Request Conventions

When opening a pull request, you MUST:

1. **Title prefix:** Start the PR title with a conventional-commits-style type followed by `: `. Allowed types:
   - `feat`: new user-visible capability
   - `fix`: bug fix
   - `refactor`: internal restructure with no behavior change
   - `perf`: performance improvement
   - `chore`: tooling, scaffolding, dependencies, build, or CI
   - `docs`: documentation only
   - `test`: tests only
   - `style`: formatting only, with no code change
2. **Type label:** Apply the label that matches the title prefix, if that label exists in the repository.
3. **Component labels:** Apply the labels for the components or crates touched by the change, if the repository defines them.

Use `gh pr create --label <type> --label <component> ...` or `gh pr edit --add-label` to set labels at PR-open time.

## 7. No Tool Attribution Rule

Do not add AI or tool attribution anywhere in commits or pull requests.

- Never append badges, bylines, or footers such as "Made with Cursor", "Generated with Claude Code", "Generated by ChatGPT", or links to the tool's website in PR titles, PR descriptions, or comments.
- Never add `Co-Authored-By:` trailers that name an AI tool or agent to commit messages. Human co-author trailers are permitted and must be preserved.
- If your tooling automatically inserts such attribution into a draft commit message or PR body, remove it before committing or opening the PR. Review the final text of every commit message and PR description for these footers before submitting.
- PR descriptions must contain only content relevant to the change, such as the summary, motivation, and testing notes.

## 8. Logging and Tracing Rule

- Use structured `tracing` events and spans. Keep each event message static and put context in named fields.
- Use `error` for failed operations or broken invariants, `warn` for recoverable protocol or policy violations, `info` for low-volume lifecycle and security events, `debug` for routing and state decisions, and `trace` for high-volume protocol mechanics.
- Never log raw XML stanzas, message bodies, presence text, roster or vCard content, SASL payloads, credentials, tokens, TLS key material, or other secrets.
- Do not log full JIDs, IP addresses, XMPP stream IDs, or client-provided stanza IDs by default. Use log-specific correlation IDs. Pass necessary identifiers through one redaction or pseudonymization helper.
- Log protocol metadata instead of payloads. Prefer fields such as `connection_id`, `direction`, `stream_phase`, `stanza_kind`, `namespace`, `outcome`, `latency_ms`, and `bytes`.
- Treat every client-provided value as untrusted. Bound its length and sanitize control characters before logging it.
- Log an error once at the layer that handles it. Lower layers must return contextual errors instead of logging duplicates.
- Logging must not block an XMPP I/O task. Use bounded asynchronous output with an explicit overload policy.
- Privacy rules apply at every level, including `debug` and `trace`.

## 9. No C or C++ Application Dependencies Rule

- Do not add application libraries implemented in C or C++. This restriction covers direct and transitive dependencies, including build and development dependencies.
- Apply this rule to enabled Cargo features and target-specific dependencies for every supported platform. Bundling, vendoring, static linking, dynamic linking, or installing a library through the operating system does not exempt it.
- Normal operating-system interfaces and platform runtime libraries are allowed. Rust bindings to these interfaces, such as `libc`, are allowed. This exception does not permit application libraries such as SQLite, OpenSSL, or RocksDB.
- A Rust wrapper does not make a C or C++ backend compliant. Check cryptography providers and other native backends separately from their Rust APIs.
- Before adding or updating a dependency or enabling a feature, inspect the resolved dependency and feature graph, relevant build scripts, and native linkage. Do not introduce a C or C++ application library through any of these paths.
