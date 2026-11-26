import os
import re
import subprocess
import sys
from pathlib import Path

from tree_sitter import Language, Parser, Query, QueryCursor
import tree_sitter_rust

RUST = Language(tree_sitter_rust.language())
NODES = Query(RUST, "[(line_comment) (block_comment)] @comment (token_tree) @tokens")
LOG_LEVEL = re.compile(rb"(?:(?:::)?tracing::)?(?:trace|debug|info|warn|error)$")
SENSITIVE = {b"body", b"payload", b"stanza", b"password", b"token"}
HUNK = re.compile(rb"^@@ -[0-9,]+ \+(\d+)(?:,(\d+))? @@", re.M)
ESCAPE = re.compile(rb"\\(?:u\{([\da-fA-F_]+)\}|x([\da-fA-F]{2})|.)")


def changed_lines(base):
    base = subprocess.check_output(["git", "merge-base", base, "HEAD"], text=True).strip()
    diff = ["git", "diff", "--no-ext-diff", "--find-renames", base]
    entries = subprocess.check_output(
        [*diff, "--name-status", "-z", "--diff-filter=AMRT", "--", "*.rs"]
    )
    names = iter(entries.split(b"\0")[:-1])
    for status in names:
        paths = [os.fsdecode(next(names))]
        if status.startswith(b"R"):
            paths.append(os.fsdecode(next(names)))
        path = Path(paths[-1])
        if path.is_symlink() or not path.is_file():
            continue
        patch = subprocess.check_output(["git", "--literal-pathspecs", *diff[1:], "--unified=0", "--", *paths])
        lines = set()
        for start, count in HUNK.findall(patch):
            lines.update(range(int(start), int(start) + int(count or 1)))
        if lines:
            yield path, lines


def in_test(node, path):
    if path.parts[:1] == ("e2e",) or "tests" in path.parts or path.name == "tests.rs":
        return True
    while node:
        if node.type in {"mod_item", "function_item"}:
            attr = node.prev_named_sibling
            while attr and attr.type in {"attribute_item", "line_comment", "block_comment"}:
                if attr.type == "attribute_item" and re.fullmatch(
                    rb"#\[(?:cfg\(test\)|(?:[\w]+::)*test(?:\(.*\))?)\]",
                    re.sub(rb"\s+", b"", attr.text), re.S,
                ):
                    return True
                attr = attr.prev_named_sibling
        node = node.parent
    return False


def comment_problem(line, node, path):
    text = re.sub(r"^(?://[/!]*|/\*+[!]?|\*)\s*", "", line.strip()).removesuffix("*/").strip()
    if re.match(r"^[-=]{3,}", text):
        return "decorative comment separator"
    if any(mark in text for mark in ("—", "…", "...")):
        return "em dash or ellipsis in comment"
    if re.search(r"\b(?:TODO|FIXME)\b", text, re.I) and not re.search(r"(?:#|/issues/)\d+\b", text):
        return "TODO or FIXME needs an issue reference"
    if re.match(r"(?:this function|helper to|here we)\b", text, re.I):
        return "narrating comment"
    if re.match(r"(?:arrange|act|assert|now|then)\b", text, re.I) and in_test(node, path):
        return "test step comment"


def arguments(tree):
    group = []
    for node in tree.children[1:-1]:
        if node.type in {"line_comment", "block_comment"}:
            continue
        if node.type == ",":
            if group:
                yield group
            group = []
        else:
            group.append(node)
    if group:
        yield group


def format_escape(match):
    value = match[1] or match[2]
    return b"{" if value and int(value, 16) == ord("{") else b" "


def log_findings(tree, lines):
    for group in arguments(tree):
        first = group[0]
        if first.type == "token_tree" and first.children[0].type == "{":
            yield from log_findings(first, lines)
            continue
        key = []
        for node in group:
            if node.type == "=":
                break
            key.append(node)
        if first.type in {"string_literal", "raw_string_literal"} and len(key) == len(group):
            for row, text in enumerate(first.text.splitlines(), first.start_point.row + 1):
                if first.type == "string_literal":
                    text = ESCAPE.sub(format_escape, text)
                if row in lines and b"{" in text.replace(b"{{", b""):
                    yield row, "error", "put interpolated log values in named fields"
            break
        if key and key[-1].text.removeprefix(b"r#").strip(b'"') in SENSITIVE:
            for row in range(first.start_point.row + 1, group[-1].end_point.row + 2):
                if row in lines:
                    yield row, "warning", "review log field " + key[-1].text.decode()
                    break


def findings(path, lines):
    root = Parser(RUST).parse(path.read_bytes()).root_node
    nodes = QueryCursor(NODES).captures(root)
    for comment in nodes.get("comment", []):
        for row, text in enumerate(comment.text.decode().splitlines(), comment.start_point.row + 1):
            if row in lines and (problem := comment_problem(text, comment, path)):
                yield row, "error", problem
    for tree in nodes.get("tokens", []):
        bang = tree.prev_sibling
        if bang and bang.type == "!" and (name := bang.prev_sibling) and LOG_LEVEL.fullmatch(name.text):
            yield from log_findings(tree, lines)


if __name__ == "__main__":
    failed = False
    for path, lines in changed_lines(sys.argv[1]):
        for row, level, problem in sorted(findings(path, lines)):
            print(f"{path}:{row}: {level}: {problem}")
            if os.environ.get("GITHUB_ACTIONS") == "true" and level == "warning":
                file = str(path).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
                file = file.replace(":", "%3A").replace(",", "%2C")
                print(f"::warning file={file},line={row}::{problem}")
            failed |= level == "error"
    sys.exit(failed)
