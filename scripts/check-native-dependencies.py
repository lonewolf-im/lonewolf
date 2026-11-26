import json
import subprocess
import sys
import tomllib
from collections import defaultdict
from pathlib import Path

BUILD_TOOLS = {"cc", "cmake", "bindgen", "pkg-config"}
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"


def weak_dependencies(pkg, node):
    # A feature such as "ring?/std" configures ring only if another feature enables it.
    # Cargo metadata can include that edge even when ring is disabled.
    enabled = set()
    weak = set()
    for feature in node["features"]:
        for item in pkg["features"].get(feature, ()):
            name, _, _ = item.partition("/")
            if name.endswith("?"):
                weak.add(name[:-1])
            elif item.startswith("dep:") or "/" in item:
                enabled.add(name.removeprefix("dep:"))
    return weak - enabled


def only_weakly_referenced(pkg, edge, child, weak):
    if not weak:
        return False
    kinds = {(k["kind"], k["target"]) for k in edge["dep_kinds"]}
    library_names = {t["name"] for t in child["targets"] if "lib" in t["kind"] or "proc-macro" in t["kind"]}
    declarations = []
    for dep in pkg["dependencies"]:
        if dep["name"] != child["name"] or (dep["kind"], dep["target"]) not in kinds:
            continue
        names = {dep["rename"].replace("-", "_")} if dep["rename"] else library_names
        if edge["name"] in names:
            declarations.append(dep)
    return bool(declarations) and all(
        d["optional"] and (d["rename"] or d["name"]) in weak for d in declarations
    )


def check(target):
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--all-features", "--locked", "--format-version", "1",
        "--filter-platform", target,
    ]))
    packages = {pkg["id"]: pkg for pkg in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    parents = defaultdict(set)
    builders = defaultdict(set)
    seen = set()
    pending = metadata["workspace_members"].copy()
    while pending:
        owner = pending.pop()
        if owner in seen:
            continue
        seen.add(owner)
        node = nodes[owner]
        pkg = packages[owner]
        weak = weak_dependencies(pkg, node)
        for edge in node["deps"]:
            child = packages[edge["pkg"]]
            if only_weakly_referenced(pkg, edge, child, weak):
                continue
            parents[child["id"]].add(owner)
            pending.append(child["id"])
            if child["name"] in BUILD_TOOLS and any(k["kind"] == "build" for k in edge["dep_kinds"]):
                builders[owner].add(child["name"])
    providers = {i for i in seen if packages[i]["name"] == "aws-lc-rs" and packages[i]["source"] == CRATES_IO}
    for i in sorted(seen):
        pkg = packages[i]
        if not pkg["links"] and not builders[i]:
            continue
        if i in providers and not builders[i]:
            continue
        if (pkg["name"] == "aws-lc-sys" and pkg["source"] == CRATES_IO and parents[i]
                and parents[i] <= providers and i not in metadata["workspace_members"]):
            continue
        yield f"{target}: {i} (links={pkg['links']!r}, build tools={', '.join(sorted(builders[i]))})"


if __name__ == "__main__":
    with Path("deny.toml").open("rb") as policy:
        targets = tomllib.load(policy)["graph"]["targets"]
    violations = [message for target in targets for message in check(target)]
    for message in violations:
        print(message, file=sys.stderr)
    sys.exit(bool(violations))
