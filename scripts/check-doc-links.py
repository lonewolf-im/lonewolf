import re
import subprocess
import sys
from pathlib import Path

LINK = re.compile(r"\]\(([^)#\s]+)#L(\d+)\)")
FUNCTION = re.compile(r"\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+\w+")


def check(document):
    for number, text in enumerate(document.read_text().splitlines(), 1):
        for link in LINK.finditer(text):
            target = document.parent / link.group(1)
            line = int(link.group(2))
            location = f"{document}:{number}: {link.group(1)}#L{line}"
            if not target.is_file():
                yield f"{location}: missing file"
                continue
            lines = target.read_text().splitlines()
            if not 1 <= line <= len(lines):
                yield f"{location}: line out of range"
            elif target.suffix == ".rs" and not FUNCTION.match(lines[line - 1]):
                yield f"{location}: not a function declaration"


if __name__ == "__main__":
    documents = sys.argv[1:] or subprocess.check_output(["git", "ls-files", "*.md"], text=True).split()
    violations = [message for document in documents for message in check(Path(document))]
    for message in violations:
        print(message, file=sys.stderr)
    sys.exit(bool(violations))
