"""Fail closed on common credential patterns without printing secret values."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {".git", ".pytest_cache", "__pycache__", ".gltest-artifacts", ".venv"}
PATTERNS = {
    "private-key-label": re.compile(r"(?i)(private[_ -]?key|secret[_ -]?key)\s*[:=]\s*[^\s$<{][^\s]{7,}"),
    "github-token": re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    "pem-private-key": re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"),
    "aws-access-key": re.compile(r"AKIA[0-9A-Z]{16}"),
}


def main() -> None:
    findings = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in EXCLUDED for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeError, OSError):
            continue
        for line_number, line in enumerate(text.splitlines(), 1):
            for name, pattern in PATTERNS.items():
                if pattern.search(line):
                    findings.append(f"{path.relative_to(ROOT)}:{line_number}:{name}")
    if findings:
        raise SystemExit("potential secrets detected (values redacted):\n" + "\n".join(findings))
    print("secret scan: clean")


if __name__ == "__main__":
    main()

