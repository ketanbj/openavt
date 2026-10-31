"""Check local Markdown links and anchors in this Git checkout; no network calls.

Uses Git's file inventory so ignored outputs and nested submodules are excluded.
Run from any working directory. Explicit paths support a focused documentation check.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def prose(text: str) -> str:
    lines, fence = [], None
    for line in text.splitlines():
        marker = re.match(r"^\s*(`{3,}|~{3,})", line)
        if marker:
            char = marker.group(1)[0]
            if fence is None:
                fence = (char, len(marker.group(1)))
            elif char == fence[0] and len(marker.group(1)) >= fence[1]:
                fence = None
            lines.append("")
        else:
            lines.append(line if fence is None else "")
    if fence is not None:
        raise ValueError("unclosed Markdown code fence")
    return re.sub(r"<!--[\s\S]*?-->", "", "\n".join(lines))


def anchors(text: str) -> set[str]:
    counts, result = {}, set()
    for line in prose(text).splitlines():
        heading = re.match(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$", line)
        if not heading:
            continue
        value = re.sub(r"<[^>]+>", "", heading.group(1)).lower()
        slug = "".join(
            c for c in value if c in " -_" or c.isalnum() or unicodedata.category(c).startswith("M")
        )
        slug = slug.replace(" ", "-")
        count = counts.get(slug, 0)
        candidate = f"{slug}-{count}" if count else slug
        while candidate in result:
            count += 1
            candidate = f"{slug}-{count}"
        counts[slug] = count + 1
        result.add(candidate)
    result.update(re.findall(r"<a\s+(?:name|id)=[\"\']([^\"\']+)[\"\']", text))
    return result


def targets(text: str):
    clean = re.sub(r"`[^`\n]*`", "", prose(text))
    definitions = {
        m.group(1).casefold(): m.group(2) for m in re.finditer(r"^\s*\[([^]]+)\]:\s*(\S+)", clean, re.M)
    }
    for match in re.finditer(r"!?\[[^]\n]*\]\((<[^>]+>|[^)\n]+)\)", clean):
        yield clean.count("\n", 0, match.start()) + 1, match.group(1)
    for match in re.finditer(r"!?\[([^]\n]+)\]\[([^]\n]*)\]", clean):
        key = (match.group(2) or match.group(1)).casefold()
        if key not in definitions:
            raise ValueError(f"undefined link reference: {key}")
        yield clean.count("\n", 0, match.start()) + 1, definitions[key]


def check(path: Path) -> list[str]:
    errors = []
    if not path.is_file():
        return [f"{path}: missing Markdown file"]
    try:
        entries = list(targets(path.read_text(encoding="utf-8")))
    except ValueError as error:
        return [f"{path}: {error}"]
    for line, raw in entries:
        target = raw[1 : raw.index(">")] if raw.startswith("<") else re.split(r"\s+[\"']", raw, maxsplit=1)[0]
        parsed = urlsplit(target.strip())
        if parsed.scheme or parsed.netloc:
            continue
        destination = path.parent / unquote(parsed.path) if parsed.path else path
        if not destination.exists():
            errors.append(f"{path}:{line}: missing local target {target}")
        elif parsed.fragment and destination.suffix.lower() == ".md":
            expected = unquote(parsed.fragment)
            if expected not in anchors(destination.read_text(encoding="utf-8")):
                errors.append(f"{path}:{line}: missing heading #{expected} in {destination}")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths", nargs="*", type=Path, help="optional Markdown paths relative to the current directory"
    )
    args = parser.parse_args()
    if args.paths:
        paths = args.paths
    else:
        output = subprocess.check_output(
            ["git", "-C", str(ROOT), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        )
        paths = [
            ROOT / p.decode()
            for p in sorted(set(output.split(b"\0")))
            if p.endswith(b".md") and (ROOT / p.decode()).is_file()
        ]
    errors = [error for path in paths for error in check(path)]
    if errors:
        raise SystemExit("\n".join(errors))
    print(f"Checked {len(paths)} Markdown files: local links, headings and code fences are valid.")


if __name__ == "__main__":
    main()
