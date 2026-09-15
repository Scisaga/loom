#!/usr/bin/env python3
"""文档入口：检查本地引用、章节锚点、孤立文档及代码/产物混入。"""

from __future__ import annotations

from collections import Counter
import html
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"\[[^\]\n]*\]\((<[^>\n]+>|[^\s)]+)(?:\s+[^)]+)?\)")
REFERENCE = re.compile(r"^\s{0,3}\[([^\]]+)\]:\s*(<[^>]+>|\S+)", re.MULTILINE)
EXPLICIT_ID = re.compile(r'<(?:a|span)\b[^>]*\bid=["\']([^"\']+)["\']', re.IGNORECASE)
DOCUMENT_EXTENSIONS = {".md", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf"}


def prose(source: str) -> str:
    """§12：忽略示例代码，保留行数使检查位置能直接定位。"""
    result: list[str] = []
    fence = ""
    for line in source.splitlines(keepends=True):
        match = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if fence:
            if match and match[1][0] == fence[0] and len(match[1]) >= len(fence):
                fence = ""
            result.append("\n")
        elif match:
            fence = match[1]
            result.append("\n")
        else:
            result.append(line)
    return "".join(result)


def anchors(source: str) -> set[str]:
    body = prose(source)
    result = set(EXPLICIT_ID.findall(body))
    duplicates: Counter[str] = Counter()
    for match in re.finditer(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$", body, re.MULTILINE):
        heading = html.unescape(match[1])
        heading = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", heading)
        heading = re.sub(r"<[^>]*>", "", heading)
        heading = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
        suffix = f"-{duplicates[heading]}" if duplicates[heading] else ""
        result.add(heading + suffix)
        duplicates[heading] += 1
    return result


def links(source: str) -> list[tuple[int, str]]:
    body = prose(source)
    found = [(m.start(), m[1].strip("<>")) for m in LINK.finditer(body)]
    found.extend((m.start(), m[2].strip("<>")) for m in REFERENCE.finditer(body))
    return [(body.count("\n", 0, offset) + 1, dest) for offset, dest in found]


def check(root: Path, files: list[Path]) -> list[str]:
    failures: list[str] = []
    documents = {p.resolve(): p.read_text() for p in files if p.is_file() and p.suffix == ".md"}
    cached_anchors = {p: anchors(source) for p, source in documents.items()}
    graph: dict[Path, set[Path]] = {p: set() for p in documents}
    for path, source in documents.items():
        for line, dest in links(source):
            try:
                parts = urlsplit(dest)
            except ValueError:
                failures.append(f"{path.relative_to(root)}:{line}: 无效链接")
                continue
            if parts.scheme or parts.netloc:
                continue
            target = (path.parent / unquote(parts.path)).resolve() if parts.path else path
            label = f"{path.relative_to(root)}:{line}"
            if not target.is_relative_to(root):
                failures.append(f"{label}: 本地链接超出仓库")
            elif not target.exists():
                failures.append(f"{label}: 文件不存在 {target.relative_to(root)}")
            elif target.suffix == ".md":
                if target not in documents:
                    failures.append(f"{label}: 链接指向未纳入版本的文档")
                    continue
                graph[path].add(target)
                if parts.fragment and unquote(parts.fragment) not in cached_anchors[target]:
                    failures.append(f"{label}: 章节不存在 {target.relative_to(root)}#{unquote(parts.fragment)}")

    entry = (root / "docs/README.md").resolve()
    if entry not in documents:
        failures.append("docs/README.md: 缺少文档入口")
    else:
        seen: set[Path] = set()
        pending = [entry]
        while pending:
            path = pending.pop()
            if path not in seen:
                seen.add(path)
                pending.extend(graph.get(path, set()) - seen)
        for path in documents:
            if path.is_relative_to(root / "docs") and path not in seen:
                failures.append(f"{path.relative_to(root)}: 文档入口不可达")

    # 文档不再接收私有运行材料；检查磁盘以免 Git 忽略掩盖 Go 包或敏感产物。
    retired = root / "docs" / "status"
    if retired.exists() or retired.with_suffix(".md").exists():
        failures.append("docs/: 已退役的私有状态目录仍存在")
    for path in (root / "docs").rglob("*"):
        if path.is_file() and path.suffix.lower() not in DOCUMENT_EXTENSIONS:
            failures.append(f"{path.relative_to(root)}: 文档目录只接收正文与配图；代码和产物须归位")
    return sorted(set(failures))


def main() -> int:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT, check=True, stdout=subprocess.PIPE,
    )
    files = [ROOT / name.decode() for name in result.stdout.split(b"\0") if name]
    failures = check(ROOT, files)
    for failure in failures:
        print(failure)
    if failures:
        print(f"文档检查失败：{len(failures)} 项")
        return 1
    print("文档入口、本地链接、章节锚点及目录边界检查通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
