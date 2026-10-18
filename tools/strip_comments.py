"""tools/strip_comments.py — token-aware comment removal for the kelan repo.

Safe: uses Python tokenize (py) and tree_sitter (js/ts/tsx). Strips only
real comment tokens; never touches string literals or interpolated content.
Optional --docstrings also removes module/class/function docstrings.

Usage:
  python tools/strip_comments.py ./kelan --ext .py,.js,.ts,.tsx --docstrings
  python tools/strip_comments.py ./kelan --dry-run              # report only
"""
from __future__ import annotations

import argparse
import io
import sys
from pathlib import Path

EXCLUDE = {".git", "node_modules", "venv", ".venv", "target", "__pycache__",
           "dist", "build", "docs"}


def _clean_line_spans(line: str, spans: list[tuple[int, int]]) -> str:
    chars = list(line)
    for c0, c1 in spans:
        for i in range(c0, min(c1, len(chars))):
            chars[i] = " "
    out = "".join(chars).rstrip()
    return out + ("\n" if line.endswith(("\n", "\r")) else "")


def _strip_python(src: str, drop_docstrings: bool) -> str:
    import tokenize
    lines = src.splitlines(keepends=True)
    spans: dict[int, list[tuple[int, int]]] = {}
    doc_locs: set[int] = set()
    try:
        toks = tokenize.generate_tokens(io.StringIO(src).readline)
        for tok in toks:
            if tok.type == tokenize.COMMENT:
                spans.setdefault(tok.start[0] - 1, []).append(
                    (tok.start[1], tok.end[1]))
            elif drop_docstrings and tok.type == tokenize.STRING:
                # treat as docstring only if first statement of a frame
                prev = tok.start[1]
                ltext = src.splitlines()[tok.start[0] - 1]
                if prev == ltext.find(ltext.lstrip()):
                    doc_locs.add(tok.start[0] - 1)
    except (tokenize.TokenError, IndentationError):
        return src
    for ln in sorted(spans):
        lines[ln] = _clean_line_spans(lines[ln], spans[ln])
    if drop_docstrings:
        for ln in doc_locs:
            lineno = ln
            # blank a single-line docstring (whole line collapses to spaces)
            line = lines[lineno] if lineno < len(lines) else ""
            if '"""' in line or "'''" in line:
                # multi-line: blank until closing quote
                start = lineno
                end = lineno
                if line.count('"""') < 2 and "'''" not in line:
                    for j in range(lineno + 1, len(lines)):
                        end = j
                        if '"""' in lines[j]:
                            break
                for k in range(start, end + 1):
                    lines[k] = _clean_line_spans(lines[k], [(0, len(lines[k]))])
    return "".join(lines)


def _strip_tree_sitter(src: str, lang_name: str) -> str:
    from tree_sitter_languages import get_parser
    parser = get_parser(lang_name)
    tree = parser.parse(src.encode("utf-8"))

    def walk(node, acc):
        if node.type in ("comment", "comment_block"):
            byte_start, byte_end = node.start_byte, node.end_byte
            acc.append((byte_start, byte_end))
        for child in node.children:
            walk(child, acc)

    comments = []
    walk(tree.root_node, comments)
    lines = src.splitlines(keepends=True)
    # map byte spans to line spans conservatively
    byte_to_line = {}
    off = 0
    for i, ln in enumerate(lines):
        byte_to_line[off] = i
        off += len(ln.encode("utf-8"))
    spans: dict[int, list[tuple[int, int]]] = {}
    for bs, be in comments:
        bl = src[:bs].count("\n")
        el = src[:be].count("\n")
        for ln in range(bl, el + 1):
            spans.setdefault(ln, []).append((0, len(lines[ln])))
    for ln, sp in spans.items():
        if ln < len(lines):
            lines[ln] = _clean_line_spans(lines[ln], sp)
    return "".join(lines)


def process(path: Path, exts: set[str], drop_docstrings: bool,
            dry_run: bool) -> int:
    stripped = 0
    for f in sorted(path.rglob("*")):
        if not f.is_file() or any(x in EXCLUDE for x in f.parts):
            continue
        if f.suffix not in exts:
            continue
        try:
            src = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if f.suffix == ".py":
            new = _strip_python(src, drop_docstrings)
        elif f.suffix in (".js", ".ts", ".tsx"):
            lang = {"js": "javascript", "ts": "typescript",
                    "tsx": "tsx", "jsx": "javascript"}[f.suffix.lstrip(".")]
            new = _strip_tree_sitter(src, lang)
        else:
            continue
        if new != src:
            stripped += 1
            if not dry_run:
                f.write_text(new, encoding="utf-8")
            print(f"  {'would strip' if dry_run else 'stripped'} {f}")
    return stripped


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", type=Path)
    ap.add_argument("--ext", default=".py,.js,.ts,.tsx")
    ap.add_argument("--docstrings", action="store_true",
                    help="also remove Python docstrings (not just # comments)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    exts = {e if e.startswith(".") else "." + e for e in args.ext.split(",")}
    total = process(args.path, exts, args.docstrings, args.dry_run)
    print(f"Done. {total} files {'would be modified' if args.dry_run else 'modified'}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
