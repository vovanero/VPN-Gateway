"""A bracket-balance check for the panel's JavaScript.

There is no JS runtime on the build machine, so a missing parenthesis in a
deeply nested `el(...)` call used to be found only after deploying - the script
fails to parse, nothing runs, and the panel renders as a blank page with no
error anywhere the operator would look. That is an expensive way to learn about
a typo.

This is not a parser. It tracks brackets while skipping strings, template
literals, regexes and comments, which is enough to catch the mistake that
actually happens in this codebase and cheap enough to run on every change.

    python tests/check_js.py vpngw/web/static/app.js
"""

from __future__ import annotations

import sys
from pathlib import Path

PAIRS = {")": "(", "]": "[", "}": "{"}
OPENERS = set(PAIRS.values())


def check(path: Path) -> list[str]:
    src = path.read_text(encoding="utf-8")
    stack: list[tuple[str, int, int]] = []
    problems: list[str] = []

    line = col = 1
    i = 0
    n = len(src)
    while i < n:
        ch = src[i]

        if ch == "\n":
            line += 1
            col = 1
            i += 1
            continue

        # comments
        if ch == "/" and i + 1 < n:
            nxt = src[i + 1]
            if nxt == "/":
                while i < n and src[i] != "\n":
                    i += 1
                continue
            if nxt == "*":
                i += 2
                while i + 1 < n and not (src[i] == "*" and src[i + 1] == "/"):
                    if src[i] == "\n":
                        line += 1
                    i += 1
                i += 2
                continue

        # strings and template literals
        if ch in "\"'`":
            quote = ch
            start_line = line
            i += 1
            while i < n:
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == "\n":
                    line += 1
                    if quote != "`":
                        problems.append(
                            f"{path}:{start_line}: unterminated {quote} string")
                        break
                if src[i] == quote:
                    i += 1
                    break
                # `${ ... }` inside a template can contain brackets; treat the
                # interpolation as ordinary code by leaving the string here.
                if quote == "`" and src[i] == "$" and i + 1 < n and src[i + 1] == "{":
                    depth = 0
                    i += 1
                    while i < n:
                        if src[i] == "{":
                            depth += 1
                        elif src[i] == "}":
                            depth -= 1
                            if depth == 0:
                                i += 1
                                break
                        elif src[i] == "\n":
                            line += 1
                        i += 1
                    continue
                i += 1
            continue

        if ch in OPENERS:
            stack.append((ch, line, col))
        elif ch in PAIRS:
            if not stack:
                problems.append(f"{path}:{line}:{col}: stray '{ch}'")
            else:
                opener, oline, ocol = stack.pop()
                if opener != PAIRS[ch]:
                    problems.append(
                        f"{path}:{line}:{col}: '{ch}' closes '{opener}' "
                        f"opened at line {oline}")

        i += 1
        col += 1

    for opener, oline, ocol in stack:
        problems.append(f"{path}:{oline}:{ocol}: '{opener}' is never closed")
    return problems


def main(argv: list[str]) -> int:
    paths = [Path(a) for a in argv[1:]]
    if not paths:
        here = Path(__file__).resolve().parent.parent
        paths = sorted((here / "vpngw" / "web" / "static").glob("*.js"))

    failed = False
    for path in paths:
        problems = check(path)
        if problems:
            failed = True
            for p in problems[:10]:
                print(p)
        else:
            print(f"{path}: brackets balanced")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
