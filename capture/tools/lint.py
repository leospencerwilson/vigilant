#!/usr/bin/env python3
"""
Structural check for the PowerShell in this kit.

⚠️ THIS IS NOT A PARSER AND IT DOES NOT PROVE THESE FILES PARSE. The kit was written on macOS
where `pwsh` is not installed, so the real check —

    [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)

— could not be run. This script exists so that the gross structural mistakes are caught anyway:
an unclosed brace, a stray parenthesis, an unterminated string or block comment. Those are the
errors that would otherwise be discovered by an engineer at a pharmacy counter at midnight.

Run the real ParseFile check on any Windows machine before this kit is used. See README.md.

What it understands:
  * # line comments and <# block comments #>
  * 'single quoted' (doubling '' is the escape) and "double quoted" (backtick is the escape)
  * @'...'@ and @"..."@ here-strings
  * brace / paren / bracket nesting outside all of the above

Usage:  python3 tools/lint.py [root]
"""
import sys
import pathlib

PAIRS = {'{': '}', '(': ')', '[': ']'}
CLOSERS = {v: k for k, v in PAIRS.items()}


def check(path: pathlib.Path):
    """Return a list of problem strings for one file."""
    src = path.read_text(encoding='utf-8')
    problems = []
    stack = []          # (char, line, col)
    i = 0
    line = 1
    col = 1
    n = len(src)

    def at(k):
        return src[k] if 0 <= k < n else ''

    while i < n:
        c = src[i]

        # ── here-strings, checked before ordinary quotes: @' and @" open a block that runs to
        # a closing delimiter which must be at the START of a line.
        if c == '@' and at(i + 1) in ("'", '"'):
            q = at(i + 1)
            close = q + '@'
            j = src.find('\n', i)
            if j == -1:
                problems.append(f'{path.name}:{line}: here-string opened at end of file')
                break
            k = j
            found = -1
            while k < n:
                nl = src.find('\n', k + 1)
                seg_start = k + 1
                seg_end = nl if nl != -1 else n
                if src[seg_start:seg_end].strip().startswith(close):
                    found = src.find(close, seg_start)
                    break
                if nl == -1:
                    break
                k = nl
            if found == -1:
                problems.append(f'{path.name}:{line}: unterminated here-string @{q}')
                break
            chunk = src[i:found + 2]
            line += chunk.count('\n')
            i = found + 2
            col = 1
            continue

        # ── block comment
        if c == '<' and at(i + 1) == '#':
            end = src.find('#>', i + 2)
            if end == -1:
                problems.append(f'{path.name}:{line}: unterminated <# block comment')
                break
            chunk = src[i:end + 2]
            line += chunk.count('\n')
            i = end + 2
            col = 1
            continue

        # ── line comment
        if c == '#':
            end = src.find('\n', i)
            if end == -1:
                break
            i = end
            continue

        # ── single-quoted string ('' escapes)
        if c == "'":
            j = i + 1
            while j < n:
                if src[j] == "'":
                    if at(j + 1) == "'":
                        j += 2
                        continue
                    break
                if src[j] == '\n':
                    line += 1
                j += 1
            if j >= n:
                problems.append(f"{path.name}:{line}: unterminated single-quoted string")
                break
            i = j + 1
            continue

        # ── double-quoted string (backtick escapes)
        if c == '"':
            j = i + 1
            while j < n:
                if src[j] == '`':
                    j += 2
                    continue
                if src[j] == '"':
                    break
                if src[j] == '\n':
                    line += 1
                j += 1
            if j >= n:
                problems.append(f'{path.name}:{line}: unterminated double-quoted string')
                break
            i = j + 1
            continue

        # ── nesting
        if c in PAIRS:
            stack.append((c, line, col))
        elif c in CLOSERS:
            if not stack:
                problems.append(f'{path.name}:{line}:{col}: stray closing {c!r}')
            else:
                op, ol, oc = stack.pop()
                if PAIRS[op] != c:
                    problems.append(
                        f'{path.name}:{line}:{col}: {c!r} closes {op!r} opened at line {ol} col {oc}')

        if c == '\n':
            line += 1
            col = 1
        else:
            col += 1
        i += 1

    for op, ol, oc in stack:
        problems.append(f'{path.name}:{ol}:{oc}: {op!r} is never closed')
    return problems


def main():
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else '.')
    files = sorted(root.rglob('*.ps1'))
    if not files:
        print('no .ps1 files found under', root)
        return 1
    bad = 0
    for f in files:
        problems = check(f)
        rel = f.relative_to(root)
        if problems:
            bad += 1
            print(f'FAIL  {rel}')
            for p in problems:
                print(f'        {p}')
        else:
            print(f'ok    {rel}')
    print()
    print(f'{len(files) - bad}/{len(files)} files structurally clean')
    print('NOTE: this is a delimiter/structure check, NOT a PowerShell parse. '
          'Run ParseFile on Windows before use.')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
