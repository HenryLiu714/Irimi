"""Credential shapes in text, where JSON escapes a letter before one, and a cut that splits none."""

import json
import re
from collections.abc import Iterable

SECRET_PATTERNS: tuple[str, ...] = (
    r"sk_(live|test)_[A-Za-z0-9]+",
    r"rk_(live|test)_[A-Za-z0-9]+",
    r"whsec_[A-Za-z0-9]+",
    r"xox[abprs]-[A-Za-z0-9-]+",
    r"xapp-[A-Za-z0-9-]+",
    r"gh[pousr]_[A-Za-z0-9]{36,}",
    r"github_pat_[A-Za-z0-9_]+",
    r"AKIA[0-9A-Z]{16}",
    r"sk-ant-[A-Za-z0-9_-]+",
    r"sk-(proj-)?[A-Za-z0-9_-]{20,}",
)
# `sk-ant-` precedes the wider `sk-`. A shape may not follow a letter or digit (`task_test_runner`
# survives) unless it ends an escape stored text uses as a separator: `\n`, ` `, `%20`.
_BOUNDARY = r"(?:(?<![A-Za-z0-9])|(?<=\\[bfnrt])|(?<=\\u[0-9A-Fa-f]{4})|(?<=%[0-9A-Fa-f]{2}))"
_SHAPES = "(?:" + "|".join(SECRET_PATTERNS) + ")"
SECRET_SHAPE = re.compile(_BOUNDARY + _SHAPES)
_UNBOUNDED_SHAPE = re.compile(_SHAPES)
# Every character a shape can hold.
_WORD_CHARACTER = re.compile(r"[A-Za-z0-9_-]")
# A JSON `\u` escape of an ASCII letter or digit, the one escape whose decoded character glues to a
# shape after it: decoded JSON reads `Ask_live_…` as a word, its raw text as a shape.
_ALNUM_ESCAPE = re.compile(r"\\u00(?:3[0-9]|[46][1-9A-Fa-f]|[57][0-9Aa])")
# A JSON string literal, and an escape in one, `\uXXXX` with its code.
_JSON_STRING = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"')
_JSON_ESCAPE = re.compile(r"\\(?:u([0-9A-Fa-f]{4})|.)")


def shapes_after_escaped_letters(text: str) -> frozenset[str]:
    """Return each shape raw JSON `text` spells right after a `\\u` escape of a letter or digit."""
    found = (SECRET_SHAPE.match(text, escape.end()) for escape in _ALNUM_ESCAPE.finditer(text))
    return frozenset(shape.group(0) for shape in found if shape)


def escaped_letters(text: str) -> dict[str, frozenset[int]]:
    """Return where each string raw JSON `text` holds, decoded, has a letter or digit it escapes.

    Keyed by the decoded string; two strings that decode alike share their offsets. Never raises.
    """
    found: dict[str, frozenset[int]] = {}
    if not _ALNUM_ESCAPE.search(text):
        return found
    for literal in _JSON_STRING.finditer(text):
        offsets = _escaped_offsets(literal.group())
        if offsets:
            value = _decoded(literal.group())
            found[value] = found.get(value, frozenset()) | offsets
    return found


def _escaped_offsets(literal: str) -> frozenset[int]:
    """Return where a JSON string literal, decoded, has a letter or digit it spells as an escape.

    A surrogate pair's two escapes decode to one character, as `json` reads them."""
    offsets, at, end, high_end = set(), 0, 1, -1
    for escape in _JSON_ESCAPE.finditer(literal, 1, len(literal) - 1):
        at += escape.start() - end
        code = int(escape.group(1), 16) if escape.group(1) else None
        if code is None or not (0xDC00 <= code <= 0xDFFF and escape.start() == high_end):
            if _ALNUM_ESCAPE.fullmatch(escape.group()):
                offsets.add(at)
            at += 1
        high_end = escape.end() if code is not None and 0xD800 <= code <= 0xDBFF else -1
        end = escape.end()
    return frozenset(offsets)


def _decoded(literal: str) -> str:
    """Return a JSON string literal's value, or the literal itself if it is not one."""
    try:
        value = json.loads(literal)
    except ValueError:
        return literal
    return value if isinstance(value, str) else literal


def shape_spans(text: str, escaped: Iterable[int] = ()) -> list[tuple[int, int]]:
    """Return where `text` holds a secret shape, also right after each of the `escaped` offsets.

    `escaped` are where decoded JSON text has a letter or digit its raw text escapes
    (`escaped_letters`); a shape may follow one, as it follows the escape in raw text."""
    spans = [shape.span() for shape in SECRET_SHAPE.finditer(text)]
    reach = -1
    for at in sorted(escaped):
        # One that starts inside a shape that ran to its word's end ends there too: skipping it
        # keeps a word of many escaped letters linear.
        if at + 1 < reach:
            continue
        shape = _UNBOUNDED_SHAPE.match(text, at + 1)
        if shape:
            spans.append(shape.span())
            if not _WORD_CHARACTER.match(text, shape.end()):
                reach = shape.end()
    return spans


# What a cut made with no redaction key, the SDK's, puts where a secret ran across it: dropping the
# secret instead would post a value that is one long key as empty.
CUT_MARK = "<redacted>"


def cut_marking_secrets(text: str, limit: int) -> str:
    """Return `cut_outside_secrets(text, limit)` with a secret the cut crosses marked CUT_MARK.

    For a cut made before redaction with no key (the SDK's); a limit too small for the mark drops
    the secret unmarked. The store, which holds a key, puts the placeholder there instead.
    """
    cut = cut_outside_secrets(text, limit)
    if len(cut) == len(text) or limit < len(CUT_MARK):
        return cut
    if SECRET_SHAPE.match(text, len(cut)) is None:
        return cut
    return cut_outside_secrets(text, max(0, limit - len(CUT_MARK))) + CUT_MARK


def cut_outside_secrets(text: str, limit: int) -> str:
    """Return `text` cut to at most `limit` chars, moved back to the start of any shape it splits.

    A key cut in half may not match and could reach disk unredacted. Raises TypeError for non-str.
    """
    if len(text) <= limit:
        return text
    for shape in SECRET_SHAPE.finditer(text):
        if shape.end() > limit:
            return text[: min(shape.start(), limit)]
    return text[:limit]
