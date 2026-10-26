"""Text helpers shared by the parsers and the verifiers.

Both sides must split lines the same way, or line numbers would disagree.
"""

from __future__ import annotations

import codecs
from pathlib import Path

_UTF16_32_BOMS = (
    (codecs.BOM_UTF32_LE, "utf-32-le"),  # before UTF-16 LE: it starts with the same bytes
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)


def decode_text(raw: bytes) -> str:
    """Decode file bytes the same way for ``git show`` and working-tree reads.

    UTF-8 is the default (invalid bytes become U+FFFD; a UTF-8 BOM is kept as
    U+FEFF so existing line/quote semantics do not change). UTF-16/32 files with
    a BOM, and BOM-less UTF-16 recognised by its NUL pattern (e.g. Windows
    PowerShell ``pip freeze > requirements.txt``), are decoded as such.
    """
    for bom, enc in _UTF16_32_BOMS:
        if raw.startswith(bom):
            return raw[len(bom) :].decode(enc, errors="replace")
    sample = raw[:4096]
    if b"\x00" in sample and len(sample) >= 4:
        half = len(sample) // 2
        odd, even = sample[1::2].count(0), sample[0::2].count(0)
        if odd >= 0.9 * half and even == 0:
            return raw.decode("utf-16-le", errors="replace")
        if even >= 0.9 * half and odd == 0:
            return raw.decode("utf-16-be", errors="replace")
    return raw.decode("utf-8", errors="replace")


def read_text_file(path: str | Path) -> str:
    """Working-tree counterpart of ``git.show_file``: same decoding rules."""
    return decode_text(Path(path).read_bytes())


def split_lines(text: str) -> list[str]:
    """Split on ``\\n`` only (not on form feeds or Unicode separators), drop a
    trailing ``\\r`` per line, and ignore the empty item after a final newline.

    Line ``n`` (1-based) of a file is ``split_lines(text)[n - 1]``, matching what an
    editor and ``git blame`` show.
    """
    if text == "":
        return []
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return [ln[:-1] if ln.endswith("\r") else ln for ln in lines]
