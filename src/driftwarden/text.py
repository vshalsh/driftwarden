"""Text helpers shared by the parsers and the verifiers.

Both sides must split lines the same way, or line numbers would disagree.
"""

from __future__ import annotations


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
