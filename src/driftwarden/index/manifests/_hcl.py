"""A small, tolerant HCL2 reader: enough structure for Terraform dependency facts.

It returns blocks (type, labels, line) and attributes whose values are string
literals or objects of string literals. Every other expression is recorded as
``None`` (present but not a literal). Unbalanced braces or unterminated strings
raise ManifestError.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from driftwarden.index.manifests._common import ManifestError

_PUNCT = set("{}[]()=,:.?!+-*/%<>&|")


@dataclass
class Tok:
    kind: str  # IDENT STRING NL PUNCT OTHER
    value: str
    line: int


@dataclass
class Attr:
    value: Any  # str | dict[str, Attr] | None
    line: int


@dataclass
class Block:
    type: str
    labels: list[str]
    line: int
    attrs: dict[str, Attr] = field(default_factory=dict)
    blocks: list[Block] = field(default_factory=list)


def _tokenize(text: str) -> list[Tok]:
    toks: list[Tok] = []
    i, n, line = 0, len(text), 1
    while i < n:
        ch = text[i]
        if ch == "\n":
            toks.append(Tok("NL", "\n", line))
            line += 1
            i += 1
        elif ch in " \t\r﻿":
            i += 1
        elif ch == "#" or text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end == -1:
                raise ManifestError(f"HCL line {line}: unterminated /* comment")
            nls = text.count("\n", i, end)
            if nls:
                line += nls
                toks.append(Tok("NL", "\n", line))
            i = end + 2
        elif ch == '"':
            start_line = line
            i, value, line = _string(text, i + 1, line)
            toks.append(Tok("STRING", value, start_line))
        elif text.startswith("<<", i) and (heredoc := _heredoc(text, i, line)) is not None:
            i, value, nls = heredoc
            toks.append(Tok("STRING", value, line))
            line += nls
        elif ch.isalpha() or ch == "_":
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] in "_-"):
                j += 1
            toks.append(Tok("IDENT", text[i:j], line))
            i = j
        elif ch in _PUNCT:
            toks.append(Tok("PUNCT", ch, line))
            i += 1
        else:
            j = i + 1
            while j < n and not (text[j].isspace() or text[j] in _PUNCT or text[j] == '"'):
                j += 1
            toks.append(Tok("OTHER", text[i:j], line))
            i = j
    return toks


def _string(text: str, i: int, line: int) -> tuple[int, str, int]:
    """Read a quoted template starting after the opening quote."""
    out: list[str] = []
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            nxt = text[i + 1]
            out.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(nxt, "\\" + nxt))
            i += 2
            continue
        if ch == '"':
            return i + 1, "".join(out), line
        if ch == "\n":
            raise ManifestError(f"HCL line {line}: unterminated string")
        if text.startswith(("${", "%{"), i):
            j = _skip_template(text, i + 2, line)
            out.append(text[i:j])
            i = j
            continue
        out.append(ch)
        i += 1
    raise ManifestError(f"HCL line {line}: unterminated string")


def _skip_template(text: str, i: int, line: int) -> int:
    depth = 1
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            i, _, line = _string(text, i + 1, line)
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        elif ch == "\n":
            line += 1
        i += 1
    raise ManifestError(f"HCL line {line}: unterminated interpolation")


def _heredoc(text: str, i: int, line: int) -> tuple[int, str, int] | None:
    j = i + 2
    if j < len(text) and text[j] == "-":
        j += 1
    k = j
    while k < len(text) and (text[k].isalnum() or text[k] == "_"):
        k += 1
    marker = text[j:k]
    if not marker or k >= len(text) or text[k] not in "\r\n":
        return None
    body_start = text.find("\n", k) + 1
    pos = body_start
    while pos <= len(text):
        eol = text.find("\n", pos)
        eol = len(text) if eol == -1 else eol
        if text[pos:eol].strip() == marker:
            body = text[body_start:pos]
            return eol, body, text.count("\n", i, eol)
        if eol >= len(text):
            break
        pos = eol + 1
    raise ManifestError(f"HCL line {line}: unterminated heredoc <<{marker}")


class _Parser:
    def __init__(self, toks: list[Tok]) -> None:
        self.toks = toks
        self.i = 0

    def peek(self, off: int = 0) -> Tok | None:
        j = self.i + off
        return self.toks[j] if j < len(self.toks) else None

    def next(self) -> Tok:
        t = self.toks[self.i]
        self.i += 1
        return t

    def is_punct(self, t: Tok | None, v: str) -> bool:
        return t is not None and t.kind == "PUNCT" and t.value == v

    def body(self, block: Block, nested: bool) -> None:
        while True:
            t = self.peek()
            if t is None:
                if nested:
                    raise ManifestError(f"HCL: block {block.type!r} (line {block.line}) not closed")
                return
            if t.kind == "NL" or self.is_punct(t, ","):
                self.i += 1
                continue
            if self.is_punct(t, "}"):
                if not nested:
                    raise ManifestError(f"HCL line {t.line}: unexpected '}}'")
                self.i += 1
                return
            if t.kind != "IDENT":
                before = self.i
                self.skip_line()
                if self.i == before:
                    self.i += 1  # stray closing bracket: always make progress
                continue
            name = self.next()
            nxt = self.peek()
            if self.is_punct(nxt, "="):
                self.i += 1
                block.attrs[name.value] = Attr(self.expr(), name.line)
                continue
            labels: list[str] = []
            while (p := self.peek()) is not None and p.kind in ("STRING", "IDENT"):
                labels.append(self.next().value)
            if self.is_punct(self.peek(), "{"):
                self.i += 1
                child = Block(name.value, labels, name.line)
                self.body(child, nested=True)
                block.blocks.append(child)
            else:
                self.skip_line()

    def skip_line(self) -> None:
        """Skip to the end of the current line, honouring bracket nesting."""
        depth = 0
        while (t := self.peek()) is not None:
            if t.kind == "PUNCT" and t.value in "{[(":
                depth += 1
            elif t.kind == "PUNCT" and t.value in "}])":
                if depth == 0:
                    return
                depth -= 1
            elif t.kind == "NL" and depth == 0:
                return
            elif depth == 0 and self.is_punct(t, ","):
                return
            self.i += 1
        if depth:
            raise ManifestError("HCL: unbalanced brackets")

    def expr(self) -> Any:
        t = self.peek()
        if t is None:
            return None
        if t.kind == "STRING":
            self.i += 1
            end = self.peek()
            if (
                end is None
                or end.kind == "NL"
                or self.is_punct(end, ",")
                or self.is_punct(end, "}")
            ):
                return t.value
            self.skip_line()  # string is part of a larger expression
            return None
        if self.is_punct(t, "{"):
            self.i += 1
            return self.obj()
        self.skip_line()
        return None

    def obj(self) -> dict[str, Attr] | None:
        out: dict[str, Attr] = {}
        while True:
            t = self.peek()
            if t is None:
                raise ManifestError("HCL: object not closed")
            if t.kind == "NL" or self.is_punct(t, ","):
                self.i += 1
                continue
            if self.is_punct(t, "}"):
                self.i += 1
                end = self.peek()
                if end is not None and not (
                    end.kind == "NL" or self.is_punct(end, ",") or self.is_punct(end, "}")
                ):
                    self.skip_line()
                    return None
                return out
            if t.kind in ("IDENT", "STRING") and (
                self.is_punct(self.peek(1), "=") or self.is_punct(self.peek(1), ":")
            ):
                self.i += 2
                out[t.value] = Attr(self.expr(), t.line)
                continue
            self.skip_line()
            if self.peek() is not None and self.is_punct(self.peek(), "}"):
                continue
            if self.peek() is not None:
                self.i += 1


def parse_hcl(text: str) -> Block:
    """Parse ``text`` into a root Block (type ``""``). Raises ManifestError."""
    root = Block("", [], 1)
    _Parser(_tokenize(text)).body(root, nested=False)
    return root
