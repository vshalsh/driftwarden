"""L-021 system tests (tester seat): adversarial coverage of the paired-emphasis normaliser."""

from __future__ import annotations

import random
import re
from pathlib import Path

import pytest

from conftest import git
from driftwarden.discover.adr import scan_adrs
from driftwarden.grounding.verify import normalise, verify_source_quote
from driftwarden.models import Provenance

_COUNTER = [0]


def _repo(tmp_path: Path, text: str) -> Path:
    _COUNTER[0] += 1
    repo = tmp_path / f"r{_COUNTER[0]}"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "commit.gpgsign", "false")
    p = repo / "docs/adr/0010-x.md"
    p.parent.mkdir(parents=True)
    p.write_text(text, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "init")
    return repo


def _prov(repo: Path, quote: str, start: int, end: int) -> Provenance:
    sha = git(repo, "rev-parse", "HEAD").strip()
    return Provenance(
        path="docs/adr/0010-x.md", line_start=start, line_end=end, commit=sha, quote=quote
    )


def _status(repo, quote, start, end):
    return verify_source_quote(repo, _prov(repo, quote, start, end)).status


def _doc(body: str) -> str:
    return "# 10. T\n\n## Decision\n\n" + body + "\n"  # body starts at line 5


def _one(tmp_path, body, quote):
    repo = _repo(tmp_path, _doc(body))
    n = body.count("\n") + 1
    return _status(repo, quote, 5, 4 + n)


# ---------------------------------------------------------- identifiers kept (both ways)
@pytest.mark.parametrize(
    "a,b",
    [
        ("snake_case", "snakecase"),
        ("MAX_VALUE_LIMIT", "MAXVALUELIMIT"),
        ("snake_case_name", "snake_casename"),
        ("a_b_c", "abc"),
        ("snake__case", "snake_case"),
        ("def f(*args, **kwargs)", "def f(args, kwargs)"),
        ("a*b*c", "abc"),
        ("2*3*4", "234"),
        ("_private", "private"),
        ("trailing_", "trailing"),
        ("* item one", "item one"),
        ("a * b * c", "a b c"),
    ],
)
def test_identifier_markers_distinct_both_directions(tmp_path, a, b):
    assert normalise(a) != normalise(b)
    assert _one(tmp_path, f"Use {a} here.", f"Use {b} here.") == "MISMATCH"
    assert _one(tmp_path, f"Use {b} here.", f"Use {a} here.") == "MISMATCH"
    assert _one(tmp_path, f"Use {a} here.", f"Use {a} here.") == "VERIFIED"


def test_snake_case_inside_bold_and_italic(tmp_path):
    assert normalise("**snake_case**") == "snake_case"
    assert normalise("*snake_case*") == "snake_case"
    assert normalise("_snake_case_") == "snake_case"
    assert normalise("**snake_case**") != normalise("snakecase")
    assert _one(tmp_path, "Use **snake_case** names.", "Use snake_case names.") == "VERIFIED"
    assert _one(tmp_path, "Use **snake_case** names.", "Use snakecase names.") == "MISMATCH"
    assert _one(tmp_path, "Use snake_case names.", "Use **snakecase** names.") == "MISMATCH"
    assert _one(tmp_path, "Use **snakecase** names.", "Use snake_case names.") == "MISMATCH"


def test_code_span_identifiers(tmp_path):
    assert _one(tmp_path, "Use `snake_case` names.", "Use `snakecase` names.") == "MISMATCH"
    assert _one(tmp_path, "Use `snake_case` names.", "Use `snake_case` names.") == "VERIFIED"
    assert _one(tmp_path, "Call `f(*args)` now.", "Call `f(args)` now.") == "MISMATCH"


def test_dunder_not_collapsed(tmp_path):
    # CommonMark renders __init__ as bold "init", but in ADR prose it is an identifier.
    assert _one(tmp_path, "Define __init__ first.", "Define __init__ first.") == "VERIFIED"
    assert _one(tmp_path, "Define __init__ first.", "Define init first.") == "MISMATCH"
    assert _one(tmp_path, "Define init first.", "Define __init__ first.") == "MISMATCH"
    assert _one(tmp_path, "See __init__.py now.", "See init.py now.") == "MISMATCH"


def test_underscores_inside_dunder_and_double_still_distinct():
    assert normalise("__my_dunder__") != normalise("mydunder")
    assert normalise("a__b") != normalise("ab")


def test_star_args_variants():
    assert normalise("f(*args)") == "f(*args)"
    assert normalise("f(**kw)") == "f(**kw)"
    assert normalise("use *args and **kwargs") == "use *args and **kwargs"


def test_multiplication_and_spaced_operators():
    assert normalise("a*b*c") == "a*b*c"
    assert normalise("x = a * b * c") == "x = a * b * c"
    assert normalise("3*4 + 5*6") == "3*4 + 5*6"
    assert normalise("a *b* c") == "a b c"  # paired around a word: emphasis


# ---------------------------------------------------------- emphasis still stripped
@pytest.mark.parametrize(
    "marked,plain",
    [
        ("*x*", "x"),
        ("_x_", "x"),
        ("**x**", "x"),
        ("__x__", "x"),
        ("***x***", "x"),
        ("~~x~~", "x"),
        ("**a *b* c**", "a b c"),
        ("*a **b** c*", "a b c"),
        ("_a **b** c_", "a b c"),
        ("**bold _it_ x**", "bold it x"),
        ("*one* and _two_ and **three**", "one and two and three"),
        ("(*x*)", "(x)"),
        ('"*x*"', '"x"'),
        ("*x*, then **y**.", "x, then y."),
        ("*café*", "café"),
        ("_naïve_ idea", "naïve idea"),
        ("**Ünï_cödé**", "Ünï_cödé"),
        ("- *x* and _y_", "- x and y"),
        ("1. **First**: go", "1. First: go"),
        ("[the _link_](http://e.com/a)", "[the link](http://e.com/a)"),
        ("**一二三**", "一二三"),
    ],
)
def test_paired_emphasis_stripped(marked, plain):
    assert normalise(marked) == normalise(plain) == plain


def test_unicode_nfc_and_curly_with_emphasis():
    assert normalise("*café*") == normalise("café")
    assert normalise("**don’t**") == "don't"


def test_link_url_underscores_preserved():
    assert normalise("[x](http://a.com/snake_case_x)") != normalise("[x](http://a.com/snakecasex)")


def test_unbalanced_markers_kept():
    assert normalise("**unclosed") == "**unclosed"
    assert normalise("a**b**c") == "a**b**c"


# ---------------------------------------------------------- legit emphasised quotes accepted
EMPH_BODIES = [
    "We **must not** use _shared_ databases across *any* service.",
    "- Use **snake_case** for *all* columns.\n- Never use ~~camelCase~~ names.",
    "The *quick* **brown**\nfox _jumps_ over the lazy dog.",
    "Prefer `snake_case`; avoid **CamelCase** and *kebab-case*.",
    "***Critical***: never call `f(*args, **kw)` here.",
]


@pytest.mark.parametrize("body", EMPH_BODIES)
def test_no_false_reject_of_emphasised_quote(tmp_path, body):
    repo = _repo(tmp_path, _doc(body))
    end = 4 + body.count("\n") + 1
    assert _status(repo, body, 5, end) == "VERIFIED"
    plain = re.sub(r"(\*\*\*|\*\*|~~)(?=\S)(.+?)(?<=\S)\1", r"\2", body)
    plain = re.sub(r"(?<![\w*])\*(?=\S)([^*\n]+?)(?<=\S)\*(?![\w*])", r"\1", plain)
    plain = re.sub(r"(?<!\w)_(?=\S)([^_\n]+?)(?<=\S)_(?!\w)", r"\1", plain)
    assert _status(repo, plain, 5, end) == "VERIFIED"


def test_multiline_quote_subrange_of_emphasised_text(tmp_path):
    body = "Line one has **bold\ntext** spanning lines.\nLine three."
    repo = _repo(tmp_path, _doc(body))
    assert _status(repo, "has bold text spanning lines.", 5, 6) == "VERIFIED"


# ---------------------------------------------------------- line-number stability
def test_line_numbers_stable_with_emphasis_and_dropped_markers(tmp_path):
    body = "\n".join(
        [
            "First **bold** line.",  # 5
            "second _it_ line with snake_case.",  # 6
            "third *a*b*c* line.",  # 7
            "fourth ~~gone~~ line.",  # 8
        ]
    )
    repo = _repo(tmp_path, _doc(body))
    assert _status(repo, "second it line with snake_case.", 6, 6) == "VERIFIED"
    assert _status(repo, "fourth gone line.", 8, 8) == "VERIFIED"
    r = verify_source_quote(repo, _prov(repo, "fourth gone line.", 5, 6))
    assert r.status == "MISMATCH" and "found at lines 8-8" in r.reason
    assert _status(repo, "bold line. second it", 5, 6) == "VERIFIED"
    r = verify_source_quote(repo, _prov(repo, "bold line. second it", 6, 7))
    assert r.status == "MISMATCH" and "found at lines 5-6" in r.reason


def test_emphasis_spanning_lines_inside_range(tmp_path):
    body = "Alpha *beta\ngamma* delta.\nOmega."
    repo = _repo(tmp_path, _doc(body))
    assert _status(repo, "Alpha beta gamma delta.", 5, 6) == "VERIFIED"
    assert _status(repo, "Omega.", 7, 7) == "VERIFIED"


# ---------------------------------------------------------- tamper property tests
def _fixture_quotes(fixture_repo):
    out = []
    for name in ("basic", "adr_tools"):
        repo = fixture_repo(name)
        for d in scan_adrs(repo).decisions:
            out.append((repo, d.source))
    return out


def test_property_single_word_mutations_caught(fixture_repo):
    rng = random.Random(21)
    quotes = _fixture_quotes(fixture_repo)
    assert quotes
    tried = 0
    for repo, src in quotes:
        words = src.quote.split()
        for _ in range(25):
            ws = list(words)
            i = rng.randrange(len(ws))
            if not any(c.isalnum() for c in ws[i]):
                continue
            ws[i] = ws[i] + "x" if rng.random() < 0.5 else "ZZ" + ws[i]
            bad = src.model_copy(update={"quote": " ".join(ws)})
            tried += 1
            assert verify_source_quote(repo, bad).status == "MISMATCH", bad.quote
    assert tried > 100


def test_property_single_char_mutations_caught(fixture_repo):
    rng = random.Random(22)
    tried = 0
    for repo, src in _fixture_quotes(fixture_repo):
        q = src.quote
        # quote matching is substring-based, so edge truncation is accepted by design;
        # mutate interior characters only.
        idxs = [i for i, c in enumerate(q) if c.isalnum() and 0 < i < len(q) - 1]
        for _ in range(25):
            i = rng.choice(idxs)
            kind = rng.choice(["sub", "del", "ins"])
            if kind == "sub":
                c = "#" if q[i] != "#" else "@"
                mq = q[:i] + c + q[i + 1 :]
            elif kind == "del":
                mq = q[:i] + q[i + 1 :]
            else:
                mq = q[:i] + "#" + q[i:]
            if normalise(mq) == normalise(q):
                continue
            tried += 1
            r = verify_source_quote(repo, src.model_copy(update={"quote": mq}))
            assert r.status == "MISMATCH", mq
    assert tried > 100


def test_property_inserting_underscore_inside_word_is_caught(fixture_repo):
    rng = random.Random(23)
    tried = 0
    for repo, src in _fixture_quotes(fixture_repo):
        q = src.quote
        for m in re.finditer(r"(?<=[A-Za-z])(?=[A-Za-z])", q):
            if rng.random() > 0.15:
                continue
            mq = q[: m.start()] + "_" + q[m.start() :]
            tried += 1
            bad = src.model_copy(update={"quote": mq})
            assert verify_source_quote(repo, bad).status == "MISMATCH", mq
    assert tried > 20


def test_fixture_quotes_with_markers_added_still_verify(fixture_repo):
    """Wrapping a mid-quote word in *...* must not cause a false reject."""
    tried = 0
    for repo, src in _fixture_quotes(fixture_repo):
        words = src.quote.split(" ")
        for i, w in enumerate(words):
            if re.fullmatch(r"[A-Za-z]{3,}", w):
                ws = list(words)
                ws[i] = f"*{w}*"
                ok = verify_source_quote(repo, src.model_copy(update={"quote": " ".join(ws)}))
                assert ok.status == "VERIFIED", (ok.reason, ws[i])
                tried += 1
                break
    assert tried >= 10


# ---------------------------------------------------------- known edge: code spans
def test_emphasis_inside_code_span_is_literal(tmp_path):
    assert _one(tmp_path, "Use `*x*` here.", "Use `x` here.") == "MISMATCH"
