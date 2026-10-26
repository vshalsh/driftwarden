"""L-021: the quote normaliser strips markdown emphasis only when it pairs up
around text; identifier underscores (and other lone markers) are preserved."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import git
from driftwarden.discover.adr import scan_adrs
from driftwarden.grounding.verify import normalise, verify_source_quote


def _repo(tmp_path: Path, text: str) -> Path:
    repo = tmp_path / "r"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "commit.gpgsign", "false")
    p = repo / "docs/adr/0010-names.md"
    p.parent.mkdir(parents=True)
    p.write_text(text, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "init")
    return repo


def _check(repo: Path, quote: str) -> str:
    (dec,) = scan_adrs(repo).decisions
    return verify_source_quote(repo, dec.source.model_copy(update={"quote": quote})).status


# ------------------------------------------------------------------ the false accept


def test_snakecase_no_longer_matches_snake_case(tmp_path):
    repo = _repo(tmp_path, "# 10. Names\n\n## Decision\n\nUse snake_case names.\n")
    assert _check(repo, "Use snakecase names.") == "MISMATCH"
    assert _check(repo, "Use snake_case names.") == "VERIFIED"


def test_reverse_false_accept_snake_case_quote_vs_snakecase_file(tmp_path):
    repo = _repo(tmp_path, "# 10. Names\n\n## Decision\n\nUse snakecase names.\n")
    assert _check(repo, "Use snake_case names.") == "MISMATCH"


@pytest.mark.parametrize(
    ("file_text", "fake"),
    [
        ("Call get_user_by_id only.", "Call getuserbyid only."),
        ("Keep MAX_RETRIES at 3.", "Keep MAXRETRIES at 3."),
        ("Name it _private.", "Name it private."),
        ("Store in my_dir/sub_dir.", "Store in mydir/subdir."),
        ("Compute a*b*c here.", "Compute abc here."),
        ("Accept f(*args, **kwargs).", "Accept f(args, kwargs)."),
        ("Match *.py files.", "Match .py files."),
    ],
)
def test_identifier_and_lone_markers_are_preserved(tmp_path, file_text, fake):
    repo = _repo(tmp_path, f"# 10. Names\n\n## Decision\n\n{file_text}\n")
    assert _check(repo, file_text) == "VERIFIED"
    assert _check(repo, fake) == "MISMATCH"


# ------------------------------------------------------------------ emphasis still stripped


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("We **must** do it", "We must do it"),
        ("We __must__ do it", "We must do it"),
        ("use _only_ this", "use only this"),
        ("use *only* this", "use only this"),
        ("not ~~legacy~~ now", "not legacy now"),
        ("***very*** strong", "very strong"),
        ("(**bold**), _it_.", "(bold), it."),
        ("**two words** here", "two words here"),
        ("**_nested_** too", "nested too"),
        ("use snake_case and _emphasis_", "use snake_case and emphasis"),
        ("**must**\nspan", "must span"),
        ("**across\nlines**", "across lines"),
    ],
)
def test_normalise_strips_paired_emphasis(text, expected):
    assert normalise(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "snake_case",
        "__init__.py is a file",  # closer followed by '.' then alnum is fine; see below
        "a_b_c",
        "* bullet item",
        "x ** 2",
        "unpaired **bold",
        "mismatched **run* here",
        "path/to_some_file.md",
    ],
)
def test_normalise_keeps_unpaired_or_intraword_markers(text):
    out = normalise(text)
    if text.startswith("__init__"):
        # Markdown renders __init__ as bold "init": the pair is stripped, like
        # a renderer would, and the same rule applies to quote and file.
        assert out == "init.py is a file"
    else:
        assert out == text


def test_emphasis_variants_of_same_sentence_verify(tmp_path):
    repo = _repo(
        tmp_path,
        "# 8. E\n\n## Decision\n\nWe **must** use _only_ ~~legacy~~ config_file names.\n",
    )
    assert _check(repo, "We must use only legacy config_file names.") == "VERIFIED"
    assert _check(repo, "We **must** use _only_ ~~legacy~~ config_file names.") == "VERIFIED"
    assert _check(repo, "We must use only legacy configfile names.") == "MISMATCH"


def test_line_mapping_survives_stripping(tmp_path):
    text = "# 8. E\n\n## Decision\n\nLine **one** here.\nLine _two_ here.\nLine three.\n"
    repo = _repo(tmp_path, text)
    (dec,) = scan_adrs(repo).decisions
    bad = dec.source.model_copy(update={"quote": "Line two here.", "line_start": 7, "line_end": 7})
    r = verify_source_quote(repo, bad)
    assert r.status == "MISMATCH" and "found at lines 6-6" in r.reason
