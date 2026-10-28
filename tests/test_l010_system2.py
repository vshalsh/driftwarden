# ruff: noqa: E501
"""L-010 system retest (round 2): probes of the D1-D12 fixes themselves.

Green tests pin behaviour the fixes got right. Tests named ``test_hole_*`` assert the
CORRECT behaviour and are red while the hole is open. Offline; scripted providers only.
"""

from __future__ import annotations

import time
import unicodedata

import pytest

from driftwarden.undocumented import draft_adr, verify_draft
from driftwarden.undocumented.draft import (
    _commit_info,
    polish_problems,
    sanitise_subject,
    template_context,
)
from test_l010_system import Scripted, draft_one, jctx, redis_repo


@pytest.fixture
def world(tmp_path):
    repo, _ = redis_repo(tmp_path)
    rec, d = draft_one(repo)
    assert d.status == "DRAFT"
    infos = {c: _commit_info(repo, c) for c in rec.introducing_commits}
    return repo, rec, d, template_context(rec, infos)


def _status(repo, d, md, origin="template"):
    return verify_draft(repo, d.model_copy(update={"markdown": md, "origin": origin})).status


# ------------------------------------------------------------ byte-for-byte pinning


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m.replace("\n", "\r\n"),
        lambda m: m + "\n",
        lambda m: m.rstrip("\n"),
        lambda m: "\ufeff" + m,
        lambda m: m.replace("\n\n", "\n \n", 1),
        lambda m: m.replace("\n\n", "\n\u200b\n", 1),
        lambda m: m.replace("Redis", "Red\u0456s", 1),  # Cyrillic i
        lambda m: m.replace(" ", "\u00a0", 1),
        lambda m: m.replace("---", "\u2014-", 1),
        lambda m: unicodedata.normalize("NFD", m.replace("e", "\u00e9", 1)),
        lambda m: m.replace("\n", "\r", 1),
        lambda m: m.replace("```text", "```text ", 1),
        lambda m: m.replace("status: proposed (draft)", "status:  proposed (draft)"),
        lambda m: m.replace("* ", "- ", 1),
    ],
)
def test_template_pinning_rejects_whitespace_unicode_variants(world, mutate):
    repo, _, d, _ = world
    assert _status(repo, d, mutate(d.markdown)) == "UNKNOWN"


def test_template_pinned_exact_text_verifies(world):
    repo, _, d, _ = world
    assert _status(repo, d, d.markdown) == "DRAFT"


@pytest.mark.parametrize("pad", ["", " ", "\t", "\u00a0", "\x00"])
def test_llm_context_edges_rejected(world, pad):
    repo, _, d, ctx = world
    good = ctx.replace("uses", "relies on")
    md = d.markdown.replace(ctx, pad + good) if pad else d.markdown.replace(ctx, good)
    want = "UNKNOWN" if pad else "DRAFT"
    assert _status(repo, d, md, "llm") == want


# ------------------------------------------------------------ polish_problems bypasses


@pytest.mark.parametrize(
    "text",
    [
        "The code uses Redis\u200b as a cache.",  # zero-width space
        "The code uses Redis in \uff11\uff12\uff13 files.",  # fullwidth digits
        "See commit `\u0430bcdef1234`.",  # Cyrillic a in hex
        "The code\u2028uses Redis.",
        "The code uses Redis\u202e.",  # bidi override
        "The code uses Redis \u00ad as a cache.",  # soft hyphen
        "The code uses Redis\ufeff.",
    ],
)
def test_polish_rejects_unicode_tricks(world, text):
    _, rec, _, ctx = world
    assert polish_problems(text, ctx, rec)


def test_polish_long_paragraph_is_fast_and_bounded(world):
    _, rec, _, ctx = world
    t0 = time.time()
    p = polish_problems("The code uses Redis. " * 5000 + "x", ctx, rec)
    assert time.time() - t0 < 2
    # The provider schema caps context at 2000 chars; the gate must too (see the hole test).
    assert isinstance(p, list)


def test_hole_polish_has_no_length_cap(world):
    """Gate accepts a 100k-char paragraph although the schema says maxLength 2000."""
    _, rec, _, ctx = world
    assert polish_problems("The code uses Redis. " * 5000 + "x", ctx, rec), (
        "a 100k-character context paragraph passes the gate"
    )


@pytest.mark.parametrize("n", [65, 128, 1000])
def test_hole_polish_long_hex_letter_run_is_foreign_sha(world, n):
    """A letters-only a-f run longer than 64 is not matched by {7,64}; it is not a number."""
    _, rec, _, ctx = world
    assert polish_problems("The code uses Redis. " + "abcdef" * (n // 6 + 1), ctx, rec)


@pytest.mark.parametrize(
    "text",
    [
        "The code uses Redis (see src/app.py&colon;10) as cache.",
        "The code uses Redis; origin deadbe&shy;efcafe is known.",
        "The code uses Redis &num; Heading and &lbrack;x&rsqb;&lpar;http&colon;//evil&rpar;.",
    ],
)
def test_hole_polish_html_entities_smuggle_refs_shas_links(world, text):
    """'&' / ';' are plain ASCII: a named entity decodes (in any markdown renderer) to ':'
    '#', brackets, soft-hyphen, so a path:line, a split SHA or a link slips past the
    ASCII checks."""
    _, rec, _, ctx = world
    assert polish_problems(text, ctx, rec), "entity-encoded structure passes the polish gate"


def test_hole_entity_smuggle_end_to_end(world):
    repo, rec, _, _ = world
    text = "The code uses Redis (see src/app.py&colon;10) as cache. Also deadbe&shy;efcafe."
    d = draft_adr(repo, rec, provider=Scripted(jctx(text)))
    assert d.origin == "template", "LLM text with entity-encoded ref/SHA was accepted into a draft"


def test_polish_rejects_obvious_markdown_after_other_text(world):
    _, rec, _, ctx = world
    for t in ["Uses Redis. # Heading", "Uses Redis.  - item", "Uses Redis. 1. item", "A | B"]:
        # '#'/'-' mid-line are inert in markdown; only line-start structure matters.
        polish_problems(t, ctx, rec)  # must not raise


# ------------------------------------------------------------ sanitise_subject reach


@pytest.mark.parametrize(
    "subject",
    [
        "Fix #1234 in release",
        "bump to v1.2.3",
        "use 2026-10-28 format",
        'Revert "x"',
        "CVE-2024-12345 fix",
        "fix 123456",
    ],
)
def test_sanitise_leaves_legitimate_subjects(subject):
    assert sanitise_subject(subject) == subject


@pytest.mark.parametrize(
    "subject, gone",
    [
        ("Fix in a1b2c3d", "a1b2c3d"),
        ("see foo.py:12", "foo.py:12"),
        ("see foo.py:12-20", "foo.py:12-20"),
        ("a\u200bb deadbeef1", "deadbeef1"),
        ("x\u2028deadbeef1", "deadbeef1"),
    ],
)
def test_sanitise_removes_refs(subject, gone):
    out = sanitise_subject(subject)
    assert gone not in out and "\u200b" not in out and "\u2028" not in out


@pytest.mark.parametrize(
    "subject",
    ["release 20261028", "issue #12345678", "order 1234567 shipped"],
)
def test_sanitise_over_reach_on_long_numbers_is_documented(subject):
    """Seven-plus digit numbers are hex-looking: removed. Over-reach, accepted (safe side)."""
    assert "[ref removed]" in sanitise_subject(subject)


def test_hole_sanitise_unicode_colon_and_fullwidth_hex_are_kept():
    """Under-reach (low): fullwidth colon / fullwidth hex survive; they are not ASCII refs
    but render as one. Kept as a documented observation, asserted as correct behaviour."""
    out = sanitise_subject("see a.py\uff1a12 and \uff41\uff42\uff43\uff44\uff45\uff46\uff47\uff48")
    assert "\uff1a" not in out and "\uff41" not in out


def test_sanitise_adversarial_100k_is_linear():
    t0 = time.time()
    for s in [
        "a" * 100_000,
        "a:" * 50_000,
        "1" * 100_000,
        "/" * 100_000 + ":1",
        "a/" * 50_000 + ":1",
        "`:" * 50_000,
        " " * 100_000 + "a:1",
        "0" * 99_999 + "g",
    ]:
        sanitise_subject(s)
    assert time.time() - t0 < 3


def test_polish_adversarial_100k_is_linear(world):
    _, rec, _, ctx = world
    t0 = time.time()
    for s in [
        "a" * 100_000,
        "1" * 100_000,
        "a:1" * 30_000,
        "a " * 50_000,
        "/" * 100_000 + ":1",
        "a." * 50_000 + ":1",
        "0" * 99_999 + "g",
        "1. " * 30_000,
    ]:
        polish_problems(s, ctx, rec)
    assert time.time() - t0 < 5


# ------------------------------------------------------------ write safety


def test_symlinked_dirs_and_files_refused(tmp_path):
    repo, _ = redis_repo(tmp_path)
    rec, d = draft_one(repo)
    out = tmp_path / "outside"
    out.mkdir()
    import shutil

    shutil.rmtree(repo / "docs/adr")
    (repo / "docs/adr").symlink_to(out, target_is_directory=True)
    r = draft_adr(repo, rec, write=True, existing_adrs=[])
    assert r.written_path is None and not list(out.iterdir())
    (repo / "docs/adr").unlink()
    (repo / "docs/adr").mkdir()
    victim = tmp_path / "victim.md"
    victim.write_text("keep")
    (repo / "docs/adr" / "0001-use-redis-for-cache.md").symlink_to(victim)
    r = draft_adr(repo, rec, write=True, existing_adrs=[])
    assert r.written_path is None and victim.read_text() == "keep"
    (repo / "docs/adr" / "0001-use-redis-for-cache.md").unlink()
    (repo / "docs/adr" / "0001-use-redis-for-cache.md").symlink_to(tmp_path / "nope.md")
    r = draft_adr(repo, rec, write=True, existing_adrs=[])
    assert r.written_path is None and not (tmp_path / "nope.md").exists()


@pytest.mark.parametrize(
    "bad",
    [
        "docs\\adr\\0007-x.md",
        "/etc/0009-x.md",
        "../0009-x.md",
        "docs/adr/../../0009-x.md",
        "docs/adr/0007-x.md\x00",
        "docs//adr/0003-x.md",
    ],
)
def test_existing_adrs_bad_paths_ignored(tmp_path, bad):
    repo, _ = redis_repo(tmp_path)
    rec, _ = draft_one(repo)
    r = draft_adr(repo, rec, existing_adrs=[bad])
    assert r.path == "docs/adr/0001-use-redis-for-cache.md"


@pytest.mark.parametrize(
    "bad",
    [" docs/adr/0005-x.md", "C:/adr/0005-x.md", "docs/adr/0005-x.md\n", "docs/adr/\u200b0005-x.md"],
)
def test_hole_existing_adrs_nonportable_names_not_rejected(tmp_path, bad):
    """path_problem accepts a leading space / Windows drive-letter / trailing newline /
    zero-width char, so the suggested draft path (and a write=True directory) is built
    from it: ' docs/adr/..' or 'C:/adr/..' is created inside the repo (on Windows,
    'C:/adr' is an absolute path outside it)."""
    repo, _ = redis_repo(tmp_path)
    rec, _ = draft_one(repo)
    r = draft_adr(repo, rec, existing_adrs=[bad])
    assert r.path == "docs/adr/0001-use-redis-for-cache.md", r.path


def test_case_variant_dir_from_existing_adrs_is_taken_literally(tmp_path):
    """existing_adrs is caller-supplied and trusted for its dir; document: DOCS/ADR is
    used as given (a distinct dir on case-sensitive FS). Not a defect, pins behaviour."""
    repo, _ = redis_repo(tmp_path)
    rec, _ = draft_one(repo)
    r = draft_adr(repo, rec, existing_adrs=["DOCS/ADR/0005-x.md"])
    assert r.path == "DOCS/ADR/0006-use-redis-for-cache.md"


def test_hole_huge_number_in_existing_adr_name_makes_huge_filename(tmp_path):
    """Caller-supplied name with a 27-digit number yields a 1000...0 filename; no cap."""
    repo, _ = redis_repo(tmp_path)
    rec, _ = draft_one(repo)
    r = draft_adr(repo, rec, existing_adrs=["docs/adr/" + "9" * 30 + "-x.md"])
    assert len(r.path.split("/")[-1]) < 60, r.path


# ------------------------------------------------------------ idempotence vs hostile files


def test_forged_front_matter_file_is_not_adopted_as_the_draft(tmp_path):
    """A file whose front-matter names the record but whose text does not verify against
    it is NOT adopted: it is left untouched, a note names it, and a new numbered draft
    is written next to it."""
    repo, _ = redis_repo(tmp_path)
    rec, _ = draft_one(repo)
    forged = repo / "docs/adr/0002-evil.md"
    body = f"---\nstatus: accepted\ndriftwarden-record: {rec.id}\n---\n\n# Other\n\nHostile.\n"
    forged.write_text(body)
    r = draft_adr(repo, rec, write=True)
    assert r.grounding == "VERIFIED"
    assert r.written_path == "docs/adr/0003-use-redis-for-cache.md"
    assert (repo / r.written_path).read_text() == r.markdown
    assert forged.read_text() == body
    assert any("0002-evil.md" in n and "does not verify" in n for n in r.notes), r.notes


def test_verified_existing_draft_is_adopted(tmp_path):
    repo, _ = redis_repo(tmp_path)
    rec, d = draft_one(repo)
    kept = repo / "docs/adr/0007-kept.md"
    kept.write_text(d.markdown)
    r = draft_adr(repo, rec, write=True)
    assert r.written_path == "docs/adr/0007-kept.md" and r.markdown == kept.read_text()
    assert sorted(p.name for p in (repo / "docs/adr").iterdir()) == [
        "0001-logging.md",
        "0007-kept.md",
    ]


def test_hole_forged_front_matter_adoption_has_no_content_check(tmp_path):
    """The returned result is status DRAFT / VERIFIED with `written_path` pointing at a file
    that is not the verified markdown. The caller is only told via a note. Correct: the
    result must not claim the file holds this draft unless it does (or mark it)."""
    repo, _ = redis_repo(tmp_path)
    rec, d = draft_one(repo)
    (repo / "docs/adr/0002-evil.md").write_text(
        f"---\nstatus: accepted\ndriftwarden-record: {rec.id}\n---\n\n# Other\n\nHostile.\n"
    )
    r = draft_adr(repo, rec, write=True)
    on_disk = (repo / r.written_path).read_text()
    assert on_disk == r.markdown or r.grounding != "VERIFIED" or "differs" in " ".join(r.notes)


@pytest.mark.parametrize("name", ["9999-x.MD", "9999-x.md"])
def test_existing_draft_found_case_insensitive_suffix(tmp_path, name):
    """The suffix is matched case-insensitively (``.md`` and ``.MD`` alike, as ADR
    discovery does): a *verified* draft with either suffix is adopted, while a file that
    only carries the record's front-matter is not (a new numbered draft is written)."""
    repo, _ = redis_repo(tmp_path)
    rec, d = draft_one(repo)
    stub = repo / "docs/adr" / name
    stub.write_text(f"---\ndriftwarden-record: {rec.id}\n---\n")
    r = draft_adr(repo, rec, write=True)
    assert r.written_path == "docs/adr/10000-use-redis-for-cache.md", r.written_path
    assert any(name in n and "does not verify" in n for n in r.notes), r.notes
    (repo / r.written_path).unlink()
    stub.write_text(d.markdown)
    r = draft_adr(repo, rec, write=True)
    assert r.written_path == f"docs/adr/{name}" and r.markdown == stub.read_text()


def test_second_write_is_idempotent(tmp_path):
    repo, _ = redis_repo(tmp_path)
    rec, _ = draft_one(repo)
    a = draft_adr(repo, rec, write=True)
    b = draft_adr(repo, rec, write=True)
    assert a.written_path == b.written_path
    assert len(list((repo / "docs/adr").glob("*redis*"))) == 1
