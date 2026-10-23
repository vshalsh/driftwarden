from __future__ import annotations

from datetime import date

import pytest

from conftest import git
from driftwarden import git as dwgit
from driftwarden.config import Config
from driftwarden.discover.adr import (
    discover_adr_files,
    is_skipped_name,
    normalise_status,
    parse_adr,
    scan_adrs,
)
from driftwarden.models import WORKTREE


@pytest.fixture
def basic(fixture_repo):
    repo = fixture_repo("basic")
    return repo, {d.id: d for d in scan_adrs(repo).decisions}


# ---------------------------------------------------------------- discovery


def test_discovery_skips_readme_and_templates(fixture_repo):
    repo = fixture_repo("basic")
    files = discover_adr_files(repo)
    names = [f.rsplit("/", 1)[1] for f in files]
    assert len(files) == 12
    assert "README.md" not in names
    assert "template.md" not in names
    assert "0000-adr-template.md" not in names


@pytest.mark.parametrize(
    "name,skipped",
    [
        ("README.md", True),
        ("index.md", True),
        ("template.md", True),
        ("adr-template.md", True),
        ("0000-adr-template.md", True),
        ("0000-use-markdown-architectural-decision-records.md", False),
        ("0001-x.md", False),
    ],
)
def test_skip_names(name, skipped):
    assert is_skipped_name(name) is skipped


def test_discovery_adr_dir_file(fixture_repo):
    repo = fixture_repo("adr_tools")
    assert discover_adr_files(repo) == ["doc/arch/0001-record-architecture-decisions.md"]


def test_discovery_config_paths_and_excludes(make_repo):
    repo = make_repo(
        {
            "design/decisions/0001-a.md": "# A\n\nbody\n",
            "docs/adr/0001-b.md": "# B\n\nbody\n",
        }
    )
    assert discover_adr_files(repo) == ["docs/adr/0001-b.md"]
    cfg = Config(adr_paths=["design/decisions"], exclude=["docs/**"])
    assert discover_adr_files(repo, cfg) == ["design/decisions/0001-a.md"]


# ---------------------------------------------------------------- parsing per format


def test_formats_counted(basic):
    _, d = basic
    by_fmt = {}
    for dec in d.values():
        by_fmt.setdefault(dec.format, []).append(dec.id)
    # 4 Nygard + superseded (Nygard) + unicode (Nygard), 4 MADR, 2 free-form
    assert len(by_fmt["nygard"]) == 6
    assert sorted(by_fmt["madr"]) == ["ADR-0005", "ADR-0006", "ADR-0007", "ADR-0008"]
    assert sorted(by_fmt["freeform"]) == ["ADR-0009", "ADR-0010"]


def test_nygard(basic):
    _, d = basic
    adr = d["ADR-0002"]
    assert adr.title == "Use PostgreSQL as the only datastore"
    assert adr.status == "accepted"
    assert adr.date == date(2026, 1, 12)
    assert adr.context.startswith("Several teams")
    assert adr.decision_text.startswith("PostgreSQL is the only datastore.")
    assert adr.decision_text.endswith("supersedes this one.")
    assert adr.consequences.startswith("Teams that need search")


def test_madr_front_matter(basic):
    _, d = basic
    adr = d["ADR-0005"]
    assert adr.format == "madr"
    assert adr.status == "accepted"
    assert adr.date == date(2026, 2, 1)
    assert adr.title == "Use FastAPI for HTTP services"
    assert adr.chosen_option == "FastAPI"
    # The ### Consequences subsection is not part of the decision quote.
    assert "Good, because" not in adr.decision_text
    assert "Good, because" in adr.consequences
    assert adr.context == "We need one web framework for all HTTP services."


def test_madr_bullet_status_and_split_consequences(basic):
    _, d = basic
    adr = d["ADR-0006"]
    assert adr.status == "accepted" and adr.date == date(2026, 2, 10)
    assert adr.chosen_option == "structlog"
    assert "Positive Consequences" in adr.consequences


def test_madr_plain_status_line(basic):
    _, d = basic
    assert d["ADR-0007"].status == "rejected"
    assert d["ADR-0007"].chosen_option == "server-rendered templates"
    assert d["ADR-0008"].status == "proposed"


def test_freeform(basic):
    _, d = basic
    adr = d["ADR-0009"]
    assert adr.title == "Keep all services in one monorepo"
    assert adr.status == "unknown"
    assert adr.decision_text.startswith("All services, libraries")
    assert adr.decision_text.endswith("services that use it.")


def test_superseded(basic):
    _, d = basic
    adr = d["ADR-0011"]
    assert adr.status == "superseded"
    assert adr.superseded_by == "ADR-0003"


def test_unicode_adr(basic):
    _, d = basic
    adr = d["ADR-0012"]
    assert adr.title == "Store names as Unicode — “café” stays “café”"
    assert adr.status == "accepted"
    assert "“normalise”" in adr.decision_text


def test_parse_never_raises_on_odd_input():
    for text in ["", "\n\n", "no heading at all\n", "---\nstatus: x\n", "# Only a title\n"]:
        dec = parse_adr(text, "docs/adr/0099-odd.md", "abc")
        assert dec.id == "ADR-0099"
        assert dec.format == "freeform"


def test_crlf_line_endings():
    text = "# 7. T\r\n\r\n## Status\r\n\r\nAccepted\r\n\r\n## Decision\r\n\r\nDo it.\r\n"
    dec = parse_adr(text, "adr/0007-t.md", "abc")
    assert dec.format == "nygard" and dec.status == "accepted"
    assert dec.decision_text == "Do it."
    assert (dec.source.line_start, dec.source.line_end) == (9, 9)


def test_heading_inside_code_fence_is_ignored():
    text = (
        "# 1. T\n\n## Decision\n\nUse this:\n\n"
        "```\n## Not a heading\n```\n\n## Consequences\n\nOk\n"
    )
    dec = parse_adr(text, "adr/0001-t.md", "abc")
    assert "## Not a heading" in dec.decision_text
    assert (dec.source.line_start, dec.source.line_end) == (5, 9)


# ---------------------------------------------------------------- status normalisation


@pytest.mark.parametrize(
    "raw,expected,by",
    [
        ("Accepted", "accepted", None),
        ("**Accepted** ✅", "accepted", None),
        ("approved", "accepted", None),
        ("Proposed", "proposed", None),
        ("Draft", "proposed", None),
        ("Rejected", "rejected", None),
        ("Deprecated", "deprecated", None),
        ("Superseded by [ADR-0005](0005-x.md)", "superseded", "ADR-0005"),
        ("Superseded by ADR-0007", "superseded", "ADR-0007"),
        ("Accepted\n\nSuperseded by [12. New thing](0012-new.md)", "superseded", "12. New thing"),
        ("Accepted; supersedes ADR-0002", "accepted", None),
        ("", "unknown", None),
        (None, "unknown", None),
        ("whatever", "unknown", None),
    ],
)
def test_status_normalisation(raw, expected, by):
    assert normalise_status(raw) == (expected, by)


# ---------------------------------------------------------------- exact line ranges


@pytest.mark.parametrize(
    "adr_id,start,end",
    [
        ("ADR-0001", 15, 15),
        ("ADR-0002", 15, 18),
        ("ADR-0003", 13, 14),
        ("ADR-0004", 13, 13),
        ("ADR-0005", 20, 20),
        ("ADR-0006", 18, 18),
        ("ADR-0007", 12, 12),
        ("ADR-0008", 16, 16),
        ("ADR-0009", 3, 6),
        ("ADR-0010", 3, 4),
        ("ADR-0011", 15, 15),
        ("ADR-0012", 13, 15),
    ],
)
def test_exact_line_ranges(basic, adr_id, start, end):
    repo, d = basic
    src = d[adr_id].source
    assert (src.line_start, src.line_end) == (start, end)
    # The quote is exactly those lines of the committed file, verbatim.
    lines = dwgit.show_file(repo, src.commit, src.path).split("\n")
    assert src.quote == "\n".join(lines[start - 1 : end])


# ---------------------------------------------------------------- provenance source


def test_provenance_uses_head_commit(basic):
    repo, d = basic
    head = dwgit.head_sha(repo)
    assert all(dec.source.commit == head for dec in d.values())


def test_reads_committed_text_not_worktree_for_clean_files(fixture_repo):
    repo = fixture_repo("basic")
    head = dwgit.head_sha(repo)
    # Modify one file: only that one switches to WORKTREE.
    p = repo / "docs/adr/0002-use-postgresql.md"
    p.write_text(p.read_text(encoding="utf-8").replace("PostgreSQL is", "MySQL is"), "utf-8")
    (repo / "docs/adr/0013-new.md").write_text("# 13. New\n\nUntracked decision.\n", "utf-8")
    d = {x.id: x for x in scan_adrs(repo).decisions}
    assert d["ADR-0002"].source.commit == WORKTREE
    assert d["ADR-0002"].decision_text.startswith("MySQL is")
    assert d["ADR-0013"].source.commit == WORKTREE
    assert d["ADR-0001"].source.commit == head


def test_repo_without_commits(make_repo):
    repo = make_repo()
    (repo / "adr").mkdir()
    (repo / "adr/0001-x.md").write_text("# 1. X\n\n## Decision\n\nDo X.\n", "utf-8")
    res = scan_adrs(repo)
    assert res.head is None
    assert res.decisions[0].source.commit == WORKTREE


def test_duplicate_ids_are_disambiguated(make_repo):
    repo = make_repo({"adr/0001-a.md": "# A\n\na\n", "docs/adr/0001-b.md": "# B\n\nb\n"})
    ids = sorted(x.id for x in scan_adrs(repo).decisions)
    assert ids == ["ADR-0001", "ADR-0001~2"]


def test_subdirectory_path_resolves_root(fixture_repo):
    repo = fixture_repo("basic")
    res = scan_adrs(repo / "docs")
    assert res.root == repo.resolve()
    assert len(res.decisions) == 12
    git(repo, "status")  # repo still healthy
