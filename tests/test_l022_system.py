"""L-022 system tests (adversarial): default ledger path + ruff-format docs exclude."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from conftest import git
from driftwarden.cli import app

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]
NYGARD = (
    "# 7. Use Redis for sessions\n\n## Status\n\nAccepted\n\n"
    "## Decision\n\nWe will use Redis for session storage.\n"
)
ADR = "docs/adr/0007-redis.md"
UGLY_MD = "# T\n\n```python\nx = {  'a':1 }\n```\n"


def _grounding(base: Path) -> Path:
    return base / ".driftwarden" / "logs" / "grounding"


@pytest.fixture
def repo(make_repo):
    return make_repo({ADR: NYGARD, "src/app/x.py": "x = 1\n"})


def _scan(*args: str, cwd: Path):
    old = Path.cwd()
    os.chdir(cwd)
    try:
        return runner.invoke(app, ["scan", *args])
    finally:
        os.chdir(old)


def test_scan_subdirectory_writes_ledger_at_repo_root(repo, tmp_path):
    res = _scan(str(repo / "src" / "app"), cwd=tmp_path)
    assert res.exit_code == 0, res.output
    assert len(list(_grounding(repo).glob("*.jsonl"))) == 1
    assert not (repo / "src" / "app" / ".driftwarden").exists()
    assert not (repo / "src" / ".driftwarden").exists()


def test_scan_default_dot_from_inside_subdirectory(repo):
    res = _scan(cwd=repo / "src" / "app")
    assert res.exit_code == 0, res.output
    assert len(list(_grounding(repo).glob("*.jsonl"))) == 1
    assert not (repo / "src" / "app" / ".driftwarden").exists()


def _unprivileged_scan(repo: Path) -> subprocess.CompletedProcess[str]:
    """Run the real CLI as an unprivileged user so mode bits are enforced (root ignores them)."""
    import tempfile

    work = Path(tempfile.mkdtemp(prefix="dw-ro-", dir="/tmp"))
    try:
        dst = work / "r"
        shutil.copytree(repo, dst)
        subprocess.run(["chown", "-R", "65534:65534", str(work)], check=True)
        (dst / ".driftwarden").mkdir(exist_ok=True)
        (dst / ".driftwarden").chmod(0o555)
        exe = Path(sys.executable).parent / "driftwarden"
        return subprocess.run(
            [
                "setpriv",
                "--reuid=65534",
                "--regid=65534",
                "--clear-groups",
                str(exe),
                "scan",
                str(dst),
            ],
            capture_output=True,
            text=True,
            env={**os.environ, "HOME": str(work)},
            check=False,
        )
    finally:
        subprocess.run(["chmod", "-R", "a+rwX", str(work)], check=False)
        shutil.rmtree(work, ignore_errors=True)


def test_scan_readonly_driftwarden_does_not_crash(repo, tmp_path):
    if os.geteuid() == 0:
        if not shutil.which("setpriv"):
            pytest.skip("root without setpriv: cannot drop privileges")
        proc = _unprivileged_scan(repo)
        out = proc.stdout + proc.stderr
        assert "Traceback" not in out and "PermissionError" not in out, out
        assert proc.returncode in (0, 2), (proc.returncode, out)
        return
    dw = repo / ".driftwarden"
    dw.mkdir()
    dw.chmod(0o555)
    try:
        res = _scan(str(repo), cwd=tmp_path)
    finally:
        dw.chmod(0o755)
    assert res.exception is None or isinstance(res.exception, SystemExit), repr(res.exception)
    assert res.exit_code in (0, 2), res.output


def test_scan_readonly_driftwarden_leaves_repo_clean(repo, tmp_path):
    dw = repo / ".driftwarden"
    dw.mkdir()
    dw.chmod(0o555)
    try:
        _scan(str(repo), cwd=tmp_path)
    finally:
        dw.chmod(0o755)
    assert git(repo, "status", "--porcelain").strip() in ("", "?? .driftwarden/")


@pytest.mark.parametrize("content", ["x\n", "", "no-trailing-newline", "!keep\n"])
def test_existing_gitignore_bytes_untouched(repo, tmp_path, content):
    gi = repo / ".driftwarden" / ".gitignore"
    gi.parent.mkdir()
    gi.write_bytes(content.encode())
    mtime = gi.stat().st_mtime_ns
    res = _scan(str(repo), cwd=tmp_path)
    assert res.exit_code == 0, res.output
    assert gi.read_bytes() == content.encode()
    assert gi.stat().st_mtime_ns == mtime


def test_rescan_does_not_treat_ledger_as_adrs(repo, tmp_path):
    first = _scan(str(repo), cwd=tmp_path)
    second = _scan(str(repo), cwd=tmp_path)
    assert first.exit_code == second.exit_code == 0
    assert "Decisions (1)" in first.output
    assert "Decisions (1)" in second.output


def test_rescan_with_custom_exclude_replacing_defaults(make_repo, tmp_path):
    # A user-supplied `exclude` replaces the defaults; ledger must still not become ADRs.
    r = make_repo({ADR: NYGARD, "driftwarden.toml": 'exclude = ["node_modules/**"]\n'})
    _scan(str(r), cwd=tmp_path)
    res = _scan(str(r), cwd=tmp_path)
    assert res.exit_code == 0, res.output
    assert "Decisions (1)" in res.output


def test_markdown_dropped_in_ledger_dir_not_picked_up(repo, tmp_path):
    d = _grounding(repo)
    d.mkdir(parents=True)
    (d / "NOTES.md").write_text(NYGARD, encoding="utf-8")
    res = _scan(str(repo), cwd=tmp_path)
    assert "Decisions (1)" in res.output


def test_git_status_clean_after_scan_and_rescan(repo, tmp_path):
    for _ in range(2):
        res = _scan(str(repo), cwd=tmp_path)
        assert res.exit_code == 0, res.output
        assert git(repo, "status", "--porcelain", "--untracked-files=all").strip() == ""


def test_out_relative_resolves_against_cwd_not_repo(repo, tmp_path):
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    res = _scan(str(repo), "--out", "rel/out", cwd=cwd)
    assert res.exit_code == 0, res.output
    assert list((cwd / "rel" / "out" / "logs" / "grounding").glob("*.jsonl"))
    assert not (repo / ".driftwarden").exists()
    assert not (repo / "rel").exists()


def test_out_dot_uses_cwd(repo, tmp_path):
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    res = _scan(str(repo), "--out", ".", cwd=cwd)
    assert res.exit_code == 0, res.output
    assert list((cwd / "logs" / "grounding").glob("*.jsonl"))
    assert not (repo / ".driftwarden").exists()


def test_out_inside_repo_is_honoured_verbatim(repo, tmp_path):
    res = _scan(str(repo), "--out", str(repo / "custom"), cwd=tmp_path)
    assert res.exit_code == 0, res.output
    assert list((repo / "custom" / "logs" / "grounding").glob("*.jsonl"))
    assert not (repo / ".driftwarden").exists()


def test_repeat_scans_append_not_clobber(repo, tmp_path):
    for _ in range(3):
        assert _scan(str(repo), cwd=tmp_path).exit_code == 0
    d = _grounding(repo)
    jsonls = sorted(d.glob("*.jsonl"))
    assert len(jsonls) == 3
    assert len(list(d.glob("*.summary.json"))) == 3
    for j in jsonls:
        rows = [json.loads(line) for line in j.read_text(encoding="utf-8").splitlines()]
        # L-028: claim-level rows follow the one decision-level G1 row.
        rows = [r for r in rows if r["check_id"] == "G1" and "." not in r["subject"]]
        assert len(rows) == 1 and rows[0]["status"] == "VERIFIED"


def test_repeat_scans_with_out_also_accumulate(repo, tmp_path):
    out = tmp_path / "o"
    for _ in range(2):
        assert _scan(str(repo), "--out", str(out), cwd=tmp_path).exit_code == 0
    assert len(list((out / "logs" / "grounding").glob("*.jsonl"))) == 2


def test_linked_worktree_gets_its_own_ledger(repo, tmp_path):
    wt = tmp_path / "wt"
    git(repo, "worktree", "add", "-q", "-b", "side", str(wt))
    res = _scan(str(wt), cwd=tmp_path)
    assert res.exit_code == 0, res.output
    assert list(_grounding(wt).glob("*.jsonl"))
    assert not (repo / ".driftwarden").exists()
    assert git(wt, "status", "--porcelain").strip() == ""
    assert git(repo, "status", "--porcelain").strip() == ""


def test_linked_worktree_subdirectory(repo, tmp_path):
    wt = tmp_path / "wt"
    git(repo, "worktree", "add", "-q", "-b", "side", str(wt))
    res = _scan(str(wt / "src"), cwd=tmp_path)
    assert res.exit_code == 0, res.output
    assert list(_grounding(wt).glob("*.jsonl"))
    assert not (wt / "src" / ".driftwarden").exists()


def test_detached_head(repo, tmp_path):
    git(repo, "checkout", "-q", "--detach")
    res = _scan(str(repo), cwd=tmp_path)
    assert res.exit_code == 0, res.output
    assert "Decisions (1)" in res.output
    assert list(_grounding(repo).glob("*.jsonl"))
    assert git(repo, "status", "--porcelain").strip() == ""


def test_repo_with_no_commits_still_defaults_to_repo(tmp_path):
    r = tmp_path / "empty"
    (r / "docs" / "adr").mkdir(parents=True)
    git(r, "init", "-q", "-b", "main")
    (r / ADR).write_text(NYGARD, encoding="utf-8")
    res = _scan(str(r), cwd=tmp_path)
    assert res.exit_code == 0, res.output
    assert list(_grounding(r).glob("*.jsonl"))


def test_non_git_dir_error_creates_nothing(tmp_path):
    d = tmp_path / "plain"
    d.mkdir()
    res = _scan(str(d), cwd=tmp_path)
    assert res.exit_code == 2
    assert not (d / ".driftwarden").exists()
    assert not (tmp_path / "logs").exists()


def test_no_adrs_still_leaves_clean_repo(make_repo, tmp_path):
    r = make_repo({"a.py": "a = 1\n"})
    res = _scan(str(r), cwd=tmp_path)
    assert res.exit_code == 0, res.output
    assert git(r, "status", "--porcelain").strip() == ""


# ------------------------------------------------------------------ ruff format


def _ruff() -> str:
    exe = shutil.which("ruff", path=str(Path(sys.executable).parent)) or shutil.which("ruff")
    if not exe:
        pytest.skip("ruff not installed")
    return exe


def test_ruff_format_check_on_repo_never_mentions_markdown():
    proc = subprocess.run(
        [_ruff(), "format", "--check", "."], cwd=ROOT, capture_output=True, text=True, check=False
    )
    text = proc.stdout + proc.stderr
    assert ".md" not in text, text
    assert "docs/" not in text, text


def test_ruff_format_in_tree_with_md_leaves_md_untouched(tmp_path):
    ruff = _ruff()
    proj = tmp_path / "p"
    proj.mkdir()
    shutil.copy(ROOT / "pyproject.toml", proj / "pyproject.toml")
    files = {
        "README.md": UGLY_MD,
        "ARCHITECTURE.md": UGLY_MD,
        "docs/guide.md": UGLY_MD,
        "docs/sub/deep.markdown": UGLY_MD,
        "docs/code.py": "y = {  'a':1 }\n",
        "pkg/NOTES.md": UGLY_MD,
        "tests/fixtures/adr/0001.md": UGLY_MD,
        "mod.py": "z = {  'a':1 }\n",
    }
    for rel, c in files.items():
        f = proj / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(c, encoding="utf-8")
    for cmd in (["."], ["--check", "."], ["README.md", "docs/guide.md"]):
        subprocess.run(
            [ruff, "format", *cmd], cwd=proj, capture_output=True, text=True, check=False
        )
    for rel, c in files.items():
        if rel.endswith((".md", ".markdown")) or rel == "docs/code.py":
            assert (proj / rel).read_text(encoding="utf-8") == c, rel
    # Sanity: non-excluded python IS formatted, so the exclude is what protected the md.
    # (--check run last-but-one does not write; the first run did.)
    assert (proj / "mod.py").read_text(encoding="utf-8") == 'z = {"a": 1}\n'


def test_ruff_format_from_subdirectory_still_honours_exclude(tmp_path):
    ruff = _ruff()
    proj = tmp_path / "p"
    (proj / "docs").mkdir(parents=True)
    shutil.copy(ROOT / "pyproject.toml", proj / "pyproject.toml")
    (proj / "docs" / "g.md").write_text(UGLY_MD, encoding="utf-8")
    subprocess.run([ruff, "format", "g.md"], cwd=proj / "docs", capture_output=True, check=False)
    assert (proj / "docs" / "g.md").read_text(encoding="utf-8") == UGLY_MD


def test_ruff_check_still_lints_python_after_exclude():
    # The format exclude must not have leaked into lint config.
    proc = subprocess.run(
        [_ruff(), "check", "--no-cache", "."], cwd=ROOT, capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0, proc.stdout
