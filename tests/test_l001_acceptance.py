"""System-test additions for L-001 (Sonnet): config precedence, git wrapper errors, CLI exits."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from driftwarden import __version__
from driftwarden import git as dwgit
from driftwarden.cli import app
from driftwarden.config import Config, ConfigError, load_config

runner = CliRunner()


# ------------------------------------------------------------------ config precedence


def _pp(path: Path, body: str) -> None:
    (path / "pyproject.toml").write_text(body, encoding="utf-8")


def test_precedence_driftwarden_toml_over_pyproject_per_field(tmp_path):
    _pp(tmp_path, '[tool.driftwarden]\nmode = "offline"\nmodel = "from-pyproject"\n')
    (tmp_path / "driftwarden.toml").write_text('mode = "llm"\n', encoding="utf-8")
    cfg = load_config(tmp_path)
    assert cfg.mode == "llm"
    assert cfg.source.endswith("driftwarden.toml")
    # No merging between files: the lower-precedence file is ignored entirely.
    assert cfg.model is None


def test_precedence_pyproject_used_when_no_driftwarden_toml(tmp_path):
    _pp(tmp_path, '[tool.driftwarden]\nmode = "offline"\n')
    cfg = load_config(tmp_path)
    assert cfg.mode == "offline" and cfg.source.endswith("pyproject.toml")


def test_precedence_defaults_when_none(tmp_path):
    cfg = load_config(tmp_path)
    assert cfg == Config() and cfg.source is None
    assert cfg.provider == "anthropic" and cfg.mode == "auto" and cfg.model is None
    assert ".git/**" in cfg.exclude


def test_pyproject_without_tool_section_falls_back_to_defaults(tmp_path):
    _pp(tmp_path, '[project]\nname = "x"\n')
    cfg = load_config(tmp_path)
    assert cfg.source is None and cfg == Config()


def test_pyproject_without_section_but_driftwarden_toml_present(tmp_path):
    _pp(tmp_path, '[project]\nname = "x"\n')
    (tmp_path / "driftwarden.toml").write_text('mode = "offline"\n', encoding="utf-8")
    assert load_config(tmp_path).mode == "offline"


def test_explicit_config_beats_both(tmp_path):
    _pp(tmp_path, '[tool.driftwarden]\nmode = "offline"\n')
    (tmp_path / "driftwarden.toml").write_text('mode = "llm"\n', encoding="utf-8")
    other = tmp_path / "other.toml"
    other.write_text('mode = "auto"\nprovider = "openai"\n', encoding="utf-8")
    cfg = load_config(tmp_path, other)
    assert cfg.provider == "openai" and cfg.mode == "auto"


def test_explicit_pyproject_config_reads_tool_section(tmp_path):
    alt = tmp_path / "alt" / "pyproject.toml"
    alt.parent.mkdir()
    alt.write_text('[tool.driftwarden]\nprovider = "openai"\n', encoding="utf-8")
    assert load_config(tmp_path, alt).provider == "openai"


def test_explicit_missing_config_is_error(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path, tmp_path / "nope.toml")


@pytest.mark.parametrize(
    "body",
    ['mode = "bogus"\n', "unknown_key = 1\n", "mode = [\n", 'provider = "gemini"\n'],
)
def test_invalid_config_raises_config_error(tmp_path, body):
    (tmp_path / "driftwarden.toml").write_text(body, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_invalid_driftwarden_toml_not_masked_by_valid_pyproject(tmp_path):
    _pp(tmp_path, '[tool.driftwarden]\nmode = "offline"\n')
    (tmp_path / "driftwarden.toml").write_text("mode = [\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_defaults_are_not_shared_between_instances():
    a, b = Config(), Config()
    a.exclude.append("x/**")
    a.adr_paths.append("y")
    assert "x/**" not in b.exclude and b.adr_paths == []


def test_cli_config_error_exit_2_no_traceback(tmp_path):
    (tmp_path / "driftwarden.toml").write_text('mode = "bogus"\n', encoding="utf-8")
    res = runner.invoke(app, ["scan", str(tmp_path)])
    assert res.exit_code == 2
    assert "config error" in res.output
    assert res.exception is None or isinstance(res.exception, SystemExit)
    assert "Traceback" not in res.output


# ------------------------------------------------------------------ git wrapper errors


def test_git_wrapper_outside_repo_all_functions(tmp_path):
    assert dwgit.is_repo(tmp_path) is False
    for fn in (dwgit.repo_root, dwgit.head_sha):
        with pytest.raises(dwgit.NotAGitRepoError):
            fn(tmp_path)
    with pytest.raises(dwgit.NotAGitRepoError):
        dwgit.show_file(tmp_path, "HEAD", "a.md")
    with pytest.raises(dwgit.NotAGitRepoError):
        dwgit.log(tmp_path)
    with pytest.raises(dwgit.NotAGitRepoError):
        dwgit.commit_exists(tmp_path, "HEAD")
    with pytest.raises(dwgit.NotAGitRepoError):
        dwgit.is_tracked_and_clean(tmp_path, "a.md")


def test_git_error_hierarchy():
    assert issubclass(dwgit.NotAGitRepoError, dwgit.GitError)
    assert issubclass(dwgit.GitNotFoundError, dwgit.GitError)


def test_git_wrapper_file_path_inside_non_repo(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x", encoding="utf-8")
    assert dwgit.is_repo(f) is False
    with pytest.raises(dwgit.NotAGitRepoError):
        dwgit.repo_root(f)


def test_git_wrapper_nonexistent_path(tmp_path):
    ghost = tmp_path / "ghost"
    assert dwgit.is_repo(ghost) is False
    with pytest.raises(dwgit.NotAGitRepoError, match="does not exist"):
        dwgit.head_sha(ghost)


def test_git_wrapper_bad_revision_in_real_repo(make_repo):
    repo = make_repo({"a.md": "x\n"})
    with pytest.raises(dwgit.GitError):
        dwgit.log(repo, rev="no-such-branch")
    assert dwgit.commit_exists(repo, "not-a-sha") is False
    # A bad revision must not be misreported as "not a git repository".
    with pytest.raises(dwgit.GitError) as ei:
        dwgit.show_file(repo, "no-such-rev", "a.md")
    assert not isinstance(ei.value, dwgit.NotAGitRepoError)


def test_git_wrapper_git_missing_from_path(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(dwgit.GitNotFoundError):
        dwgit.repo_root(tmp_path)
    assert dwgit.is_repo(tmp_path) is False  # GitError is swallowed by is_repo


def test_git_wrapper_nested_non_repo_inside_repo_resolves_to_outer(make_repo):
    repo = make_repo({"a/b.md": "x\n"})
    assert dwgit.repo_root(repo / "a") == repo.resolve()


# ------------------------------------------------------------------ CLI


def test_help_lists_commands():
    res = runner.invoke(app, ["--help"])
    assert res.exit_code == 0
    for cmd in ("scan", "version", "verify"):
        assert cmd in res.output


def test_no_args_shows_help():
    res = runner.invoke(app, [])
    assert "Usage" in res.output


def test_version_matches_package():
    res = runner.invoke(app, ["version"])
    assert res.exit_code == 0 and res.output.strip() == f"driftwarden {__version__}"


def test_console_script_installed_and_runs():
    exe = shutil.which("driftwarden", path=str(Path(sys.executable).parent))
    assert exe, "driftwarden console script missing after pip install -e"
    out = subprocess.run([exe, "version"], capture_output=True, text=True, check=False)
    assert out.returncode == 0 and __version__ in out.stdout
    out = subprocess.run([exe, "--help"], capture_output=True, text=True, check=False)
    assert out.returncode == 0 and "scan" in out.stdout


def test_verify_exit_code_2_with_message_on_stderr():
    res = runner.invoke(app, ["verify"])
    assert res.exit_code == 2
    assert "not yet implemented" in res.output


def test_verify_exit_code_2_via_subprocess():
    exe = shutil.which("driftwarden", path=str(Path(sys.executable).parent))
    out = subprocess.run([exe, "verify"], capture_output=True, text=True, check=False)
    assert out.returncode == 2
    assert "not yet implemented" in out.stderr
    assert "Traceback" not in out.stderr


def test_scan_missing_path_exit_2(tmp_path):
    res = runner.invoke(app, ["scan", str(tmp_path / "ghost")])
    assert res.exit_code == 2
    assert "does not exist" in res.output
    assert "Traceback" not in res.output


def test_scan_bad_format_message(tmp_path):
    res = runner.invoke(app, ["scan", str(tmp_path), "--format", "pdf"])
    assert res.exit_code == 2
    assert "unknown format" in res.output


def test_scan_explicit_config_flag_used(make_repo, tmp_path):
    repo = make_repo({"a.md": "x\n"})
    cfg = tmp_path / "c.toml"
    cfg.write_text('mode = "offline"\n', encoding="utf-8")
    res = runner.invoke(app, ["scan", str(repo), "--config", str(cfg)])
    assert res.exit_code == 0
    assert "c.toml" in res.output.replace("\n", "")


@pytest.mark.xfail(
    reason="DEFECT D-001: L-001 scan never checks for a git repo (exit 0, no error); "
    "fixed by L-002 cli.py",
    strict=False,
)
def test_scan_on_non_git_directory_clear_error_not_traceback(tmp_path):
    """A scan of a directory that is not a git repository must fail clearly."""
    d = tmp_path / "plain"
    d.mkdir()
    (d / "README.md").write_text("hi\n", encoding="utf-8")
    res = runner.invoke(app, ["scan", str(d)])
    assert res.exit_code != 0, f"expected non-zero exit, got 0:\n{res.output}"
    assert "git" in res.output.lower()
    assert "Traceback" not in res.output
    assert res.exception is None or isinstance(res.exception, SystemExit)


@pytest.mark.xfail(
    reason="DEFECT D-001: L-001 scan never checks for a git repo (exit 0, no error); "
    "fixed by L-002 cli.py",
    strict=False,
)
def test_scan_on_non_git_directory_subprocess(tmp_path):
    exe = shutil.which("driftwarden", path=str(Path(sys.executable).parent))
    d = tmp_path / "plain"
    d.mkdir()
    out = subprocess.run([exe, "scan", str(d)], capture_output=True, text=True, check=False)
    assert out.returncode != 0
    assert "Traceback" not in out.stderr + out.stdout
    assert "git" in (out.stderr + out.stdout).lower()


def test_scan_on_git_repo_succeeds(make_repo):
    repo = make_repo({"a.md": "x\n"})
    res = runner.invoke(app, ["scan", str(repo)])
    assert res.exit_code == 0
