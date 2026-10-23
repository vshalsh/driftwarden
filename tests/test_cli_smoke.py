from __future__ import annotations

from typer.testing import CliRunner

from driftwarden import __version__
from driftwarden.cli import app
from driftwarden.config import Config, load_config

runner = CliRunner()


def test_version():
    res = runner.invoke(app, ["version"])
    assert res.exit_code == 0
    assert __version__ in res.output


def test_verify_placeholder():
    res = runner.invoke(app, ["verify"])
    assert res.exit_code == 2
    assert "not yet implemented" in res.output


def test_scan_bad_format(tmp_path):
    res = runner.invoke(app, ["scan", str(tmp_path), "--format", "json,pdf"])
    assert res.exit_code != 0


def test_config_defaults(tmp_path):
    cfg = load_config(tmp_path)
    assert cfg == Config()
    assert cfg.mode == "auto"
    assert cfg.adr_paths == []


def test_config_from_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.driftwarden]\nadr_paths = ["design/adr"]\nmode = "offline"\n', encoding="utf-8"
    )
    cfg = load_config(tmp_path)
    assert cfg.adr_paths == ["design/adr"]
    assert cfg.mode == "offline"


def test_config_driftwarden_toml_wins(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.driftwarden]\nmode = "offline"\n')
    (tmp_path / "driftwarden.toml").write_text('mode = "llm"\nprovider = "openai"\n')
    cfg = load_config(tmp_path)
    assert cfg.mode == "llm" and cfg.provider == "openai"


def test_scan_reports_unimplemented_stages(tmp_path):
    res = runner.invoke(app, ["scan", str(tmp_path), "--mode", "offline", "--format", "json,md"])
    assert res.exit_code == 0
    assert "not yet implemented" in res.output
    assert "mode=offline" in res.output
