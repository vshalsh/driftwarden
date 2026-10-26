"""Configuration loading.

Order of precedence (first found wins):
1. An explicit ``--config FILE`` (either a driftwarden.toml or a pyproject.toml).
2. ``driftwarden.toml`` at the repository root.
3. ``[tool.driftwarden]`` in ``pyproject.toml`` at the repository root.
4. Built-in defaults (no config file needed).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on 3.10 only
    import tomli as tomllib

Mode = Literal["auto", "offline", "llm"]
Provider = Literal["anthropic", "openai"]

DEFAULT_EXCLUDES = [
    ".git/**",
    ".driftwarden/**",
    "node_modules/**",
    ".venv/**",
    "venv/**",
    "dist/**",
    "build/**",
    "__pycache__/**",
]


class ConfigError(Exception):
    """Raised when a configuration file exists but cannot be used."""


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")

    adr_paths: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    mode: Mode = "auto"
    provider: Provider = "anthropic"
    model: str | None = None
    # Where the config came from; informational only.
    source: str | None = Field(default=None, exclude=True)


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc


def _section(path: Path, data: dict[str, Any]) -> dict[str, Any] | None:
    if path.name == "pyproject.toml":
        section = data.get("tool", {}).get("driftwarden")
        return section if isinstance(section, dict) else None
    return data


def _build(path: Path, section: dict[str, Any]) -> Config:
    try:
        cfg = Config(**section)
    except ValidationError as exc:
        raise ConfigError(f"{path}: invalid driftwarden config:\n{exc}") from exc
    cfg.source = str(path)
    return cfg


def load_config(root: str | Path = ".", config_file: str | Path | None = None) -> Config:
    """Load configuration for the repository at ``root``.

    Returns defaults when no configuration is present.
    """
    if config_file is not None:
        path = Path(config_file)
        if not path.is_file():
            raise ConfigError(f"config file not found: {path}")
        section = _section(path, _read_toml(path))
        if section is None:
            raise ConfigError(f"{path}: no [tool.driftwarden] section")
        return _build(path, section)

    root = Path(root)
    dw = root / "driftwarden.toml"
    if dw.is_file():
        return _build(dw, _read_toml(dw))

    pp = root / "pyproject.toml"
    if pp.is_file():
        section = _section(pp, _read_toml(pp))
        if section is not None:
            return _build(pp, section)

    return Config()
