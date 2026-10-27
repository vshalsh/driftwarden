"""Configuration loading.

Order of precedence (first found wins):
1. An explicit ``--config FILE`` (either a driftwarden.toml or a pyproject.toml).
2. ``driftwarden.toml`` at the repository root.
3. ``[tool.driftwarden]`` in ``pyproject.toml`` at the repository root.
4. Built-in defaults (no config file needed).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on 3.10 only
    import tomli as tomllib

Mode = Literal["auto", "offline", "llm"]
Provider = Literal["anthropic", "openai"]

LEDGER_EXCLUDE = ".driftwarden/**"
_ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}")


def is_env_var_name(value: object) -> bool:
    """True for a conventional UPPER_SNAKE environment variable name.

    Rejects anything shaped like a pasted secret: lowercase letters, punctuation,
    more than 64 characters, or an underscore-separated segment that is

    * 24+ characters long (``ABCDEFGHIJKLMNOPQRSTUVWXYZ``),
    * 16+ characters with any digit (``AKIAIOSFODNN7EXAMPLE``), or
    * 8+ characters mixing letters with 2+ digits (``A1B2C3D4``, ``AB12CD34``).

    Real variable names (ANTHROPIC_API_KEY, AZURE_OPENAI_API_KEY_V2,
    GOOGLE_APPLICATION_CREDENTIALS, LLM_KEY_20261027...) are words, short
    version suffixes or all-digit dates.
    """
    if not isinstance(value, str) or not _ENV_NAME.fullmatch(value):
        return False
    for seg in value.split("_"):
        digits = sum(c.isdigit() for c in seg)
        if len(seg) >= 24 or (len(seg) >= 16 and digits):
            return False
        if len(seg) >= 8 and digits >= 2 and digits < len(seg):
            return False
    return True


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
    # hide_input_in_errors: a mistyped key field (``api_key = "sk-..."``) must never be
    # echoed back in an error message or CI log.
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    adr_paths: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDES))

    @field_validator("exclude")
    @classmethod
    def _always_exclude_ledger(cls, value: list[str]) -> list[str]:
        # Run output must never be read as ADRs, even when the user replaces `exclude`.
        return value if LEDGER_EXCLUDE in value else [*value, LEDGER_EXCLUDE]

    mode: Mode = "auto"
    provider: Provider = "anthropic"
    model: str | None = None
    # LLM provider settings (see driftwarden.llm.get_provider). API keys are never
    # stored in config: ``api_key_env`` names the environment variable to read.
    base_url: str | None = None
    api_key_env: str | None = None
    timeout_s: float = Field(default=600.0, gt=0)
    max_attempts: int = Field(default=3, ge=1, le=10)
    input_cost_per_mtok: float | None = Field(default=None, ge=0)
    output_cost_per_mtok: float | None = Field(default=None, ge=0)

    @field_validator("api_key_env")
    @classmethod
    def _env_var_name_only(cls, value: str | None) -> str | None:
        if value is not None and not is_env_var_name(value):
            # Deliberately does not echo the value: it may be a pasted secret.
            raise ValueError(
                "api_key_env must be the NAME of an environment variable in UPPER_SNAKE "
                "case, at most 64 characters (e.g. ANTHROPIC_API_KEY), never the key itself"
            )
        return value

    @field_validator("base_url")
    @classmethod
    def _http_url(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith(("http://", "https://")):
            raise ValueError("base_url must start with http:// or https://")
        return value

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
