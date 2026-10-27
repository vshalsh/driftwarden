"""L-005 system RE-TEST (round 2, independent). No network, no real key.

Round 1 (tests/test_l005_system.py) found D1-D11; Opus fixed them. This file
(a) tries to break each fix with new variants, (b) probes regressions the fixes
could have introduced, and (c) strengthens the api_key_env echo check that Opus
rewrote.

Tests marked ``xfail(strict=True)`` document DEFECTS found in round 2; they turn
red (XPASS) when the defect is fixed so the marker gets removed. Defect ids D12+
continue the round-1 numbering.
"""

# ruff: noqa: E501 - xfail reasons are single-line defect descriptions
from __future__ import annotations

import io
import json
import socket
import subprocess
import sys
import textwrap
import threading
import traceback
import urllib.error
import warnings

import pytest
from pydantic import BaseModel, ConfigDict

from driftwarden.config import Config, ConfigError, is_env_var_name, load_config
from driftwarden.llm import (
    CostLog,
    OfflineProvider,
    ProviderConfigError,
    RefusalError,
    RetryPolicy,
    SchemaValidationError,
    TransportError,
    get_provider,
)
from driftwarden.llm.anthropic import AnthropicProvider
from driftwarden.llm.base import LLMError, Usage, token_count
from driftwarden.llm.openai_compat import OpenAICompatProvider
from driftwarden.llm.pricing import cost_usd
from driftwarden.llm.schema import validate_json
from driftwarden.llm.transport import _host, urllib_transport

KEY = "sk-ant-SECRETSECRET-1234567890abcdef"
OKEY = "sk-proj-OPENAISECRET-0987654321fedcba"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*_a, **_k):
        raise OSError("network disabled")

    class Blocked(socket.socket):
        def connect(self, *a, **k):
            blocked()

        connect_ex = connect

    monkeypatch.setattr(socket, "socket", Blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


class Fake:
    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls = []

    def __call__(self, url, headers, body, timeout):
        self.calls.append((url, headers, body, timeout))
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def a_reply(text, inp=10, out=5, stop="end_turn", model="claude-sonnet-5-5", usage=None):
    return {
        "id": "msg_1", "type": "message", "model": model, "stop_reason": stop,
        "content": [{"type": "text", "text": text}],
        "usage": usage if usage is not None else {"input_tokens": inp, "output_tokens": out},
    }  # fmt: skip


def o_reply(text, finish="stop", refusal=None):
    msg = {"role": "assistant", "content": text}
    if refusal:
        msg["refusal"] = refusal
    return {"id": "c1", "model": "m", "choices": [{"message": msg, "finish_reason": finish}],
            "usage": {"prompt_tokens": 7, "completion_tokens": 3}}  # fmt: skip


def anth(transport, tmp_path=None, attempts=3, sleeps=None, key=KEY):
    sl = sleeps if sleeps is not None else []
    log = CostLog(tmp_path) if tmp_path else CostLog(None)
    return AnthropicProvider(
        "claude-sonnet-5-5", api_key=key, transport=transport, cost_log=log,
        retry=RetryPolicy(max_attempts=attempts, sleep=sl.append),
    )  # fmt: skip


def oai(transport, tmp_path=None, attempts=3, key=OKEY):
    log = CostLog(tmp_path) if tmp_path else CostLog(None)
    return OpenAICompatProvider(
        "m", api_key=key, base_url="http://localhost:11434/v1", transport=transport,
        cost_log=log, retry=RetryPolicy(max_attempts=attempts, sleep=lambda s: None),
    )  # fmt: skip


def log_text(p) -> str:
    path = p.cost_log.path
    return path.read_text() if path is not None and path.exists() else ""


def all_logged(p) -> str:
    """Everything the cost log holds: the JSONL file and the in-memory records."""
    return log_text(p) + json.dumps(p.cost_log.records, default=str)


SCHEMA = {
    "type": "object",
    "properties": {"n": {"type": "integer"}, "tag": {"enum": ["a", "b"]}},
    "required": ["n"],
    "additionalProperties": False,
}


# =========================================================================== D1 / api_key_env
#
# Opus rewrote test_api_key_env_pasted_underscore_key_not_echoed: the original asserted
# that a pasted key which PASSED validation was not echoed by get_provider; the rewrite
# asserts Config REJECTS the key and that get_provider never echoes it on a
# model_construct()-built Config. Judgement: the rewrite is correct but WEAKER:
#   1. get_provider's guard uses the same predicate (is_env_var_name) as Config, so a
#      secret that fools the predicate is accepted AND echoed: no defence in depth.
#   2. it checks one shape (gsk_...); D1 was a class of shapes.
#   3. it only builds the Config directly, not via load_config() or by assignment.
# The tests below restore the end-to-end invariant over many shapes: "for every
# pasted-secret shape, either Config rejects it, or nothing echoes it".

LEGIT_ENV_NAMES = [
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "MY_ORG_LLM_TOKEN",
    "AZURE_OPENAI_API_KEY",
    "GROQ_API_KEY",
    "OPENROUTER_API_KEY",
    "MISTRAL_API_KEY",
    "COHERE_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "ANTHROPIC_API_KEY_2",
    "DW_KEY_2",
    "LLM_KEY_20261027",
    "AZURE_OPENAI_API_KEY_V2",
    "A",
    "B" * 23,
    "ACME_CORPORATION_INTERNAL_LLM_GATEWAY_TOKEN",
]

SECRET_SHAPES = [
    "sk-ant-api03-abcDEF123456",
    "gsk_SECRETabcdef0123456789",
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "xoxb-1234-5678",
    "sk_live_abcdefgh",
    "A" * 65,
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789ABCDEF0123456789ABCDEF",
    "JBSWY3DPEHPK3PXP",
    "Bearer abc123",
    "KEY=abc",
    "ＡＢＣ",
]
WHITESPACE_SHAPES = [
    "ANTHROPIC_API_KEY\n",
    " ANTHROPIC_API_KEY",
    "ANTHROPIC_API_KEY ",
    "ANTHROPIC\tAPI_KEY",
]


@pytest.mark.parametrize("name", LEGIT_ENV_NAMES)
def test_regression_legit_env_names_still_accepted(name):
    cfg = Config(api_key_env=name)
    assert cfg.api_key_env == name
    assert is_env_var_name(name)
    # and the provider really reads that variable
    p = get_provider(Config(api_key_env=name, mode="llm"), env={name: KEY}, transport=Fake())
    assert p.name == "anthropic"
    off = get_provider(Config(api_key_env=name), env={})
    assert isinstance(off, OfflineProvider)
    assert name in off.reason  # the variable NAME is still reported: useful, and safe


def test_regression_legit_env_name_from_toml_files(tmp_path):
    (tmp_path / "driftwarden.toml").write_text('api_key_env = "MY_ORG_LLM_TOKEN"\n')
    assert load_config(tmp_path).api_key_env == "MY_ORG_LLM_TOKEN"
    (tmp_path / "driftwarden.toml").unlink()
    (tmp_path / "pyproject.toml").write_text(
        '[tool.driftwarden]\napi_key_env = "AZURE_OPENAI_API_KEY"\nprovider = "openai"\n'
    )
    assert load_config(tmp_path).api_key_env == "AZURE_OPENAI_API_KEY"


@pytest.mark.parametrize("shape", SECRET_SHAPES)
def test_pasted_secret_shapes_rejected_without_echo(shape):
    with pytest.raises(ValueError) as ei:
        Config(api_key_env=shape)
    text = str(ei.value) + repr(ei.value)
    assert shape.strip() not in text


@pytest.mark.parametrize("value", ["", *WHITESPACE_SHAPES])
def test_empty_or_whitespace_api_key_env_rejected(value):
    with pytest.raises(ValueError):
        Config(api_key_env=value)


@pytest.mark.parametrize("shape", ["gsk_SECRETabcdef0123456789", "AKIAIOSFODNN7EXAMPLE"])
@pytest.mark.parametrize("where", ["driftwarden.toml", "pyproject.toml"])
def test_toml_pasted_secret_rejected_without_echo(tmp_path, shape, where):
    if where == "driftwarden.toml":
        (tmp_path / where).write_text(f'api_key_env = "{shape}"\n')
    else:
        (tmp_path / where).write_text(f'[tool.driftwarden]\napi_key_env = "{shape}"\n')
    with pytest.raises(ConfigError) as ei:
        load_config(tmp_path)
    assert shape not in str(ei.value)


def test_toml_key_in_wrong_field_not_echoed(tmp_path):
    (tmp_path / "driftwarden.toml").write_text(f'api_key = "{KEY}"\n')
    with pytest.raises(ConfigError) as ei:
        load_config(tmp_path)
    assert KEY not in str(ei.value)


def _assigned(shape, mode):
    cfg = Config(mode=mode)
    cfg.api_key_env = shape  # Config has no validate_assignment
    return cfg


@pytest.mark.parametrize("shape", SECRET_SHAPES)
@pytest.mark.parametrize("mode", ["auto", "llm"])
def test_unvalidated_config_never_echoes_pasted_secret(shape, mode):
    """Configs that skip validation (model_construct / attribute assignment /
    model_copy) must not echo a key-shaped api_key_env from get_provider."""
    for cfg in (
        Config.model_construct(api_key_env=shape, mode=mode),
        _assigned(shape, mode),
        Config(mode=mode).model_copy(update={"api_key_env": shape}),
    ):
        try:
            p = get_provider(cfg, env={})
            blob = repr(p) + getattr(p, "reason", "")
        except ProviderConfigError as exc:
            blob = str(exc)
        assert shape.strip() not in blob


# Shapes built to look like an env var name to the shape heuristic: UPPER-only, short
# underscore-separated groups containing digits.
SEGMENTED_SECRETS = [
    "A1B2C3D4_E5F6A7B8_C9D0E1F2_A3B4C5D6",  # uppercase hex split into 8-char groups
    "AB12CD34_EF56AB78_CD90EF12",
    "SK_ANT_API03_9XQ2LM7PZ4TV8RK",
]


@pytest.mark.parametrize("shape", SEGMENTED_SECRETS)
def test_segmented_uppercase_secret_not_accepted_or_echoed(shape):
    """Strengthened D1 invariant: a value is either rejected by Config, or never echoed.
    (The rewritten round-1 test cannot see this: it only tried one shape.)"""
    try:
        cfg = Config(api_key_env=shape)
    except ValueError:
        return  # rejected: fine
    p = get_provider(cfg, env={})
    assert shape not in getattr(p, "reason", "")


# =========================================================================== D2 / base_url


@pytest.mark.parametrize(
    "url,secrets",
    [
        ("http://user:hunter2pw@localhost:11434/v1", ["hunter2pw"]),
        ("https://:tokentoken123@proxy.example.com/v1", ["tokentoken123"]),
        ("http://us%40er:p%40ssword9@[::1]:9/v1", ["p%40ssword9", "p@ssword9"]),
        ("http://admin:pa@ss-word-9@host.example.com/v1", ["pa@ss-word-9", "ss-word-9"]),
    ],
)
def test_base_url_userinfo_never_in_repr_error_or_log(url, secrets, tmp_path, monkeypatch):
    """Real urllib_transport; the (mocked) socket layer echoes the full URL in its errors."""
    seen = []

    def echoing_urlopen(req, timeout=None):
        raise urllib.error.URLError(f"failed to open {req.full_url}")

    monkeypatch.setattr("urllib.request.urlopen", echoing_urlopen)
    for cls in (AnthropicProvider, OpenAICompatProvider):
        kw = {"api_key": KEY, "base_url": url, "transport": urllib_transport,
              "cost_log": CostLog(tmp_path), "retry": RetryPolicy(max_attempts=2, sleep=lambda s: None)}  # fmt: skip
        p = cls("m", **kw)
        seen.append(repr(p))
        seen.append(_host(url))
        try:
            p.complete("x")
        except TransportError as exc:
            seen.append(str(exc))
        seen.append(all_logged(p))
    blob = "\n".join(seen)
    for s in secrets:
        assert s not in blob, s


def test_base_url_userinfo_scrubbed_in_http_error_body(monkeypatch):
    url = "http://svc:hunter2pw@localhost:9/v1"

    def fake(req, timeout=None):
        raise urllib.error.HTTPError(
            req.full_url, 502, "bad", {}, io.BytesIO(f"proxy {url}".encode())
        )

    monkeypatch.setattr("urllib.request.urlopen", fake)
    with pytest.raises(TransportError) as ei:
        urllib_transport(url + "/chat/completions", {}, {}, 1)
    assert "hunter2pw" not in str(ei.value)


# =========================================================================== D10 / secrets in error bodies


def _http_error(monkeypatch, body, code=401):
    def fake(req, timeout=None):
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            "x",
            {},
            io.BytesIO(body if isinstance(body, bytes) else body.encode()),
        )

    monkeypatch.setattr("urllib.request.urlopen", fake)


@pytest.mark.parametrize(
    "body",
    [
        f"bad key {KEY}",
        f"x-api-key: {KEY}",
        f"X-API-KEY: {KEY}",
        f"Authorization: Bearer {KEY}",
        f"authorization: Bearer {KEY}",
        json.dumps({"error": {"message": f"Invalid key {KEY}"}}),
        json.dumps({"headers": {"x-api-key": KEY, "anthropic-version": "2026-10-21"}}),
        f"{KEY} {KEY} {KEY}",
        "x" * 200 + KEY,  # fully inside the 300-char window
    ],
)
def test_error_body_echoing_key_or_header_is_redacted_end_to_end(monkeypatch, tmp_path, body):
    _http_error(monkeypatch, body)
    p = AnthropicProvider(
        "claude-sonnet-5-5", api_key=KEY, transport=urllib_transport, cost_log=CostLog(tmp_path),
        retry=RetryPolicy(max_attempts=2, sleep=lambda s: None),
    )  # fmt: skip
    with pytest.raises(TransportError) as ei:
        p.complete("hi")
    chain = "".join(traceback.format_exception(ei.value))
    assert KEY not in str(ei.value) + repr(ei.value) + chain + all_logged(p)


def test_openai_bearer_echo_redacted_end_to_end(monkeypatch, tmp_path):
    _http_error(monkeypatch, f"Authorization: Bearer {OKEY}")
    p = OpenAICompatProvider(
        "m", api_key=OKEY, base_url="https://llm.example.com/v1", transport=urllib_transport,
        cost_log=CostLog(tmp_path), retry=RetryPolicy(max_attempts=1, sleep=lambda s: None),
    )  # fmt: skip
    with pytest.raises(TransportError) as ei:
        p.complete("hi")
    assert OKEY not in str(ei.value) + all_logged(p)


@pytest.mark.parametrize("offset", [265, 275, 285])
def test_key_straddling_the_300_char_cut_not_leaked(monkeypatch, tmp_path, offset):
    _http_error(monkeypatch, "x" * offset + KEY)
    p = AnthropicProvider(
        "claude-sonnet-5-5", api_key=KEY, transport=urllib_transport, cost_log=CostLog(tmp_path),
        retry=RetryPolicy(max_attempts=1, sleep=lambda s: None),
    )  # fmt: skip
    with pytest.raises(TransportError) as ei:
        p.complete("hi")
    assert KEY[:8] not in str(ei.value)


@pytest.mark.parametrize(
    "variant",
    [
        pytest.param(KEY.lower(), id="lowercase"),
        pytest.param(KEY.upper(), id="uppercase"),
        pytest.param(KEY.replace("-", "%2D"), id="urlencoded"),
        pytest.param(KEY.replace("-", "\\u002d"), id="json-unicode-escaped"),
    ],
)
@pytest.mark.xfail(
    strict=True,
    reason="D17 (INFO / accepted residual risk): redaction is exact-match only; a server that echoes the key "
    "re-cased or re-encoded is not redacted. Not known to happen with Anthropic/OpenAI. Known limit, "
    "documented in the driftwarden.llm.transport module docstring; deliberately not fixed in L-005.",
)
def test_transformed_key_echo_is_redacted(monkeypatch, variant):
    _http_error(monkeypatch, f"bad key {variant}")
    with pytest.raises(TransportError) as ei:
        urllib_transport("https://api.example.com/v1/m", {"x-api-key": KEY}, {}, 1)
    assert variant[:20] not in str(ei.value)


def test_provider_level_error_payloads_redacted_and_status_only_in_log(tmp_path):
    """200-OK style error documents (no HTTP error) carrying the key."""
    p = anth(
        Fake({"type": "error", "error": {"type": "authentication_error", "message": f"bad {KEY}"}}),
        tmp_path,
    )
    with pytest.raises(TransportError) as ei:
        p.complete("x")
    assert KEY not in str(ei.value)
    assert KEY not in all_logged(p)
    q = oai(Fake({"error": {"message": f"key {OKEY} invalid"}}), tmp_path)
    with pytest.raises(TransportError) as ei:
        q.complete("x")
    assert OKEY not in str(ei.value)
    assert OKEY not in all_logged(q)


def test_retryable_exhaustion_redacts_final_error(tmp_path):
    errs = [TransportError(f"HTTP 503: echo {KEY}", status=503, retryable=True) for _ in range(3)]
    p = anth(Fake(*errs), tmp_path)
    with pytest.raises(TransportError) as ei:
        p.complete("x")
    assert KEY not in str(ei.value) and KEY not in all_logged(p)
    assert ei.value.status == 503 and ei.value.retryable is True


# =========================================================================== D5 / token counts


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param("abc", id="alpha"),
        pytest.param("1e3", id="sci"),
        pytest.param("0x10", id="hex"),
        pytest.param("1_0", id="underscore"),
        pytest.param(None, id="none"),
        pytest.param([], id="list"),
        pytest.param({}, id="dict"),
        pytest.param(float("nan"), id="nan"),
        pytest.param(float("inf"), id="inf"),
        pytest.param(-5, id="negative"),
        pytest.param(True, id="bool"),
        pytest.param("١٢٣", id="arabic-indic-digits"),
        pytest.param("²", id="superscript-two"),
        pytest.param("①", id="circled-one"),
        pytest.param("9" * 5000, id="5000-digit-string"),
    ],
)
def test_token_count_hostile_usage_never_escapes(bad):
    assert token_count(bad) >= 0


@pytest.mark.parametrize("field", ["input_tokens", "output_tokens"])
@pytest.mark.parametrize("bad", ["abc", None, -1, float("nan"), [1], {"a": 1}, "١٢٣", 1.9])
def test_hostile_usage_end_to_end_logs_clean_record(tmp_path, field, bad):
    usage = {"input_tokens": 3, "output_tokens": 2, field: bad}
    p = anth(Fake(a_reply("hello", usage=usage)), tmp_path)
    p.complete("x")
    rec = json.loads(log_text(p).splitlines()[-1])
    assert isinstance(rec["input_tokens"], int) and rec["input_tokens"] >= 0
    assert isinstance(rec["output_tokens"], int) and rec["output_tokens"] >= 0


@pytest.mark.parametrize(
    "usage",
    [
        pytest.param({"input_tokens": "²", "output_tokens": 1}, id="superscript-str"),
        pytest.param({"input_tokens": 10**400, "output_tokens": 1}, id="int-beyond-float"),
    ],
)
def test_pathological_usage_raises_no_bare_exception(tmp_path, usage):
    p = anth(Fake(a_reply("hello", usage=usage)), tmp_path)
    try:
        p.complete("x")
    except LLMError:
        pass  # a typed error is acceptable; a bare ValueError/OverflowError is not


# =========================================================================== D4 / backoff


@pytest.mark.parametrize("attempt", [0, -3, 1, 64, 65, 1025, 10**6, 10**18])
@pytest.mark.parametrize("base", [0.0, 0.5, 1.0, 1e300])
def test_backoff_delay_bounded_for_any_attempt(attempt, base):
    pol = RetryPolicy(max_attempts=2, base_delay=base, max_delay=30.0)
    d = pol.delay(attempt)
    assert 0.0 <= d <= 30.0


def test_backoff_sequence_is_exponential_and_capped():
    pol = RetryPolicy(max_attempts=10, base_delay=1.0, max_delay=30.0)
    assert [pol.delay(i) for i in range(1, 8)] == [1, 2, 4, 8, 16, 30, 30]


# =========================================================================== D6 / refusal text


@pytest.mark.parametrize(
    "text", ["I cannot help with sk-ant-LEAKYREFUSAL-123456", "x" * 5000, "ünï‮code"]
)
def test_openai_refusal_text_never_logged(tmp_path, text):
    p = oai(Fake(o_reply("", refusal=text)), tmp_path)
    with pytest.raises(RefusalError):
        p.complete("x")
    assert text[:20] not in all_logged(p)
    rec = json.loads(log_text(p).splitlines()[-1])
    assert rec["outcome"] == "refusal"


def test_openai_refusal_inside_complete_json_not_retried_not_logged(tmp_path):
    p = oai(Fake(o_reply("", refusal="SECRETREFUSALTEXT")), tmp_path)
    with pytest.raises(RefusalError):
        p.complete_json("x", SCHEMA)
    assert "SECRETREFUSALTEXT" not in all_logged(p)
    assert len(p.cost_log.records) == 1


@pytest.mark.parametrize(
    "category", ["bad category with text!", {"x": 1}, ["a"], 7, "a" * 10, "__import__"]
)
def test_anthropic_refusal_category_is_sanitised(tmp_path, category):
    reply = a_reply("I will not discuss SECRETREFUSALTEXT", stop="refusal")
    reply["stop_details"] = {"category": category}
    p = anth(Fake(reply), tmp_path)
    with pytest.raises(RefusalError):
        p.complete("x")
    assert "SECRETREFUSALTEXT" not in all_logged(p)
    if not (isinstance(category, str) and category.isidentifier()):
        assert "bad category" not in all_logged(p)


# =========================================================================== D7 / cyclic $ref


CYCLES = {
    "self-root": {"$ref": "#"},
    "mutual": {
        "$ref": "#/$defs/a",
        "$defs": {"a": {"$ref": "#/$defs/b"}, "b": {"$ref": "#/$defs/a"}},
    },
    "allof": {"$defs": {"a": {"allOf": [{"$ref": "#/$defs/a"}]}}, "$ref": "#/$defs/a"},
    "unresolvable": {"$ref": "#/$defs/missing"},
    "remote": {"$ref": "http://evil.example/schema.json"},
    "non-schema-target": {"$ref": "#/type", "type": "object"},
}


@pytest.mark.parametrize("name", sorted(CYCLES))
def test_bad_ref_schemas_give_typed_errors_not_recursionerror(tmp_path, name):
    schema = CYCLES[name]
    assert isinstance(validate_json({"a": 1}, schema), list)  # documented: never raises
    p = anth(Fake(a_reply("{}"), a_reply("{}"), a_reply("{}")), tmp_path)
    with pytest.raises(LLMError):
        p.complete_json("x", schema)


def test_legit_recursive_schema_has_no_false_cycle_positive(tmp_path):
    tree = {
        "$ref": "#/$defs/node",
        "$defs": {
            "node": {
                "type": "object",
                "properties": {
                    "v": {"type": "integer"},
                    "kids": {"type": "array", "items": {"$ref": "#/$defs/node"}},
                },
                "required": ["v"],
                "additionalProperties": False,
            }
        },
    }
    good = {"v": 1, "kids": [{"v": 2, "kids": [{"v": 3, "kids": []}]}, {"v": 2}]}
    assert validate_json(good, tree) == []
    bad = {"v": 1, "kids": [{"v": 2, "kids": [{"v": "x"}]}]}
    assert validate_json(bad, tree) != []
    p = anth(Fake(a_reply(json.dumps(good))), tmp_path)
    assert p.complete_json("x", tree).value == good
    # same scalar object reused at several levels (json.loads shares None/small ints)
    chain = {
        "$ref": "#/$defs/n",
        "$defs": {
            "n": {
                "anyOf": [
                    {"type": "null"},
                    {"type": "object", "properties": {"x": {"$ref": "#/$defs/n"}}},
                ]
            }
        },
    }
    assert validate_json({"x": {"x": {"x": None}}}, chain) == []
    assert validate_json({"x": {"x": {"x": 5}}}, chain) != []


# =========================================================================== D8 / bad patterns


@pytest.mark.parametrize(
    "pattern",
    [
        pytest.param("[", id="unclosed-class"),
        pytest.param("(?P<n>a)(?P<n>b)", id="dup-group"),
        pytest.param("(a)\\2", id="bad-backref"),
        pytest.param("a**", id="nothing-to-repeat"),
        pytest.param("\\", id="trailing-backslash"),
        pytest.param("(?<=a+)b", id="variable-lookbehind"),
        pytest.param(5, id="non-string"),
        pytest.param(None, id="none"),
        pytest.param("a{99999999999}", id="overflow-repeat"),
        pytest.param("a{1,99999999999}", id="overflow-range"),
        pytest.param("(" * 3000 + ")" * 3000, id="deeply-nested-groups"),
    ],
)
def test_bad_pattern_gives_typed_error_and_validate_json_never_raises(tmp_path, pattern):
    schema = {"type": "string", "pattern": pattern}
    assert isinstance(validate_json("x", schema), list)
    p = anth(Fake(a_reply('"x"'), a_reply('"x"')), tmp_path)
    with pytest.raises(LLMError):
        p.complete_json("x", schema)


def test_good_patterns_still_match(tmp_path):
    schema = {"type": "string", "pattern": "^[a-z]+-[0-9]{2}$"}
    assert validate_json("abc-12", schema) == []
    assert validate_json("ABC-12", schema) != []


# =========================================================================== D15 / ReDoS


_REDOS = textwrap.dedent(
    """
    import json, sys
    from driftwarden.llm import RetryPolicy, SchemaValidationError
    from driftwarden.llm.anthropic import AnthropicProvider

    def tr(u, h, b, t):
        return {"type": "message", "model": "m", "stop_reason": "end_turn", "usage": {},
                "content": [{"type": "text", "text": json.dumps("a" * 34 + "!")}]}

    p = AnthropicProvider("m", api_key="K" * 20, transport=tr,
                          retry=RetryPolicy(max_attempts=1, sleep=lambda s: None))
    try:
        p.complete_json("x", {"type": "string", "pattern": sys.argv[1]})
    except SchemaValidationError:
        print("rejected")
    """
)


def _run_redos(pattern: str, timeout: float) -> str:
    proc = subprocess.Popen(
        [sys.executable, "-c", _REDOS, pattern],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )  # fmt: skip
    try:
        out, _ = proc.communicate(timeout=timeout)
        return out.strip()
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return "TIMEOUT"


def test_ordinary_pattern_on_long_reply_is_fast():
    assert _run_redos("^[a-z]+$", 30) == "rejected"  # '!' fails the match: normal path


def test_catastrophic_backtracking_pattern_is_bounded():
    assert _run_redos("^(a+)+$", 6) == "rejected"


# =========================================================================== deep nesting


def _deep(shape: str, d: int) -> str:
    if shape == "array":
        return "[" * d + "]" * d
    if shape == "object":
        return '{"a":' * d + "1" + "}" * d
    if shape == "mixed":
        return '[{"a":' * d + "1" + "}]" * d
    raise AssertionError(shape)


DEEP_SCHEMAS = {
    "empty": {},
    "object": {"type": "object"},
    "recursive-additional": {"type": "object", "additionalProperties": {"$ref": "#"}},
    "uniqueItems": {"type": "array", "uniqueItems": True},
    "enum": {"enum": [1]},
    "const": {"const": 1},
    "anyOf": {"anyOf": [{"type": "string"}, {"type": "number"}]},
    "oneOf": {"oneOf": [{"type": "string"}, {"type": "number"}]},
}


@pytest.mark.parametrize("depth", [200, 1500, 20000, 400000])
@pytest.mark.parametrize("shape", ["array", "object", "mixed"])
@pytest.mark.parametrize("sname", sorted(DEEP_SCHEMAS))
def test_deeply_nested_reply_is_rejected_or_accepted_but_never_crashes(
    tmp_path, depth, shape, sname
):
    p = anth(Fake(a_reply(_deep(shape, depth)), a_reply(_deep(shape, depth))), tmp_path, attempts=2)
    try:
        p.complete_json("x", DEEP_SCHEMAS[sname])
    except SchemaValidationError as exc:
        assert exc.attempts == 2
        # the log line is bounded and clean even for megabyte replies
        for line in log_text(p).splitlines():
            assert len(line) < 2000
            json.loads(line)


class Node(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kids: list[Node] = []


Node.model_rebuild()


@pytest.mark.parametrize("depth", [50, 1000, 5000, 100000])
def test_deeply_nested_pydantic_reply_never_crashes(tmp_path, depth):
    text = '{"kids":[' * depth + "]}" * depth
    p = anth(Fake(a_reply(text), a_reply(text)), tmp_path, attempts=2)
    try:
        p.complete_json("x", Node)
    except SchemaValidationError:
        pass
    for line in log_text(p).splitlines():
        json.loads(line)


# =========================================================================== D9 / reply values never logged


LEAK = "sk-ant-REPLYLEAK-9988776655"


def _schema_cases():
    return [
        ("enum", {"type": "object", "properties": {"tag": {"enum": ["a", "b"]}}}, {"tag": LEAK}),
        ("const", {"type": "object", "properties": {"tag": {"const": "a"}}}, {"tag": LEAK}),
        ("extra-key", {"type": "object", "additionalProperties": False}, {LEAK: 1}),
        (
            "extra-key-nested",
            {
                "type": "object",
                "properties": {"o": {"type": "object", "additionalProperties": False}},
            },
            {"o": {LEAK: 1}},
        ),
        (
            "addl-schema",
            {"type": "object", "additionalProperties": {"type": "integer"}},
            {LEAK: LEAK},
        ),
        (
            "pattern",
            {"type": "object", "properties": {"s": {"type": "string", "pattern": "^x$"}}},
            {"s": LEAK},
        ),
        (
            "maxLength",
            {"type": "object", "properties": {"s": {"type": "string", "maxLength": 3}}},
            {"s": LEAK},
        ),
        ("type", {"type": "object", "properties": {"s": {"type": "integer"}}}, {"s": LEAK}),
        ("oneOf", {"oneOf": [{"type": "integer"}, {"type": "boolean"}]}, LEAK),
        ("anyOf", {"anyOf": [{"type": "integer"}, {"type": "boolean"}]}, LEAK),
        ("uniqueItems", {"type": "array", "uniqueItems": True}, [LEAK, LEAK]),
        ("items-enum", {"type": "array", "items": {"enum": ["a"]}}, [LEAK]),
        ("ref-enum", {"$ref": "#/$defs/e", "$defs": {"e": {"enum": ["a"]}}}, LEAK),
        ("number", {"type": "object", "properties": {"n": {"maximum": 1}}}, {"n": 123456789}),
    ]


@pytest.mark.parametrize("case", _schema_cases(), ids=lambda c: c[0])
def test_dict_schema_mismatch_logs_no_reply_value_or_key_but_retry_prompt_has_detail(
    tmp_path, case
):
    _name, schema, value = case
    bad = json.dumps(value)
    t = Fake(a_reply(bad), a_reply(bad))
    p = anth(t, tmp_path, attempts=2)
    with pytest.raises(SchemaValidationError):
        p.complete_json("original prompt", schema)
    logged = all_logged(p)
    assert LEAK not in logged and "123456789" not in logged
    assert {json.loads(x)["outcome"] for x in log_text(p).splitlines()} == {"schema_error"}
    # the retry prompt still carries actionable detail (regression probe)
    retry_prompt = t.calls[1][2]["messages"][0]["content"]
    assert retry_prompt.startswith("original prompt")
    assert "rejected" in retry_prompt and "\n- " in retry_prompt


def test_retry_prompt_keeps_detailed_validation_errors(tmp_path):
    t = Fake(a_reply('{"tag": "zzz", "extra": 1}'), a_reply('{"n": 1}'))
    p = anth(t, tmp_path)
    res = p.complete_json("original prompt", SCHEMA)
    assert res.attempts == 2 and res.value == {"n": 1}
    prompt2 = t.calls[1][2]["messages"][0]["content"]
    assert "missing required property 'n'" in prompt2
    assert "'zzz' is not one of ['a', 'b']" in prompt2
    assert "unexpected property 'extra'" in prompt2
    assert "$.tag" in prompt2
    # and the first request did NOT carry them
    assert "rejected" not in t.calls[0][2]["messages"][0]["content"]
    # system prompt still carries the schema on both calls
    assert '"required"' in t.calls[1][2]["system"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")
    n: int
    d: dict[str, int] = {}


@pytest.mark.parametrize(
    "reply",
    [
        {"n": "x", LEAK: 1},
        {"n": 1, "d": {LEAK: "no"}},
        {"n": 1, "d": {LEAK: LEAK}},
        {"n": LEAK},
    ],
)
def test_pydantic_mismatch_logs_error_types_only(tmp_path, reply):
    t = Fake(a_reply(json.dumps(reply)), a_reply("{}"))
    p = anth(t, tmp_path, attempts=2)
    with pytest.raises(SchemaValidationError):
        p.complete_json("x", Strict)
    assert LEAK not in all_logged(p)
    # but the retry prompt names the field path for the model
    assert "n" in t.calls[1][2]["messages"][0]["content"]


@pytest.mark.parametrize(
    "junk", [LEAK, f'{{"a": "{LEAK}"', f"{LEAK} trailing", f'"{LEAK}', "```json\n" + LEAK + "\n```"]
)
def test_invalid_json_log_has_no_reply_text(tmp_path, junk):
    p = anth(Fake(a_reply(junk), a_reply(junk)), tmp_path, attempts=2)
    with pytest.raises(SchemaValidationError):
        p.complete_json("x", {})
    assert LEAK not in all_logged(p)
    assert {json.loads(x)["outcome"] for x in log_text(p).splitlines()} == {"invalid_json"}


def test_cost_log_record_field_set_is_stable(tmp_path):
    p = anth(Fake(a_reply("{}", model="claude-sonnet-5-5")), tmp_path)
    p.complete_json("x", {})
    rec = json.loads(log_text(p).splitlines()[-1])
    assert set(rec) == {
        "ts", "run_id", "provider", "model", "purpose", "attempt", "outcome",
        "input_tokens", "output_tokens", "cost_usd", "latency_ms", "error",
    }  # fmt: skip


# =========================================================================== D3 / attempt numbering + cost-log regression


def test_cost_log_has_tokens_cost_latency(tmp_path):
    p = anth(Fake(a_reply("{}", inp=1000, out=500)), tmp_path)
    p.complete_json("x", {}, purpose="unit")
    rec = json.loads(log_text(p).splitlines()[-1])
    assert rec["provider"] == "anthropic" and rec["model"] == "claude-sonnet-5-5"
    assert rec["input_tokens"] == 1000 and rec["output_tokens"] == 500
    assert rec["cost_usd"] == pytest.approx(0.007)  # 1000*$2 + 500*$10 per Mtok
    assert isinstance(rec["latency_ms"], int) and rec["latency_ms"] >= 0
    assert rec["outcome"] == "ok" and rec["attempt"] == 1 and rec["purpose"] == "unit"
    assert rec["ts"] and rec["run_id"]
    t = p.cost_log.totals()
    assert t["calls"] == 1 and t["input_tokens"] == 1000 and t["output_tokens"] == 500
    assert t["cost_usd"] == pytest.approx(0.007) and t["cost_complete"] is True


def test_cost_log_openai_override_price_and_unknown_model_null_cost(tmp_path):
    log = CostLog(tmp_path)
    p = OpenAICompatProvider(
        "local-llama", base_url="http://localhost:11434/v1", transport=Fake(o_reply("{}"), o_reply("{}")),
        cost_log=log, price_per_mtok=(1.0, 2.0), retry=RetryPolicy(sleep=lambda s: None),
    )  # fmt: skip
    p.complete("x")
    assert log.records[-1]["cost_usd"] == pytest.approx((7 * 1 + 3 * 2) / 1e6)
    q = oai(Fake(o_reply("{}")), tmp_path)
    q.complete("x")
    assert q.cost_log.records[-1]["cost_usd"] is None
    assert q.cost_log.totals()["cost_complete"] is False


def test_attempt_numbers_contiguous_across_transport_and_schema_retries(tmp_path):
    t = Fake(
        TransportError("HTTP 503", status=503, retryable=True),
        TransportError("HTTP 429", status=429, retryable=True),
        a_reply("not json"),
        TransportError("HTTP 500", status=500, retryable=True),
        a_reply('{"n": 1}'),
    )
    sleeps: list[float] = []
    p = anth(t, tmp_path, attempts=4, sleeps=sleeps)
    res = p.complete_json("x", SCHEMA)
    recs = [json.loads(x) for x in log_text(p).splitlines()]
    assert [r["attempt"] for r in recs] == [1, 2, 3, 4, 5]
    assert [r["outcome"] for r in recs] == [
        "transport_error",
        "transport_error",
        "invalid_json",
        "transport_error",
        "ok",
    ]
    assert res.attempts == 2  # schema attempts, as documented
    assert len(sleeps) == 4  # one backoff after every failed attempt except the last


def test_attempt_numbers_restart_per_call_not_per_provider(tmp_path):
    t = Fake(a_reply("{}"), a_reply("{}"))
    p = anth(t, tmp_path)
    p.complete_json("a", {})
    p.complete_json("b", {})
    assert [r["attempt"] for r in p.cost_log.records] == [1, 1]


def test_complete_attempt_numbers_across_transport_retries(tmp_path):
    t = Fake(TransportError("x", status=503, retryable=True), a_reply("hi"))
    p = anth(t, tmp_path)
    p.complete("x")
    assert [r["attempt"] for r in p.cost_log.records] == [1, 2]
    assert [r["outcome"] for r in p.cost_log.records] == ["transport_error", "ok"]


@pytest.mark.parametrize("n", [1, 2, 3, 5])
def test_request_count_is_bounded(tmp_path, n):
    """Worst case: every send transport-fails n-1 times then returns invalid JSON.
    Documented bound: at most max_attempts**2 HTTP calls (attempts apply per layer)."""
    replies = []
    for _ in range(n):
        replies += [TransportError("x", status=503, retryable=True)] * (n - 1) + [a_reply("nope")]
    t = Fake(*replies)
    p = anth(t, tmp_path, attempts=n)
    with pytest.raises(SchemaValidationError):
        p.complete_json("x", {})
    assert len(t.calls) <= n * n


# =========================================================================== D11 / concurrency


def _hammer(make_log, threads=32, repeats=50):
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        for rep in range(repeats):
            log = make_log(rep)
            barrier = threading.Barrier(threads)
            errors: list[BaseException] = []

            def work(i, log=log, barrier=barrier, errors=errors):
                try:
                    barrier.wait()
                    log.append(provider="x", model="m", attempt=i, outcome="ok", input_tokens=1)
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)

            ts = [threading.Thread(target=work, args=(i,)) for i in range(threads)]
            for t in ts:
                t.start()
            for t in ts:
                t.join()
            assert not errors, errors
            yield rep, log
    finally:
        sys.setswitchinterval(old)


def test_first_append_race_32_threads_x50_root(tmp_path):
    for rep, log in _hammer(lambda rep: CostLog(tmp_path / f"r{rep}")):
        lines = log.path.read_text().splitlines()
        assert len(lines) == 32, f"rep {rep}: {len(lines)} lines"
        assert sorted(json.loads(x)["attempt"] for x in lines) == list(range(32))
        assert len(log.records) == 32


def test_first_append_race_32_threads_x50_base_dir(tmp_path):
    for rep, log in _hammer(lambda rep: CostLog(None, base_dir=tmp_path / f"b{rep}")):
        lines = log.path.read_text().splitlines()
        assert len(lines) == 32, f"rep {rep}: {len(lines)} lines"
        assert len({json.loads(x)["attempt"] for x in lines}) == 32


def test_first_append_race_unwritable_target_warns_once_keeps_all_records(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("not a dir")
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        for _rep, log in _hammer(lambda rep: CostLog(None, base_dir=blocker), repeats=20):
            assert len(log.records) == 32
            assert log.path is None
    assert len(w) == 20  # exactly one warning per log, never zero, never several


def test_shared_provider_race_through_complete(tmp_path):
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        for rep in range(50):
            t = Fake(*[a_reply("hi") for _ in range(32)])
            p = anth(t, tmp_path / f"p{rep}")
            barrier = threading.Barrier(32)
            errors = []

            def work(p=p, barrier=barrier, errors=errors):
                try:
                    barrier.wait()
                    p.complete("x")
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)

            ts = [threading.Thread(target=work) for _ in range(32)]
            for x in ts:
                x.start()
            for x in ts:
                x.join()
            assert not errors, errors
            assert len(p.cost_log.path.read_text().splitlines()) == 32
            assert p.cost_log.totals()["calls"] == 32
    finally:
        sys.setswitchinterval(old)


def test_totals_consistent_while_appending(tmp_path):
    log = CostLog(tmp_path)
    stop = threading.Event()
    bad: list[object] = []

    def writer():
        for i in range(300):
            log.append(
                provider="x",
                model="m",
                attempt=i,
                outcome="ok",
                input_tokens=2,
                output_tokens=1,
                cost_usd=0.5,
            )
        stop.set()

    th = threading.Thread(target=writer)
    th.start()
    while not stop.is_set():
        t = log.totals()
        if t["input_tokens"] != 2 * t["calls"] or t["output_tokens"] != t["calls"]:
            bad.append(t)
    th.join()
    assert not bad


# =========================================================================== swap via config / offline


def test_config_swaps_providers_and_offline_needs_no_key_or_network(tmp_path):
    (tmp_path / "driftwarden.toml").write_text(
        'provider = "openai"\nmodel = "llama3.1"\nbase_url = "http://localhost:11434/v1"\n'
    )
    cfg = load_config(tmp_path)
    assert isinstance(get_provider(cfg, env={}, transport=Fake()), OpenAICompatProvider)
    assert isinstance(
        get_provider(
            Config(provider="anthropic", mode="llm"),
            env={"ANTHROPIC_API_KEY": KEY},
            transport=Fake(),
        ),
        AnthropicProvider,
    )
    off = get_provider(Config(mode="offline"), env={"ANTHROPIC_API_KEY": KEY})
    assert off.offline
    with pytest.raises(LLMError):
        off.complete("x")  # no network attempted: the autouse fixture would have raised OSError
    with pytest.raises(ProviderConfigError) as ei:
        get_provider(Config(mode="llm"), env={})
    assert KEY not in str(ei.value) and "ANTHROPIC_API_KEY" in str(ei.value)


def test_cost_function_totality():
    assert (
        cost_usd("anthropic", "claude-sonnet-5-5", Usage(input_tokens=1_000_000, output_tokens=0))
        == 2.0
    )
    assert cost_usd("openai", "gpt-x", Usage(input_tokens=1)) is None
