"""L-005: LLM provider layer. No real network and no real API key anywhere in here.

Every test runs with network sockets disabled (``no_network`` fixture, autouse):
providers talk to fake transports, and the one test that uses the real urllib
transport proves it fails cleanly instead of reaching the network.
"""

from __future__ import annotations

import email.message
import io
import json
import socket
import urllib.request
import urllib.response
from pathlib import Path
from typing import Literal

import pytest
from pydantic import BaseModel

from driftwarden.config import Config, ConfigError, load_config
from driftwarden.llm import (
    CostLog,
    OfflineModeError,
    OfflineProvider,
    Provider,
    ProviderConfigError,
    RefusalError,
    RetryPolicy,
    SchemaValidationError,
    TransportError,
    get_provider,
)
from driftwarden.llm.anthropic import API_VERSION, AnthropicProvider
from driftwarden.llm.openai_compat import OpenAICompatProvider
from driftwarden.llm.schema import parse_json_reply, validate_json
from driftwarden.llm.transport import urllib_transport

FAKE_KEY = "test-key-not-a-secret-0123456789"


# ------------------------------------------------------------------ fixtures / fakes


class NetworkBlocked(OSError):
    pass


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Fail any attempt to open a network socket or resolve a host name."""

    def blocked(*_a, **_k):
        raise NetworkBlocked("network access is disabled in tests")

    class BlockedSocket(socket.socket):
        def connect(self, *_a, **_k):
            blocked()

        def connect_ex(self, *_a, **_k):
            blocked()

    monkeypatch.setattr(socket, "socket", BlockedSocket)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


class FakeTransport:
    """Returns queued replies (dicts) or raises queued exceptions, recording each call."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls: list[dict] = []

    def __call__(self, url, headers, body, timeout):
        self.calls.append({"url": url, "headers": headers, "body": body, "timeout": timeout})
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def anthropic_reply(text: str, *, inp: int = 1000, out: int = 500, stop: str = "end_turn"):
    return {
        "id": "msg_test",
        "type": "message",
        "model": "claude-opus-5-5",
        "content": [{"type": "thinking", "thinking": ""}, {"type": "text", "text": text}],
        "stop_reason": stop,
        "usage": {"input_tokens": inp, "output_tokens": out},
    }


def openai_reply(text: str, *, inp: int = 10, out: int = 5):
    return {
        "id": "chatcmpl-test",
        "model": "llama3.1",
        "choices": [{"message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": inp, "completion_tokens": out},
    }


class Sleeps:
    def __init__(self):
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def policy(attempts: int = 3) -> tuple[RetryPolicy, Sleeps]:
    s = Sleeps()
    return RetryPolicy(max_attempts=attempts, base_delay=0.5, max_delay=4.0, sleep=s), s


def anthropic(transport, *, attempts: int = 3, log: CostLog | None = None, **kw):
    retry, sleeps = policy(attempts)
    p = AnthropicProvider(
        api_key=FAKE_KEY, transport=transport, retry=retry, cost_log=log or CostLog(None), **kw
    )
    return p, sleeps


class Finding(BaseModel):
    claim_id: str
    status: Literal["HOLDING", "DRIFTING", "VIOLATED", "UNKNOWN"]
    lines: list[int]


VALID = '{"claim_id": "ADR-0007.c1", "status": "VIOLATED", "lines": [3, 4]}'


# ------------------------------------------------------------------ config wiring


def test_config_defaults_and_toml(tmp_path):
    cfg = Config()
    assert (cfg.provider, cfg.model, cfg.base_url, cfg.api_key_env) == (
        "anthropic",
        None,
        None,
        None,
    )
    assert cfg.max_attempts == 3
    (tmp_path / "driftwarden.toml").write_text(
        'mode = "llm"\nprovider = "openai"\nmodel = "llama3.1"\n'
        'base_url = "http://localhost:11434/v1"\napi_key_env = "MY_LLM_KEY"\nmax_attempts = 5\n'
    )
    cfg = load_config(tmp_path)
    assert (cfg.provider, cfg.model, cfg.api_key_env, cfg.max_attempts) == (
        "openai",
        "llama3.1",
        "MY_LLM_KEY",
        5,
    )


@pytest.mark.parametrize(
    "line",
    [
        'api_key_env = "sk-ant-api03-PASTEDSECRET"',  # the key itself, not a variable name
        'api_key = "sk-ant-api03-PASTEDSECRET"',  # keys can never be stored in config
    ],
)
def test_config_rejects_keys_without_echoing_them(tmp_path, line):
    (tmp_path / "driftwarden.toml").write_text(line + "\n")
    with pytest.raises(ConfigError) as ei:
        load_config(tmp_path)
    assert "PASTEDSECRET" not in str(ei.value)


def test_config_rejects_non_http_base_url():
    with pytest.raises(ValueError):
        Config(base_url="file:///etc/passwd")


# ------------------------------------------------------------------ factory


def test_offline_mode_needs_no_key_and_no_network(tmp_path):
    p = get_provider(Config(mode="offline"), tmp_path, env={"ANTHROPIC_API_KEY": FAKE_KEY})
    assert isinstance(p, OfflineProvider) and isinstance(p, Provider) and p.offline
    with pytest.raises(OfflineModeError, match="claims"):
        p.complete("hello", purpose="claims")
    with pytest.raises(OfflineModeError):
        p.complete_json("hello", Finding)


def test_auto_mode_without_key_falls_back_to_offline(tmp_path):
    p = get_provider(Config(), tmp_path, env={})
    assert p.offline and "ANTHROPIC_API_KEY" in p.reason


def test_auto_mode_with_key_uses_anthropic_default_model(tmp_path):
    p = get_provider(Config(), tmp_path, env={"ANTHROPIC_API_KEY": FAKE_KEY})
    assert isinstance(p, AnthropicProvider) and not p.offline
    assert p.model == "claude-opus-5-5"
    assert FAKE_KEY not in repr(p)


def test_llm_mode_without_key_is_an_error_naming_the_variable(tmp_path):
    with pytest.raises(ProviderConfigError, match="CUSTOM_KEY"):
        get_provider(Config(mode="llm", api_key_env="CUSTOM_KEY"), tmp_path, env={})


def test_custom_key_env_and_model(tmp_path):
    cfg = Config(mode="llm", model="claude-sonnet-5-5", api_key_env="CUSTOM_KEY")
    t = FakeTransport(anthropic_reply("hi"))
    p = get_provider(cfg, tmp_path, env={"CUSTOM_KEY": FAKE_KEY}, transport=t)
    assert p.complete("x").text == "hi"
    assert t.calls[0]["headers"]["x-api-key"] == FAKE_KEY
    assert t.calls[0]["body"]["model"] == "claude-sonnet-5-5"


def test_openai_local_endpoint_needs_no_key(tmp_path):
    cfg = Config(mode="llm", provider="openai", model="llama3.1", base_url="http://h:11434/v1/")
    t = FakeTransport(openai_reply("ok"))
    p = get_provider(cfg, tmp_path, env={}, transport=t)
    assert isinstance(p, OpenAICompatProvider)
    assert p.complete("x").text == "ok"
    assert t.calls[0]["url"] == "http://h:11434/v1/chat/completions"
    assert "authorization" not in t.calls[0]["headers"]


def test_openai_with_key_sends_bearer(tmp_path):
    cfg = Config(mode="llm", provider="openai", model="gpt-x")
    t = FakeTransport(openai_reply("ok"))
    p = get_provider(cfg, tmp_path, env={"OPENAI_API_KEY": FAKE_KEY}, transport=t)
    p.complete("x")
    assert t.calls[0]["url"] == "https://api.openai.com/v1/chat/completions"
    assert t.calls[0]["headers"]["authorization"] == f"Bearer {FAKE_KEY}"


def test_openai_without_model_is_an_error(tmp_path):
    cfg = Config(mode="llm", provider="openai", base_url="http://h/v1")
    with pytest.raises(ProviderConfigError, match="model"):
        get_provider(cfg, tmp_path, env={})


def test_openai_auto_without_key_or_base_url_is_offline(tmp_path):
    p = get_provider(Config(provider="openai", model="m"), tmp_path, env={})
    assert p.offline and "OPENAI_API_KEY" in p.reason


def test_max_attempts_from_config(tmp_path):
    p = get_provider(Config(max_attempts=5), tmp_path, env={"ANTHROPIC_API_KEY": FAKE_KEY})
    assert p.retry.max_attempts == 5


# ------------------------------------------------------------------ request shapes


def test_anthropic_request_shape():
    t = FakeTransport(anthropic_reply(VALID))
    p, _ = anthropic(t)
    res = p.complete_json("Judge this claim.", Finding, system="You are a judge.")
    call = t.calls[0]
    assert call["url"] == "https://api.anthropic.com/v1/messages"
    assert call["headers"] == {"x-api-key": FAKE_KEY, "anthropic-version": API_VERSION}
    body = call["body"]
    assert body["messages"] == [{"role": "user", "content": "Judge this claim."}]
    assert body["system"].startswith("You are a judge.") and '"claim_id"' in body["system"]
    assert "output_config" not in body and "temperature" not in body
    assert isinstance(res.value, Finding) and res.value.status == "VIOLATED"
    assert res.attempts == 1 and res.response.usage.output_tokens == 500


def test_anthropic_native_structured_output_flag():
    t = FakeTransport(anthropic_reply(VALID))
    p, _ = anthropic(t, structured_output=True)
    p.complete_json("x", Finding)
    fmt = t.calls[0]["body"]["output_config"]["format"]
    assert fmt["type"] == "json_schema" and "claim_id" in fmt["schema"]["properties"]


def test_openai_json_mode():
    t = FakeTransport(openai_reply(VALID))
    p = OpenAICompatProvider("m", base_url="http://h/v1", transport=t, cost_log=CostLog(None))
    res = p.complete_json("x", Finding, system="sys")
    body = t.calls[0]["body"]
    assert body["response_format"] == {"type": "json_object"}
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    assert res.value.claim_id == "ADR-0007.c1"


def test_refusal_is_not_retried():
    t = FakeTransport(anthropic_reply("", stop="refusal"), anthropic_reply(VALID))
    p, sleeps = anthropic(t)
    with pytest.raises(RefusalError):
        p.complete_json("x", Finding)
    assert len(t.calls) == 1 and sleeps.calls == []


# ------------------------------------------------------------------ retries + validation


def test_invalid_json_is_retried_with_feedback_then_succeeds():
    t = FakeTransport(anthropic_reply("Sure! Here you go: {oops"), anthropic_reply(VALID))
    p, sleeps = anthropic(t)
    res = p.complete_json("Judge.", Finding)
    assert res.attempts == 2 and res.value.lines == [3, 4]
    assert sleeps.calls == [0.5]
    second = t.calls[1]["body"]["messages"][0]["content"]
    assert second.startswith("Judge.") and "not valid JSON" in second


def test_schema_mismatch_is_retried_then_succeeds():
    bad = '{"claim_id": "ADR-0007.c1", "status": "MAYBE", "lines": [3]}'
    t = FakeTransport(anthropic_reply(bad), anthropic_reply(VALID))
    p, sleeps = anthropic(t)
    res = p.complete_json("Judge.", Finding)
    assert res.attempts == 2 and sleeps.calls == [0.5]
    assert "status" in t.calls[1]["body"]["messages"][0]["content"]


def test_retries_are_bounded_and_backoff_grows():
    t = FakeTransport(*[anthropic_reply("nope") for _ in range(4)])
    p, sleeps = anthropic(t, attempts=4)
    with pytest.raises(SchemaValidationError) as ei:
        p.complete_json("x", Finding)
    assert ei.value.attempts == 4 and ei.value.last_text == "nope"
    assert len(t.calls) == 4 and sleeps.calls == [0.5, 1.0, 2.0]


def test_backoff_is_capped():
    retry = RetryPolicy(max_attempts=10, base_delay=1.0, max_delay=4.0)
    assert [retry.delay(n) for n in range(1, 6)] == [1.0, 2.0, 4.0, 4.0, 4.0]
    with pytest.raises(ValueError):
        RetryPolicy(max_attempts=0)


def test_retryable_transport_error_is_retried():
    t = FakeTransport(
        TransportError("HTTP 429", status=429, retryable=True), anthropic_reply(VALID)
    )
    p, sleeps = anthropic(t)
    assert p.complete_json("x", Finding).attempts == 1
    assert len(t.calls) == 2 and sleeps.calls == [0.5]


def test_client_error_is_not_retried():
    t = FakeTransport(TransportError("HTTP 400", status=400, retryable=False))
    p, sleeps = anthropic(t)
    with pytest.raises(TransportError):
        p.complete("x")
    assert len(t.calls) == 1 and sleeps.calls == []


def test_server_errors_exhaust_attempts():
    t = FakeTransport(*[TransportError("HTTP 503", status=503, retryable=True)] * 3)
    p, sleeps = anthropic(t)
    with pytest.raises(TransportError):
        p.complete("x")
    assert len(t.calls) == 3 and sleeps.calls == [0.5, 1.0]


def test_json_schema_dict_and_fenced_reply():
    schema = {
        "type": "object",
        "properties": {"ok": {"type": "boolean"}, "n": {"type": "integer", "minimum": 0}},
        "required": ["ok", "n"],
        "additionalProperties": False,
    }
    t = FakeTransport(
        anthropic_reply('{"ok": 1, "n": 2}'),  # 1 is not a boolean
        anthropic_reply('```json\n{"ok": true, "n": 2}\n```'),
    )
    p, _ = anthropic(t)
    res = p.complete_json("x", schema)
    assert res.value == {"ok": True, "n": 2} and res.attempts == 2


def test_offline_responder_goes_through_validation_and_retries():
    replies = iter(["not json", VALID])
    retry, sleeps = policy()
    p = OfflineProvider(responder=lambda req: next(replies), retry=retry, cost_log=CostLog(None))
    res = p.complete_json("x", Finding)
    assert res.attempts == 2 and res.value.status == "VIOLATED" and sleeps.calls == [0.5]


# ------------------------------------------------------------------ schema validator


def test_validator_handles_pydantic_refs_and_nullable():
    class Ref(BaseModel):
        path: str
        line: int

    class Out(BaseModel):
        refs: list[Ref]
        note: str | None = None

    schema = Out.model_json_schema()
    assert validate_json({"refs": [{"path": "a.py", "line": 3}], "note": None}, schema) == []
    errs = validate_json({"refs": [{"path": "a.py", "line": "3"}], "note": 5}, schema)
    assert any("refs[0].line" in e for e in errs) and any("note" in e for e in errs)


@pytest.mark.parametrize(
    ("value", "schema", "ok"),
    [
        (True, {"type": "integer"}, False),
        (3.0, {"type": "integer"}, True),
        ("b", {"enum": ["a", "b"]}, True),
        ("c", {"enum": ["a", "b"]}, False),
        ([1, 1], {"type": "array", "uniqueItems": True}, False),
        ([], {"type": "array", "minItems": 1}, False),
        ("abc", {"type": "string", "pattern": "^a", "maxLength": 3}, True),
        ({"x": 1}, {"type": "object", "additionalProperties": {"type": "string"}}, False),
        (5, {"oneOf": [{"type": "integer"}, {"type": "number"}]}, False),
        (None, {"anyOf": [{"type": "string"}, {"type": "null"}]}, True),
        (1, {"$ref": "#/$defs/missing"}, False),
    ],
)
def test_validator_keywords(value, schema, ok):
    assert (validate_json(value, schema) == []) is ok


def test_parse_json_reply_rejects_prose_and_empty():
    for text in ("", "   ", "Here is the JSON: {}", "{} trailing"):
        with pytest.raises(ValueError):
            parse_json_reply(text)
    assert parse_json_reply("```\n[1, 2]\n```") == [1, 2]


# ------------------------------------------------------------------ cost log


def _llm_logs(base: Path) -> list[Path]:
    return sorted(base.glob(".driftwarden/logs/llm/*.jsonl"))


def test_cost_log_written_under_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    t = FakeTransport(anthropic_reply("{oops"), anthropic_reply(VALID, inp=1000, out=500))
    p = get_provider(
        Config(), repo, env={"ANTHROPIC_API_KEY": FAKE_KEY}, transport=t,
        retry=RetryPolicy(sleep=lambda s: None),
    )  # fmt: skip
    p.complete_json("SECRET-PROMPT-TEXT", Finding, purpose="judge")
    (log,) = _llm_logs(repo)
    lines = [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines()]
    assert [r["outcome"] for r in lines] == ["invalid_json", "ok"]
    last = lines[-1]
    assert last["provider"] == "anthropic" and last["model"] == "claude-opus-5-5"
    assert last["purpose"] == "judge" and last["attempt"] == 2
    assert (last["input_tokens"], last["output_tokens"]) == (1000, 500)
    # claude-opus-5-5: $4 / $20 per MTok
    assert last["cost_usd"] == pytest.approx(0.014)
    raw = log.read_text(encoding="utf-8")
    assert "SECRET-PROMPT-TEXT" not in raw and FAKE_KEY not in raw
    assert (repo / ".driftwarden" / ".gitignore").read_text().endswith("*\n")
    totals = p.cost_log.totals()
    assert totals["calls"] == 2 and totals["input_tokens"] == 2000


def test_cost_log_price_override_and_unknown_model(tmp_path):
    cfg = Config(
        mode="llm", provider="openai", model="m", base_url="http://h/v1",
        input_cost_per_mtok=1.0, output_cost_per_mtok=2.0,
    )  # fmt: skip
    t = FakeTransport(openai_reply("x", inp=1000, out=1000))
    p = get_provider(cfg, tmp_path, env={}, transport=t)
    p.complete("x")
    assert p.cost_log.records[-1]["cost_usd"] == pytest.approx(0.003)
    cfg2 = Config(mode="llm", provider="openai", model="m", base_url="http://h/v1")
    p2 = get_provider(cfg2, tmp_path, env={}, transport=FakeTransport(openai_reply("x")))
    p2.complete("x")
    assert p2.cost_log.records[-1]["cost_usd"] is None
    assert p2.cost_log.totals()["cost_usd"] is None


def _deny(monkeypatch, *bases: Path) -> None:
    import driftwarden.llm.costlog as cl

    real = cl._writable
    denied = {b.resolve() for b in bases}
    monkeypatch.setattr(cl, "_writable", lambda b: b.resolve() not in denied and real(b))


def test_cost_log_falls_back_when_repo_dir_unwritable(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    cache = tmp_path / "cache"
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache))
    _deny(monkeypatch, repo / ".driftwarden")
    log = CostLog(repo)
    with pytest.warns(RuntimeWarning, match="cannot write"):
        log.append(provider="x", input_tokens=1)
    assert list(cache.glob("driftwarden/*/logs/llm/*.jsonl"))
    assert not _llm_logs(repo)


def test_cost_log_nothing_writable_keeps_records_in_memory(tmp_path, monkeypatch):
    import driftwarden.llm.costlog as cl

    monkeypatch.setattr(cl, "_writable", lambda b: False)
    log = CostLog(tmp_path)
    with pytest.warns(RuntimeWarning, match="memory only"):
        log.append(provider="x")
    log.append(provider="y")  # warns once only; no exception
    assert log.path is None and len(log.records) == 2


# ------------------------------------------------------------------ no network


def test_real_transport_cannot_reach_network(tmp_path):
    """With sockets disabled, the real urllib transport fails as a retryable TransportError."""
    with pytest.raises(TransportError) as ei:
        urllib_transport("https://api.anthropic.com/v1/messages", {"x-api-key": FAKE_KEY}, {}, 1)
    assert ei.value.retryable and FAKE_KEY not in str(ei.value)
    p = AnthropicProvider(
        api_key=FAKE_KEY,
        retry=RetryPolicy(max_attempts=2, sleep=lambda s: None),
        cost_log=CostLog(tmp_path),
    )
    with pytest.raises(TransportError):
        p.complete("x")
    assert [r["outcome"] for r in p.cost_log.records] == ["transport_error"] * 2


def test_non_http_base_url_rejected():
    with pytest.raises(ValueError):
        AnthropicProvider(api_key=FAKE_KEY, base_url="file:///etc/passwd")


# ------------------------------------------------------------------ review fixes (D1-D11)


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "string", "pattern": "("},
        {"$ref": "#"},
        {"$defs": {"A": {"$ref": "#/$defs/B"}, "B": {"$ref": "#/$defs/A"}}, "$ref": "#/$defs/A"},
        {"$ref": "#/$defs/missing"},
    ],
)
def test_unusable_caller_schema_is_a_config_error_before_any_call(schema):
    t = FakeTransport()
    p, _ = anthropic(t)
    with pytest.raises(ProviderConfigError, match="invalid JSON schema"):
        p.complete_json("x", schema)
    assert t.calls == []


def test_schema_error_log_names_schema_locations_only(tmp_path):
    t = FakeTransport(*[anthropic_reply('{"claim_id": "X", "status": "LEAKY", "lines": []}')] * 2)
    p, _ = anthropic(t, attempts=2, log=CostLog(tmp_path))
    with pytest.raises(SchemaValidationError):
        p.complete_json("x", Finding)
    rec = p.cost_log.records[0]
    assert rec["outcome"] == "schema_error" and rec["error"] == "literal_error"
    assert "LEAKY" not in p.cost_log.path.read_text(encoding="utf-8")


def test_key_echoed_by_server_is_redacted_from_raised_error():
    t = FakeTransport(TransportError(f"HTTP 401: bad key {FAKE_KEY}", status=401))
    p, _ = anthropic(t)
    with pytest.raises(TransportError) as ei:
        p.complete("x")
    assert FAKE_KEY not in str(ei.value) and ei.value.status == 401


def test_base_url_userinfo_not_in_repr():
    p = OpenAICompatProvider(
        "m", base_url="https://u:pw-secret@h.example/v1", cost_log=CostLog(None)
    )
    assert "pw-secret" not in repr(p)


@pytest.mark.parametrize("name", ["ANTHROPIC_API_KEY", "MY_LLM_KEY", "AZURE_OPENAI_API_KEY", "X"])
def test_conventional_env_names_accepted(name):
    assert Config(api_key_env=name).api_key_env == name


@pytest.mark.parametrize(
    "pasted", ["gsk_SECRETabcdef0123456789", "AKIAIOSFODNN7EXAMPLE", "A" * 65, "lower_case"]
)
def test_key_shaped_env_names_rejected(pasted):
    with pytest.raises(ValueError) as ei:
        Config(api_key_env=pasted)
    assert pasted not in str(ei.value)


def test_backoff_huge_attempt_is_capped():
    assert RetryPolicy(max_delay=7.0).delay(10**6) == 7.0


@pytest.mark.parametrize(
    ("pattern", "nested"),
    [
        ("^(a+)+$", True),
        ("(a?)+", True),
        ("(x|y+)*", True),
        ("^[a-z]+-[0-9]{2}$", False),
        ("^(ab)+$", False),
        ("([a-z]{3})+", False),
    ],
)
def test_nested_repeat_detection(pattern, nested):
    from driftwarden.llm.schema import has_nested_repeat

    assert has_nested_repeat(pattern) is nested


def test_redos_prone_pattern_is_bounded_not_run_on_long_text():
    schema = {"type": "string", "pattern": "^(a+)+$"}
    assert validate_json("a" * 10, schema) == []
    (err,) = validate_json("a" * 40 + "!", schema)
    assert "ReDoS guard" in err


# ------------------------------------------------------------------ Codex review (PR #12)


class _Redirecting(urllib.request.BaseHandler):
    """Fake http(s) handler: every request is answered with a 302 to ``target``."""

    handler_order = 200  # before urllib's real HTTP(S)Handler (500)

    def __init__(self, target: str) -> None:
        self.target = target
        self.requests: list[urllib.request.Request] = []

    def _answer(self, req):
        self.requests.append(req)
        hdrs = email.message.Message()
        hdrs["Location"] = self.target
        resp = urllib.response.addinfourl(io.BytesIO(b""), hdrs, req.full_url, 302)
        resp.msg = "Found"
        return resp

    https_open = http_open = _answer


@pytest.mark.parametrize(
    "target", ["http://api.example.com/v1/x", "https://evil.example.net/steal", "/same/origin"]
)
def test_redirects_are_refused_and_credentials_never_resent(monkeypatch, target):
    import driftwarden.llm.transport as tr

    fake = _Redirecting(target)
    monkeypatch.setattr(tr, "_OPENER", urllib.request.build_opener(tr._RefuseRedirects, fake))
    with pytest.raises(TransportError) as ei:
        urllib_transport("https://api.example.com/v1/x", {"x-api-key": FAKE_KEY}, {}, 1)
    assert ei.value.status == 302 and not ei.value.retryable
    assert "redirect" in str(ei.value) and FAKE_KEY not in str(ei.value)
    assert len(fake.requests) == 1  # the redirect target was never contacted


def test_default_opener_refuses_redirects():
    import driftwarden.llm.transport as tr

    handlers = [type(h) for h in tr._OPENER.handlers]
    assert tr._RefuseRedirects in handlers
    assert urllib.request.HTTPRedirectHandler not in handlers


@pytest.mark.parametrize(
    "props",
    [
        {"pattern": {"type": "string"}, "$ref": {"type": "integer"}},
        {"pattern": {"type": "string", "pattern": "^[a-z]+$"}},
    ],
)
def test_property_names_that_are_keywords_are_not_schemas(props):
    from driftwarden.llm.schema import check_schema

    schema = {"type": "object", "properties": props, "required": list(props)}
    assert check_schema(schema) == []
    assert validate_json({k: ("abc" if k == "pattern" else 1) for k in props}, schema) == []


def test_pydantic_field_named_pattern():
    class Rule(BaseModel):
        pattern: str
        ref: int

    t = FakeTransport(anthropic_reply('{"pattern": "a.*", "ref": 1}'))
    p, _ = anthropic(t)
    assert p.complete_json("x", Rule).value.pattern == "a.*"


def test_nested_schemas_still_checked():
    from driftwarden.llm.schema import check_schema

    bad = {"type": "string", "pattern": "("}
    for schema in (
        {"properties": {"a": bad}},
        {"items": bad},
        {"anyOf": [bad]},
        {"$defs": {"X": bad}},
        {"not": bad},
        {"prefixItems": [bad]},
    ):
        assert check_schema(schema), schema


@pytest.mark.parametrize("text", ["NaN", "[Infinity]", '{"n": -Infinity}', "1e999", "[-1e400]"])
def test_non_finite_numbers_are_invalid_json_and_retried(text):
    with pytest.raises(ValueError, match="non-finite|out of range"):
        parse_json_reply(text)
    t = FakeTransport(anthropic_reply(text), anthropic_reply('{"n": 1}'))
    p, _ = anthropic(t)
    res = p.complete_json("x", {"type": "object"})
    assert res.attempts == 2 and res.value == {"n": 1}


@pytest.mark.parametrize(
    ("value", "schema", "ok"),
    [
        ([1], {"enum": [[True]]}, False),
        ([True], {"const": [True]}, True),
        ({"a": 1}, {"const": {"a": True}}, False),
        ({"a": 1.0}, {"const": {"a": 1}}, True),
        ([1, 2], {"enum": [[1]]}, False),
        ([], {"type": "array", "items": False}, True),
        ([1], {"type": "array", "items": False}, False),
        ([1], {"type": "array", "items": True}, True),
    ],
)
def test_nested_json_equality_and_boolean_items(value, schema, ok):
    assert (validate_json(value, schema) == []) is ok


# ------------------------------------------------------------------ Codex review round 2


@pytest.mark.parametrize("text", ["9" * 5000, '{"n": ' + "1" * 5000 + "}"])
def test_overlong_integer_is_invalid_json_and_retried(text):
    with pytest.raises(ValueError) as ei:
        parse_json_reply(text)
    assert type(ei.value).__name__ == "JsonSchemaError" and ei.value.kind == "json"
    t = FakeTransport(anthropic_reply(text), anthropic_reply('{"n": 1}'))
    p, _ = anthropic(t)
    assert p.complete_json("x", {"type": "object"}).attempts == 2


def test_json_pointer_keeps_empty_tokens_and_escapes():
    defs = {"": {"type": "integer"}, "a/b": {"type": "string"}, "~x": {"type": "boolean"}}
    root = {"$defs": defs, "alts": [{"type": "number"}]}
    cases = [
        ("#/$defs/", 1, "x"),  # member named "" -- not $defs itself
        ("#/$defs/a~1b", "s", 1),
        ("#/$defs/~0x", True, 1),
        ("#/%24defs/a~1b", "s", 1),  # percent-decoded fragment
        ("#/alts/0", 1.5, "x"),  # array index
    ]
    for ref, good, bad in cases:
        schema = {**root, "$ref": ref}
        assert validate_json(good, schema) == [], ref
        assert validate_json(bad, schema) != [], ref
    # "#" is the root itself; "#/" is the root's member named "".
    assert validate_json(1, {"$ref": "#/", "": {"type": "string"}}) != []
    assert validate_json("s", {"$ref": "#/", "": {"type": "string"}}) == []


@pytest.mark.parametrize("ref", ["#/$defs//", "#/$defs/missing", "#/allOf/5", "#$defs", "#/x/01"])
def test_bad_json_pointers_are_config_errors(ref):
    from driftwarden.llm.schema import check_schema

    schema = {"$defs": {"": {"type": "integer"}}, "allOf": [{}], "x": [{}, {}], "$ref": ref}
    assert check_schema(schema)


def test_refusal_logs_billed_usage_and_model(tmp_path):
    reply = anthropic_reply("", inp=1200, out=30, stop="refusal")
    reply["model"] = "claude-sonnet-5-5"
    p, sleeps = anthropic(FakeTransport(reply), log=CostLog(tmp_path))
    with pytest.raises(RefusalError) as ei:
        p.complete("x")
    assert ei.value.usage.input_tokens == 1200 and ei.value.model == "claude-sonnet-5-5"
    (rec,) = p.cost_log.records
    assert rec["outcome"] == "refusal" and rec["model"] == "claude-sonnet-5-5"
    assert (rec["input_tokens"], rec["output_tokens"]) == (1200, 30)
    assert rec["cost_usd"] == pytest.approx((1200 * 2.0 + 30 * 10.0) / 1e6)
    assert sleeps.calls == []


def test_openai_refusal_logs_usage_but_not_text(tmp_path):
    reply = openai_reply("", inp=40, out=6)
    reply["choices"][0]["message"]["refusal"] = "REFUSAL-CANARY"
    p = OpenAICompatProvider(
        "m", base_url="http://h/v1", transport=FakeTransport(reply), cost_log=CostLog(tmp_path)
    )
    with pytest.raises(RefusalError):
        p.complete("x")
    (rec,) = p.cost_log.records
    assert (rec["input_tokens"], rec["output_tokens"]) == (40, 6)
    assert "REFUSAL-CANARY" not in p.cost_log.path.read_text(encoding="utf-8")
