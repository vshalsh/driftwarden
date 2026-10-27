"""L-005 system tests (independent, adversarial). No network, no real key.

Tests marked ``xfail(strict=True)`` document DEFECTS found by this suite; they
turn red (XPASS) when the defect is fixed so the marker gets removed.
"""

# ruff: noqa: E501 - xfail reasons are single-line defect descriptions
from __future__ import annotations

import json
import socket
import threading
import warnings
from pathlib import Path

import pytest
from pydantic import BaseModel

from driftwarden.config import ConfigError, load_config
from driftwarden.llm import (
    CostLog,
    OfflineModeError,
    OfflineProvider,
    ProviderConfigError,
    RefusalError,
    RetryPolicy,
    SchemaValidationError,
    TransportError,
    get_provider,
)
from driftwarden.llm.anthropic import AnthropicProvider
from driftwarden.llm.openai_compat import OpenAICompatProvider
from driftwarden.llm.schema import validate_json
from driftwarden.llm.transport import urllib_transport

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


def a_reply(text, inp=10, out=5, stop="end_turn", model="claude-sonnet-5-5"):
    return {
        "id": "msg_1", "type": "message", "model": model, "stop_reason": stop,
        "content": [{"type": "text", "text": text}],
        "usage": {"input_tokens": inp, "output_tokens": out},
    }  # fmt: skip


def o_reply(text, finish="stop", refusal=None):
    msg = {"role": "assistant", "content": text}
    if refusal:
        msg["refusal"] = refusal
    return {"id": "c1", "model": "m", "choices": [{"message": msg, "finish_reason": finish}],
            "usage": {"prompt_tokens": 7, "completion_tokens": 3}}  # fmt: skip


def anth(transport, tmp_path=None, attempts=3, sleeps=None, **kw):
    sl = sleeps if sleeps is not None else []
    log = CostLog(tmp_path) if tmp_path else CostLog(None)
    return AnthropicProvider(
        "claude-sonnet-5-5", api_key=KEY, transport=transport, cost_log=log,
        retry=RetryPolicy(max_attempts=attempts, sleep=sl.append), **kw,
    )  # fmt: skip


def oai(transport, tmp_path=None, attempts=3, sleeps=None, key=OKEY):
    sl = sleeps if sleeps is not None else []
    log = CostLog(tmp_path) if tmp_path else CostLog(None)
    return OpenAICompatProvider(
        "m", api_key=key, base_url="http://localhost:11434/v1", transport=transport,
        cost_log=log, retry=RetryPolicy(max_attempts=attempts, sleep=sl.append),
    )  # fmt: skip


SCHEMA = {
    "type": "object",
    "properties": {"n": {"type": "integer"}, "tag": {"enum": ["a", "b"]}},
    "required": ["n"],
    "additionalProperties": False,
}


class Item(BaseModel):
    n: int
    tag: str = "a"


def log_text(p) -> str:
    return "\n".join(f.read_text() for f in Path(p.cost_log.path).parent.glob("*.jsonl"))


# --------------------------------------------------------------- transport failures


@pytest.mark.parametrize(
    "status,retryable",
    [(429, True), (500, True), (502, True), (503, True), (529, True), (408, True),
     (400, False), (401, False), (403, False), (404, False), (422, False)],
)  # fmt: skip
def test_http_status_retry_classification(monkeypatch, status, retryable):
    import urllib.error

    from driftwarden.llm import transport as tr

    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, status, "x", {}, None)

    monkeypatch.setattr(tr, "_open", fake_urlopen)
    with pytest.raises(TransportError) as ei:
        urllib_transport("https://api.example/v1", {"x-api-key": KEY}, {}, 5)
    assert ei.value.retryable is retryable
    assert ei.value.status == status
    assert KEY not in str(ei.value)


@pytest.mark.parametrize("make", [anth, oai])
def test_429_then_success_retries_with_backoff(make):
    sleeps = []
    t = Fake(TransportError("429", status=429, retryable=True),
             TransportError("503", status=503, retryable=True), None)  # fmt: skip
    prov = make(t, sleeps=sleeps)
    t.replies[2] = a_reply("hi") if make is anth else o_reply("hi")
    assert prov.complete("p").text == "hi"
    assert sleeps == [1.0, 2.0]
    assert len(t.calls) == 3


@pytest.mark.parametrize("make", [anth, oai])
def test_4xx_is_not_retried(make):
    sleeps = []
    t = Fake(TransportError("HTTP 400", status=400, retryable=False))
    with pytest.raises(TransportError):
        make(t, sleeps=sleeps).complete("p")
    assert len(t.calls) == 1 and sleeps == []


def test_timeout_is_retried_then_exhausted_and_bounded():
    sleeps = []
    t = Fake(*[TransportError("timed out", retryable=True)] * 3)
    with pytest.raises(TransportError):
        anth(t, sleeps=sleeps).complete("p")
    assert len(t.calls) == 3
    assert len(sleeps) == 2  # no sleep after the last attempt


def test_backoff_is_capped():
    p = RetryPolicy(max_attempts=10, base_delay=1.0, max_delay=30.0)
    assert [p.delay(i) for i in (1, 2, 3, 6, 7, 50, 1000)] == [1, 2, 4, 30, 30, 30, 30]


def test_backoff_huge_attempt_no_overflow():
    assert RetryPolicy().delay(5000) == 30.0


def test_retry_policy_rejects_zero_attempts():
    with pytest.raises(ValueError):
        RetryPolicy(max_attempts=0)


def test_timeout_passed_to_transport():
    t = Fake(a_reply("x"))
    anth(t, timeout=12.5).complete("p")
    assert t.calls[0][3] == 12.5


def test_transport_error_in_body_anthropic_error_object():
    t = Fake({"type": "error", "error": {"type": "invalid_request_error", "message": "bad"}})
    with pytest.raises(TransportError, match="invalid_request_error"):
        anth(t).complete("p")


def test_malformed_responses_are_transport_errors_not_crashes():
    for bad in ({}, {"content": "str"}, {"content": None}):
        with pytest.raises(TransportError):
            anth(Fake(*[bad] * 3)).complete("p")
    for bad in ({}, {"choices": []}, {"choices": ["x"]}, {"choices": None}):
        with pytest.raises(TransportError):
            oai(Fake(*[bad] * 3)).complete("p")


@pytest.mark.parametrize("usage", [None, {}, {"input_tokens": None, "output_tokens": None}])
def test_missing_usage_counts_as_zero(usage):
    r = a_reply("x")
    r["usage"] = usage
    assert anth(Fake(r)).complete("p").usage.input_tokens == 0


def test_garbage_usage_value_does_not_crash_with_untyped_error():
    r = a_reply("x")
    r["usage"] = {"input_tokens": "lots"}
    try:
        anth(Fake(r)).complete("p")
    except Exception as exc:  # any LLMError is acceptable; a bare ValueError is not
        from driftwarden.llm import LLMError

        assert isinstance(exc, LLMError), f"leaked {type(exc).__name__}: {exc}"


# --------------------------------------------------------------- refusals


def test_anthropic_refusal_not_retried_and_logged(tmp_path):
    t = Fake(a_reply("", stop="refusal"))
    p = anth(t, tmp_path)
    with pytest.raises(RefusalError):
        p.complete_json("p", SCHEMA)
    assert len(t.calls) == 1
    assert json.loads(log_text(p).splitlines()[0])["outcome"] == "refusal"


def test_openai_refusal_not_retried():
    t = Fake(o_reply("", refusal="I can't help"))
    with pytest.raises(RefusalError):
        oai(t).complete_json("p", SCHEMA)
    assert len(t.calls) == 1


def test_openai_refusal_text_not_copied_into_cost_log(tmp_path):
    """Acceptance: cost log never contains replies. A refusal IS model reply text."""
    secret_reply = "REFUSAL-TEXT-FROM-MODEL-ZZZ"
    p = oai(Fake(o_reply("", refusal=secret_reply)), tmp_path)
    with pytest.raises(RefusalError):
        p.complete("p")
    assert secret_reply not in log_text(p)


# --------------------------------------------------------------- JSON handling


def test_invalid_json_then_valid_succeeds_and_feeds_back_errors():
    t = Fake(a_reply("not json at all"), a_reply('{"n": 1}'))
    sleeps = []
    r = anth(t, sleeps=sleeps).complete_json("PROMPT", SCHEMA)
    assert r.value == {"n": 1} and r.attempts == 2
    retry_prompt = t.calls[1][2]["messages"][0]["content"]
    assert retry_prompt.startswith("PROMPT") and "rejected" in retry_prompt
    assert sleeps == [1.0]


@pytest.mark.parametrize(
    "text",
    ['```json\n{"n": 1}\n```', '```\n{"n": 1}\n```', '  ```JSON\n{"n": 1}```  ', '{"n": 1}\n'],
)
def test_code_fenced_json_accepted(text):
    assert anth(Fake(a_reply(text))).complete_json("p", SCHEMA).value == {"n": 1}


def test_prose_around_json_is_rejected_not_guessed():
    t = Fake(*[a_reply('Sure! {"n": 1} hope that helps')] * 3)
    with pytest.raises(SchemaValidationError) as ei:
        anth(t).complete_json("p", SCHEMA)
    assert ei.value.attempts == 3 and len(t.calls) == 3


def test_empty_reply_rejected():
    with pytest.raises(SchemaValidationError):
        anth(Fake(*[a_reply("")] * 3)).complete_json("p", SCHEMA)


def test_schema_mismatch_exhaustion_bounded_exactly():
    t = Fake(*[a_reply('{"n": "x"}')] * 5)
    sleeps = []
    with pytest.raises(SchemaValidationError) as ei:
        anth(t, attempts=4, sleeps=sleeps).complete_json("p", SCHEMA)
    assert len(t.calls) == 4 and ei.value.attempts == 4 and len(sleeps) == 3
    assert ei.value.last_text == '{"n": "x"}'


def test_pydantic_schema_returns_instance_and_rejects_bad():
    r = anth(Fake(a_reply('{"n": 3}'))).complete_json("p", Item)
    assert isinstance(r.value, Item) and r.value.n == 3
    with pytest.raises(SchemaValidationError):
        anth(Fake(*[a_reply('{"n": "zzz"}')] * 3)).complete_json("p", Item)


def test_json_top_level_types_validated():
    arr = {"type": "array", "items": {"type": "integer"}, "minItems": 1}
    assert anth(Fake(a_reply("[1,2]"))).complete_json("p", arr).value == [1, 2]
    with pytest.raises(SchemaValidationError):
        anth(Fake(*[a_reply("[]")] * 3)).complete_json("p", arr)


def test_nan_and_infinity_literals():
    # json.loads accepts NaN; a schema of number should arguably still pass, but
    # must not crash.
    anth(Fake(a_reply('{"n": NaN}'), a_reply('{"n": 1}'))).complete_json("p", SCHEMA)


def test_bool_is_not_integer_and_float_integral_is():
    assert validate_json(True, {"type": "integer"})
    assert not validate_json(2.0, {"type": "integer"})
    assert validate_json(True, {"enum": [1]})
    assert validate_json(1, {"const": True})


def test_ref_schema_resolves_and_enforces():
    schema = {
        "$defs": {
            "P": {"type": "object", "properties": {"x": {"type": "integer"}}, "required": ["x"]}
        },  # fmt: skip
        "type": "object",
        "properties": {"pts": {"type": "array", "items": {"$ref": "#/$defs/P"}}},
        "required": ["pts"],
    }
    ok = anth(Fake(a_reply('{"pts": [{"x": 1}]}'))).complete_json("p", schema)
    assert ok.value["pts"][0]["x"] == 1
    with pytest.raises(SchemaValidationError):
        anth(Fake(*[a_reply('{"pts": [{"x": "no"}]}')] * 3)).complete_json("p", schema)
    with pytest.raises(SchemaValidationError):
        anth(Fake(*[a_reply('{"pts": [{}]}')] * 3)).complete_json("p", schema)


def test_ref_with_siblings_both_enforced():
    s = {"$defs": {"D": {"type": "integer"}}, "$ref": "#/$defs/D", "maximum": 5}
    assert validate_json(3, s) == []
    assert validate_json(9, s)
    assert validate_json("s", s)


def test_pydantic_nested_model_refs_validate():
    class Inner(BaseModel):
        v: int

    class Outer(BaseModel):
        inner: Inner
        many: list[Inner]

    sch = Outer.model_json_schema()
    assert "$defs" in sch
    assert validate_json({"inner": {"v": 1}, "many": [{"v": 2}]}, sch) == []
    assert validate_json({"inner": {"v": "x"}, "many": []}, sch)


def test_dangling_and_remote_ref_reported_not_raised():
    assert validate_json(1, {"$ref": "#/$defs/nope"})
    assert validate_json(1, {"$ref": "http://evil/x.json"})


def test_self_referential_ref_does_not_hang_or_recursion_error():
    # {"$ref": "#"} validates a value against itself forever.
    try:
        validate_json(1, {"$ref": "#"})
    except RecursionError:
        pytest.fail("RecursionError leaked from validate_json on a cyclic $ref")


def test_recursive_tree_schema_ok():
    tree = {"$defs": {"T": {"type": "object", "properties": {
        "kids": {"type": "array", "items": {"$ref": "#/$defs/T"}}}}}, "$ref": "#/$defs/T"}  # fmt: skip
    assert validate_json({"kids": [{"kids": [{}]}]}, tree) == []
    assert validate_json({"kids": [{"kids": 3}]}, tree)


def test_invalid_regex_in_schema_does_not_leak_re_error():
    import re

    try:
        validate_json("x", {"type": "string", "pattern": "("})
    except re.error:
        pytest.fail("re.error leaked from validate_json")


def test_anyof_oneof_allof_basic():
    assert validate_json(1, {"anyOf": [{"type": "string"}, {"type": "integer"}]}) == []
    assert validate_json(1, {"oneOf": [{"type": "integer"}, {"minimum": 0}]})
    assert validate_json(1, {"allOf": [{"minimum": 2}]})


def test_json_mode_request_bodies():
    t = Fake(a_reply('{"n":1}'))
    anth(t, structured_output=True).complete_json("p", SCHEMA)
    assert t.calls[0][2]["output_config"]["format"]["schema"] == SCHEMA
    t2 = Fake(o_reply('{"n":1}'))
    oai(t2).complete_json("p", SCHEMA)
    assert t2.calls[0][2]["response_format"] == {"type": "json_object"}


# --------------------------------------------------------------- secrets


def _all_outputs_for_failure(make, tmp_path, key, errors):
    t = Fake(*errors)
    p = make(t, tmp_path)
    caught = []
    for _ in range(2):
        try:
            p.complete_json("p", SCHEMA)
        except Exception as exc:  # noqa: BLE001
            caught.append(f"{exc!r} {exc}")
        t.replies = list(errors)
    return p, caught


@pytest.mark.parametrize("make,key", [(anth, KEY), (oai, OKEY)])
def test_key_not_in_repr_errors_or_log(tmp_path, make, key):
    errs = [TransportError("HTTP 503", status=503, retryable=True)] * 3
    p, caught = _all_outputs_for_failure(make, tmp_path, key, errs)
    blob = " ".join(caught) + repr(p) + str(vars(p).get("retry", "")) + log_text(p)
    blob += json.dumps(p.cost_log.records)
    assert key not in blob


@pytest.mark.parametrize("make,key", [(anth, KEY), (oai, OKEY)])
def test_key_only_in_auth_header(tmp_path, make, key):
    t = Fake(a_reply('{"n":1}') if make is anth else o_reply('{"n":1}'))
    make(t, tmp_path).complete_json("p", SCHEMA)
    url, headers, body, _ = t[0] if False else t.calls[0]
    assert key not in json.dumps(body) and key not in url
    assert key in json.dumps(headers)


def test_cost_log_has_no_prompt_or_reply_on_success_and_schema_failure(tmp_path):
    prompt = "PROMPT-CANARY-12345"
    reply = '{"n": "REPLY-CANARY-67890"}'
    p = anth(Fake(*[a_reply(reply)] * 3), tmp_path)
    with pytest.raises(SchemaValidationError):
        p.complete_json(prompt, SCHEMA, system="SYSTEM-CANARY", purpose="unit")
    txt = log_text(p)
    assert "PROMPT-CANARY" not in txt and "SYSTEM-CANARY" not in txt
    assert "REPLY-CANARY" not in txt, "reply text leaked into the cost log"


def test_cost_log_enum_mismatch_does_not_echo_reply_value(tmp_path):
    p = anth(Fake(*[a_reply('{"n": 1, "tag": "REPLY-CANARY-ENUM"}')] * 3), tmp_path)
    with pytest.raises(SchemaValidationError):
        p.complete_json("p", SCHEMA)
    assert "REPLY-CANARY-ENUM" not in log_text(p)


def test_cost_log_unexpected_property_name_not_echoed(tmp_path):
    p = anth(Fake(*[a_reply('{"n": 1, "REPLY-CANARY-KEY": 1}')] * 3), tmp_path)
    with pytest.raises(SchemaValidationError):
        p.complete_json("p", SCHEMA)
    assert "REPLY-CANARY-KEY" not in log_text(p)


def test_invalid_json_error_does_not_echo_reply(tmp_path):
    p = anth(Fake(*[a_reply("REPLY-CANARY-NOTJSON")] * 3), tmp_path)
    with pytest.raises(SchemaValidationError):
        p.complete_json("p", SCHEMA)
    assert "REPLY-CANARY" not in log_text(p)


def test_server_error_body_echoing_key_is_not_persisted(tmp_path):
    """A hostile/buggy server can echo the Authorization header in an error body."""
    p = oai(Fake(TransportError(f"HTTP 401 from x: bad key {OKEY}", status=401)), tmp_path)
    with pytest.raises(TransportError):
        p.complete("p")
    assert OKEY not in log_text(p)


def test_cost_log_record_fields_whitelist(tmp_path):
    p = anth(Fake(a_reply('{"n":1}')), tmp_path)
    p.complete_json("p", SCHEMA, purpose="claims")
    rec = json.loads(log_text(p).splitlines()[0])
    allowed = {"ts", "run_id", "provider", "model", "purpose", "attempt", "outcome",
               "input_tokens", "output_tokens", "cost_usd", "latency_ms", "error"}  # fmt: skip
    assert set(rec) <= allowed
    assert rec["input_tokens"] == 10 and rec["output_tokens"] == 5
    assert rec["cost_usd"] == round((10 * 2.0 + 5 * 10.0) / 1e6, 8)


# --------------------------------------------------------------- config & provider choice


def write_cfg(tmp_path, body):
    (tmp_path / "driftwarden.toml").write_text(body)
    return tmp_path


def test_config_rejects_api_key_field_without_echo(tmp_path):
    write_cfg(tmp_path, f'[tool.driftwarden]\napi_key = "{KEY}"\n')
    pyp = tmp_path / "pyproject.toml"
    pyp.write_text(f'[tool.driftwarden]\napi_key = "{KEY}"\n')
    with pytest.raises(ConfigError) as ei:
        load_config(tmp_path)
    assert KEY not in str(ei.value) and "SECRETSECRET" not in str(ei.value)


@pytest.mark.parametrize("pasted", [KEY, "sk-ant-api03-abc", "key with space", "a.b", ""])
def test_api_key_env_rejects_key_shaped_values_without_echo(tmp_path, pasted):
    (tmp_path / "pyproject.toml").write_text(f'[tool.driftwarden]\napi_key_env = "{pasted}"\n')
    with pytest.raises(ConfigError) as ei:
        load_config(tmp_path)
    assert pasted not in str(ei.value) or pasted == ""


def test_api_key_env_pasted_underscore_key_not_echoed():
    from driftwarden.config import Config

    pasted = "gsk_SECRETabcdef0123456789"  # matched the old env-name regex
    # Fixed in L-005 by rejecting it at config validation (without echoing it)...
    with pytest.raises(ValueError) as ei:
        Config(api_key_env=pasted)
    assert pasted not in str(ei.value)
    # ...and, for configs built without validation, by never echoing it.
    cfg = Config.model_construct(api_key_env=pasted)
    prov = get_provider(cfg, env={})
    assert pasted not in repr(prov) and pasted not in getattr(prov, "reason", "")
    cfg2 = Config.model_construct(api_key_env=pasted, mode="llm")
    with pytest.raises((ProviderConfigError, ValueError)) as ei:
        get_provider(cfg2, env={})
    assert pasted not in str(ei.value)


def test_base_url_scheme_validation():
    from pydantic import ValidationError

    from driftwarden.config import Config

    for bad in ("file:///etc/passwd", "ftp://x", "localhost:11434", "javascript:1"):
        with pytest.raises(ValidationError):
            Config(base_url=bad)


def test_base_url_credentials_not_in_transport_errors(monkeypatch):
    import urllib.error

    from driftwarden.llm import transport as tr

    def boom(req, timeout=None):
        raise urllib.error.URLError("refused")

    monkeypatch.setattr(tr, "_open", boom)
    with pytest.raises(TransportError) as ei:
        urllib_transport("https://user:hunter2pw@host.example/v1", {}, {}, 1)
    assert "hunter2pw" not in str(ei.value)


def test_get_provider_mode_matrix(tmp_path):
    from driftwarden.config import Config

    # offline: no key needed, never builds a network provider
    p = get_provider(Config(mode="offline"), tmp_path, env={"ANTHROPIC_API_KEY": KEY})
    assert p.offline and isinstance(p, OfflineProvider)
    # auto without key -> offline with reason
    p = get_provider(Config(mode="auto"), tmp_path, env={})
    assert p.offline and "ANTHROPIC_API_KEY" in p.reason
    # auto with key -> anthropic
    p = get_provider(Config(mode="auto"), tmp_path, env={"ANTHROPIC_API_KEY": KEY})
    assert p.name == "anthropic" and not p.offline
    # llm without key -> error naming the variable, not a value
    with pytest.raises(ProviderConfigError, match="ANTHROPIC_API_KEY"):
        get_provider(Config(mode="llm"), tmp_path, env={})
    # empty-string key counts as missing
    assert get_provider(Config(), tmp_path, env={"ANTHROPIC_API_KEY": ""}).offline
    # openai: needs model
    with pytest.raises(ProviderConfigError, match="model"):
        get_provider(Config(provider="openai", base_url="http://localhost:1/v1"), tmp_path, env={})
    # openai local server needs no key
    p = get_provider(
        Config(provider="openai", model="llama3", base_url="http://localhost:11434/v1"),
        tmp_path, env={},
    )  # fmt: skip
    assert p.name == "openai" and not p.offline
    # openai without base_url and without key in auto -> offline
    assert get_provider(Config(provider="openai", model="m"), tmp_path, env={}).offline
    # custom key env var is honoured
    p = get_provider(Config(api_key_env="MY_KEY"), tmp_path, env={"MY_KEY": KEY})
    assert p.name == "anthropic"


def test_swapping_provider_via_config_changes_endpoint(tmp_path):
    from driftwarden.config import Config

    ta, to = Fake(a_reply('{"n":1}')), Fake(o_reply('{"n":1}'))
    a = get_provider(Config(), tmp_path, env={"ANTHROPIC_API_KEY": KEY}, transport=ta)
    o = get_provider(
        Config(provider="openai", model="m", base_url="http://h:1/v1"), tmp_path,
        env={}, transport=to,
    )  # fmt: skip
    a.complete_json("p", SCHEMA)
    o.complete_json("p", SCHEMA)
    assert ta.calls[0][0].endswith("/v1/messages")
    assert to.calls[0][0] == "http://h:1/v1/chat/completions"
    assert "authorization" not in to.calls[0][1]


def test_config_max_attempts_and_cost_override_flow_through(tmp_path):
    from driftwarden.config import Config

    t = Fake(*[a_reply("bad")] * 10)
    p = get_provider(
        Config(max_attempts=2, input_cost_per_mtok=1.0, output_cost_per_mtok=2.0),
        tmp_path, env={"ANTHROPIC_API_KEY": KEY}, transport=t,
        retry=None,
    )  # fmt: skip
    p.retry.sleep = lambda s: None
    with pytest.raises(SchemaValidationError):
        p.complete_json("p", SCHEMA)
    assert len(t.calls) == 2
    assert p.cost_log.records[0]["cost_usd"] == round((10 * 1 + 5 * 2) / 1e6, 8)


def test_config_bounds():
    from pydantic import ValidationError

    from driftwarden.config import Config

    for kw in ({"max_attempts": 0}, {"max_attempts": 11}, {"timeout_s": 0},
               {"input_cost_per_mtok": -1}, {"mode": "bogus"}, {"provider": "gemini"}):  # fmt: skip
        with pytest.raises(ValidationError):
            Config(**kw)


# --------------------------------------------------------------- compounding retries


def test_total_http_calls_bounded_by_max_attempts_squared_documented():
    """Transport retries nest inside schema retries: worst case max_attempts**2 requests."""
    errs = []
    for _ in range(3):  # each schema attempt: 1 retryable failure then bad json
        errs += [TransportError("503", status=503, retryable=True), a_reply("bad")]
    t = Fake(*errs, *[a_reply("bad")] * 20)
    p = anth(t, attempts=3)
    with pytest.raises(SchemaValidationError):
        p.complete_json("p", SCHEMA)
    assert len(t.calls) <= 9


def test_cost_log_attempt_numbers_monotonic(tmp_path):
    t = Fake(TransportError("503", status=503, retryable=True), a_reply("bad"), a_reply("bad"),
             a_reply('{"n": 1}'))  # fmt: skip
    p = anth(t, tmp_path)
    p.complete_json("p", SCHEMA)
    attempts = [r["attempt"] for r in p.cost_log.records]
    assert attempts == sorted(attempts) and len(set(attempts)) == len(attempts), attempts


def test_complete_after_transport_retries_logs_ok_and_failures(tmp_path):
    t = Fake(TransportError("503", status=503, retryable=True), a_reply("hi"))
    p = anth(t, tmp_path)
    p.complete("p")
    outs = [r["outcome"] for r in p.cost_log.records]
    assert outs == ["transport_error", "ok"]


# --------------------------------------------------------------- offline


def test_offline_raises_offline_mode_error_and_is_logged_free(tmp_path):
    p = OfflineProvider()
    with pytest.raises(OfflineModeError):
        p.complete("x")
    with pytest.raises(OfflineModeError):
        p.complete_json("x", SCHEMA, purpose="claims")
    assert p.offline and p.model == "offline"


def test_offline_error_not_retried_no_sleep():
    sleeps = []
    p = OfflineProvider(retry=RetryPolicy(sleep=sleeps.append))
    with pytest.raises(OfflineModeError):
        p.complete_json("x", SCHEMA)
    assert sleeps == []


def test_offline_responder_goes_through_schema_validation():
    r = OfflineProvider(responder=lambda req: '{"n": 5}').complete_json("p", SCHEMA)
    assert r.value == {"n": 5}
    with pytest.raises(SchemaValidationError):
        OfflineProvider(responder=lambda req: "{}").complete_json("p", SCHEMA)


def test_offline_with_no_env_no_network_no_key_end_to_end(tmp_path, monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    from driftwarden.config import Config

    p = get_provider(Config(mode="offline"), tmp_path)
    assert p.offline
    with pytest.raises(OfflineModeError):
        p.complete("x")


def test_default_transport_under_blocked_sockets_fails_cleanly():
    with pytest.raises(TransportError) as ei:
        urllib_transport("https://api.anthropic.com/v1/messages", {"x-api-key": KEY}, {}, 1)
    assert ei.value.retryable and KEY not in str(ei.value)


def test_real_provider_default_transport_retry_exhaustion_blocked_network(tmp_path):
    sleeps = []
    p = AnthropicProvider(
        api_key=KEY, cost_log=CostLog(tmp_path), retry=RetryPolicy(sleep=sleeps.append)
    )
    with pytest.raises(TransportError):
        p.complete("x")
    assert len(sleeps) == 2 and KEY not in log_text(p)


def test_import_has_no_network_side_effect_in_subprocess():
    import subprocess
    import sys

    code = (
        "import socket\n"
        "def b(*a,**k): raise SystemExit('NETWORK TOUCHED')\n"
        "socket.socket.connect=b; socket.getaddrinfo=b; socket.create_connection=b\n"
        "import driftwarden.llm as m; from driftwarden.config import Config\n"
        "p=m.get_provider(Config(mode='offline'))\nassert p.offline\n"
    )
    r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


# --------------------------------------------------------------- cost log location / fallback


def test_cost_log_location_and_gitignore(tmp_path):
    p = anth(Fake(a_reply("x")), tmp_path)
    p.complete("p")
    path = Path(p.cost_log.path)
    assert path.parent == tmp_path.resolve() / ".driftwarden" / "logs" / "llm"
    assert path.suffix == ".jsonl" and path.exists()
    assert (tmp_path / ".driftwarden" / ".gitignore").exists()
    for line in path.read_text().splitlines():
        json.loads(line)


def test_log_dir_unwritable_falls_back_with_warning(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".driftwarden").write_text("i am a file, so mkdir fails (works even as root)")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    p = anth(Fake(a_reply("x")), repo)
    with pytest.warns(RuntimeWarning, match="cannot write"):
        p.complete("p")
    path = Path(p.cost_log.path)
    assert str(path).startswith(str(tmp_path / "cache"))
    assert path.exists() and not (repo / ".driftwarden").is_dir()


def test_all_log_dirs_unwritable_keeps_memory_and_never_raises(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".driftwarden").write_text("file")
    blocker = tmp_path / "blocker"
    blocker.write_text("file")
    monkeypatch.setenv("XDG_CACHE_HOME", str(blocker))
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(blocker))
    p = anth(Fake(a_reply("x"), a_reply("y")), repo)
    with pytest.warns(RuntimeWarning, match="memory only"):
        p.complete("p")
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # warned once only
        p.complete("p2")
    assert p.cost_log.path is None and len(p.cost_log.records) == 2


def test_log_file_becomes_unwritable_midrun_does_not_abort(tmp_path):
    p = anth(Fake(a_reply("x"), a_reply("y")), tmp_path)
    p.complete("p")
    path = Path(p.cost_log.path)
    path.unlink()
    path.mkdir()  # appending now raises IsADirectoryError (OSError), even as root
    with pytest.warns(RuntimeWarning, match="cannot append"):
        p.complete("q")
    assert len(p.cost_log.records) == 2


def test_totals():
    p = anth(Fake(a_reply("x", 100, 50), a_reply("y", 1, 1)))
    p.complete("a")
    p.complete("b")
    t = p.cost_log.totals()
    assert t["calls"] == 2 and t["input_tokens"] == 101 and t["output_tokens"] == 51
    assert t["cost_complete"] is True


def test_unknown_model_cost_null_not_guessed():
    p = AnthropicProvider("mystery-1", api_key=KEY, transport=Fake(a_reply("x", model="mystery-1")),
                          cost_log=CostLog(None))  # fmt: skip
    p.complete("a")
    assert p.cost_log.records[0]["cost_usd"] is None
    assert p.cost_log.totals()["cost_complete"] is False


def test_cache_tokens_counted_as_input():
    r = a_reply("x")
    r["usage"] = {"input_tokens": 1, "cache_creation_input_tokens": 2, "cache_read_input_tokens": 3,
                  "output_tokens": 4}  # fmt: skip
    assert anth(Fake(r)).complete("p").usage.input_tokens == 6


# --------------------------------------------------------------- concurrency


def test_concurrent_appends_one_log_no_torn_lines(tmp_path):
    log = CostLog(tmp_path)
    assert log.path is not None  # resolve up front
    n_threads, per = 16, 100
    barrier = threading.Barrier(n_threads)

    def work(i):
        barrier.wait()
        for j in range(per):
            log.append(provider="x", model="m", purpose=f"t{i}", attempt=j, outcome="ok",
                       input_tokens=1, output_tokens=1, cost_usd=0.0, latency_ms=1,
                       error="é" * 200)  # fmt: skip

    ts = [threading.Thread(target=work, args=(i,)) for i in range(n_threads)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    lines = Path(log.path).read_text(encoding="utf-8").splitlines()
    assert len(lines) == n_threads * per == len(log.records)
    assert all(json.loads(line)["outcome"] == "ok" for line in lines)


def test_concurrent_first_append_does_not_lose_file_records(tmp_path):
    """First use of .path is lazy and not locked; racing threads must not drop records."""
    lost = 0
    for trial in range(40):
        root = tmp_path / f"r{trial}"
        root.mkdir()
        log = CostLog(root)
        barrier = threading.Barrier(8)

        def work(log=log, barrier=barrier):
            barrier.wait()
            log.append(provider="x", model="m", attempt=1, outcome="ok")

        ts = [threading.Thread(target=work) for _ in range(8)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        files = list((root / ".driftwarden" / "logs" / "llm").glob("*.jsonl"))
        on_disk = sum(len(f.read_text().splitlines()) for f in files)
        lost += 8 - on_disk
    assert lost == 0, f"{lost} records missing from the JSONL file (in memory but not on disk)"


def test_two_logs_same_run_id_interleave_safely(tmp_path):
    a = CostLog(tmp_path, run_id="same")
    b = CostLog(tmp_path, run_id="same")

    def work(log):
        for _ in range(200):
            log.append(provider="x", model="m", attempt=1, outcome="ok", error="x" * 500)

    ts = [threading.Thread(target=work, args=(lg,)) for lg in (a, b)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    lines = Path(a.path).read_text().splitlines()
    assert len(lines) == 400 and all(json.loads(line) for line in lines)


def test_concurrent_providers_distinct_run_ids(tmp_path):
    logs = [CostLog(tmp_path) for _ in range(20)]
    assert len({lg.run_id for lg in logs}) == 20


def test_shared_provider_across_threads(tmp_path):
    class T:
        def __call__(self, url, headers, body, timeout):
            return a_reply('{"n": 1}')

    p = anth(T(), tmp_path)
    errs = []

    def work():
        try:
            for _ in range(25):
                assert p.complete_json("p", SCHEMA).value == {"n": 1}
        except Exception as e:  # noqa: BLE001
            errs.append(e)

    ts = [threading.Thread(target=work) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errs
    assert len(Path(p.cost_log.path).read_text().splitlines()) == 200


# --------------------------------------------------------------- scope hygiene


def test_no_real_sdk_or_secret_in_source_tree():
    import re

    root = Path(__file__).resolve().parent.parent / "src" / "driftwarden" / "llm"
    pat = re.compile(r"sk-(ant|proj)-[A-Za-z0-9_-]{20,}")
    for f in root.glob("*.py"):
        assert not pat.search(f.read_text()), f
