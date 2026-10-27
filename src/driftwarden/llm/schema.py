"""Parse a model's JSON reply and validate it against a schema. No network, no LLM.

A schema is either a Pydantic model class (validated by Pydantic) or a JSON Schema
dict, validated by the small dependency-free validator below. It covers the subset
of JSON Schema that structured-output prompts use, including what Pydantic's
``model_json_schema()`` emits:

    type (string or list), enum, const, properties, required,
    additionalProperties (bool or schema), items (schema), minItems, maxItems,
    uniqueItems, minLength, maxLength, pattern, minimum, maximum,
    exclusiveMinimum, exclusiveMaximum, anyOf, oneOf, allOf, $ref (local "#/...").

Unknown keywords (``format``, ``title``, ``description``, ``default``...) are ignored.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from typing import Any, Literal, NamedTuple, Union

from pydantic import BaseModel, ValidationError

Schema = Union[type[BaseModel], dict[str, Any]]  # noqa: UP007 - runtime alias on 3.10

_FENCE = re.compile(r"\A```[A-Za-z0-9_-]*[ \t]*\n(?P<body>.*?)\n?```\Z", re.DOTALL)
_TOO_DEEP = "nested too deeply"


class JsonSchemaError(ValueError):
    """A reply failed parsing (``kind="json"``) or validation (``kind="schema"``).

    ``errors`` are detailed messages for the model's retry prompt; they may quote
    reply values. ``log_errors`` name only schema locations and error kinds (never
    reply values or reply-chosen keys); they are what the cost log records.
    """

    def __init__(
        self,
        kind: Literal["json", "schema"],
        errors: list[str],
        log_errors: list[str] | None = None,
    ) -> None:
        super().__init__("; ".join(errors))
        self.kind = kind
        self.errors = errors
        self.log_errors = log_errors if log_errors is not None else [kind]


class InvalidSchemaError(ValueError):
    """The caller's schema itself is unusable (bad or cyclic $ref, bad pattern)."""


def schema_dict(schema: Schema) -> dict[str, Any]:
    if isinstance(schema, dict):
        return schema
    if isinstance(schema, type) and issubclass(schema, BaseModel):
        return schema.model_json_schema()
    raise TypeError("schema must be a Pydantic model class or a JSON Schema dict")


def schema_text(schema: dict[str, Any]) -> str:
    return json.dumps(schema, indent=2, sort_keys=True)


def parse_json_reply(text: str) -> Any:
    """Parse ``text`` as JSON. One surrounding Markdown code fence is tolerated."""
    body = text.strip()
    m = _FENCE.match(body)
    if m:
        body = m.group("body").strip()
    if not body:
        raise JsonSchemaError("json", ["reply was empty"], ["empty reply"])
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise JsonSchemaError(
            "json", [f"reply is not valid JSON: {exc}"], [f"not valid JSON ({exc.msg})"]
        ) from exc
    except RecursionError as exc:
        raise JsonSchemaError("json", [f"reply is {_TOO_DEEP}"], [_TOO_DEEP]) from exc


def validate_reply(data: Any, schema: Schema) -> Any:
    """Return the validated value (a model instance for Pydantic schemas)."""
    if isinstance(schema, dict):
        try:
            issues = _validate(data, schema, schema, "$", "#", frozenset())
        except RecursionError as exc:
            raise JsonSchemaError("schema", [f"reply is {_TOO_DEEP}"], [_TOO_DEEP]) from exc
        if issues:
            raise JsonSchemaError(
                "schema",
                [i.message for i in issues],
                sorted({f"{i.schema_path} ({i.keyword})" for i in issues}),
            )
        return data
    try:
        return schema.model_validate(data)
    except RecursionError as exc:
        raise JsonSchemaError("schema", [f"reply is {_TOO_DEEP}"], [_TOO_DEEP]) from exc
    except ValidationError as exc:
        details = exc.errors(include_input=False, include_url=False)
        errors = [f"{'/'.join(str(p) for p in e['loc']) or '(root)'}: {e['msg']}" for e in details]
        # loc can hold reply-chosen keys (extra fields, dict keys): log error types only.
        raise JsonSchemaError("schema", errors, sorted({str(e["type"]) for e in details})) from exc


# --------------------------------------------------------------------------- validator

_TYPES: dict[str, Any] = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "null": type(None),
}


class _Issue(NamedTuple):
    schema_path: str  # built from schema keys only: safe to log
    keyword: str
    message: str  # may quote the instance: for the retry prompt only


def _is_type(value: Any, name: str) -> bool:
    if name == "integer":
        if isinstance(value, bool):
            return False
        return isinstance(value, int) or (isinstance(value, float) and value.is_integer())
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    py = _TYPES.get(name)
    return py is not None and isinstance(value, py)


def _resolve(ref: Any, root: Any) -> Any:
    if not isinstance(ref, str) or not ref.startswith("#"):
        raise InvalidSchemaError(f"only local $ref is supported: {ref!r}")
    node: Any = root
    for part in ref[1:].strip("/").split("/"):
        if not part:
            continue
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            raise InvalidSchemaError(f"unresolvable $ref: {ref}")
        node = node[part]
    if not isinstance(node, (dict, bool)):
        raise InvalidSchemaError(f"$ref does not point at a schema: {ref}")
    return node


@lru_cache(maxsize=256)
def _regex(pattern: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern)
    except Exception as exc:  # noqa: BLE001 - re.error, OverflowError, RecursionError...
        shown = pattern if len(pattern) <= 80 else pattern[:77] + "..."
        raise InvalidSchemaError(
            f"invalid pattern {shown!r}: {type(exc).__name__}: {str(exc)[:120]}"
        ) from None


# ReDoS guard (D15). Python's ``re`` backtracks and has no timeout, and the text
# matched against a caller's ``pattern`` is model output. Patterns with a repeat
# nested inside another repeat (``(a+)+``, ``(\w+\s?)*``) can take exponential
# time; they are only run on strings up to NESTED_REPEAT_MAX_LEN characters, and
# every pattern is only run on strings up to PATTERN_MAX_LEN characters. Longer
# strings fail the pattern with an explicit message (and are retried as usual).
# Residual risk: overlapping alternations (``(a|a)*``) are not detected.
PATTERN_MAX_LEN = 4096
NESTED_REPEAT_MAX_LEN = 20


def _sre_parser():
    try:
        import re._parser as parser  # Python >= 3.11

        return parser
    except ImportError:  # pragma: no cover - Python 3.10
        import sre_parse as parser

        return parser


def _children(av: Any):
    """Sub-sequences of ``(op, av)`` items inside a parsed-regex argument."""
    items = av if isinstance(av, (tuple, list)) else (av,)
    for item in items:
        if hasattr(item, "data"):  # SubPattern
            yield item
        elif isinstance(item, list):
            if item and all(hasattr(x, "data") for x in item):  # BRANCH alternatives
                yield from item
            elif all(isinstance(x, tuple) and len(x) == 2 for x in item):  # IN items
                yield item


def _repeat_ops() -> set[Any]:
    c = _sre_parser()
    return {
        getattr(c, n) for n in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT") if hasattr(c, n)
    }


def _contains_repeat(items: Any, repeats: set[Any]) -> bool:
    for op, av in items:
        if op in repeats and av[0] != av[1]:  # variable-length repeat
            return True
        if any(_contains_repeat(ch, repeats) for ch in _children(av)):
            return True
    return False


def _nested_repeat(items: Any, repeats: set[Any]) -> bool:
    for op, av in items:
        if op in repeats:
            if av[1] > 1 and _contains_repeat(av[2], repeats):
                return True
            if _nested_repeat(av[2], repeats):
                return True
        elif any(_nested_repeat(ch, repeats) for ch in _children(av)):
            return True
    return False


@lru_cache(maxsize=256)
def has_nested_repeat(pattern: str) -> bool:
    """True when ``pattern`` repeats something that itself repeats (ReDoS-prone).

    Anything that cannot be analysed counts as nested (the safe answer).
    """
    try:
        parsed = _sre_parser().parse(pattern)
        return _nested_repeat(parsed.data if hasattr(parsed, "data") else parsed, _repeat_ops())
    except Exception:  # noqa: BLE001 - unknown shapes are treated as risky
        return True


def _pattern_mismatch(pattern: str, value: str) -> str | None:
    """Why ``value`` fails ``pattern`` (None when it matches). Raises InvalidSchemaError."""
    compiled = _regex(pattern)
    limit = NESTED_REPEAT_MAX_LEN if has_nested_repeat(pattern) else PATTERN_MAX_LEN
    if len(value) > limit:
        return (
            f"is longer than {limit} characters, the most this pattern is checked "
            f"against (ReDoS guard): {pattern!r}"
        )
    if compiled.search(value) is None:
        return f"does not match pattern {pattern!r}"
    return None


def _equal(a: Any, b: Any) -> bool:
    # JSON equality: True != 1, 1 == 1.0
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    return a == b


def _walk(schema: Any):
    """Yield every sub-schema dict of ``schema`` (including itself), iteratively."""
    stack = [schema]
    seen: set[int] = set()
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(node)
            continue
        if not isinstance(node, dict) or id(node) in seen:
            continue
        seen.add(id(node))
        yield node
        for key, sub in node.items():
            if key not in ("enum", "const", "default", "examples") and isinstance(
                sub, (dict, list)
            ):
                stack.append(sub)


def check_schema(schema: Any) -> list[str]:
    """Problems with the caller's schema itself (empty list when usable).

    Finds up front what would otherwise only show while validating a reply:
    unresolvable or cyclic ``$ref`` chains and invalid ``pattern`` regexes.
    """
    problems: set[str] = set()
    for node in _walk(schema):
        if "pattern" in node:
            try:
                if not isinstance(node["pattern"], str):
                    raise InvalidSchemaError("pattern must be a string")
                _regex(node["pattern"])
            except InvalidSchemaError as exc:
                problems.add(str(exc))
        if "$ref" in node:
            chain: set[int] = set()
            current: Any = node
            try:
                while isinstance(current, dict) and "$ref" in current:
                    if id(current) in chain:
                        raise InvalidSchemaError(f"cyclic $ref: {node['$ref']}")
                    chain.add(id(current))
                    current = _resolve(current["$ref"], schema)
            except InvalidSchemaError as exc:
                problems.add(str(exc))
    return sorted(problems)


def validate_json(value: Any, schema: Any) -> list[str]:
    """Return a list of human-readable errors (empty when ``value`` is valid).

    Never raises for a bad schema: problems with the schema itself (cyclic $ref,
    invalid pattern...) come back as errors; ``check_schema`` finds them up front.
    """
    try:
        return [i.message for i in _validate(value, schema, schema, "$", "#", frozenset())]
    except RecursionError:
        return [f"$: value or schema is {_TOO_DEEP}"]


def _validate(
    value: Any, schema: Any, root: Any, path: str, spath: str, active: frozenset
) -> list[_Issue]:
    if schema is True or schema == {}:
        return []
    if schema is False:
        return [_Issue(spath, "false", f"{path}: no value allowed here")]
    if not isinstance(schema, dict):
        return [_Issue(spath, "schema", f"{path}: schema is not an object")]
    issues: list[_Issue] = []

    def sub(v: Any, s: Any, p: str, sp: str) -> list[_Issue]:
        return _validate(v, s, root, p, sp, active)

    def add(keyword: str, message: str, where: str | None = None) -> None:
        issues.append(_Issue(where or f"{spath}/{keyword}", keyword, f"{path}: {message}"))

    if "$ref" in schema:
        ref = schema["$ref"]
        # Re-entering the same $ref for the same value without consuming it is a cycle.
        token = (id(schema), id(value))
        if token in active:
            return [_Issue(spath, "$ref", f"{path}: cyclic $ref {ref!r} in schema")]
        try:
            target = _resolve(ref, root)
        except InvalidSchemaError as exc:
            return [_Issue(spath, "$ref", f"{path}: {exc}")]
        issues += _validate(value, target, root, path, str(ref), active | {token})

    t = schema.get("type")
    if t is not None:
        names = [n for n in (t if isinstance(t, list) else [t]) if isinstance(n, str)]
        if not any(_is_type(value, n) for n in names):
            add("type", f"expected {' or '.join(names)}, got {_kind(value)}")
            return issues

    enum = schema.get("enum")
    if isinstance(enum, list) and not any(_equal(value, e) for e in enum):
        add("enum", f"{value!r} is not one of {enum!r}")
    if "const" in schema and not _equal(value, schema["const"]):
        add("const", f"must equal {schema['const']!r}")

    for i, s in enumerate(schema.get("allOf") or []):
        issues += sub(value, s, path, f"{spath}/allOf/{i}")
    if "anyOf" in schema:
        alts = schema["anyOf"] or []
        if not any(not sub(value, s, path, f"{spath}/anyOf/{i}") for i, s in enumerate(alts)):
            add("anyOf", "does not match any allowed alternative (anyOf)")
    if "oneOf" in schema:
        alts = schema["oneOf"] or []
        n = sum(not sub(value, s, path, f"{spath}/oneOf/{i}") for i, s in enumerate(alts))
        if n != 1:
            add("oneOf", f"must match exactly one alternative (oneOf), matched {n}")

    if isinstance(value, dict):
        _validate_object(value, schema, path, spath, sub, add, issues)
    elif isinstance(value, list):
        items = schema.get("items")
        if isinstance(items, dict):
            for i, v in enumerate(value):
                issues += sub(v, items, f"{path}[{i}]", f"{spath}/items")
        if "minItems" in schema and len(value) < schema["minItems"]:
            add("minItems", f"fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            add("maxItems", f"more than {schema['maxItems']} items")
        if schema.get("uniqueItems"):
            seen = [json.dumps(v, sort_keys=True) for v in value]
            if len(seen) != len(set(seen)):
                add("uniqueItems", "items are not unique")
    elif isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            add("minLength", f"shorter than {schema['minLength']} characters")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            add("maxLength", f"longer than {schema['maxLength']} characters")
        if "pattern" in schema:
            try:
                why = _pattern_mismatch(str(schema["pattern"]), value)
            except InvalidSchemaError as exc:
                why = str(exc)
            if why is not None:
                add("pattern", why)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        for key, words in (
            ("minimum", "less than minimum"),
            ("maximum", "greater than maximum"),
            ("exclusiveMinimum", "not greater than"),
            ("exclusiveMaximum", "not less than"),
        ):
            bound = schema.get(key)
            if not isinstance(bound, (int, float)) or isinstance(bound, bool):
                continue
            bad = {
                "minimum": value < bound,
                "maximum": value > bound,
                "exclusiveMinimum": value <= bound,
                "exclusiveMaximum": value >= bound,
            }[key]
            if bad:
                add(key, f"{words} {bound}")
    return issues


def _validate_object(value, schema, path, spath, sub, add, issues) -> None:
    props = schema.get("properties") or {}
    for req in schema.get("required") or []:
        if req not in value:
            # ``req`` comes from the schema, not the reply: safe in the log path.
            add("required", f"missing required property {req!r}", f"{spath}/required/{req}")
    extra = schema.get("additionalProperties", True)
    for k, v in value.items():
        if k in props:
            issues += sub(v, props[k], f"{path}.{k}", f"{spath}/properties/{k}")
        elif extra is False:
            add("additionalProperties", f"unexpected property {k!r}")
        elif isinstance(extra, dict):
            issues += sub(v, extra, f"{path}.{k}", f"{spath}/additionalProperties")


def _kind(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__
