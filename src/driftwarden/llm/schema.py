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
from typing import Any, Literal, Union

from pydantic import BaseModel, ValidationError

Schema = Union[type[BaseModel], dict[str, Any]]  # noqa: UP007 - runtime alias on 3.10

_FENCE = re.compile(r"\A```[A-Za-z0-9_-]*[ \t]*\n(?P<body>.*?)\n?```\Z", re.DOTALL)


class JsonSchemaError(ValueError):
    def __init__(self, kind: Literal["json", "schema"], errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.kind = kind
        self.errors = errors


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
        raise JsonSchemaError("json", ["reply was empty"])
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise JsonSchemaError("json", [f"reply is not valid JSON: {exc}"]) from exc


def validate_reply(data: Any, schema: Schema) -> Any:
    """Return the validated value (a model instance for Pydantic schemas)."""
    if isinstance(schema, dict):
        errors = validate_json(data, schema)
        if errors:
            raise JsonSchemaError("schema", errors)
        return data
    try:
        return schema.model_validate(data)
    except ValidationError as exc:
        errors = [
            f"{'/'.join(str(p) for p in e['loc']) or '(root)'}: {e['msg']}" for e in exc.errors()
        ]
        raise JsonSchemaError("schema", errors) from exc


# --------------------------------------------------------------------------- validator

_TYPES: dict[str, Any] = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "null": type(None),
}


def _is_type(value: Any, name: str) -> bool:
    if name == "integer":
        if isinstance(value, bool):
            return False
        return isinstance(value, int) or (isinstance(value, float) and value.is_integer())
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    py = _TYPES.get(name)
    return py is not None and isinstance(value, py)


def _resolve(ref: str, root: dict[str, Any]) -> dict[str, Any]:
    if not ref.startswith("#"):
        raise ValueError(f"only local $ref is supported: {ref}")
    node: Any = root
    for part in ref.lstrip("#").strip("/").split("/"):
        if not part:
            continue
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            raise ValueError(f"unresolvable $ref: {ref}")
        node = node[part]
    if not isinstance(node, dict):
        raise ValueError(f"$ref does not point at a schema: {ref}")
    return node


def _equal(a: Any, b: Any) -> bool:
    # JSON equality: True != 1, 1 == 1.0
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    return a == b


def validate_json(value: Any, schema: dict[str, Any], *, _root: Any = None, _path: str = "$"):
    """Return a list of human-readable errors (empty when ``value`` is valid)."""
    root = schema if _root is None else _root
    errors: list[str] = []
    if schema is True or schema == {}:
        return errors
    if schema is False:
        return [f"{_path}: no value allowed here"]

    if "$ref" in schema:
        try:
            target = _resolve(schema["$ref"], root)
        except ValueError as exc:
            return [f"{_path}: {exc}"]
        errors += validate_json(value, target, _root=root, _path=_path)

    t = schema.get("type")
    if t is not None:
        names = t if isinstance(t, list) else [t]
        if not any(_is_type(value, n) for n in names):
            return errors + [f"{_path}: expected {' or '.join(names)}, got {_kind(value)}"]

    if "enum" in schema and not any(_equal(value, e) for e in schema["enum"]):
        errors.append(f"{_path}: {value!r} is not one of {schema['enum']!r}")
    if "const" in schema and not _equal(value, schema["const"]):
        errors.append(f"{_path}: must equal {schema['const']!r}")

    for key in ("allOf",):
        for sub in schema.get(key, []):
            errors += validate_json(value, sub, _root=root, _path=_path)
    if "anyOf" in schema:
        if not any(not validate_json(value, s, _root=root, _path=_path) for s in schema["anyOf"]):
            errors.append(f"{_path}: does not match any allowed alternative (anyOf)")
    if "oneOf" in schema:
        n = sum(not validate_json(value, s, _root=root, _path=_path) for s in schema["oneOf"])
        if n != 1:
            errors.append(f"{_path}: must match exactly one alternative (oneOf), matched {n}")

    if isinstance(value, dict):
        props = schema.get("properties", {})
        for req in schema.get("required", []):
            if req not in value:
                errors.append(f"{_path}: missing required property {req!r}")
        extra = schema.get("additionalProperties", True)
        for k, v in value.items():
            sub_path = f"{_path}.{k}"
            if k in props:
                errors += validate_json(v, props[k], _root=root, _path=sub_path)
            elif extra is False:
                errors.append(f"{_path}: unexpected property {k!r}")
            elif isinstance(extra, dict):
                errors += validate_json(v, extra, _root=root, _path=sub_path)
    elif isinstance(value, list):
        items = schema.get("items")
        if isinstance(items, dict):
            for i, v in enumerate(value):
                errors += validate_json(v, items, _root=root, _path=f"{_path}[{i}]")
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{_path}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{_path}: more than {schema['maxItems']} items")
        if schema.get("uniqueItems"):
            seen = [json.dumps(v, sort_keys=True) for v in value]
            if len(seen) != len(set(seen)):
                errors.append(f"{_path}: items are not unique")
    elif isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{_path}: shorter than {schema['minLength']} characters")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{_path}: longer than {schema['maxLength']} characters")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            errors.append(f"{_path}: does not match pattern {schema['pattern']!r}")
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{_path}: less than minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{_path}: greater than maximum {schema['maximum']}")
        if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
            errors.append(f"{_path}: not greater than {schema['exclusiveMinimum']}")
        if "exclusiveMaximum" in schema and value >= schema["exclusiveMaximum"]:
            errors.append(f"{_path}: not less than {schema['exclusiveMaximum']}")
    return errors


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
