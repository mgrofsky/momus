"""JSON answers: extracting one object from model text, validating it against a schema, and the wire form of a schema.

The schemas this project sends are written in one small dialect that all four providers' structured-output features
accept: the root is an object; every object lists all its properties as required and sets additionalProperties
false; types are object, array, string, integer, boolean; enum on strings; no union types, no null, no anyOf, no
numeric or length bounds on the wire. Bounds (maxLength, maxItems, minItems, minimum, maximum, pattern) are written
in the same schema but are enforced here, by validate(), and removed by wire() before the schema is sent: some
providers refuse them (see docs/analyst.md). test_every_outgoing_schema_is_in_the_common_dialect walks every schema
the loop sends."""
import json
import re

MAX_ANSWER_CHARS = 200000
MAX_DEPTH = 20
LOCAL_ONLY = ("maxLength", "minLength", "maxItems", "minItems", "minimum", "maximum", "pattern", "description")
_FENCE = re.compile(r"^\s*```(?:json)?\s*\n?(.*?)\n?\s*```\s*$", re.S | re.I)


class _Dup(ValueError):
    pass


def _no_dups(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise _Dup(k)
        out[k] = v
    return out


def _depth(v, d=0):
    if d > MAX_DEPTH:
        return d
    if isinstance(v, dict):
        return max([_depth(x, d + 1) for x in v.values()] or [d])
    if isinstance(v, list):
        return max([_depth(x, d + 1) for x in v] or [d])
    return d


def extract_json(text):
    """The one JSON object in a model answer (the whole answer, or a fenced block, or the span from the first "{" to
    the last "}"), or None. Duplicate keys, deep nesting and oversized answers give None."""
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_ANSWER_CHARS:
        return None
    candidates = [text.strip()]
    m = _FENCE.match(text)
    if m:
        candidates.append(m.group(1).strip())
    a, b = text.find("{"), text.rfind("}")
    if 0 <= a < b:
        candidates.append(text[a:b + 1])
    for c in candidates:
        try:
            v = json.loads(c, object_pairs_hook=_no_dups)
        except (ValueError, RecursionError):
            continue
        if isinstance(v, dict) and _depth(v) <= MAX_DEPTH:
            return v
    return None


def validate(v, schema, path="$"):
    """A list of problems (paths and rule names only, never the value), empty when v matches."""
    out = []
    t = schema.get("type")
    if t == "object":
        if not isinstance(v, dict):
            return [f"{path}: not an object"]
        props = schema.get("properties", {})
        for k in schema.get("required", []):
            if k not in v:
                out.append(f"{path}.{k}: missing")
        if schema.get("additionalProperties") is False:
            for k in v:
                if k not in props:
                    out.append(f"{path}: unknown field")
                    break
        for k, sub in props.items():
            if k in v:
                out += validate(v[k], sub, f"{path}.{k}")
    elif t == "array":
        if not isinstance(v, list):
            return [f"{path}: not a list"]
        if "maxItems" in schema and len(v) > schema["maxItems"]:
            out.append(f"{path}: too many items")
        if "minItems" in schema and len(v) < schema["minItems"]:
            out.append(f"{path}: too few items")
        for i, x in enumerate(v[:200]):
            out += validate(x, schema.get("items", {}), f"{path}[{i}]")
    elif t == "string":
        if not isinstance(v, str):
            return [f"{path}: not a string"]
        if "enum" in schema and v not in schema["enum"]:
            out.append(f"{path}: not one of the allowed values")
        if "maxLength" in schema and len(v) > schema["maxLength"]:
            out.append(f"{path}: too long")
        if "minLength" in schema and len(v) < schema["minLength"]:
            out.append(f"{path}: too short")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], v):
            out.append(f"{path}: wrong form")
    elif t == "integer":
        if not isinstance(v, int) or isinstance(v, bool):
            return [f"{path}: not an integer"]
        if "minimum" in schema and v < schema["minimum"]:
            out.append(f"{path}: too small")
        if "maximum" in schema and v > schema["maximum"]:
            out.append(f"{path}: too large")
    elif t == "boolean":
        if not isinstance(v, bool):
            return [f"{path}: not a boolean"]
    else:
        out.append(f"{path}: schema type not supported")
    return out[:50]


def wire(schema):
    """The schema as sent to a provider: the same structure without the locally enforced keywords."""
    if isinstance(schema, dict):
        return {k: wire(v) for k, v in schema.items() if k not in LOCAL_ONLY}
    if isinstance(schema, list):
        return [wire(x) for x in schema]
    return schema


def dialect_problems(schema, path="$", root=True):
    """Why a schema is outside the common dialect (empty when it is inside). Used by the tests on every outgoing
    schema."""
    out = []
    if not isinstance(schema, dict):
        return [f"{path}: not a schema object"]
    if root and schema.get("type") != "object":
        out.append(f"{path}: the root must be an object")
    for bad in ("anyOf", "oneOf", "allOf", "not", "$ref", "$defs", "if", "then", "else", "const", "format"):
        if bad in schema:
            out.append(f"{path}: {bad} is not in the dialect")
    t = schema.get("type")
    if not isinstance(t, str) or t not in ("object", "array", "string", "integer", "boolean"):
        out.append(f"{path}: type must be one plain type")
    if t == "object":
        props = schema.get("properties")
        if not isinstance(props, dict) or not props:
            out.append(f"{path}: an object needs properties")
            props = {}
        if schema.get("additionalProperties") is not False:
            out.append(f"{path}: additionalProperties must be false")
        if sorted(schema.get("required", [])) != sorted(props):
            out.append(f"{path}: every property must be required")
        for k, sub in props.items():
            out += dialect_problems(sub, f"{path}.{k}", False)
    if t == "array":
        out += dialect_problems(schema.get("items"), f"{path}[]", False)
        if schema.get("minItems", 0) not in (0, 1):
            out.append(f"{path}: minItems above 1 is refused by some providers")
    return out
