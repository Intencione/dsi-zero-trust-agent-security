"""Closed JSON codec for trusted runtime snapshots; never imports named classes."""
import json
from dataclasses import fields, is_dataclass
from enum import Enum
import secure_runtime as runtime
import agent_demo as policy

_TYPES = {c.__name__: c for c in (
    runtime.ToolCall, runtime.AuthorizationRecord, runtime.TaskGrant,
    runtime.CallRule, runtime.ArgumentConstraint, runtime.RuntimeResult,
    policy.PlanContext, policy.EnvironmentContext, policy.EnvironmentType,
    policy.NetworkAccess, policy.Decision,
)}


def pack(value):
    if isinstance(value, Enum):
        return {"$enum": type(value).__name__, "value": value.value}
    if is_dataclass(value):
        return {"$type": type(value).__name__, "fields": {
            f.name: pack(getattr(value, f.name)) for f in fields(value)}}
    if isinstance(value, (tuple, set)):
        return {"$collection": type(value).__name__, "items": [pack(v) for v in value]}
    if isinstance(value, list):
        return [pack(v) for v in value]
    if isinstance(value, dict):
        return {k: pack(v) for k, v in value.items()}
    return value


def unpack(value):
    if isinstance(value, list):
        return [unpack(v) for v in value]
    if not isinstance(value, dict):
        return value
    if "$enum" in value:
        return _TYPES[value["$enum"]](value["value"])
    if "$type" in value:
        return _TYPES[value["$type"]](**{k: unpack(v) for k, v in value["fields"].items()})
    if "$collection" in value:
        return {"tuple": tuple, "set": set}[value["$collection"]](unpack(v) for v in value["items"])
    return {k: unpack(v) for k, v in value.items()}


def dumps(value):
    return json.dumps(pack(value), allow_nan=False, sort_keys=True)


def loads(value):
    return unpack(json.loads(value))
