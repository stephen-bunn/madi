import os
from pathlib import Path
from string import printable
from typing import Any

from hypothesis import assume
from hypothesis.strategies import (
    DrawFn,
    SearchStrategy,
    booleans,
    composite,
    dictionaries,
    floats,
    integers,
    just,
    lists,
    none,
    one_of,
    sampled_from,
    sets,
    text,
    tuples,
)

from madi.types import Policy, PolicyAction, PolicyRule


@composite
def missing_path(draw: DrawFn) -> Path:
    path = Path(os.path.sep.join(draw(lists(text(printable), min_size=1))))
    assume(not path.exists())
    return path


@composite
def base_type(draw: DrawFn, allow_none: bool = True) -> Any:
    strategies = [
        integers(),
        floats(),
        text(printable),
        booleans(),
    ]

    if allow_none:
        strategies.append(none())

    return draw(one_of(strategies))


@composite
def iterable_type(draw: DrawFn, allow_none: bool = True, allow_nested: bool = False) -> Any:
    strategies = [
        lists(base_type(allow_none=allow_none)),
        dictionaries(keys=text(printable), values=base_type(allow_none=allow_none)),
        tuples(base_type(allow_none=allow_none)),
        sets(base_type(allow_none=allow_none)),
    ]

    if allow_nested:
        strategies.append(iterable_type(allow_none=allow_none, allow_nested=allow_nested))

    return draw(one_of(strategies))


@composite
def builtin_type(
    draw: DrawFn,
    allow_none: bool = True,
    allow_iterable: bool = True,
    allow_nested: bool = False,
) -> Any:
    strategies = [base_type(allow_none=allow_none)]
    if allow_iterable:
        strategies.append(iterable_type(allow_none=allow_none, allow_nested=allow_nested))

    return draw(one_of(strategies))


@composite
def policy_action(draw: DrawFn, action: SearchStrategy[PolicyAction] | None = None) -> PolicyAction:
    return draw(action if action is not None else sampled_from(["ALLOW", "DENY"]))


@composite
def policy_rule(
    draw: DrawFn,
    ref: SearchStrategy[str] | None = None,
    action: SearchStrategy[PolicyAction] | None = None,
    select: SearchStrategy[str] | None = None,
    schema: SearchStrategy[dict] | None = None,
    description: SearchStrategy[str] | None = None,
    strict: SearchStrategy[bool] | None = None,
) -> PolicyRule:
    rule: PolicyRule = {
        "uid": draw(text(printable, min_size=1)),
        "ref": draw(ref if ref is not None else text(printable, min_size=1)),
        "action": draw(action if action is not None else policy_action()),
        "select": draw(select if select is not None else just("test")),
        "schema": draw(
            schema
            if schema is not None
            else dictionaries(
                sampled_from(["type"]),
                sampled_from(["string", "number", "boolean", "object", "array"]),
            )
        ),
    }

    for key, value in {"description": description, "strict": strict}.items():
        if value is not None:
            rule[key] = draw(value)

    return rule


@composite
def policy(
    draw: DrawFn,
    v: SearchStrategy[str] | None = None,
    ref: SearchStrategy[str] | None = None,
    rules: SearchStrategy[list[PolicyRule]] | None = None,
    description: SearchStrategy[str] | None = None,
    strict: SearchStrategy[bool] | None = None,
) -> Policy:
    policy: Policy = {
        "uid": draw(text(printable, min_size=1)),
        "ref": draw(ref or text(printable, min_size=1)),
        "rules": draw(rules if rules is not None else lists(policy_rule(), min_size=1, max_size=3)),
    }

    for key, value in {"v": v, "description": description, "strict": strict}.items():
        if value is not None:
            policy[key] = draw(value)

    return policy


@composite
def policy_with_action(
    draw: DrawFn,
    action: SearchStrategy[PolicyAction] | None = None,
    select: SearchStrategy[str] | None = None,
    schema: SearchStrategy[dict] | None = None,
) -> Policy:
    return draw(
        policy(rules=lists(policy_rule(select=select, schema=schema, action=action), min_size=1))
    )
