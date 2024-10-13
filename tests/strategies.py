import os
from pathlib import Path
from string import printable
from typing import Literal

from hypothesis import assume
from hypothesis.strategies import (
    DrawFn,
    SearchStrategy,
    composite,
    dictionaries,
    just,
    lists,
    sampled_from,
    text,
)

from madi.types import Policy, PolicyRule


@composite
def missing_path(draw: DrawFn) -> Path:
    path = Path(os.path.sep.join(draw(lists(text(printable), min_size=1))))
    assume(not path.exists())
    return path


@composite
def policy_rule(
    draw: DrawFn,
    ref: SearchStrategy[str] | None = None,
    action: SearchStrategy[Literal["ALLOW", "DENY"]] | None = None,
    select: SearchStrategy[str] | None = None,
    schema: SearchStrategy[dict] | None = None,
    description: SearchStrategy[str] | None = None,
    strict: SearchStrategy[bool] | None = None,
) -> PolicyRule:
    rule: PolicyRule = {
        "ref": draw(ref if ref is not None else text(printable, min_size=1)),
        "action": draw(action if action is not None else sampled_from(["ALLOW", "DENY"])),
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
    action: SearchStrategy[Literal["ALLOW", "DENY"]] | None = None,
    select: SearchStrategy[str] | None = None,
    schema: SearchStrategy[dict] | None = None,
) -> Policy:
    return draw(
        policy(rules=lists(policy_rule(select=select, schema=schema, action=action), min_size=1))
    )
