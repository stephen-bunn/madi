from typing import Literal, NotRequired, TypedDict

type PolicyAction = Literal["ALLOW", "DENY"]
"""A type alias for policy actions."""


class PolicyRule(TypedDict):
    """Defines a policy rule."""

    ref: str
    """A reference identifier for the rule."""

    uid: str
    """A unique identifier for the rule."""

    strict: NotRequired[bool]
    """If true, the rule is strict and must be enforced."""

    description: NotRequired[str]
    """An optional description of the rule."""

    action: PolicyAction
    """The decision to make when the rule is evaluated."""

    select: str
    """A JMESPath query to query against the input data."""

    schema: dict
    """A JSONSchema to validate the result of the query."""


class Policy(TypedDict):
    """Defines a policy."""

    ref: str
    """A reference identifier for the policy."""

    uid: str
    """A unique identifier for the policy."""

    strict: NotRequired[bool]
    """
    If true, the policy is strict and must be enforced.
    This implicitly sets all included policy rules as strict.
    """

    description: NotRequired[str]
    """An optional description of the policy."""

    rules: list[PolicyRule]
    """A list of policy rules."""
