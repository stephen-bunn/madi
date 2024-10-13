from typing import cast

from madi.types import Policy, PolicyRule


class MadiError(Exception):
    @staticmethod
    def rule_ref(policy: Policy, rule: PolicyRule) -> str:
        """Build a reference string for a policy rule."""

        return f"{policy['ref']}.{rule['ref']}"


class InvalidPolicy(MadiError):
    """Raised when an encountered policy is invalid."""

    def __init__(self, message: str, policy: dict | Policy):
        super().__init__(message)
        self.policy = policy

    @classmethod
    def from_policy(cls, policy: dict | Policy, rule: PolicyRule, message: str | None = None):
        """Create an InvalidPolicy error from a policy and rule."""

        return cls(
            f"INVALID {cls.rule_ref(cast(Policy, policy), rule)}"
            + (f": {message}" if message else ""),
            policy,
        )


class DeniedPolicy(MadiError):
    """Raised when the evaluation of a policy reaches a failure state."""

    def __init__(self, message: str, policy: Policy, rule: PolicyRule):
        super().__init__(message)
        self.policy = policy
        self.rule = rule

    @classmethod
    def from_policy(cls, policy: Policy, rule: PolicyRule, message: str | None = None):
        """Create a DeniedPolicy error from a policy and rule."""

        return cls(
            f"DENY {cls.rule_ref(policy, rule)}" + (f": {message}" if message else ""),
            policy,
            rule,
        )

    @classmethod
    def from_query(cls, policy: Policy, rule: PolicyRule, query: str, query_result: dict):
        """Create a DeniedPolicy error from a query and its result."""

        return cls.from_policy(
            policy,
            rule,
            f"{query_result!r} from {query!r} matched {rule['schema']}",
        )


class AllowedPolicy(MadiError):
    """Raised when the evaluation of a policy reaches an acceptance state."""

    def __init__(self, message: str, policy: Policy, rule: PolicyRule):
        super().__init__(message)
        self.policy = policy
        self.rule = rule

    @classmethod
    def from_policy(cls, policy: Policy, rule: PolicyRule, message: str | None = None):
        """Create an AllowedPolicy error from a policy and rule."""

        return cls(
            (f"ALLOW {cls.rule_ref(policy, rule)}" + (f": {message}" if message else "")),
            policy,
            rule,
        )

    @classmethod
    def from_query(cls, policy: Policy, rule: PolicyRule, query: str, query_result: dict):
        """Create an AllowedPolicy error from a query and its result."""

        return cls.from_policy(
            policy,
            rule,
            f"{query_result!r} from {query!r} matched {rule['schema']}",
        )
