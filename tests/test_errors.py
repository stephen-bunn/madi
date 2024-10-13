from typing import cast

from hypothesis import given
from hypothesis.strategies import text
from hypothesis.strategies._internal.core import dictionaries

from madi.errors import AllowedPolicy, DeniedPolicy, InvalidPolicy, MadiError
from madi.types import Policy, PolicyRule
from tests.strategies import policy, policy_rule


def describe_MadiError():
    def describe_rule_ref():
        @given(policy(), policy_rule())
        def it_returns_a_rule_ref(policy: Policy, rule: PolicyRule):
            assert MadiError.rule_ref(policy, rule) == f"{policy['ref']}.{rule['ref']}"


def describe_InvalidPolicy():
    def it_subclasses_MadiError():
        assert issubclass(InvalidPolicy, MadiError)

    def describe_from_policy():
        @given(policy(), policy_rule())
        def it_returns_an_InvalidPolicy(policy: dict, rule: PolicyRule):
            error = InvalidPolicy.from_policy(policy, rule)
            assert str(error) == f"INVALID {InvalidPolicy.rule_ref(cast(Policy, policy), rule)}"
            assert error.policy == policy

        @given(policy(), policy_rule(), text(min_size=1))
        def it_returns_an_InvalidPolicy_with_message(policy: dict, rule: PolicyRule, message: str):
            error = InvalidPolicy.from_policy(policy, rule, message)
            assert (
                str(error)
                == f"INVALID {InvalidPolicy.rule_ref(cast(Policy, policy), rule)}: {message}"
            )
            assert error.policy == policy


def describe_DeniedPolicy():
    def it_subclasses_MadiError():
        assert issubclass(DeniedPolicy, MadiError)

    def describe_from_policy():
        @given(policy(), policy_rule())
        def it_returns_a_DeniedPolicy(policy: Policy, policy_rule: PolicyRule):
            error = DeniedPolicy.from_policy(policy, policy_rule)
            assert str(error) == f"DENY {policy['ref']}.{policy_rule['ref']}"
            assert error.policy == policy
            assert error.rule == policy_rule

        @given(policy(), policy_rule(), text(min_size=1))
        def it_returns_a_DeniedPolicy_with_message(
            policy: Policy,
            policy_rule: PolicyRule,
            message: str,
        ):
            error = DeniedPolicy.from_policy(policy, policy_rule, message)
            assert str(error) == f"DENY {policy['ref']}.{policy_rule['ref']}: {message}"
            assert error.policy == policy
            assert error.rule == policy_rule

    def describe_from_query():
        @given(policy(), policy_rule(), text(min_size=1), dictionaries(text(), text()))
        def it_returns_a_DeniedPolicy(
            policy: Policy,
            policy_rule: PolicyRule,
            query: str,
            query_result: dict[str, str],
        ):
            error = DeniedPolicy.from_query(policy, policy_rule, query, query_result)
            assert str(error) == (
                f"DENY {policy['ref']}.{policy_rule['ref']}: "
                f"{query_result!r} from {query!r} matched {policy_rule['schema']}"
            )
            assert error.policy == policy
            assert error.rule == policy_rule


def describe_AllowedPolicy():
    def it_subclasses_MadiError():
        assert issubclass(AllowedPolicy, MadiError)

    def describe_from_policy():
        @given(policy(), policy_rule())
        def it_returns_an_AllowedPolicy(policy: Policy, policy_rule: PolicyRule):
            error = AllowedPolicy.from_policy(policy, policy_rule)
            assert str(error) == f"ALLOW {policy['ref']}.{policy_rule['ref']}"
            assert error.policy == policy
            assert error.rule == policy_rule

        @given(policy(), policy_rule(), text(min_size=1))
        def it_returns_an_AllowedPolicy_with_message(
            policy: Policy,
            policy_rule: PolicyRule,
            message: str,
        ):
            error = AllowedPolicy.from_policy(policy, policy_rule, message)
            assert str(error) == f"ALLOW {policy['ref']}.{policy_rule['ref']}: {message}"
            assert error.policy == policy
            assert error.rule == policy_rule

    def describe_from_query():
        @given(policy(), policy_rule(), text(min_size=1), dictionaries(text(), text()))
        def it_returns_an_AllowedPolicy(
            policy: Policy,
            policy_rule: PolicyRule,
            query: str,
            query_result: dict[str, str],
        ):
            error = AllowedPolicy.from_query(policy, policy_rule, query, query_result)
            assert str(error) == (
                f"ALLOW {policy['ref']}.{policy_rule['ref']}: "
                f"{query_result!r} from {query!r} matched {policy_rule['schema']}"
            )
            assert error.policy == policy
            assert error.rule == policy_rule
