import string
from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest
from hypothesis import assume, given
from hypothesis.strategies import just, lists, none, nothing, sampled_from, text
from msgspec import json

from madi.constants import DEFAULT_POLICY_META_SCHEMA, POLICY_META_SCHEMAS, POLICY_SUFFIX
from madi.errors import AllowedPolicy, DeniedPolicy, InvalidPolicy
from madi.policy import (
    get_policy_meta_schema,
    is_valid_policy,
    validate_policy,
    validate_policy_dir,
    validate_policy_file,
    validate_policy_rule,
)
from madi.types import Policy
from tests.helpers import temp_dirpath
from tests.strategies import missing_path, policy, policy_rule, policy_with_action


def describe_get_policy_meta_schema():
    @given(policy())
    def it_returns_default_policy_meta_schema_if_no_version_is_included(policy: dict):
        assert get_policy_meta_schema(policy) == DEFAULT_POLICY_META_SCHEMA

    @given(policy(v=just("1")), none())
    def it_returns_default_policy_meta_schema_if_passed_version_is_None(
        policy: dict, version: None
    ):
        assert get_policy_meta_schema(policy, version) == DEFAULT_POLICY_META_SCHEMA

    @given(policy(v=text(string.digits, min_size=1)))
    def it_raises_InvalidPolicy_if_included_policy_version_is_not_handled(policy: dict):
        assume(policy["v"] not in POLICY_META_SCHEMAS)
        with pytest.raises(InvalidPolicy):
            get_policy_meta_schema(policy)

    @given(policy(), text(string.digits, min_size=1))
    def it_raises_InvalidPolicy_if_passed_policy_version_is_not_handled(policy: dict, version: str):
        assume(version not in POLICY_META_SCHEMAS)
        with pytest.raises(InvalidPolicy):
            get_policy_meta_schema(policy, version)

    @given(policy(v=just("1")))
    def it_returns_the_appropriate_policy_meta_schema_for_included_v1(policy: dict):
        assert get_policy_meta_schema(policy) == POLICY_META_SCHEMAS["1"]

    @given(policy(), just("1"))
    def it_returns_the_appropriate_policy_meta_schema_for_passed_v1(policy: dict, version: str):
        assert get_policy_meta_schema(policy, version) == POLICY_META_SCHEMAS["1"]


def describe_is_valid_policy():
    @given(policy())
    def it_returns_true_for_valid_policy(policy: dict):
        assert is_valid_policy(policy)

    def it_raises_InvalidPolicy_if_policy_is_invalid():
        with pytest.raises(InvalidPolicy):
            is_valid_policy({})

    @given(
        policy(
            rules=lists(
                policy_rule(schema=just({"type": "invalid"})),
                min_size=1,
                max_size=1,
            )
        )
    )
    def it_raises_InvalidPolicy_if_policy_has_invalid_rule_schemas(policy: dict):
        with pytest.raises(InvalidPolicy):
            is_valid_policy(policy)

    @given(
        policy(
            rules=lists(
                policy_rule(select=sampled_from(["", ".", "(al]"])),
                min_size=1,
                max_size=1,
            )
        )
    )
    def it_raises_InvalidPolicy_if_policy_has_invalid_rule_selects(policy: dict):
        with pytest.raises(InvalidPolicy):
            is_valid_policy(policy)


def describe_validate_policy_rule():
    @given(policy(rules=lists(policy_rule(strict=just(False)), min_size=1, max_size=1)))
    def it_does_not_raise_by_default_if_selection_is_none(policy: Policy):
        assert validate_policy_rule(policy, policy["rules"][0], {}) is None

    @given(policy(rules=lists(policy_rule(strict=just(True)), min_size=1, max_size=1)))
    def it_raises_DeniedPolicy_if_rule_is_strict_and_selection_is_none(policy: Policy):
        with pytest.raises(DeniedPolicy):
            validate_policy_rule(policy, policy["rules"][0], {})

    @given(
        policy(
            rules=lists(
                policy_rule(
                    strict=just(False), select=just("test"), schema=just({"type": "number"})
                ),
                min_size=1,
                max_size=1,
            )
        )
    )
    def it_does_not_raise_if_selection_does_not_match_schema(policy: Policy):
        assert validate_policy_rule(policy, policy["rules"][0], {"test": "selection"}) is None

    @given(
        policy(
            rules=lists(
                policy_rule(
                    strict=just(True), select=just("test"), schema=just({"type": "number"})
                ),
                min_size=1,
                max_size=1,
            )
        )
    )
    def it_raises_DeniedPolicy_if_rule_is_strict_and_selection_does_not_match_schema(
        policy: Policy,
    ):
        with pytest.raises(DeniedPolicy):
            validate_policy_rule(policy, policy["rules"][0], {"test": "selection"})

    @given(
        policy(
            rules=lists(
                policy_rule(
                    action=just("DENY"),
                    strict=just(False),
                    select=just("test"),
                    schema=just({"type": "string"}),
                ),
                min_size=1,
                max_size=1,
            )
        )
    )
    def it_raises_DeniedPolicy_if_selection_matches_schema_and_action_is_DENY(policy: Policy):
        with pytest.raises(DeniedPolicy):
            validate_policy_rule(policy, policy["rules"][0], {"test": "selection"})

    @given(
        policy(
            rules=lists(
                policy_rule(
                    action=just("ALLOW"),
                    strict=just(False),
                    select=just("test"),
                    schema=just({"type": "string"}),
                ),
                min_size=1,
                max_size=1,
            )
        )
    )
    def it_raises_AllowedPolicy_if_selection_matches_schema_and_action_is_ALLOW(policy: Policy):
        with pytest.raises(AllowedPolicy):
            validate_policy_rule(policy, policy["rules"][0], {"test": "selection"})


def describe_validate_policy():
    @given(policy(rules=lists(nothing(), max_size=0)))
    def it_does_not_raise_if_policy_contains_no_rules(policy: Policy):
        assert validate_policy(policy, {}) is None

    @given(
        policy_with_action(
            action=just("DENY"), select=just("test"), schema=just({"type": "string"})
        )
    )
    def it_raises_DeniedPolicy_if_policy_matches_DENY_rules(policy: Policy):
        with pytest.raises(DeniedPolicy):
            validate_policy(policy, {"test": "selection"})

    @given(
        policy_with_action(
            action=just("ALLOW"), select=just("test"), schema=just({"type": "string"})
        )
    )
    def it_does_not_raise_AllowedPolicy_if_policy_matches_ALLOW_rules_by_default(
        policy: Policy,
    ):
        assert validate_policy(policy, {"test": "selection"}) is None

    @given(
        policy_with_action(
            action=just("ALLOW"), select=just("test"), schema=just({"type": "string"})
        )
    )
    def it_raises_AllowedPolicy_if_policy_matches_ALLOW_rules_and_raise_allowed_is_true(
        policy: Policy,
    ):
        with pytest.raises(AllowedPolicy):
            validate_policy(policy, {"test": "selection"}, raise_allowed=True)


def describe_validate_policy_file():
    @given(missing_path())
    def it_raises_FileNotFoundError_if_filepath_does_not_exist(path: Path):
        with pytest.raises(FileNotFoundError):
            validate_policy_file(path, {})

    @given(policy())
    def it_does_not_raise_if_policy_contains_no_rules(policy: Policy):
        with temp_dirpath() as dirpath, NamedTemporaryFile(dir=dirpath) as file_io:
            file_io.write(json.encode(policy))
            file_io.flush()

            assert validate_policy_file(Path(file_io.name), {}) is None

    @given(
        policy_with_action(
            action=just("DENY"), select=just("test"), schema=just({"type": "string"})
        )
    )
    def it_raises_DeniedPolicy_if_policy_matches_DENY_rules(policy: Policy):
        with temp_dirpath() as dirpath, NamedTemporaryFile(dir=dirpath) as file_io:
            file_io.write(json.encode(policy))
            file_io.flush()

            with pytest.raises(DeniedPolicy):
                validate_policy(policy, {"test": "selection"})

    @given(
        policy_with_action(
            action=just("ALLOW"), select=just("test"), schema=just({"type": "string"})
        )
    )
    def it_raises_AllowedPolicy_if_policy_matches_ALLOW_rules_and_raise_allowed_is_true(
        policy: Policy,
    ):
        with temp_dirpath() as dirpath, NamedTemporaryFile(dir=dirpath) as file_io:
            file_io.write(json.encode(policy))
            file_io.flush()

            with pytest.raises(AllowedPolicy):
                validate_policy_file(Path(file_io.name), {"test": "selection"}, raise_allowed=True)


def describe_validate_policy_dir():
    @given(missing_path())
    def it_raises_NotADirectoryError_if_dirpath_is_not_a_directory(dirpath: Path):
        with pytest.raises(NotADirectoryError):
            validate_policy_dir(dirpath, {})

    def it_returns_None_if_dirpath_is_empty():
        with temp_dirpath() as dirpath:
            assert validate_policy_dir(dirpath, {}) is None

    @given(text(string.ascii_letters + string.digits, min_size=1))
    def it_skips_non_files_in_dirpath_with_default_suffix(dirname: str):
        with temp_dirpath() as dirpath:
            (dirpath / (dirname + POLICY_SUFFIX)).mkdir()
            assert validate_policy_dir(dirpath, {}) is None

    @given(
        text(string.ascii_letters + string.digits, min_size=1),
        text(string.ascii_letters + string.digits, min_size=1),
    )
    def it_skips_non_files_in_dirpath_with_passed_suffix(dirname: str, suffix: str):
        with temp_dirpath() as dirpath:
            (dirpath / (dirname + suffix)).mkdir()
            assert validate_policy_dir(dirpath, {}, suffix=suffix) is None

    @given(
        policy_with_action(
            action=just("DENY"), select=just("test"), schema=just({"type": "string"})
        )
    )
    def it_validates_policy_file_in_dirpath_with_default_suffix(policy: dict):
        with (
            temp_dirpath() as dirpath,
            NamedTemporaryFile(dir=dirpath, suffix=POLICY_SUFFIX) as file_io,
        ):
            file_io.write(json.encode(policy))
            file_io.flush()

            with pytest.raises(DeniedPolicy):
                assert validate_policy_dir(dirpath, {"test": "selection"}) is None

    @given(
        policy_with_action(
            action=just("ALLOW"), select=just("test"), schema=just({"type": "string"})
        )
    )
    def it_raises_AllowedPolicy_if_policy_matches_ALLOW_rules_and_raise_allowed_is_true(
        policy: Policy,
    ):
        with (
            temp_dirpath() as dirpath,
            NamedTemporaryFile(dir=dirpath, suffix=POLICY_SUFFIX) as file_io,
        ):
            file_io.write(json.encode(policy))
            file_io.flush()

            with pytest.raises(AllowedPolicy):
                validate_policy_dir(dirpath, {"test": "selection"}, raise_allowed=True)
