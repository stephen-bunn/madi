from os import PathLike
from pathlib import Path
from typing import TypeGuard

import jmespath
import jsonschema
from jmespath.exceptions import EmptyExpressionError, ParseError
from msgspec import json

from madi.cache import PolicyCache
from madi.constants import DEFAULT_POLICY_META_SCHEMA, POLICY_META_SCHEMAS, POLICY_SUFFIX
from madi.errors import AllowedPolicy, DeniedPolicy, InvalidPolicy
from madi.types import Policy, PolicyRule


def get_policy_meta_schema(policy: dict | Policy, version: str | None = None) -> dict:
    """Get the appropriate policy meta schema for a given policy.

    You can provide a specific version to use, otherwise the function will use the version
    specified in the policy. If no version is specified, it will assume the default policy schema.
    """

    schema_version = policy.get("v", version)
    if schema_version is None:
        return DEFAULT_POLICY_META_SCHEMA

    if schema_version not in POLICY_META_SCHEMAS:
        raise InvalidPolicy(f"Unknown policy version {schema_version!r}", policy)

    return POLICY_META_SCHEMAS[schema_version]


def is_valid_policy(policy: dict | Policy) -> TypeGuard[Policy]:
    """Validate if a given dictionary is a valid policy.

    This function validates the given policy against the `POLICY_SCHEMA` and checks
    if each rule in the policy has a valid schema. It uses JSONSchema (draft v7) for validation.
    """

    try:
        jsonschema.validate(policy, get_policy_meta_schema(policy))
        for rule in policy.get("rules", []):
            jsonschema.validate(rule.get("schema"), jsonschema.Draft7Validator.META_SCHEMA)

            try:
                jmespath.compile(rule.get("select"))
            except (ParseError, EmptyExpressionError) as err:
                raise InvalidPolicy.from_policy(
                    policy, rule, f"Rule select compilation failed, {rule.get('select')!r}"
                ) from err

        return True
    except jsonschema.ValidationError as err:
        raise InvalidPolicy("Policy validation failed", policy) from err


def validate_policy_rule(
    policy: Policy,
    rule: PolicyRule,
    payload: dict,
    cache: PolicyCache | None = None,
):
    """Validate a policy rule against a payload.

    This function validates a policy rule against a given payload. It uses JMESPath to query
    the payload and then validates the result against the provided JSONSchema (draft v7) in the
    rule.
    """

    strict = rule.get("strict", policy.get("strict", False))
    select = rule["select"]
    selection = jmespath.search(select, payload)
    if selection is None:
        if strict:
            message = f"Rule select returned nothing, {select!r}"
            if cache is not None:
                cache.add(policy, payload, rule, "DENY", message)
            raise DeniedPolicy.from_policy(policy, rule, message)

        return

    try:
        jsonschema.validate(selection, rule["schema"])
    except jsonschema.ValidationError as err:
        if strict:
            if cache is not None:
                cache.add(policy, payload, rule, "DENY")
            raise DeniedPolicy.from_policy(policy, rule) from err

        return

    try:
        raise (DeniedPolicy if rule["action"] == "DENY" else AllowedPolicy).from_query(
            policy, rule, select, selection
        )
    except (DeniedPolicy, AllowedPolicy):
        if cache is not None:
            cache.add(policy, payload, rule, rule["action"], select, selection)
        raise


def validate_policy(
    policy: Policy,
    payload: dict,
    raise_allowed: bool = False,
    cache: PolicyCache | None = None,
):
    """Validate each rule in a policy against a payload.

    This will raise a `DeniedPolicy` exception on the first rule that fails. If no rule fails,
    it will raise an `AllowedPolicy` exception if `raise_allowed` is set to `True`. Otherwise,
    it will return `None`.
    """

    if cache is not None:
        cache_result = cache.get(policy, payload)
        if cache_result is not None:
            if cache_result["action"] == "DENY":
                if "select" in cache_result and "selection" in cache_result:
                    raise DeniedPolicy.from_query(
                        policy,
                        cache_result["rule"],
                        cache_result["select"],
                        cache_result["selection"],
                    )
                raise DeniedPolicy.from_policy(
                    policy, cache_result["rule"], cache_result.get("message")
                )
            elif cache_result["action"] == "ALLOW":
                if raise_allowed:
                    if "select" in cache_result and "selection" in cache_result:
                        raise AllowedPolicy.from_query(
                            policy,
                            cache_result["rule"],
                            cache_result["select"],
                            cache_result["selection"],
                        )

                    raise AllowedPolicy.from_policy(
                        policy, cache_result["rule"], cache_result.get("message")
                    )
                return

    for rule in policy["rules"]:
        try:
            validate_policy_rule(policy, rule, payload, cache=cache)
        except AllowedPolicy as err:
            if raise_allowed:
                raise err


def validate_policy_file(filepath: PathLike[str], payload: dict, raise_allowed: bool = False):
    """Validate a policy file against a payload.

    This function reads a policy file from the given path and validates it against the provided
    payload.
    """

    filepath = Path(filepath)
    if not filepath.is_file():
        raise FileNotFoundError(f"{filepath} is not a file")

    policy = json.decode(filepath.read_bytes())
    if is_valid_policy(policy):
        validate_policy(policy, payload, raise_allowed=raise_allowed)


def validate_policy_dir(
    dirpath: PathLike[str],
    payload: dict,
    deep: bool = False,
    suffix: str = POLICY_SUFFIX,
    raise_allowed: bool = False,
):
    """Validate all policy files in a directory against a payload.

    This function will validate all policy files in the given directory against the provided
    payload. If `deep` is set to `True`, it will search for policy files recursively.
    """

    dirpath = Path(dirpath)
    if not dirpath.is_dir():
        raise NotADirectoryError(f"{dirpath} is not a directory")

    for policy_path in dirpath.glob(("**/" if deep else "") + f"*{suffix}"):
        if not policy_path.is_file():
            continue

        validate_policy_file(policy_path, payload, raise_allowed=raise_allowed)
