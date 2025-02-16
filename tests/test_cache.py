import time
from hashlib import sha1
from string import hexdigits, printable
from unittest import mock

from hypothesis import given
from hypothesis.strategies import dictionaries, integers, none, one_of, sampled_from, text
from msgspec import json

from madi.cache import (
    DEFAULT_FINGERPRINT_POLICY,
    FINGERPRINT_POLICIES,
    FingerprintPolicy,
    PolicyCache,
)
from madi.types import Policy, PolicyAction
from tests.strategies import base_type, policy, policy_action


def describe_PolicyCache():
    @given(one_of([none(), integers(min_value=0)]))
    def it_has_a_ttl_property(ttl: int):
        assert PolicyCache().ttl is None
        assert PolicyCache(ttl=ttl).ttl == ttl

    @given(sampled_from(list(FINGERPRINT_POLICIES)))
    def it_has_a_fingerprint_policy_property(fingerprint_policy: FingerprintPolicy):
        assert PolicyCache().fingerprint_policy == DEFAULT_FINGERPRINT_POLICY
        assert (
            PolicyCache(fingerprint_policy=fingerprint_policy).fingerprint_policy
            == fingerprint_policy
        )

    @given(policy(), policy_action())
    def it_has_a_size_property(policy: Policy, action: PolicyAction):
        cache = PolicyCache()
        assert cache.size == 0

        cache.add(policy, {}, policy["rules"][0], action)
        assert cache.size == 1

    @given(policy(), policy_action())
    def it_has_a_cache_property(policy: Policy, action: PolicyAction):
        cache = PolicyCache()
        assert isinstance(cache.cache, dict)
        assert len(cache.cache) == 0

        cache.add(policy, {}, policy["rules"][0], action)
        assert isinstance(cache.cache, dict)
        assert len(cache.cache) == 1

    def describe_from_file():
        @given(
            policy(),
            policy_action(),
            text(hexdigits, min_size=40, max_size=40),
            one_of([none(), integers(min_value=0)]),
            sampled_from(list(FINGERPRINT_POLICIES)),
        )
        def it_loads_a_saved_policy_cache_from_an_open_file(
            policy: Policy,
            action: PolicyAction,
            fingerprint: str,
            ttl: int | None,
            fingerprint_policy: FingerprintPolicy,
        ):
            with mock.patch(
                "msgspec.json.decode",
                return_value={fingerprint: {"rule": policy["rules"][0], "action": action}},
            ):
                file_io = mock.MagicMock()
                cache = PolicyCache.from_file(file_io, ttl, fingerprint_policy)

                file_io.read.assert_called_once()
                assert cache.size == 1
                assert cache.cache[fingerprint] == {"rule": policy["rules"][0], "action": action}

    def describe_to_file():
        @given(
            policy(),
            policy_action(),
            text(hexdigits, min_size=40, max_size=40),
            one_of([none(), integers(min_value=0)]),
            sampled_from(list(FINGERPRINT_POLICIES)),
        )
        def it_writes_the_policy_cache_to_an_open_file(
            policy: Policy,
            action: PolicyAction,
            fingerprint: str,
            ttl: int | None,
            fingerprint_policy: FingerprintPolicy,
        ):
            file_io = mock.MagicMock()
            cache = PolicyCache(ttl=ttl, fingerprint_policy=fingerprint_policy)
            cache.cache[fingerprint] = {"rule": policy["rules"][0], "action": action}

            cache.to_file(file_io)
            file_io.write.assert_called_once_with(json.encode(cache.cache))

    def describe_build_policy_fingerprint():
        @given(policy())
        def it_builds_a_full_fingerprint(policy: Policy):
            # This test is just a validation of the implementation as we want to ensure that the
            # fingerprint logic is consistent
            cache = PolicyCache(fingerprint_policy="full")
            assert (
                cache._build_policy_fingerprint(policy)
                == sha1(json.encode(policy, order="sorted")).digest()
            )

        @given(policy())
        def it_builds_a_fast_fingerprint(policy: Policy):
            # This test is just a validation of the implementation as we want to ensure that the
            # fingerprint logic is consistent
            cache = PolicyCache(fingerprint_policy="fast")
            assert (
                cache._build_policy_fingerprint(policy)
                == sha1(
                    json.encode([policy["uid"], sorted([rule["uid"] for rule in policy["rules"]])])
                ).digest()
            )

    def describe_build_cache_key():
        @given(policy(), dictionaries(min_size=1, keys=text(printable), values=base_type()))
        def it_builds_a_cache_key(policy: Policy, payload: dict):
            # This test is just a validation of the implementation as we want to ensure that the
            # cache key logic is consistent
            cache = PolicyCache()
            assert (
                cache._build_cache_key(policy, payload)
                == sha1(
                    cache._build_policy_fingerprint(policy) + json.encode(payload, order="sorted")
                ).hexdigest()
            )

    def describe_build_cache_entry():
        @given(policy(), policy_action())
        def it_builds_a_cache_entry_with_a_rule_and_action(policy: Policy, action: PolicyAction):
            cache = PolicyCache()
            cache_entry = cache._build_cache_entry(policy["rules"][0], action)
            assert cache_entry["rule"] == policy["rules"][0]
            assert cache_entry["action"] == action

        @given(
            policy(),
            policy_action(),
            text(printable, min_size=1),
            dictionaries(
                min_size=1,
                max_size=5,
                keys=text(printable, min_size=1),
                values=base_type(),
            ),
        )
        def it_builds_a_cache_entry_with_a_select_and_selection(
            policy: Policy, action: PolicyAction, select: str, selection: dict
        ):
            cache = PolicyCache()
            cache_entry = cache._build_cache_entry(
                policy["rules"][0],
                action,
                select,
                selection,
            )

            assert cache_entry.get("select") == select
            assert cache_entry.get("selection") == selection

        @given(policy(), policy_action(), text(printable))
        def it_builds_a_cache_entry_with_a_message(
            policy: Policy, action: PolicyAction, message: str
        ):
            cache = PolicyCache()
            cache_entry = cache._build_cache_entry(policy["rules"][0], action, message=message)
            assert cache_entry.get("message") == message

        @given(policy(), policy_action(), integers(min_value=1), integers(min_value=0))
        def it_builds_a_cache_entry_with_a_ttl_and_timestamp(
            policy: Policy, action: PolicyAction, ttl: int, timestamp: int
        ):
            cache = PolicyCache()
            with mock.patch("time.time", return_value=timestamp):
                cache_entry = cache._build_cache_entry(policy["rules"][0], action, ttl=ttl)

            assert cache_entry.get("ttl") == ttl
            assert cache_entry.get("timestamp") == timestamp

    def describe_clear():
        @given(policy(), policy_action())
        def it_clears_the_cache(policy: Policy, action: PolicyAction):
            cache = PolicyCache()
            cache.add(policy, {}, policy["rules"][0], action)
            assert cache.size == 1

            cache.clear()
            assert cache.size == 0

    def describe_has():
        @given(policy(), policy_action())
        def it_returns_true_when_a_cache_entry_exists(policy: Policy, action: PolicyAction):
            cache = PolicyCache()
            assert not cache.has(policy, {})

            cache.add(policy, {}, policy["rules"][0], action)
            assert cache.has(policy, {})

        @given(policy(), policy_action())
        def it_returns_false_when_no_cache_entry_exists(policy: Policy, action: PolicyAction):
            cache = PolicyCache()
            assert not cache.has(policy, {})

    def describe_add():
        @given(
            policy(),
            policy_action(),
            one_of(text(printable), none()),
            one_of(dictionaries(min_size=1, keys=text(printable), values=base_type()), none()),
            one_of(text(printable), none()),
            one_of(integers(min_value=1), none()),
        )
        def it_adds_a_cache_entry(
            policy: Policy,
            action: PolicyAction,
            select: str | None,
            selection: dict | None,
            message: str | None,
            ttl: int | None,
        ):
            cache = PolicyCache()
            cache_entry = cache.add(
                policy, {}, policy["rules"][0], action, select, selection, message, ttl
            )
            assert cache_entry["rule"] == policy["rules"][0]
            assert cache_entry["action"] == action

            if select is not None and selection is not None:
                assert cache_entry.get("select") == select
                assert cache_entry.get("selection") == selection

            assert cache_entry.get("message") == message
            assert cache_entry.get("ttl") == ttl
            assert cache.size == 1

    def describe_remove():
        @given(policy(), policy_action())
        def it_removes_and_returns_a_cache_entry(policy: Policy, action: PolicyAction):
            cache = PolicyCache()
            cache.add(policy, {}, policy["rules"][0], action)
            assert cache.size == 1

            cache_entry = cache.remove(policy, {})
            assert cache_entry is not None
            assert cache_entry["rule"] == policy["rules"][0]
            assert cache_entry["action"] == action
            assert cache.size == 0

        @given(policy())
        def it_returns_none_when_no_cache_entry_exists(policy: Policy):
            cache = PolicyCache()
            assert cache.remove(policy, {}) is None

    def describe_get():
        @given(policy())
        def it_returns_none_when_no_cache_entry_exists(policy: Policy):
            cache = PolicyCache()
            assert cache.get(policy, {}) is None

        @given(
            policy(),
            policy_action(),
            integers(min_value=1, max_value=999_999),
            integers(min_value=0, max_value=999_999),
        )
        def it_returns_none_when_the_ttl_has_expired(
            policy: Policy, action: PolicyAction, ttl: int, ttl_offset: int
        ):
            cache = PolicyCache()
            with mock.patch("time.time", return_value=(time.time() - ttl - ttl_offset)):
                cache.add(policy, {}, policy["rules"][0], action, ttl=ttl)
                assert cache.size == 1

            cache_entry = cache.get(policy, {})
            assert cache_entry is None
            assert cache.size == 0

        @given(policy(), policy_action())
        def it_returns_the_cached_entry(policy: Policy, action: PolicyAction):
            cache = PolicyCache()
            cache.add(policy, {}, policy["rules"][0], action)
            assert cache.size == 1

            cache_entry = cache.get(policy, {})
            assert cache_entry is not None
            assert cache_entry["rule"] == policy["rules"][0]
            assert cache_entry["action"] == action
            assert cache.size == 1
