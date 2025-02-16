import time
from hashlib import sha1
from io import BufferedReader, BufferedWriter
from typing import Literal, NotRequired, TypedDict

from attr import define, field, validators
from msgspec import json

from madi.types import Policy, PolicyAction, PolicyRule

type FingerprintPolicy = Literal["fast", "full"]
"""
The fingerprint policy determines how much information is included in the fingerprint.

    * `fast` includes only the policy ID and the policy's rules.
        This means that if a policy rule's `select` or `selection` is updated,
        you should also update the rule's `uid` to avoid potential false positive cache hits.
    * `full` includes the policy ID, the policy's rules, and the policy's actions.
        This avoids potential false positive cache hits as it includes the entire policy state in
        the fingerprint generation, but may be slower to calculate as it requires that we serialize
        and hash the entire policy for every fingerprint calculation.
"""

FINGERPRINT_POLICIES: set[FingerprintPolicy] = {"fast", "full"}
"""The set of all available fingerprint policies."""

DEFAULT_FINGERPRINT_POLICY: FingerprintPolicy = "full"
"""The default fingerprint policy."""


class PolicyCacheEntry(TypedDict):
    """Represents a cached policy result."""

    rule: PolicyRule
    """The policy rule that was evaluated to get the `action`."""

    action: PolicyAction
    """The resulting policy action from the policy rule evaluation."""

    select: NotRequired[str]
    """The evaluated policy rule's selection criteria."""

    selection: NotRequired[dict]
    """The evaluated policy rule's selection criteria."""

    message: NotRequired[str]
    """The evaluation message associated with the policy rule evaluation."""

    ttl: NotRequired[int]
    """The time-to-live in seconds for the created cache entry."""

    timestamp: NotRequired[float]
    """The unix timestamp when the cache entry was created."""


@define
class PolicyCache:
    """A cache for policy results."""

    ttl: int | None = field(
        default=None,
        validator=validators.optional(
            validators.and_(validators.instance_of(int), validators.ge(0))
        ),
    )
    """Time-to-live in seconds for created cache entries."""

    fingerprint_policy: FingerprintPolicy = field(
        default=DEFAULT_FINGERPRINT_POLICY,
        validator=validators.in_(FINGERPRINT_POLICIES),
    )
    """Fingerprint policy used to identify policy rules in cache entries."""

    cache: dict[str, PolicyCacheEntry] = field(factory=dict, repr=False, init=False)

    @property
    def size(self) -> int:
        """The number of entries in the cache."""

        return len(self.cache)

    @classmethod
    def from_file(
        cls,
        file_io: BufferedReader,
        ttl: int | None = None,
        fingerprint_policy: FingerprintPolicy = DEFAULT_FINGERPRINT_POLICY,
    ) -> "PolicyCache":
        """Load a saved policy cache from an open file."""

        policy_cache = cls(ttl=ttl, fingerprint_policy=fingerprint_policy)
        policy_cache.cache = json.decode(file_io.read())
        return policy_cache

    def to_file(self, file_io: BufferedWriter):
        """Write the policy cache to an open file."""

        file_io.write(json.encode(self.cache))

    def _build_policy_fingerprint(self, policy: Policy) -> bytes:
        """Build a identification fingerprint for a policy."""

        if self.fingerprint_policy == "full":
            return sha1(json.encode(policy, order="sorted")).digest()

        return sha1(
            json.encode([policy["uid"], sorted([rule["uid"] for rule in policy["rules"]])])
        ).digest()

    def _build_cache_key(self, policy: Policy, payload: dict) -> str:
        """Build a cache key for a policy and payload."""

        return sha1(
            self._build_policy_fingerprint(policy) + json.encode(payload, order="sorted")
        ).hexdigest()

    def _build_cache_entry(
        self,
        rule: PolicyRule,
        action: PolicyAction,
        select: str | None = None,
        selection: dict | None = None,
        message: str | None = None,
        ttl: int | None = None,
    ) -> PolicyCacheEntry:
        """Build a cache entry for a policy and payload."""

        cache_entry: PolicyCacheEntry = {"rule": rule, "action": action}
        if select is not None and selection is not None:
            cache_entry = {**cache_entry, "select": select, "selection": selection}

        if message is not None:
            cache_entry = {**cache_entry, "message": message}

        if ttl is not None:
            cache_entry = {**cache_entry, "ttl": ttl, "timestamp": time.time()}

        return cache_entry

    def clear(self):
        """Clear the cache."""

        self.cache.clear()

    def has(self, policy: Policy, payload: dict) -> bool:
        """Check if a cache entry exists for a policy and payload."""

        cache_key = self._build_cache_key(policy, payload)
        return cache_key in self.cache

    def add(
        self,
        policy: Policy,
        payload: dict,
        rule: PolicyRule,
        action: PolicyAction,
        select: str | None = None,
        selection: dict | None = None,
        message: str | None = None,
        ttl: int | None = None,
    ) -> PolicyCacheEntry:
        """Add a cache entry for a policy and payload."""

        cache_key = self._build_cache_key(policy, payload)
        cache_entry = self._build_cache_entry(
            rule, action, select, selection, message, ttl or self.ttl
        )
        self.cache[cache_key] = cache_entry
        return cache_entry

    def remove(self, policy: Policy, payload: dict) -> PolicyCacheEntry | None:
        """Remove a cache entry for a policy and payload."""

        cache_key = self._build_cache_key(policy, payload)
        return self.cache.pop(cache_key, None)

    def get(self, policy: Policy, payload: dict) -> PolicyCacheEntry | None:
        """Get a cache entry for a policy and payload."""

        cache_key = self._build_cache_key(policy, payload)
        cache_entry = self.cache.get(cache_key)
        if cache_entry is None:
            return None

        cache_entry_ttl = cache_entry.get("ttl")
        cache_entry_timestamp = cache_entry.get("timestamp")
        if cache_entry_ttl is not None and cache_entry_timestamp is not None:
            if time.time() - cache_entry_timestamp > cache_entry_ttl:
                self.cache.pop(cache_key)
                return None

        return cache_entry
