import time
from hashlib import sha1
from io import BufferedReader, BufferedWriter
from pathlib import Path
from typing import Literal, NotRequired, TypedDict

from attr import define, field
from msgspec import json

from madi.types import Policy, PolicyAction, PolicyRule

type FingerprintPolicy = Literal["fast", "full"]
DEFAULT_FINGERPRINT_POLICY: FingerprintPolicy = "fast"


class PolicyCacheEntry(TypedDict):
    rule: PolicyRule
    action: PolicyAction
    select: NotRequired[str]
    selection: NotRequired[dict]
    message: NotRequired[str]
    ttl: NotRequired[int]
    timestamp: NotRequired[float]


@define
class PolicyCache:
    ttl: int | None = field(default=None)
    fingerprint_policy: FingerprintPolicy = field(default=DEFAULT_FINGERPRINT_POLICY)
    _result_cache: dict[str, PolicyCacheEntry] = field(factory=dict, repr=False, init=False)

    @classmethod
    def from_file(
        cls,
        file_io: BufferedReader,
        ttl: int | None = None,
        fingerprint_policy: FingerprintPolicy = DEFAULT_FINGERPRINT_POLICY,
    ) -> "PolicyCache":
        cache = cls(ttl=ttl, fingerprint_policy=fingerprint_policy)
        cache._result_cache = json.decode(file_io.read())
        return cache

    def to_file(self, file_io: BufferedWriter):
        file_io.write(json.encode(self._result_cache))

    def to_filepath(self, filepath: Path):
        with filepath.open("wb") as file_io:
            file_io.write(json.encode(self._result_cache))

    def _build_policy_fingerprint(self, policy: Policy) -> bytes:
        if self.fingerprint_policy == "full":
            return sha1(json.encode(policy, order="sorted")).digest()

        return sha1(
            json.encode([policy["uid"], sorted([rule["uid"] for rule in policy["rules"]])])
        ).digest()

    def _build_cache_key(self, policy: Policy, payload: dict) -> str:
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
        cache_entry: PolicyCacheEntry = {"rule": rule, "action": action}
        if select is not None and selection is not None:
            cache_entry = {**cache_entry, "select": select, "selection": selection}

        if message is not None:
            cache_entry = {**cache_entry, "message": message}

        if ttl is not None:
            cache_entry = {**cache_entry, "ttl": ttl, "timestamp": time.time()}

        return cache_entry

    def clear(self):
        self._result_cache.clear()

    def has(self, policy: Policy, payload: dict) -> bool:
        cache_key = self._build_cache_key(policy, payload)
        return cache_key in self._result_cache

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
        cache_key = self._build_cache_key(policy, payload)
        cache_entry = self._build_cache_entry(
            rule, action, select, selection, message, ttl or self.ttl
        )
        self._result_cache[cache_key] = cache_entry
        return cache_entry

    def remove(self, policy: Policy, payload: dict) -> PolicyCacheEntry | None:
        cache_key = self._build_cache_key(policy, payload)
        return self._result_cache.pop(cache_key, None)

    def get(self, policy: Policy, payload: dict) -> PolicyCacheEntry | None:
        cache_key = self._build_cache_key(policy, payload)
        cache_entry = self._result_cache.get(cache_key)
        if cache_entry is None:
            return None

        cache_entry_ttl = cache_entry.get("ttl")
        cache_entry_timestamp = cache_entry.get("timestamp")
        if cache_entry_ttl is not None and cache_entry_timestamp is not None:
            if time.time() - cache_entry_timestamp > cache_entry_ttl:
                self._result_cache.pop(cache_key)
                return None

        return cache_entry
