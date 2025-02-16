# MADI

Dead simple JSON policy engine.

## Usage

Policies are defined in JSON following the following format.

```json
// test-policy.policy.json
{
  "$schema": "https://raw.githubusercontent.com/stephen-bunn/madi/refs/heads/main/schemas/v1/MadiPolicy.json",
  "ref": "PolicyReference",
  "uid": "0ae1ef57-45b4-4725-9555-19cd273836c4",
  "rules": [
    {
      "ref": "RuleReference",
      "uid": "4a46a22a-5954-42b0-9238-390967b5d1cf",
      "action": "DENY", // DENY or ALLOW
      "select": "test", // A JMESPath expression to select data from the input <https://jmespath.org/>
      "schema": {
        // A JSONSchema (draft-07) to validate the selected data <https://json-schema.org/>
        "type": "string"
      }
    }
  ]
}
```

This policy is loaded into memory and some provided input dictionary is evaluated against this policy.
Policy rules are evaluated in order, and the first rule to match the input dictionary will determine the outcome.

```python
from madi import validate_policy_file

# Because the above policy has the `DENY` action, and the JMESPath expression `test` selects a string,
# and the JSONSchema `{"type": "string"}` validates against the selected string, the following call will
# raise a `madi.errors.DeniedPolicy` exception.
validate_policy_file("test-policy.policy.json", {"test": "selection"})

# Because the JMESPath expression `test` selects a string, and the JSONSchema `{"type": "string"}` does
# NOT validate against the selected integer, the following call will return `None`.
validate_policy_file("test-policy.policy.json", {"test": 1})
```

Policies can exit immediately if any `ALLOW` rule is matched.

```json
// test-policy.policy.json
{
  "$schema": "https://raw.githubusercontent.com/stephen-bunn/madi/refs/heads/main/schemas/v1/MadiPolicy.json",
  "ref": "PolicyReference",
  "uid": "b727732c-4a3c-4f17-b0c7-fc1fccbc95c9",
  "rules": [
    {
      "ref": "RuleReference",
      "uid": "3eb7816d-ecb5-452c-897a-c01628192bcd",
      "action": "ALLOW",
      "select": "test",
      "schema": {
        "type": "string"
      }
    },
    {
      "ref": "RuleReference",
      "uid": "9f356f7c-0cb0-4eee-aaaa-3e9a1d7d760c",
      "action": "DENY",
      "select": "test",
      "schema": {
        "type": "string"
      }
    }
  ]
}
```

```python
from madi import validate_policy_file

# Because the above policy has the `ALLOW` action, the following call will return `None`.
# Will not raise a `madi.errors.DeniedPolicy` exception as the `ALLOW` rule was matched.
validate_policy_file("test-policy.policy.json", {"test": "selection"})

# If you want to understand that the policy was explicitly allowed, you can pass in the `raise_allowed`
# parameter to raise a `madi.errors.AllowedPolicy` exception.
validate_policy_file("test-policy.policy.json", {"test": "selection"}, raise_allowed=True)
```

Policies can be loaded from a directory, and all policies in the directory will be evaluated.

```python
from madi import validate_policy_dir

# By default, any files matching the pattern `*.policy.json` will be loaded.
# You can customize this suffix by passing in the `suffix` parameter.
validate_policy_dir("path/to/policies", {"test": "selection"}, suffix=".json")
```

## Cache

The `PolicyCache` class allows caching policy validation results to avoid redundant evaluations of the same policy and payload combinations.

```python
from madi import PolicyCache, validate_policy_file, validate_policy_dir

# Create a cache instance with an optional TTL (in seconds)
cache = PolicyCache(ttl=3600)  # Cache entries expire after 1 hour

# Use cache with single policy file validation
validate_policy_file(
    "test-policy.policy.json",
    {"test": "selection"},
    cache=cache
)

# Cache results can be persisted to disk
with open("policy-cache.json", "wb") as f:
    cache.to_file(f)

# And loaded back
with open("policy-cache.json", "rb") as f:
    cache = PolicyCache.from_file(f)
```

The cache uses a combination of the policy fingerprint and payload to create unique keys. You can control the fingerprint generation using the `fingerprint_policy` parameter:

- `"fast"`: Uses only policy UID and rule UIDs (faster but less precise)
- `"full"`: Uses entire policy content (slower but more precise)

```python
cache = PolicyCache(
    ttl=3600,
    fingerprint_policy="full"  # or "fast"
)
```
