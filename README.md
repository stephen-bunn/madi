# MADI
Dead simple JSON policy engine.

## Usage

Policies are defined in JSON following the following format.

```json
// test-policy.policy.json
{
  "ref": "PolicyReference",
  "rules": [
    {
      "ref": "RuleReference",
      "action": "DENY", // DENY or ALLOW
      "select": "test", // A JMESPath expression to select data from the input <https://jmespath.org/>
      "schema": { // A JSONSchema (draft-07) to validate the selected data <https://json-schema.org/>
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
  "ref": "PolicyReference",
  "rules": [
    {
      "ref": "RuleReference",
      "action": "ALLOW",
      "select": "test",
      "schema": {
        "type": "string"
      }
    },
    {
      "ref": "RuleReference",
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
validate_policy_dir("path/to/policies", {"test": "selection"})
```
