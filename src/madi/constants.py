POLICY_SUFFIX = ".policy.json"
"""The suffix for policy files."""

POLICY_META_SCHEMA_V1 = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Madi Policy (v1)",
    "description": "Defines a Madi Policy (v1) containing multiple rules that can be evaluated against JSON objects.",
    "definitions": {
        "rule": {
            "type": "object",
            "required": ["ref", "uid", "action", "select", "schema"],
            "properties": {
                "ref": {
                    "description": "A identifying reference to this rule; preferably a unique identifier.",
                    "type": "string",
                    "minLength": 1,
                },
                "uid": {
                    "description": "A unique identifier for this rule; preferably a UUID.",
                    "type": "string",
                    "minLength": 1,
                },
                "action": {
                    "description": "The action to take if the rule selection matches the schema.",
                    "type": "string",
                    "enum": ["DENY", "ALLOW"],
                },
                "select": {
                    "description": "A JMESPath expression to select the object to evaluate against the schema.",
                    "type": "string",
                    "minLength": 1,
                },
                "schema": {
                    "description": "A JSONSchema (draft 7) to evaluate the selected object against.",
                    "$ref": "http://json-schema.org/draft-07/schema#",
                },
                "strict": {
                    "description": "If true, the rule will fail if the schema does not match the selected object.",
                    "type": "boolean",
                },
                "description": {
                    "description": "A human-readable description of the rule.",
                    "type": "string",
                },
            },
        }
    },
    "type": "object",
    "required": ["ref", "uid", "rules"],
    "properties": {
        "v": {
            "description": "The version identifier of the policy schema.",
            "type": "string",
            "const": "1",
        },
        "ref": {
            "description": "A identifying reference to this policy; preferably a unique identifier.",
            "type": "string",
            "minLength": 1,
        },
        "uid": {
            "description": "A unique identifier for this policy; preferably a UUID.",
            "type": "string",
            "minLength": 1,
        },
        "strict": {
            "description": "If true, the policy will fail if any rule fails.",
            "type": "boolean",
        },
        "description": {
            "description": "A human-readable description of the policy.",
            "type": "string",
        },
        "rules": {
            "description": "An array of rules to evaluate against JSON objects.",
            "type": "array",
            "items": {"$ref": "#/definitions/rule"},
        },
    },
}
"""The Madi Policy (v1) meta JSONSchema (draft v7) for validating a policy specification."""

POLICY_META_SCHEMAS = {"1": POLICY_META_SCHEMA_V1}
"""A mapping of policy schema versions to their respective JSONSchema."""

DEFAULT_POLICY_META_SCHEMA = POLICY_META_SCHEMA_V1
"""The default policy schema to use when validating a policy."""
