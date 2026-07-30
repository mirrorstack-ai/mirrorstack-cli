use serde_json::Value;

pub(crate) struct Validator(jsonschema::Validator);

impl Validator {
    pub(crate) fn compile(schema: &Value) -> Result<Self, String> {
        jsonschema::draft202012::options()
            .build(schema)
            .map(Self)
            .map_err(|error| format!("invalid schema: {error}"))
    }

    pub(crate) fn validate(&self, value: &Value) -> Result<(), String> {
        self.0.validate(value).map_err(|error| {
            let mut path = error.instance_path().to_string();
            match error.kind() {
                jsonschema::error::ValidationErrorKind::AdditionalProperties { unexpected } => {
                    if let Some(property) = unexpected.first() {
                        push_pointer_segment(&mut path, property);
                    }
                }
                jsonschema::error::ValidationErrorKind::Required { property } => {
                    if let Some(property) = property.as_str() {
                        push_pointer_segment(&mut path, property);
                    }
                }
                _ => {}
            }
            format!("{path}: {error}")
        })
    }
}

fn push_pointer_segment(pointer: &mut String, segment: &str) {
    pointer.push('/');
    pointer.push_str(&segment.replace('~', "~0").replace('/', "~1"));
}

#[cfg(test)]
mod tests {
    use super::Validator;
    use serde_json::{Value, json};

    /// Captured from the Go SDK reflector: validation keywords live under
    /// `$defs`, while the slot schema root points at the reflected Go type.
    fn manifest() -> Value {
        serde_json::from_str(include_str!(
            "../../../../tests/fixtures/sdk-capabilities-manifest.json"
        ))
        .unwrap()
    }

    fn schema(slot: &str) -> Value {
        manifest()["provides"]
            .as_array()
            .unwrap()
            .iter()
            .find(|provide| provide["key"] == slot)
            .unwrap()["payload"]
            .clone()
    }

    fn validate(schema: &Value, value: &Value) -> Result<(), String> {
        Validator::compile(schema)?.validate(value)
    }

    #[test]
    fn accepts_a_conforming_payload() {
        assert!(
            validate(
                &schema("user-detail-blocks"),
                &json!({"title": "Roles", "bodyUrl": "/users/roles"})
            )
            .is_ok()
        );
    }

    #[test]
    fn missing_required_property_names_the_path() {
        let err = validate(
            &schema("user-detail-blocks"),
            &json!({"totally": "wrong", "nope": [1, 2, 3]}),
        )
        .unwrap_err();
        assert!(
            err.contains("/title") || err.contains("/bodyUrl"),
            "got {err}"
        );
    }

    #[test]
    fn wrong_property_type_names_the_expected_type() {
        let err = validate(
            &schema("users-table-columns"),
            &json!("i am not even an object"),
        )
        .unwrap_err();
        assert!(err.contains("object"), "got {err}");
    }

    #[test]
    fn cyclic_defs_terminate() {
        assert!(
            validate(
                &schema("cyclic-node"),
                &json!({"value": "root", "next": {"value": "child"}})
            )
            .is_ok()
        );
    }

    #[test]
    fn recursive_defs_reject_invalid_nested_values_at_their_path() {
        let err = validate(
            &schema("cyclic-node"),
            &json!({
                "value": "root",
                "next": {
                    "value": "child",
                    "next": {"value": 42}
                }
            }),
        )
        .unwrap_err();
        assert!(err.contains("/next/next/value"), "got {err}");
        assert!(err.contains("string"), "got {err}");
    }

    #[test]
    fn recursive_defs_accept_deeply_nested_valid_values() {
        assert!(
            validate(
                &schema("cyclic-node"),
                &json!({"value": "root", "next": {"value": 42}})
            )
            .is_err()
        );
        assert!(
            validate(
                &schema("cyclic-node"),
                &json!({
                    "value": "root",
                    "next": {
                        "value": "child",
                        "next": {
                            "value": "grandchild",
                            "next": {"value": "great-grandchild"}
                        }
                    }
                })
            )
            .is_ok()
        );
    }

    #[test]
    fn schema_valued_additional_properties_validate_map_values() {
        let map_schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "#/$defs/StringMap",
            "$defs": {
                "StringMap": {
                    "type": "object",
                    "additionalProperties": {"$ref": "#/$defs/Entry"}
                },
                "Entry": {
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"],
                    "additionalProperties": false
                }
            }
        });

        let err = validate(&map_schema, &json!({"first": {"value": 42}})).unwrap_err();
        assert!(err.contains("/first/value"), "got {err}");
        assert!(err.contains("string"), "got {err}");
    }

    #[test]
    fn additional_properties_false_rejects_unknown_keys() {
        let err = validate(
            &schema("auth-provider"),
            &json!({"slug": "google", "unknown": true}),
        )
        .unwrap_err();
        assert!(err.contains("/unknown"), "got {err}");
        assert!(err.contains("Additional properties"), "got {err}");
    }

    #[test]
    fn unsupported_refs_are_loud() {
        let err = Validator::compile(&json!({"$ref": "https://example.com/schema.json"}))
            .err()
            .unwrap();
        assert!(err.contains("invalid schema"), "got {err}");
    }

    #[test]
    fn missing_refs_are_loud() {
        let err = Validator::compile(&json!({"$ref": "#/$defs/Absent"}))
            .err()
            .unwrap();
        assert!(err.contains("invalid schema"), "got {err}");
        assert!(err.contains("Absent"), "got {err}");
    }

    #[test]
    fn an_empty_schema_validates_anything() {
        assert!(validate(&json!({}), &json!("anything")).is_ok());
    }
}
