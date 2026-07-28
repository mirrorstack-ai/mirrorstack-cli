use serde_json::Value;

pub(crate) fn validate(schema: &Value, value: &Value) -> Result<(), String> {
    validate_at(schema, value, "")
}

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn validate_at(schema: &Value, value: &Value, path: &str) -> Result<(), String> {
    let Some(obj) = schema.as_object() else {
        return Ok(());
    };
    if obj.is_empty() {
        return Ok(());
    }
    if let Some(values) = obj.get("enum").and_then(Value::as_array)
        && !values.contains(value)
    {
        return Err(format!("{path}: value is not in enum"));
    }
    // Go zero values and pointer fields commonly serialize as null, so null is
    // accepted even when a generated SDK schema names a concrete type.
    if !value.is_null()
        && let Some(types) = obj.get("type")
    {
        let allowed: Vec<&str> = match types {
            Value::String(s) => vec![s],
            Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        let actual = kind(value);
        let matches = allowed
            .iter()
            .any(|t| *t == actual || (*t == "number" && actual == "integer"));
        if !allowed.is_empty() && !matches {
            return Err(format!(
                "{path}: expected {}, got {actual}",
                allowed.join(" or ")
            ));
        }
    }
    if let Some(map) = value.as_object() {
        let properties = obj.get("properties").and_then(Value::as_object);
        if let Some(required) = obj.get("required").and_then(Value::as_array) {
            for name in required.iter().filter_map(Value::as_str) {
                if !map.contains_key(name) {
                    return Err(format!("{path}/{name}: required property is missing"));
                }
            }
        }
        if let Some(properties) = properties {
            for (key, child_schema) in properties {
                if let Some(child) = map.get(key) {
                    validate_at(child_schema, child, &format!("{path}/{key}"))?;
                }
            }
        }
        if obj.get("additionalProperties") == Some(&Value::Bool(false))
            && let Some(key) = map
                .keys()
                .find(|key| properties.is_none_or(|p| !p.contains_key(*key)))
        {
            return Err(format!("{path}/{key}: additional property is not allowed"));
        }
    }
    if let (Some(items), Some(values)) = (obj.get("items"), value.as_array()) {
        for (i, child) in values.iter().enumerate() {
            validate_at(items, child, &format!("{path}/{i}"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate;
    use serde_json::json;

    /// The shape an SDK-derived schema takes: typed properties, a required
    /// list, a nested array item schema, and a keyword this validator does
    /// not know (`futureKeyword`) that must be ignored rather than rejected.
    fn schema() -> serde_json::Value {
        json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {"type": "string"},
                "age": {"type": ["integer", "null"]},
                "tags": {"type": "array", "items": {"enum": ["a", "b"]}}
            },
            "additionalProperties": false,
            "futureKeyword": 42
        })
    }

    #[test]
    fn accepts_a_conforming_payload() {
        assert!(validate(&schema(), &json!({"name": "x", "age": null, "tags": ["a"]})).is_ok());
    }

    #[test]
    fn missing_required_property_names_the_path() {
        let err = validate(&schema(), &json!({"age": 1, "tags": []})).unwrap_err();
        assert!(err.contains("/name"), "got {err}");
    }

    #[test]
    fn wrong_property_type_names_the_expected_type() {
        let err = validate(&schema(), &json!({"name": 3, "tags": []})).unwrap_err();
        assert!(err.contains("expected string"), "got {err}");
    }

    #[test]
    fn enum_violation_inside_an_array_names_the_index() {
        let err = validate(&schema(), &json!({"name": "x", "tags": ["c"]})).unwrap_err();
        assert!(err.contains("/tags/0"), "got {err}");
    }

    #[test]
    fn additional_property_rejected_only_when_explicitly_closed() {
        let err = validate(&schema(), &json!({"name": "x", "tags": [], "extra": 1})).unwrap_err();
        assert!(err.contains("additional"), "got {err}");
        // Same payload, schema silent on additionalProperties → allowed.
        let open = json!({"type": "object", "properties": {"name": {"type": "string"}}});
        assert!(validate(&open, &json!({"name": "x", "extra": 1})).is_ok());
    }

    #[test]
    fn a_present_but_null_value_satisfies_a_concrete_type() {
        // Go zero values and pointer fields serialize as null; treating that as
        // a mismatch would fail every optional field.
        let s = json!({"type": "object", "properties": {"name": {"type": "string"}}});
        assert!(validate(&s, &json!({"name": null})).is_ok());
    }

    #[test]
    fn an_integer_satisfies_a_number_type() {
        assert!(validate(&json!({"type": "number"}), &json!(1)).is_ok());
    }

    #[test]
    fn an_empty_or_non_object_schema_validates_anything() {
        assert!(validate(&json!({}), &json!("anything")).is_ok());
        assert!(validate(&json!("not schema"), &json!(1)).is_ok());
    }
}
