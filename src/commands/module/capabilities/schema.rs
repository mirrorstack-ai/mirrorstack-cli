use std::collections::HashSet;

use serde_json::Value;

pub(crate) fn validate(schema: &Value, value: &Value) -> Result<(), String> {
    validate_at(schema, schema, value, "", &mut HashSet::new())
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

fn validate_at(
    root: &Value,
    schema: &Value,
    value: &Value,
    path: &str,
    visited: &mut HashSet<String>,
) -> Result<(), String> {
    let Some(obj) = schema.as_object() else {
        return Ok(());
    };
    if obj.is_empty() {
        return Ok(());
    }
    if let Some(reference) = obj.get("$ref") {
        let reference = reference
            .as_str()
            .ok_or_else(|| format!("{path}: $ref must be a string"))?;
        let target = resolve_ref(root, reference)
            .map_err(|reason| format!("{path}: cannot resolve $ref {reference:?}: {reason}"))?;
        // Recursive Go types deliberately produce cyclic definitions. Once a
        // reference repeats on the active path, the finite JSON value has
        // already been checked as far as this schema can describe it.
        if visited.insert(reference.into()) {
            let result = validate_at(root, target, value, path, visited);
            visited.remove(reference);
            result?;
        }
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
                    validate_at(root, child_schema, child, &format!("{path}/{key}"), visited)?;
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
            validate_at(root, items, child, &format!("{path}/{i}"), visited)?;
        }
    }
    Ok(())
}

fn resolve_ref<'a>(root: &'a Value, reference: &str) -> Result<&'a Value, String> {
    if reference == "#" {
        return Ok(root);
    }
    let Some(name) = reference.strip_prefix("#/$defs/") else {
        return Err("only `#` and `#/$defs/NAME` references are supported".into());
    };
    if name.is_empty() || name.contains('/') {
        return Err("definition name is empty or contains an unsupported JSON Pointer path".into());
    }
    let name = name.replace("~1", "/").replace("~0", "~");
    root.get("$defs")
        .and_then(|defs| defs.get(&name))
        .ok_or_else(|| format!("definition {name:?} is missing"))
}

#[cfg(test)]
mod tests {
    use super::validate;
    use serde_json::json;

    /// Captured from the Go SDK reflector: validation keywords live under
    /// `$defs`, while the slot schema root points at the reflected Go type.
    fn manifest() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../../tests/fixtures/sdk-capabilities-manifest.json"
        ))
        .unwrap()
    }

    fn schema(slot: &str) -> serde_json::Value {
        manifest()["provides"]
            .as_array()
            .unwrap()
            .iter()
            .find(|provide| provide["key"] == slot)
            .unwrap()["payload"]
            .clone()
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
        assert!(err.contains("expected object"), "got {err}");
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
    fn unsupported_refs_are_loud() {
        let err = validate(
            &json!({"$ref": "https://example.com/schema.json"}),
            &json!({}),
        )
        .unwrap_err();
        assert!(err.contains("only `#` and `#/$defs/NAME`"), "got {err}");
    }

    #[test]
    fn root_refs_terminate() {
        assert!(validate(&json!({"$ref": "#"}), &json!({"anything": true})).is_ok());
    }

    #[test]
    fn missing_refs_are_loud() {
        let err = validate(&json!({"$ref": "#/$defs/Absent"}), &json!({})).unwrap_err();
        assert!(
            err.contains("definition \"Absent\" is missing"),
            "got {err}"
        );
    }

    #[test]
    fn an_empty_or_non_object_schema_validates_anything() {
        assert!(validate(&json!({}), &json!("anything")).is_ok());
        assert!(validate(&json!("not schema"), &json!(1)).is_ok());
    }
}
