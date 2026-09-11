use serde_json::Value;

/// Recognize both Dynamic REST bulk payload forms: a bare JSON array or an
/// object containing exactly the plural resource envelope.
#[must_use]
pub fn bulk_payload<'a>(plural_name: &str, value: &'a Value) -> Option<&'a [Value]> {
    if let Value::Array(values) = value {
        return Some(values);
    }
    let object = value.as_object()?;
    if object.len() != 1 {
        return None;
    }
    object.get(plural_name)?.as_array().map(Vec::as_slice)
}

/// Unwrap a single-resource envelope when it is the payload's only key.
#[must_use]
pub fn unwrap_single_payload(name: &str, value: Value) -> Value {
    let Some(object) = value.as_object() else {
        return value;
    };
    if object.len() == 1 {
        if let Some(nested) = object.get(name) {
            return nested.clone();
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn recognizes_bare_and_enveloped_bulk_payloads() {
        let bare = json!([{"id": 1}]);
        let enveloped = json!({"users": [{"id": 1}]});
        assert_eq!(bulk_payload("users", &bare).unwrap().len(), 1);
        assert_eq!(bulk_payload("users", &enveloped).unwrap().len(), 1);
        assert!(bulk_payload("groups", &enveloped).is_none());
    }

    #[test]
    fn only_unwraps_an_exact_single_envelope() {
        assert_eq!(
            unwrap_single_payload("user", json!({"user": {"name": "A"}})),
            json!({"name": "A"})
        );
        assert_eq!(
            unwrap_single_payload("user", json!({"user": {}, "meta": {}})),
            json!({"user": {}, "meta": {}})
        );
    }
}
