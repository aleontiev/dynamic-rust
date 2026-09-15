use serde_json::{Map, Value};

use crate::{
    Principal, Resource, apply_field_choice_overrides, field_permissions, operation_granted,
};

/// Build the Dynamic REST OPTIONS document for a resource from its extracted
/// serializer metadata and the current principal's permission facts.
#[must_use]
pub fn resource_metadata(resource: &Resource, principal: Option<Principal<'_>>) -> Value {
    let mut metadata = resource
        .metadata
        .clone()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    metadata
        .entry("label")
        .or_insert_with(|| Value::String(python_title(&resource.plural_name)));
    apply_field_choice_overrides(resource, principal, &mut metadata);

    let mut permissions = Map::new();
    if !resource.role_grants.is_empty() {
        // A superuser principal is created only deliberately, so metadata reports its real access.
        for operation in ["create", "update", "delete", "list", "read"] {
            permissions.insert(
                operation.into(),
                Value::Bool(operation_granted(resource, principal, operation, true)),
            );
        }
    }
    permissions.insert("fields".into(), field_permissions(resource, principal));
    metadata.insert("permissions".into(), Value::Object(permissions));
    metadata.insert(
        "actions".into(),
        Value::Array(resource.metadata_actions.clone()),
    );
    Value::Object(metadata)
}

/// Match Python's `str.title()` behavior used for fallback resource labels.
#[must_use]
pub fn python_title(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut previous_alphabetic = false;
    for character in value.chars() {
        if character.is_alphabetic() && !previous_alphabetic {
            output.extend(character.to_uppercase());
        } else {
            output.extend(character.to_lowercase());
        }
        previous_alphabetic = character.is_alphabetic();
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_keeps_python_underscore_boundary_behavior() {
        assert_eq!(python_title("asset_assignments"), "Asset_Assignments");
    }
}
