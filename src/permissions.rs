use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use crate::{PermissionFilter, Resource};

/// Authentication facts required by Dynamic REST's role-based permission
/// protocol. Applications remain responsible for establishing identity.
#[derive(Clone, Copy, Debug)]
pub struct Principal<'a> {
    pub id: &'a str,
    pub roles: &'a BTreeSet<String>,
    pub is_superuser: bool,
}

/// Combine the row filters of every matching role with Dynamic REST's OR
/// semantics. The caller handles the superuser bypass before applying this
/// predicate to a queryset.
#[must_use]
pub fn row_filter(
    resource: &Resource,
    principal: Option<Principal<'_>>,
    operation: &str,
) -> PermissionFilter {
    let mut filters = Vec::new();
    for role in std::iter::once("*").chain(
        principal
            .into_iter()
            .flat_map(|principal| principal.roles.iter().map(String::as_str)),
    ) {
        let Some(filter) = resource
            .role_filters
            .get(role)
            .and_then(|operations| operations.get(operation))
        else {
            // A role granted the operation without declaring a row filter is
            // unrestricted; only roles with a filter narrow what they see.
            if resource
                .role_grants
                .get(role)
                .is_some_and(|operations| operations.iter().any(|value| value == operation))
            {
                return PermissionFilter::All;
            }
            continue;
        };
        if matches!(filter, PermissionFilter::All) {
            return PermissionFilter::All;
        }
        if !matches!(filter, PermissionFilter::None) {
            filters.push(filter.clone());
        }
    }
    match filters.len() {
        0 => PermissionFilter::None,
        1 => filters.pop().unwrap_or(PermissionFilter::None),
        _ => PermissionFilter::Group {
            connector: "or".into(),
            negated: false,
            children: filters,
        },
    }
}

/// Resolve an operation against declared HTTP methods and role grants.
#[must_use]
pub fn operation_granted(
    resource: &Resource,
    principal: Option<Principal<'_>>,
    operation: &str,
    superuser_bypass: bool,
) -> bool {
    if resource.role_grants.is_empty() {
        return true;
    }
    if superuser_bypass && principal.is_some_and(|principal| principal.is_superuser) {
        return true;
    }
    let declares = |method: &str| resource.allowed_methods.iter().any(|value| value == method);
    let allowed = match operation {
        "create" => declares("POST"),
        "update" => declares("PUT"),
        "delete" => declares("DELETE"),
        "list" | "read" => declares("GET"),
        _ => false,
    };
    allowed && role_grants_operation(resource, principal, operation)
}

#[must_use]
pub fn role_grants_operation(
    resource: &Resource,
    principal: Option<Principal<'_>>,
    operation: &str,
) -> bool {
    let granted = |role: &str| {
        resource
            .role_grants
            .get(role)
            .is_some_and(|operations| operations.iter().any(|value| value == operation))
    };
    granted("*")
        || principal.is_some_and(|principal| principal.roles.iter().any(|role| granted(role)))
}

/// Dynamic REST field permissions after applying matching role overrides in
/// serializer declaration order.
#[must_use]
pub fn field_permissions(resource: &Resource, principal: Option<Principal<'_>>) -> Value {
    let roles = effective_roles(resource, principal);
    let mut fields = Map::new();
    for field in &resource.fields {
        let name = field.name.as_str();
        let read_only = overridden_flag(
            resource,
            &roles,
            name,
            "read_only",
            field.read_only_for("OPTIONS"),
        );
        let write_only = overridden_flag(resource, &roles, name, "write_only", field.write_only);
        let immutable = overridden_flag(resource, &roles, name, "immutable", field.immutable);
        let only_update = overridden_flag(resource, &roles, name, "only_update", field.only_update);
        let mut permission = Map::new();
        permission.insert("read".into(), Value::Bool(!write_only));
        let write = if read_only {
            Value::Bool(false)
        } else if immutable || only_update {
            json!({"update": !immutable, "create": !only_update})
        } else {
            Value::Bool(true)
        };
        permission.insert("write".into(), write);
        let create = field_override(resource, &roles, name, "create")
            .and_then(Value::as_bool)
            .or(field.create);
        if let Some(create) = create {
            permission.insert("create".into(), Value::Bool(create));
        }
        fields.insert(field.name.clone(), Value::Object(permission));
    }
    Value::Object(fields)
}

/// Clone a resource with serializer field flags resolved for the current
/// principal and request method. This gives storage/representation adapters a
/// protocol-level view without coupling them to an application's user type.
#[must_use]
pub fn resource_for_principal(
    resource: &Resource,
    principal: Option<Principal<'_>>,
    method: &str,
) -> Resource {
    let operation = match method {
        "POST" => "create",
        "PUT" | "PATCH" => "update",
        "DELETE" => "delete",
        "GET" => "read",
        _ => "",
    };
    resource_for_principal_operation(resource, principal, method, operation)
}

/// Resolve field and row permissions when an HTTP method maps to a specific
/// queryset operation, such as GET list versus GET detail.
#[must_use]
pub fn resource_for_principal_operation(
    resource: &Resource,
    principal: Option<Principal<'_>>,
    method: &str,
    operation: &str,
) -> Resource {
    let roles = effective_roles(resource, principal);
    let mut effective = resource.clone();
    if !resource.role_filters.is_empty()
        && !principal.is_some_and(|principal| principal.is_superuser)
        && !operation.is_empty()
    {
        effective.effective_row_filter = Some(row_filter(resource, principal, operation));
        effective.row_actor_id = principal.map(|principal| principal.id.to_owned());
    }
    for field in &mut effective.fields {
        field.read_only = overridden_flag(
            resource,
            &roles,
            &field.name,
            "read_only",
            field.read_only_for(method),
        );
        field.write_only = overridden_flag(
            resource,
            &roles,
            &field.name,
            "write_only",
            field.write_only,
        );
        field.immutable =
            overridden_flag(resource, &roles, &field.name, "immutable", field.immutable);
        field.only_update = overridden_flag(
            resource,
            &roles,
            &field.name,
            "only_update",
            field.only_update,
        );
        field.create = field_override(resource, &roles, &field.name, "create")
            .and_then(Value::as_bool)
            .or(field.create);
    }
    effective
}

/// Apply role-selected choice overrides to an extracted metadata document.
pub fn apply_field_choice_overrides(
    resource: &Resource,
    principal: Option<Principal<'_>>,
    metadata: &mut Map<String, Value>,
) {
    let roles = effective_roles(resource, principal);
    let Some(fields) = metadata.get_mut("fields").and_then(Value::as_object_mut) else {
        return;
    };
    for field in &resource.fields {
        let Some(choices) = field_override(resource, &roles, &field.name, "choices") else {
            continue;
        };
        let Some(choices) = choices.as_array() else {
            continue;
        };
        let Some(info) = fields.get_mut(&field.name).and_then(Value::as_object_mut) else {
            continue;
        };
        let rendered = choices
            .iter()
            .map(|choice| match choice {
                Value::Array(pair) if pair.len() >= 2 => json!({
                    "id": pair[0].clone(),
                    "label": pair[1].clone(),
                    "description": Value::Null,
                }),
                value => json!({
                    "id": value.clone(),
                    "label": value.clone(),
                    "description": Value::Null,
                }),
            })
            .collect();
        info.insert("choices".into(), Value::Array(rendered));
    }
}

fn effective_roles<'a>(resource: &'a Resource, principal: Option<Principal<'_>>) -> Vec<&'a str> {
    resource
        .role_order
        .iter()
        .map(String::as_str)
        .filter(|role| {
            *role == "*" || principal.is_some_and(|principal| principal.roles.contains(*role))
        })
        .collect()
}

fn field_override<'a>(
    resource: &'a Resource,
    roles: &[&str],
    field: &str,
    key: &str,
) -> Option<&'a Value> {
    roles.iter().find_map(|role| {
        resource
            .role_field_overrides
            .get(*role)?
            .get(field)?
            .get(key)
    })
}

fn overridden_flag(
    resource: &Resource,
    roles: &[&str],
    field: &str,
    key: &str,
    default: bool,
) -> bool {
    field_override(resource, roles, field, key)
        .and_then(Value::as_bool)
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{Action, Field, FieldKind};

    fn resource() -> Resource {
        Resource {
            namespace: "admin".into(),
            name: "record".into(),
            plural_name: "records".into(),
            table: "record".into(),
            id_field: "id".into(),
            fields: vec![Field {
                name: "secret".into(),
                label: None,
                description: None,
                source: "secret".into(),
                column: Some("secret".into()),
                kind: FieldKind::String,
                required: false,
                read_only: false,
                write_only: false,
                deferred: false,
                nullable: false,
                many: false,
                immutable: false,
                only_update: false,
                create: None,
                creator: false,
                decimal_places: None,
                related_table: None,
                related_pk_column: None,
                reverse_column: None,
                through_table: None,
                through_source_column: None,
                through_target_column: None,
                related_resource: None,
                relation_order: Vec::new(),
                link: crate::RelationLink::Default,
            }],
            actions: Vec::<Action>::new(),
            metadata_actions: Vec::new(),
            allowed_methods: vec!["GET".into(), "POST".into()],
            permission_classes: Vec::new(),
            role_grants: BTreeMap::from([(
                "Admin".into(),
                vec!["list".into(), "read".into(), "create".into()],
            )]),
            role_filters: BTreeMap::new(),
            effective_row_filter: None,
            row_actor_id: None,
            role_order: vec!["Admin".into()],
            role_field_overrides: BTreeMap::from([(
                "Admin".into(),
                json!({"secret": {"write_only": true}}),
            )]),
            list_fields: None,
            default_sort: Vec::new(),
            metadata: None,
        }
    }

    #[test]
    fn combines_methods_roles_and_field_overrides() {
        let resource = resource();
        let roles = BTreeSet::from(["Admin".into()]);
        let principal = Some(Principal {
            id: "actor-id",
            roles: &roles,
            is_superuser: false,
        });
        assert!(operation_granted(&resource, principal, "list", false));
        assert!(!operation_granted(&resource, principal, "update", false));
        assert_eq!(
            field_permissions(&resource, principal)["secret"]["read"],
            false
        );
        assert!(resource_for_principal(&resource, principal, "GET").fields[0].write_only);
    }

    #[test]
    fn combines_matching_row_filters_with_or_semantics() {
        let mut resource = resource();
        resource.role_filters = BTreeMap::from([
            (
                "*".into(),
                BTreeMap::from([(
                    "list".into(),
                    PermissionFilter::Condition {
                        lookup: "is_shared".into(),
                        value: json!(true),
                    },
                )]),
            ),
            (
                "Admin".into(),
                BTreeMap::from([(
                    "list".into(),
                    PermissionFilter::Condition {
                        lookup: "creator".into(),
                        value: json!({"kind": "actor", "path": "id"}),
                    },
                )]),
            ),
        ]);
        let roles = BTreeSet::from(["Admin".into()]);
        let principal = Some(Principal {
            id: "actor-id",
            roles: &roles,
            is_superuser: false,
        });
        let effective = resource_for_principal_operation(&resource, principal, "GET", "list");
        assert!(matches!(
            effective.effective_row_filter,
            Some(PermissionFilter::Group {
                ref connector,
                ref children,
                ..
            }) if connector == "or" && children.len() == 2
        ));
        assert_eq!(effective.row_actor_id.as_deref(), Some("actor-id"));

        let superuser = Some(Principal {
            id: "root",
            roles: &roles,
            is_superuser: true,
        });
        assert!(
            resource_for_principal_operation(&resource, superuser, "GET", "list")
                .effective_row_filter
                .is_none()
        );
    }

    #[test]
    fn validates_required_and_non_null_fields_for_full_writes() {
        let mut resource = resource();
        resource.fields[0].required = true;
        assert_eq!(
            resource
                .validate_input_for(json!({}), "POST")
                .expect_err("required field")
                .to_string(),
            "Field is required: secret"
        );
        assert_eq!(
            resource
                .validate_input_for(json!({"secret": null}), "PUT")
                .expect_err("non-null field")
                .to_string(),
            "Field may not be null: secret"
        );
        assert!(
            resource
                .validate_input_for(json!({}), "PATCH")
                .expect("partial update")
                .is_empty()
        );
    }
}
