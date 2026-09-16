//! Access maps: the rules a running application stores on its roles and
//! merges with the grants its code declares.
//!
//! An access map is grouped by resource, then by operation. Each rule is
//! `true`, `false`, or a condition that must hold for the rows the operation
//! may touch:
//!
//! ```json
//! {"loans": {"list": true, "read": true,
//!            "update": {"$or": [{"owner": "$user.id"}, {"status": "draft"}]},
//!            "delete": false},
//!  "users": {"list": true}}
//! ```
//!
//! A condition is an object whose keys are field lookups (all of which must
//! match), or one of `$or`, `$and` (arrays of conditions) and `$not`. A lookup
//! is a field name with an optional operator suffix — `amount__gte`,
//! `status__in`, `name__icontains`, `closed__isnull` — defaulting to exact
//! equality. Values are scalars or the actor reference `$user.id`; `in` takes
//! an array of them and `isnull` a boolean. Rules combine with the union
//! semantics of Dynamic REST role grants: any role that grants an operation
//! grants it, and conditional rules are OR-ed together.
use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::{PermissionFilter, Resource};

/// The operations an access map can grant.
pub const OPERATIONS: [&str; 5] = ["list", "read", "create", "update", "delete"];

/// The comparison operators a condition lookup may carry after `__`.
pub const CONDITION_OPERATORS: [&str; 8] = [
    "exact",
    "in",
    "icontains",
    "gt",
    "gte",
    "lt",
    "lte",
    "isnull",
];

/// Split a condition lookup into its field and operator (`exact` when absent).
#[must_use]
pub fn split_lookup(lookup: &str) -> (&str, &str) {
    match lookup.rsplit_once("__") {
        Some((field, operator)) if CONDITION_OPERATORS.contains(&operator) => (field, operator),
        _ => (lookup, "exact"),
    }
}

/// Whether a condition holds for one record, with `actor_id` standing in for
/// `$user.id`. Numbers compare numerically, everything else as text; `in`
/// matches any of its values, `icontains` is a case-insensitive substring
/// test, and a missing field counts as null.
#[must_use]
pub fn condition_matches(record: &Value, lookup: &str, expected: &Value, actor_id: &str) -> bool {
    use std::cmp::Ordering;
    let (field, operator) = split_lookup(lookup);
    let actual = &record[field];
    let resolve = |value: &Value| -> Value {
        if value == "$user.id" {
            Value::String(actor_id.to_owned())
        } else {
            value.clone()
        }
    };
    let as_text = |value: &Value| {
        value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned)
    };
    let number = |value: &Value| -> Option<f64> {
        value
            .as_f64()
            .or_else(|| value.as_str().and_then(|s| s.trim().parse().ok()))
    };
    let compare = |expected: &Value| -> Option<Ordering> {
        if actual.is_null() {
            return None;
        }
        match (number(actual), number(expected)) {
            (Some(a), Some(b)) => a.partial_cmp(&b),
            _ => Some(as_text(actual).cmp(&as_text(expected))),
        }
    };
    let equals = |expected: &Value| compare(expected) == Some(Ordering::Equal);
    match operator {
        "isnull" => actual.is_null() == expected.as_bool().unwrap_or(true),
        "in" => expected
            .as_array()
            .is_some_and(|items| items.iter().any(|item| equals(&resolve(item)))),
        "icontains" => {
            !actual.is_null()
                && as_text(actual)
                    .to_lowercase()
                    .contains(&as_text(&resolve(expected)).to_lowercase())
        }
        "gt" => compare(&resolve(expected)) == Some(Ordering::Greater),
        "gte" => matches!(
            compare(&resolve(expected)),
            Some(Ordering::Greater | Ordering::Equal)
        ),
        "lt" => compare(&resolve(expected)) == Some(Ordering::Less),
        "lte" => matches!(
            compare(&resolve(expected)),
            Some(Ordering::Less | Ordering::Equal)
        ),
        _ => equals(&resolve(expected)),
    }
}

/// Rules for one resource keyed by operation. A `false` rule is not stored:
/// it grants nothing and therefore has no effect under union semantics.
pub type AccessRules = BTreeMap<String, PermissionFilter>;

/// Rules keyed by resource name.
pub type AccessMap = BTreeMap<String, AccessRules>;

/// What rules may say about one resource: `Some(fields)` allows conditions on
/// those fields, `None` allows only `true` and `false` (resources whose
/// storage cannot apply row filters).
pub type AccessTargets = BTreeMap<String, Option<BTreeSet<String>>>;

/// Parse and validate an access map against the resources it may name.
///
/// # Errors
/// Returns a message naming the offending resource, operation or field.
pub fn parse_access_map(value: &Value, targets: &AccessTargets) -> Result<AccessMap, String> {
    let Some(resources) = value.as_object() else {
        return Err("Permissions must be an object keyed by resource.".into());
    };
    let mut map = AccessMap::new();
    for (resource, rules) in resources {
        let Some(fields) = targets.get(resource) else {
            return Err(format!("Unknown resource: {resource}"));
        };
        let Some(rules) = rules.as_object() else {
            return Err(format!(
                "{resource}: rules must be an object keyed by operation."
            ));
        };
        let mut parsed = AccessRules::new();
        for (operation, rule) in rules {
            if !OPERATIONS.contains(&operation.as_str()) {
                return Err(format!("{resource}: unknown operation {operation}"));
            }
            let filter = parse_rule(rule, fields.as_ref())
                .map_err(|error| format!("{resource}.{operation}: {error}"))?;
            if let Some(filter) = filter {
                parsed.insert(operation.clone(), filter);
            }
        }
        if !parsed.is_empty() {
            map.insert(resource.clone(), parsed);
        }
    }
    Ok(map)
}

/// Parse one rule. `Ok(None)` is a rule that grants nothing.
///
/// # Errors
/// Returns a message describing why the rule is malformed.
pub fn parse_rule(
    value: &Value,
    fields: Option<&BTreeSet<String>>,
) -> Result<Option<PermissionFilter>, String> {
    match value {
        Value::Bool(true) => Ok(Some(PermissionFilter::All)),
        Value::Bool(false) | Value::Null => Ok(None),
        Value::Object(_) => {
            let Some(fields) = fields else {
                return Err("only true or false is allowed for this resource.".into());
            };
            parse_condition(value, fields, 0).map(Some)
        }
        _ => Err("a rule must be true, false, or a condition object.".into()),
    }
}

fn parse_condition(
    value: &Value,
    fields: &BTreeSet<String>,
    depth: usize,
) -> Result<PermissionFilter, String> {
    if depth > 8 {
        return Err("conditions are nested too deeply.".into());
    }
    let Some(object) = value.as_object() else {
        return Err("a condition must be an object.".into());
    };
    if object.is_empty() {
        return Err("a condition must name at least one field.".into());
    }
    let mut children = Vec::new();
    for (key, value) in object {
        children.push(match key.as_str() {
            "$or" | "$and" => {
                let Some(items) = value.as_array().filter(|items| !items.is_empty()) else {
                    return Err(format!("{key} must be a non-empty array of conditions."));
                };
                PermissionFilter::Group {
                    connector: key.trim_start_matches('$').into(),
                    negated: false,
                    children: items
                        .iter()
                        .map(|item| parse_condition(item, fields, depth + 1))
                        .collect::<Result<_, _>>()?,
                }
            }
            "$not" => PermissionFilter::Group {
                connector: "and".into(),
                negated: true,
                children: vec![parse_condition(value, fields, depth + 1)?],
            },
            _ => {
                let (name, operator) = split_lookup(key);
                if !fields.contains(name) {
                    return Err(format!("unknown field {name}"));
                }
                let scalar = |value: &Value| -> Result<(), String> {
                    if !(value.is_string() || value.is_number() || value.is_boolean()) {
                        return Err(format!(
                            "{name} must compare with a string, number or boolean."
                        ));
                    }
                    if value
                        .as_str()
                        .is_some_and(|s| s.starts_with('$') && s != "$user.id")
                    {
                        return Err(format!(
                            "{name}: only $user.id may reference the signed-in user."
                        ));
                    }
                    Ok(())
                };
                match operator {
                    "in" => match value.as_array().filter(|items| !items.is_empty()) {
                        Some(items) => items.iter().try_for_each(scalar)?,
                        None => {
                            return Err(format!("{name}__in needs a non-empty list of values."));
                        }
                    },
                    "isnull" => {
                        if !value.is_boolean() {
                            return Err(format!("{name}__isnull must be true or false."));
                        }
                    }
                    _ => scalar(value)?,
                }
                PermissionFilter::Condition {
                    lookup: if operator == "exact" {
                        name.into()
                    } else {
                        format!("{name}__{operator}")
                    },
                    value: value.clone(),
                }
            }
        });
    }
    Ok(if children.len() == 1 {
        children.pop().unwrap_or(PermissionFilter::All)
    } else {
        PermissionFilter::Group {
            connector: "and".into(),
            negated: false,
            children,
        }
    })
}

/// Add a role's rules for one resource to the grants the application declared.
///
/// A resource that declares no grants at all is open to every signed-in user,
/// so rules for it change nothing. Otherwise every granted operation is
/// recorded, and its row filter is the union of what the code and the role say:
/// an unconditional grant from either side lifts the condition of the other.
pub fn grant_access(resource: &mut Resource, role: &str, rules: &AccessRules) {
    if resource.role_grants.is_empty() {
        return;
    }
    for (operation, filter) in rules {
        let operations = resource.role_grants.entry(role.into()).or_default();
        let declared = operations.iter().any(|value| value == operation);
        if !declared {
            operations.push(operation.clone());
        }
        if !resource.role_order.iter().any(|value| value == role) {
            resource.role_order.push(role.into());
        }
        let filters = resource.role_filters.entry(role.into()).or_default();
        let combined = match (declared, filters.remove(operation), filter) {
            // The code granted this operation without a condition: nothing to narrow.
            (true, None, _) | (_, _, PermissionFilter::All) => PermissionFilter::All,
            (_, Some(existing), condition) => PermissionFilter::Group {
                connector: "or".into(),
                negated: false,
                children: vec![existing, condition.clone()],
            },
            (false, None, condition) => condition.clone(),
        };
        filters.insert(operation.clone(), combined);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn targets() -> AccessTargets {
        BTreeMap::from([
            (
                "loans".into(),
                Some(BTreeSet::from(["owner".to_string(), "status".into()])),
            ),
            ("users".into(), None),
        ])
    }

    #[test]
    fn parses_booleans_conditions_and_groups() {
        let map = parse_access_map(
            &json!({"loans": {"list": true, "read": {"owner": "$user.id", "status": "open"}, "update": {"$or": [{"owner": "$user.id"}, {"$not": {"status": "closed"}}]}, "delete": false}, "users": {"list": true}}),
            &targets(),
        )
        .unwrap();
        assert_eq!(map["loans"]["list"], PermissionFilter::All);
        assert!(!map["loans"].contains_key("delete"));
        assert!(
            matches!(&map["loans"]["read"], PermissionFilter::Group { connector, negated: false, children } if connector == "and" && children.len() == 2)
        );
        assert!(
            matches!(&map["loans"]["update"], PermissionFilter::Group { connector, children, .. } if connector == "or" && matches!(children[1], PermissionFilter::Group { negated: true, .. }))
        );
        assert_eq!(map["users"]["list"], PermissionFilter::All);
    }

    #[test]
    fn parses_operators_and_evaluates_them_on_records() {
        let map = parse_access_map(
            &json!({"loans": {"list": {"status__in": ["open", "$user.id"], "owner__icontains": "ann", "status__gte": 3, "owner__isnull": false}}}),
            &targets(),
        )
        .unwrap();
        let PermissionFilter::Group { children, .. } = &map["loans"]["list"] else {
            panic!("expected a group");
        };
        assert_eq!(
            children
                .iter()
                .map(|c| match c {
                    PermissionFilter::Condition { lookup, .. } => lookup.as_str(),
                    _ => "?",
                })
                .collect::<Vec<_>>(),
            vec![
                "owner__icontains",
                "owner__isnull",
                "status__gte",
                "status__in"
            ]
        );
        assert_eq!(split_lookup("owner__exact"), ("owner", "exact"));
        assert_eq!(split_lookup("owner__id"), ("owner__id", "exact"));
        for (value, message) in [
            (json!({"status__in": []}), "non-empty list"),
            (json!({"status__in": "open"}), "non-empty list"),
            (
                json!({"status__in": [{"x": 1}]}),
                "string, number or boolean",
            ),
            (json!({"status__isnull": "yes"}), "true or false"),
            (json!({"status__gte": [1]}), "string, number or boolean"),
        ] {
            let error =
                parse_access_map(&json!({"loans": {"list": value}}), &targets()).unwrap_err();
            assert!(error.contains(message), "{error}");
        }

        let record = json!({"amount": 10, "status": "open", "name": "Annual audit", "owner": "u1"});
        for (lookup, expected, holds) in [
            ("amount", json!(10), true),
            ("amount", json!("10"), true),
            ("amount__gt", json!(9.5), true),
            ("amount__gte", json!(11), false),
            ("amount__lt", json!(11), true),
            ("amount__lte", json!(9), false),
            ("status__in", json!(["closed", "open"]), true),
            ("status__in", json!(["closed"]), false),
            ("name__icontains", json!("AUDIT"), true),
            ("name__icontains", json!("budget"), false),
            ("status__gte", json!("m"), true),
            ("owner__in", json!(["$user.id"]), true),
            ("owner", json!("$user.id"), true),
            ("missing__isnull", json!(true), true),
            ("owner__isnull", json!(true), false),
            ("owner__isnull", json!(false), true),
            ("missing__gt", json!(1), false),
        ] {
            assert_eq!(
                condition_matches(&record, lookup, &expected, "u1"),
                holds,
                "{lookup} {expected}"
            );
        }
    }

    #[test]
    fn rejects_unknown_targets_and_malformed_rules() {
        let cases = [
            (json!({"cars": {"list": true}}), "Unknown resource: cars"),
            (json!({"loans": {"drive": true}}), "unknown operation drive"),
            (
                json!({"loans": {"list": "yes"}}),
                "must be true, false, or a condition",
            ),
            (json!({"loans": {"list": {}}}), "at least one field"),
            (
                json!({"loans": {"list": {"colour": "red"}}}),
                "unknown field colour",
            ),
            (
                json!({"loans": {"list": {"owner": "$user.email"}}}),
                "only $user.id",
            ),
            (json!({"loans": {"list": {"$or": []}}}), "non-empty array"),
            (
                json!({"loans": {"list": {"owner": {"nested": 1}}}}),
                "string, number or boolean",
            ),
            (
                json!({"users": {"list": {"name": "x"}}}),
                "only true or false",
            ),
            (json!([]), "keyed by resource"),
        ];
        for (value, message) in cases {
            let error = parse_access_map(&value, &targets()).unwrap_err();
            assert!(error.contains(message), "{value}: {error}");
        }
    }

    #[test]
    fn grants_union_with_declared_rules_and_leave_open_resources_alone() {
        let mut open = Resource::default();
        grant_access(
            &mut open,
            "clerk",
            &BTreeMap::from([("list".into(), PermissionFilter::All)]),
        );
        assert!(open.role_grants.is_empty());

        let owner = PermissionFilter::Condition {
            lookup: "owner".into(),
            value: json!("$user.id"),
        };
        let draft = PermissionFilter::Condition {
            lookup: "status".into(),
            value: json!("draft"),
        };
        let mut resource = Resource::default();
        resource
            .role_grants
            .insert("clerk".into(), vec!["list".into(), "update".into()]);
        resource.role_order.push("clerk".into());
        resource.role_filters.insert(
            "clerk".into(),
            BTreeMap::from([("update".into(), owner.clone())]),
        );
        grant_access(
            &mut resource,
            "clerk",
            &BTreeMap::from([
                ("list".into(), draft.clone()),
                ("update".into(), draft.clone()),
                ("delete".into(), owner.clone()),
            ]),
        );
        // Declared without a condition: the role's condition cannot narrow it.
        assert_eq!(
            resource.role_filters["clerk"]["list"],
            PermissionFilter::All
        );
        // Both sides conditional: either condition suffices.
        assert!(
            matches!(&resource.role_filters["clerk"]["update"], PermissionFilter::Group { connector, children, .. } if connector == "or" && children == &vec![owner.clone(), draft.clone()])
        );
        // New operation: exactly the role's condition.
        assert_eq!(
            resource.role_grants["clerk"],
            vec!["list", "update", "delete"]
        );
        assert_eq!(resource.role_filters["clerk"]["delete"], owner);

        grant_access(
            &mut resource,
            "manager",
            &BTreeMap::from([("update".into(), PermissionFilter::All)]),
        );
        assert_eq!(resource.role_order, vec!["clerk", "manager"]);
        assert_eq!(
            resource.role_filters["manager"]["update"],
            PermissionFilter::All
        );
    }
}
