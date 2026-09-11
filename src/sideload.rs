use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::{ApiDocument, representation::IDENTITY_KEY};

/// Dynamic REST's prefix when a related object has the same type as the
/// primary resource.
pub const ADDITIONAL_PRIMARY_RESOURCE_PREFIX: &str = "+";

/// Convert nested tagged resource objects into Dynamic REST sideload buckets.
pub struct SideloadingProcessor {
    primary_plural: String,
    buckets: BTreeMap<String, Vec<Value>>,
    seen: BTreeMap<String, BTreeSet<String>>,
}

impl SideloadingProcessor {
    #[must_use]
    pub fn new(primary_plural: impl Into<String>) -> Self {
        Self {
            primary_plural: primary_plural.into(),
            buckets: BTreeMap::new(),
            seen: BTreeMap::new(),
        }
    }

    /// Process every primary object in a document, preserving the primary
    /// envelope and adding related resource buckets.
    pub fn process(mut self, document: &mut ApiDocument) {
        let primary_names: Vec<_> = document.resources.keys().cloned().collect();
        for name in primary_names {
            if let Some(value) = document.resources.get_mut(&name) {
                self.visit(value, 0);
            }
        }
        document.resources.extend(
            self.buckets
                .into_iter()
                .map(|(name, values)| (name, Value::Array(values))),
        );
    }

    fn visit(&mut self, value: &mut Value, depth: usize) {
        match value {
            Value::Array(values) => {
                for value in values {
                    self.visit(value, depth);
                }
            }
            Value::Object(object) => {
                let child_names: Vec<_> = object
                    .keys()
                    .filter(|name| name.as_str() != IDENTITY_KEY)
                    .cloned()
                    .collect();
                for name in child_names {
                    if let Some(child) = object.get_mut(&name) {
                        if child.is_array() || child.is_object() {
                            self.visit(child, depth + 1);
                        }
                    }
                }
                let Some(identity) = object.get(IDENTITY_KEY).and_then(Value::as_object) else {
                    return;
                };
                let Some(resource_type) = identity.get("type").and_then(Value::as_str) else {
                    return;
                };
                let Some(id) = identity.get("id").cloned() else {
                    return;
                };
                let embed = identity
                    .get("embed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if depth == 0 || embed {
                    return;
                }
                let bucket_name = if resource_type == self.primary_plural {
                    format!("{ADDITIONAL_PRIMARY_RESOURCE_PREFIX}{resource_type}")
                } else {
                    resource_type.to_owned()
                };
                let seen_key = serde_json::to_string(&id).unwrap_or_default();
                let already_seen = !self
                    .seen
                    .entry(bucket_name.clone())
                    .or_default()
                    .insert(seen_key);
                let object_value = Value::Object(object.clone());
                if already_seen {
                    merge_duplicate(
                        self.buckets.entry(bucket_name).or_default(),
                        &id,
                        &object_value,
                    );
                } else {
                    self.buckets
                        .entry(bucket_name)
                        .or_default()
                        .push(object_value);
                }
                *value = id;
            }
            _ => {}
        }
    }
}

fn merge_duplicate(bucket: &mut [Value], id: &Value, duplicate: &Value) {
    let Some(duplicate) = duplicate.as_object() else {
        return;
    };
    for existing in bucket {
        let same_id = existing.get(IDENTITY_KEY).and_then(|meta| meta.get("id")) == Some(id);
        if same_id {
            if let Some(existing) = existing.as_object_mut() {
                existing.extend(duplicate.clone());
            }
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::tag_resource;

    #[test]
    fn sideloads_deduplicates_and_replaces_relations_with_ids() {
        let mut location = json!({"id": 7, "name": "Kampala"});
        tag_resource(location.as_object_mut().unwrap(), "locations", &json!(7));
        let mut first = json!({"id": 1, "location": location.clone()});
        tag_resource(first.as_object_mut().unwrap(), "users", &json!(1));
        let mut second = json!({"id": 2, "location": location});
        tag_resource(second.as_object_mut().unwrap(), "users", &json!(2));
        let mut document = ApiDocument::many_unpaged("users", vec![first, second]);

        SideloadingProcessor::new("users").process(&mut document);

        assert_eq!(document.resources["users"][0]["location"], json!(7));
        assert_eq!(document.resources["users"][1]["location"], json!(7));
        assert_eq!(document.resources["locations"].as_array().unwrap().len(), 1);
        let wire = serde_json::to_value(document).unwrap();
        assert!(!wire.to_string().contains(IDENTITY_KEY));
    }

    #[test]
    fn prefixes_related_primary_resource_type() {
        let mut manager = json!({"id": 2});
        tag_resource(manager.as_object_mut().unwrap(), "users", &json!(2));
        let mut user = json!({"id": 1, "manager": manager});
        tag_resource(user.as_object_mut().unwrap(), "users", &json!(1));
        let mut document = ApiDocument::one("user", user);
        SideloadingProcessor::new("users").process(&mut document);
        assert!(document.resources.contains_key("+users"));
    }
}
