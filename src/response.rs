use std::collections::BTreeMap;

use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;

use crate::sanitize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PageMeta {
    pub page: u32,
    pub per_page: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_results: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_pages: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub more_pages: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

impl PageMeta {
    #[must_use]
    pub fn new(page: u32, per_page: u32, total_results: u64) -> Self {
        let total_pages = total_results
            .div_ceil(u64::from(per_page))
            .max(1)
            .try_into()
            .unwrap_or(u32::MAX);
        Self {
            page,
            per_page,
            total_results: Some(total_results),
            total_pages: Some(total_pages),
            more_pages: None,
            cursor: None,
        }
    }

    #[must_use]
    pub fn without_count(page: u32, per_page: u32, more_pages: bool) -> Self {
        Self {
            page,
            per_page,
            total_results: None,
            total_pages: None,
            more_pages: Some(more_pages),
            cursor: None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
pub struct ApiDocument {
    pub resources: BTreeMap<String, Value>,
    pub meta: Option<Value>,
}

impl Serialize for ApiDocument {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut wire = self
            .resources
            .iter()
            .map(|(name, value)| (name.clone(), sanitize(value)))
            .collect::<BTreeMap<_, _>>();
        if let Some(meta) = &self.meta {
            wire.insert("meta".into(), sanitize(meta));
        }
        wire.serialize(serializer)
    }
}

impl ApiDocument {
    #[must_use]
    pub fn one(name: impl Into<String>, value: Value) -> Self {
        Self {
            resources: BTreeMap::from([(name.into(), value)]),
            meta: None,
        }
    }

    #[must_use]
    pub fn many(name: impl Into<String>, values: Vec<Value>, page: PageMeta) -> Self {
        let name = name.into();
        Self {
            resources: BTreeMap::from([(name.clone(), Value::Array(values))]),
            meta: Some(serde_json::to_value(page).unwrap_or(Value::Null)),
        }
    }

    #[must_use]
    pub fn many_unpaged(name: impl Into<String>, values: Vec<Value>) -> Self {
        Self {
            resources: BTreeMap::from([(name.into(), Value::Array(values))]),
            meta: None,
        }
    }

    pub fn sideload(&mut self, name: impl Into<String>, values: Vec<Value>) {
        self.resources.insert(name.into(), Value::Array(values));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_page_count() {
        assert_eq!(PageMeta::new(1, 50, 101).total_pages, Some(3));
        assert_eq!(PageMeta::new(1, 50, 0).total_pages, Some(1));
    }

    #[test]
    fn internal_resource_identity_is_never_serialized() {
        let document = ApiDocument::one(
            "user",
            serde_json::json!({"id": 1, "_meta": {"id": 1, "type": "users"}}),
        );
        assert_eq!(
            serde_json::to_value(document).unwrap(),
            serde_json::json!({"user": {"id": 1}})
        );
    }
}
