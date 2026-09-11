use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ApiError;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RouteRegistration {
    pub resource_key: String,
    pub resource_name: String,
    pub path: String,
}

/// Framework-neutral canonical resource registry matching Dynamic REST's
/// global reverse routing contract.
#[derive(Clone, Debug, Default)]
pub struct DynamicRouter {
    script_prefix: String,
    by_key: BTreeMap<String, RouteRegistration>,
    key_by_name: BTreeMap<String, String>,
}

impl DynamicRouter {
    #[must_use]
    pub fn new(script_prefix: impl Into<String>) -> Self {
        Self {
            script_prefix: normalize_prefix(&script_prefix.into()),
            ..Self::default()
        }
    }

    /// Register the one canonical path for a resource key and singular name.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Conflict`] if either identity is already mapped.
    pub fn register(
        &mut self,
        resource_key: impl Into<String>,
        resource_name: impl Into<String>,
        path: impl Into<String>,
    ) -> Result<(), ApiError> {
        let resource_key = resource_key.into();
        let resource_name = resource_name.into();
        let path = path.into().trim_matches('/').to_owned();
        if let Some(existing) = self.by_key.get(&resource_key) {
            return Err(ApiError::Conflict(format!(
                "The resource '{resource_key}' is already mapped to '{}'.",
                existing.path
            )));
        }
        if let Some(existing_key) = self.key_by_name.get(&resource_name) {
            return Err(ApiError::Conflict(format!(
                "The resource name '{resource_name}' is already mapped to '{existing_key}'."
            )));
        }
        self.key_by_name
            .insert(resource_name.clone(), resource_key.clone());
        self.by_key.insert(
            resource_key.clone(),
            RouteRegistration {
                resource_key,
                resource_name,
                path,
            },
        );
        Ok(())
    }

    #[must_use]
    pub fn canonical_path(&self, resource_key: &str, pk: Option<&str>) -> Option<String> {
        let registration = self.by_key.get(resource_key)?;
        let base = format!("{}{}", self.script_prefix, registration.path);
        Some(pk.map_or(base.clone(), |pk| format!("{base}/{pk}/")))
    }

    #[must_use]
    pub fn canonical_path_by_name(&self, resource_name: &str, pk: Option<&str>) -> Option<String> {
        self.key_by_name
            .get(resource_name)
            .and_then(|key| self.canonical_path(key, pk))
    }

    #[must_use]
    pub fn registration(&self, resource_key: &str) -> Option<&RouteRegistration> {
        self.by_key.get(resource_key)
    }
}

fn normalize_prefix(prefix: &str) -> String {
    if prefix.is_empty() || prefix == "/" {
        "/".into()
    } else {
        format!("/{}/", prefix.trim_matches('/'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_upstream_canonical_path_cases() {
        let mut router = DynamicRouter::new("");
        router.register("dogs_table", "dog", "dogs").unwrap();
        assert_eq!(router.canonical_path("dogs_table", None).unwrap(), "/dogs");
        assert_eq!(
            router.canonical_path("dogs_table", Some("1")).unwrap(),
            "/dogs/1/"
        );

        let mut prefixed = DynamicRouter::new("/v2/");
        prefixed.register("cats_table", "cat", "cats").unwrap();
        assert_eq!(
            prefixed.canonical_path("cats_table", None).unwrap(),
            "/v2/cats"
        );
        assert_eq!(
            prefixed.canonical_path_by_name("cat", Some("8")).unwrap(),
            "/v2/cats/8/"
        );
    }

    #[test]
    fn rejects_duplicate_canonical_identities() {
        let mut router = DynamicRouter::new("/");
        router.register("dogs", "dog", "dogs").unwrap();
        assert!(router.register("dogs", "hound", "hounds").is_err());
        assert!(router.register("hounds", "dog", "hounds").is_err());
    }
}
