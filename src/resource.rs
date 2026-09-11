use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

use crate::{ApiDocument, ApiError, QueryFeatures, Sort};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Boolean,
    Date,
    DateTime,
    Decimal,
    Duration,
    Email,
    File,
    Float,
    Integer,
    Json,
    Money,
    Relation,
    String,
    Time,
    Uuid,
}

/// Relationship link behavior declared by a Dynamic REST field.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum RelationLink {
    #[default]
    Default,
    Disabled,
    Static(String),
    /// The host adapter must resolve the serializer's callable link.
    Custom,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct Field {
    pub name: String,
    pub source: String,
    /// Concrete legacy database column. `None` denotes a computed/reverse field.
    pub column: Option<String>,
    pub kind: FieldKind,
    pub required: bool,
    pub read_only: bool,
    pub write_only: bool,
    pub deferred: bool,
    pub nullable: bool,
    pub many: bool,
    /// Writable on create but not on update.
    pub immutable: bool,
    /// Writable on update but not on create.
    pub only_update: bool,
    /// Serializer-declared `create` permission, absent for most fields.
    pub create: Option<bool>,
    /// Populated from the authenticated actor by `DynamicCreatorField`.
    #[serde(default)]
    pub creator: bool,
    /// Decimal scale declared by the serializer, when applicable.
    pub decimal_places: Option<u32>,
    pub related_table: Option<String>,
    pub related_pk_column: Option<String>,
    pub reverse_column: Option<String>,
    pub through_table: Option<String>,
    pub through_source_column: Option<String>,
    pub through_target_column: Option<String>,
    pub related_resource: Option<String>,
    /// Ordering declared by a relation field's queryset.
    #[serde(default)]
    pub relation_order: Vec<Sort>,
    #[serde(default)]
    pub link: RelationLink,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Action {
    pub name: String,
    pub methods: Vec<String>,
    pub detail: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct PermissionSet {
    pub list: bool,
    pub read: bool,
    pub create: bool,
    pub update: bool,
    pub delete: bool,
}

/// Portable representation of a Dynamic REST role's row-level queryset filter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PermissionFilter {
    All,
    None,
    Group {
        connector: String,
        negated: bool,
        children: Vec<Self>,
    },
    Condition {
        lookup: String,
        value: Value,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resource {
    pub namespace: String,
    pub name: String,
    pub plural_name: String,
    pub table: String,
    pub id_field: String,
    pub fields: Vec<Field>,
    pub actions: Vec<Action>,
    pub metadata_actions: Vec<Value>,
    pub allowed_methods: Vec<String>,
    pub permission_classes: Vec<String>,
    pub role_grants: BTreeMap<String, Vec<String>>,
    /// Row-level filters keyed by role and operation.
    #[serde(default)]
    pub role_filters: BTreeMap<String, BTreeMap<String, PermissionFilter>>,
    /// Request-specific row predicate resolved from the authenticated roles.
    #[serde(skip)]
    pub effective_row_filter: Option<PermissionFilter>,
    /// Authenticated user used to resolve symbolic actor values in that predicate.
    #[serde(skip)]
    pub row_actor_id: Option<String>,
    /// Serializer declaration order of roles. Dynamic REST merges field
    /// overrides so that the earliest declared matching role wins.
    pub role_order: Vec<String>,
    pub role_field_overrides: BTreeMap<String, Value>,
    pub list_fields: Option<Vec<String>>,
    /// Queryset/model ordering used when the request does not supply sort[].
    pub default_sort: Vec<Sort>,
    pub metadata: Option<Value>,
}

impl Field {
    /// Dynamic REST rewrites `read_only` per request method for immutable and
    /// only-update fields, overriding whatever the serializer declared.
    #[must_use]
    pub fn read_only_for(&self, method: &str) -> bool {
        if self.only_update {
            // `DynamicModelSerializer.get_fields` tests `method in ("POST")`,
            // a substring match, so a missing method reads as POST.
            return "POST".contains(method);
        }
        if self.immutable {
            return matches!(method, "GET" | "PUT" | "PATCH");
        }
        self.read_only
    }
}

impl Resource {
    #[must_use]
    pub fn requires_authentication(&self) -> bool {
        self.permission_classes
            .iter()
            .any(|permission| permission.ends_with(".IsAuthenticated"))
    }
}

impl Resource {
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|field| field.name == name)
    }

    /// Validate and unwrap an incoming resource object.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Parse`] when the payload is not an object, names an
    /// unknown field, or attempts to write a read-only field.
    pub fn validate_input(&self, value: Value) -> Result<Map<String, Value>, ApiError> {
        self.validate_input_for(value, "POST")
    }

    /// Validate input using request-specific immutable/only-update semantics.
    /// Optional non-null fields supplied as `null` are discarded to match the
    /// compatibility behavior for frontends that encode `undefined` as null.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Parse`] for a non-object, unknown field, or field
    /// that is read-only for `method`.
    pub fn validate_input_for(
        &self,
        mut value: Value,
        method: &str,
    ) -> Result<Map<String, Value>, ApiError> {
        let object = value
            .as_object_mut()
            .ok_or_else(|| ApiError::Parse("Expected a JSON object.".into()))?;
        let names: Vec<_> = object.keys().cloned().collect();
        for key in names {
            let field = self
                .field(&key)
                .ok_or_else(|| ApiError::Parse(format!("Unknown field: {key}")))?;
            if field.read_only_for(method) {
                return Err(ApiError::Parse(format!("Field is read-only: {key}")));
            }
            if object.get(&key) == Some(&Value::Null) && !field.nullable {
                if field.required {
                    return Err(ApiError::Parse(format!("Field may not be null: {key}")));
                }
                object.remove(&key);
            }
        }
        if matches!(method, "POST" | "PUT") {
            if let Some(field) = self.fields.iter().find(|field| {
                field.required && !field.read_only_for(method) && !object.contains_key(&field.name)
            }) {
                return Err(ApiError::Parse(format!(
                    "Field is required: {}",
                    field.name
                )));
            }
        }
        Ok(std::mem::take(object))
    }
}

#[async_trait]
pub trait ResourceStore: Send + Sync + 'static {
    async fn list(
        &self,
        resource: &Resource,
        query: &QueryFeatures,
    ) -> Result<ApiDocument, ApiError>;

    async fn retrieve(
        &self,
        resource: &Resource,
        id: &str,
        query: Option<&QueryFeatures>,
    ) -> Result<ApiDocument, ApiError>;

    async fn create(
        &self,
        resource: &Resource,
        data: Map<String, Value>,
    ) -> Result<ApiDocument, ApiError>;

    async fn update(
        &self,
        resource: &Resource,
        id: &str,
        data: Map<String, Value>,
        partial: bool,
    ) -> Result<ApiDocument, ApiError>;

    async fn delete(&self, resource: &Resource, id: &str) -> Result<(), ApiError>;
}
