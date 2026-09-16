//! Dynamic REST protocol primitives.
//!
//! This crate deliberately has no application-specific or database-specific dependencies. It owns the
//! public wire contract: resource metadata, query feature parsing, envelopes,
//! pagination metadata, permissions, and storage traits.

mod access;
mod error;
mod links;
mod metadata;
mod payload;
mod permissions;
mod query;
mod representation;
mod resource;
mod response;
mod router;
mod selection;
mod sideload;

pub use access::{
    AccessMap, AccessRules, AccessTargets, CONDITION_OPERATORS, OPERATIONS as ACCESS_OPERATIONS,
    condition_matches, grant_access, parse_access_map, parse_rule, split_lookup,
};
pub use error::{ApiError, ErrorBody, FieldErrors};
pub use links::{LinkOptions, build_links};
pub use metadata::{python_title, resource_metadata};
pub use payload::{bulk_payload, unwrap_single_payload};
pub use permissions::{
    Principal, apply_field_choice_overrides, field_permissions, operation_granted,
    resource_for_principal, resource_for_principal_operation, role_grants_operation, row_filter,
};
pub use query::{Filter, FilterOperator, QueryFeatures, Sort};
pub use representation::{normalize_field_value, sanitize, tag_resource};
pub use resource::{
    Action, Field, FieldKind, PermissionFilter, PermissionSet, RelationLink, Resource,
    ResourceStore,
};
pub use response::{ApiDocument, PageMeta};
pub use router::{DynamicRouter, RouteRegistration};
pub use selection::{FieldSelection, SelectionTree, selected_fields};
pub use sideload::{ADDITIONAL_PRIMARY_RESOURCE_PREFIX, SideloadingProcessor};

#[cfg(feature = "application")]
pub mod application;
