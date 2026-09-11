use serde_json::{Map, Value};

use crate::{
    ApiError, FieldKind, FieldSelection, QueryFeatures, RelationLink, Resource, SelectionTree,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkOptions {
    pub self_links: bool,
    pub related_links: bool,
}

impl Default for LinkOptions {
    fn default() -> Self {
        Self {
            self_links: true,
            related_links: true,
        }
    }
}

/// Build the Dynamic REST `links` object for a rendered resource.
///
/// Callable relationship links are intentionally left to the host adapter;
/// static and convention-based links are resolved here.
///
/// # Errors
///
/// Returns a parse error when the request field tree is malformed.
pub fn build_links(
    resource: &Resource,
    query: Option<&QueryFeatures>,
    rendered: &Map<String, Value>,
    base_url: &str,
    options: LinkOptions,
) -> Result<Map<String, Value>, ApiError> {
    if query.is_some_and(|query| query.exclude_links) {
        return Ok(Map::new());
    }
    let selection = query
        .map(|query| SelectionTree::parse(&query.include, &query.exclude))
        .transpose()?
        .unwrap_or_default();
    let mut links = Map::new();
    if options.self_links {
        links.insert("self".into(), Value::String(base_url.to_owned()));
    }
    if !options.related_links {
        return Ok(links);
    }
    for field in &resource.fields {
        if field.kind != FieldKind::Relation || field.link == RelationLink::Disabled {
            continue;
        }
        if matches!(selection.get(&field.name), Some(FieldSelection::Nested(_))) {
            continue;
        }
        if rendered
            .get(&field.name)
            .is_some_and(|value| !truthy(value))
        {
            continue;
        }
        let target = match &field.link {
            RelationLink::Default => format!("{base_url}{}/", field.name),
            RelationLink::Static(url) => url.clone(),
            RelationLink::Custom | RelationLink::Disabled => continue,
        };
        links.insert(field.name.clone(), Value::String(target));
    }
    Ok(links)
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
        Value::Number(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{Action, Field};

    fn field(name: &str, many: bool, link: RelationLink) -> Field {
        Field {
            name: name.into(),
            source: name.into(),
            column: None,
            kind: FieldKind::Relation,
            required: false,
            read_only: true,
            write_only: false,
            deferred: true,
            nullable: true,
            many,
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
            link,
        }
    }

    fn resource() -> Resource {
        Resource {
            namespace: "v2".into(),
            name: "cat".into(),
            plural_name: "cats".into(),
            table: "cats".into(),
            id_field: "id".into(),
            fields: vec![
                field("home", false, RelationLink::Disabled),
                field("foobar", true, RelationLink::Default),
                field(
                    "static_home",
                    false,
                    RelationLink::Static("/home/1/".into()),
                ),
            ],
            actions: Vec::<Action>::new(),
            metadata_actions: Vec::new(),
            allowed_methods: vec!["GET".into()],
            permission_classes: Vec::new(),
            role_grants: BTreeMap::new(),
            role_filters: BTreeMap::new(),
            effective_row_filter: None,
            row_actor_id: None,
            role_order: Vec::new(),
            role_field_overrides: BTreeMap::new(),
            list_fields: None,
            default_sort: Vec::new(),
            metadata: None,
        }
    }

    #[test]
    fn matches_empty_deferred_and_sideloaded_link_rules() {
        let resource = resource();
        let mut rendered = Map::new();
        let links = build_links(
            &resource,
            None,
            &rendered,
            "/v2/cats/1/",
            LinkOptions::default(),
        )
        .unwrap();
        assert_eq!(links["foobar"], "/v2/cats/1/foobar/");
        assert!(!links.contains_key("home"));
        assert_eq!(links["static_home"], "/home/1/");

        rendered.insert("foobar".into(), Value::Array(Vec::new()));
        assert!(
            !build_links(
                &resource,
                None,
                &rendered,
                "/v2/cats/1/",
                LinkOptions::default()
            )
            .unwrap()
            .contains_key("foobar")
        );

        let query = QueryFeatures::parse("include[]=foobar.", 100).unwrap();
        rendered.insert("foobar".into(), serde_json::json!([1]));
        assert!(
            !build_links(
                &resource,
                Some(&query),
                &rendered,
                "/v2/cats/1/",
                LinkOptions::default()
            )
            .unwrap()
            .contains_key("foobar")
        );
    }
}
