use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{ApiError, Field, QueryFeatures, Resource};

/// A Dynamic REST field selection. Nested maps request a relationship object;
/// scalar includes request an otherwise deferred field by value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldSelection {
    Include,
    Exclude,
    Nested(SelectionTree),
}

/// The nested representation produced by Dynamic REST's `include[]` and
/// `exclude[]` request features.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SelectionTree {
    fields: BTreeMap<String, FieldSelection>,
}

impl SelectionTree {
    /// Build the request-field tree using Dynamic REST's ordering: includes
    /// are applied first and excludes second, regardless of query-string order.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Parse`] for an empty non-terminal path segment or
    /// for a path that attempts to descend through an existing scalar choice.
    pub fn parse(includes: &[String], excludes: &[String]) -> Result<Self, ApiError> {
        let mut tree = Self::default();
        for (paths, include) in [(includes, true), (excludes, false)] {
            for path in paths {
                tree.insert_path(path, include)?;
            }
        }
        Ok(tree)
    }

    #[must_use]
    pub fn get(&self, field: &str) -> Option<&FieldSelection> {
        self.fields.get(field)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &FieldSelection)> {
        self.fields
            .iter()
            .map(|(name, selection)| (name.as_str(), selection))
    }

    fn insert_path(&mut self, path: &str, include: bool) -> Result<(), ApiError> {
        let segments: Vec<_> = path.split('.').collect();
        let mut current = self;
        for (index, segment) in segments.iter().enumerate() {
            let last = index + 1 == segments.len();
            if segment.is_empty() {
                if last {
                    break;
                }
                return Err(ApiError::Parse(format!("\"{path}\" is not a valid field.")));
            }
            if last {
                current.fields.insert(
                    (*segment).to_owned(),
                    if include {
                        FieldSelection::Include
                    } else {
                        FieldSelection::Exclude
                    },
                );
                continue;
            }
            let selection = current
                .fields
                .entry((*segment).to_owned())
                .or_insert_with(|| FieldSelection::Nested(Self::default()));
            let FieldSelection::Nested(child) = selection else {
                return Err(ApiError::Parse(format!(
                    "\"{path}\" cannot descend through \"{segment}\"."
                )));
            };
            current = child;
        }
        Ok(())
    }
}

/// Decide whether a field belongs in a representation, including the
/// serializer's deferred and list-field defaults.
///
/// # Errors
///
/// Returns [`ApiError::Parse`] when a request names a field that the resource
/// does not expose, matching Dynamic REST's serializer validation.
pub fn selected_fields<'a>(
    resource: &'a Resource,
    query: Option<&QueryFeatures>,
    list: bool,
) -> Result<Vec<&'a Field>, ApiError> {
    let Some(query) = query else {
        return Ok(resource
            .fields
            .iter()
            .filter(|field| !field.deferred && !field.write_only)
            .collect());
    };
    let tree = SelectionTree::parse(&query.include, &query.exclude)?;
    for (name, _) in tree.iter() {
        if name != "*" && name != "pk" && resource.field(name).is_none() {
            return Err(ApiError::Parse(format!(
                "\"{name}\" is not a valid field name for \"{}\".",
                resource.name
            )));
        }
    }

    let exclude_all = matches!(tree.get("*"), Some(FieldSelection::Exclude));
    Ok(resource
        .fields
        .iter()
        .filter(|field| !field.write_only)
        .filter(|field| {
            let requested = tree.get(&field.name);
            if matches!(requested, Some(FieldSelection::Exclude)) {
                return false;
            }
            if exclude_all {
                return requested.is_some();
            }
            if list && tree.is_empty() {
                if let Some(list_fields) = &resource.list_fields {
                    return list_fields.contains(&field.name);
                }
            }
            !field.deferred || requested.is_some()
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_fields_and_applies_excludes_after_includes() {
        let tree = SelectionTree::parse(
            &["groups.permissions".into(), "name".into()],
            &["groups.name".into(), "name".into()],
        )
        .unwrap();
        assert_eq!(tree.get("name"), Some(&FieldSelection::Exclude));
        let Some(FieldSelection::Nested(groups)) = tree.get("groups") else {
            panic!("groups should be nested")
        };
        assert_eq!(groups.get("permissions"), Some(&FieldSelection::Include));
        assert_eq!(groups.get("name"), Some(&FieldSelection::Exclude));
    }

    #[test]
    fn rejects_empty_non_terminal_segment() {
        let error = SelectionTree::parse(&["groups..name".into()], &[]).unwrap_err();
        assert!(error.to_string().contains("not a valid field"));
    }
}
