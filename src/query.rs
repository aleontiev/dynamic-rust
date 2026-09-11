use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ApiError;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FilterOperator {
    Eq,
    In,
    Any,
    All,
    Contains,
    IContains,
    StartsWith,
    IStartsWith,
    EndsWith,
    IEndsWith,
    Lt,
    Lte,
    Gt,
    Gte,
    IsNull,
    Range,
    Year,
    Month,
    Day,
    WeekDay,
    Regex,
    HasKey,
    HasKeys,
    HasAnyKeys,
    ContainedBy,
}

impl FilterOperator {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "in" => Self::In,
            "any" => Self::Any,
            "all" => Self::All,
            "contains" => Self::Contains,
            "icontains" => Self::IContains,
            "startswith" => Self::StartsWith,
            "istartswith" => Self::IStartsWith,
            "endswith" => Self::EndsWith,
            "iendswith" => Self::IEndsWith,
            "lt" => Self::Lt,
            "lte" => Self::Lte,
            "gt" => Self::Gt,
            "gte" => Self::Gte,
            "isnull" => Self::IsNull,
            "range" => Self::Range,
            "year" => Self::Year,
            "month" => Self::Month,
            "day" => Self::Day,
            "week_day" => Self::WeekDay,
            "regex" => Self::Regex,
            "has_key" => Self::HasKey,
            "has_keys" => Self::HasKeys,
            "has_any_keys" => Self::HasAnyKeys,
            "contained_by" => Self::ContainedBy,
            "eq" => Self::Eq,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Filter {
    /// Optional relation path before Dynamic REST's `|` separator.
    pub relation: Vec<String>,
    pub field: String,
    pub operator: FilterOperator,
    pub values: Vec<String>,
    pub exclude: bool,
    pub field_reference: bool,
    pub count: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Sort {
    pub field: String,
    pub descending: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct QueryFeatures {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub filters: Vec<Filter>,
    pub sort: Vec<Sort>,
    pub page: u32,
    pub per_page: u32,
    pub sideloading: bool,
    pub combine: BTreeMap<String, Vec<String>>,
    pub debug: bool,
    pub exclude_count: bool,
    pub exclude_links: bool,
    pub cursor: Option<String>,
    pub cursor_order: String,
}

impl Default for QueryFeatures {
    fn default() -> Self {
        Self {
            include: Vec::new(),
            exclude: Vec::new(),
            filters: Vec::new(),
            sort: Vec::new(),
            page: 1,
            per_page: 50,
            sideloading: true,
            combine: BTreeMap::new(),
            debug: false,
            exclude_count: false,
            exclude_links: false,
            cursor: None,
            cursor_order: "-created".into(),
        }
    }
}

impl QueryFeatures {
    /// Parse Dynamic REST's bracketed query syntax without losing repeated keys.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Parse`] for malformed filters, invalid page values,
    /// or a requested page size above `max_page_size`.
    pub fn parse(raw: &str, max_page_size: u32) -> Result<Self, ApiError> {
        Self::parse_with_page_size(raw, 50, max_page_size)
    }

    /// Parse with an application-specific default page size.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Parse`] under the same conditions as [`Self::parse`].
    pub fn parse_with_page_size(
        raw: &str,
        page_size: u32,
        max_page_size: u32,
    ) -> Result<Self, ApiError> {
        let mut result = Self {
            per_page: page_size,
            ..Self::default()
        };
        for (raw_key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
            let key = raw_key.as_ref();
            let value = value.into_owned();
            match key {
                "include[]" => result.include.push(value),
                "exclude[]" => result.exclude.push(value),
                "sort[]" => result.sort.push(parse_sort(&value)?),
                "page" => result.page = parse_positive("page", &value)?,
                "per_page" => {
                    let size = parse_positive("per_page", &value)?;
                    if size > max_page_size {
                        return Err(ApiError::Parse(format!(
                            "Invalid page size {size}; maximum is {max_page_size}."
                        )));
                    }
                    result.per_page = size;
                }
                "sideloading" => result.sideloading = truthy(&value),
                "debug" => result.debug = truthy(&value),
                // Dynamic REST's paginator reads the value directly. Any
                // non-empty string (including "false") therefore disables
                // the count query.
                "exclude_count" => result.exclude_count = !value.is_empty(),
                // The serializer checks only for key presence, so even an
                // empty or false-looking value suppresses relationship links.
                "exclude_links" => result.exclude_links = true,
                "cursor" => result.cursor = Some(value),
                "cursor.order" => result.cursor_order = value,
                _ if key.starts_with("filter{") => {
                    let filter = parse_filter(key, value)?;
                    if let Some(existing) = result.filters.iter_mut().find(|existing| {
                        existing.relation == filter.relation
                            && existing.field == filter.field
                            && existing.operator == filter.operator
                            && existing.exclude == filter.exclude
                            && existing.field_reference == filter.field_reference
                            && existing.count == filter.count
                    }) {
                        existing.values.extend(filter.values);
                    } else {
                        result.filters.push(filter);
                    }
                }
                _ if key == "combine" => {
                    result.combine.entry(String::new()).or_default().push(value);
                }
                _ if key.starts_with("combine.") => {
                    let suffix = key.trim_start_matches("combine.");
                    if suffix.contains('.') {
                        return Err(ApiError::Parse(format!(
                            "\"{key}\" is not a well-formed combine key"
                        )));
                    }
                    result
                        .combine
                        .entry(suffix.to_owned())
                        .or_default()
                        .push(value);
                }
                _ => {}
            }
        }
        result
            .filters
            .retain(|filter| !filter.values.iter().all(String::is_empty));
        for filter in &mut result.filters {
            normalize_filter_values(filter)?;
        }
        result
            .combine
            .retain(|_, values| !values.iter().all(String::is_empty));
        Ok(result)
    }
}

fn parse_positive(name: &str, value: &str) -> Result<u32, ApiError> {
    value
        .parse::<u32>()
        .ok()
        .filter(|number| *number > 0)
        .ok_or_else(|| ApiError::Parse(format!("Invalid {name}: {value}")))
}

fn parse_sort(value: &str) -> Result<Sort, ApiError> {
    let value = value.trim();
    let descending = value.starts_with('-');
    let field = value.trim_start_matches('-');
    if field.is_empty() {
        return Err(ApiError::Parse("Invalid empty sort field.".into()));
    }
    Ok(Sort {
        field: field.into(),
        descending,
    })
}

fn parse_filter(key: &str, value: String) -> Result<Filter, ApiError> {
    let expression_end = if key.ends_with("}[]") {
        key.len() - 3
    } else if key.ends_with('}') {
        key.len() - 1
    } else {
        return Err(ApiError::Parse(format!(
            "\"{key}\" is not a well-formed filter key."
        )));
    };
    let mut expression = &key[7..expression_end];
    let exclude = expression.starts_with('-');
    expression = expression.trim_start_matches('-');
    let (relation, rest) = expression.split_once('|').map_or_else(
        || (Vec::new(), expression),
        |(relation, rest)| (relation.split('.').map(str::to_owned).collect(), rest),
    );
    expression = rest;
    let field_reference = expression.ends_with('*');
    expression = expression.trim_end_matches('*');
    let normalized = expression.replace("__", ".");
    let mut terms: Vec<_> = normalized.split('.').collect();
    let count = terms.len() > 1 && terms[terms.len() - 2] == "$count";
    if count {
        terms.remove(terms.len() - 2);
    }
    let normalized = terms.join(".");
    let mut parts = normalized.rsplitn(2, '.');
    let suffix = parts.next().unwrap_or_default();
    let (field, operator) = if let Some(operator) = FilterOperator::parse(suffix) {
        (parts.next().unwrap_or_default(), operator)
    } else {
        (expression, FilterOperator::Eq)
    };
    if field.is_empty() {
        return Err(ApiError::Parse("Invalid empty filter field.".into()));
    }
    Ok(Filter {
        relation,
        field: field.into(),
        operator,
        values: vec![value],
        exclude,
        field_reference,
        count,
    })
}

fn normalize_filter_values(filter: &mut Filter) -> Result<(), ApiError> {
    match filter.operator {
        FilterOperator::In => {}
        FilterOperator::Range => {
            if filter.values.len() < 2 {
                return Err(ApiError::Parse("Range filters require two values.".into()));
            }
            filter.values.truncate(2);
            if filter.values[0].is_empty() {
                filter.operator = FilterOperator::Lte;
                filter.values.remove(0);
            } else if filter.values[1].is_empty() {
                filter.operator = FilterOperator::Gte;
                filter.values.truncate(1);
            }
        }
        _ => filter.values.truncate(1),
    }
    Ok(())
}

fn truthy(value: &str) -> bool {
    !matches!(value.to_ascii_lowercase().as_str(), "" | "0" | "false")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dynamic_query_features() {
        let query = QueryFeatures::parse(
            "include[]=borrower.*&exclude[]=secret&filter{-status.in}=late&sort[]=-created_at&page=2&per_page=25&sideloading=false&combine.total[]=principal",
            1000,
        )
        .unwrap();
        assert_eq!(query.page, 2);
        assert_eq!(query.per_page, 25);
        assert!(!query.sideloading);
        assert_eq!(query.filters[0].field, "status");
        assert_eq!(query.filters[0].operator, FilterOperator::In);
        assert!(query.filters[0].exclude);
        assert_eq!(query.sort[0].field, "created_at");
        assert!(query.sort[0].descending);
    }

    #[test]
    fn matches_v5_0_8_repeated_in_and_json_filter_parsing() {
        let query = QueryFeatures::parse(
            "filter{name.in}=0&filter{name.in}=1&filter{data__has_key}=enquiry&filter{username*}=last_name&exclude_count=1&cursor.order=-created",
            u32::MAX,
        )
        .unwrap();
        assert_eq!(query.filters[0].values, ["0", "1"]);
        assert_eq!(query.filters[1].field, "data");
        assert_eq!(query.filters[1].operator, FilterOperator::HasKey);
        assert!(query.filters[2].field_reference);
        assert!(query.exclude_count);
        assert_eq!(query.cursor_order, "-created");
    }

    #[test]
    fn matches_relation_count_range_and_truthiness_rules() {
        let query = QueryFeatures::parse(
            "filter{groups|members.$count.range}=&filter{groups|members.$count.range}=4&sideloading=no&filter{name}=first&filter{name}=ignored",
            100,
        )
        .unwrap();
        assert_eq!(query.filters[0].relation, ["groups"]);
        assert_eq!(query.filters[0].field, "members");
        assert!(query.filters[0].count);
        assert_eq!(query.filters[0].operator, FilterOperator::Lte);
        assert_eq!(query.filters[0].values, ["4"]);
        assert_eq!(query.filters[1].values, ["first"]);
        assert!(
            query.sideloading,
            "any value except 0/false/empty is truthy"
        );
    }

    #[test]
    fn accepts_ember_filter_array_suffix_and_rejects_deep_combine() {
        let query = QueryFeatures::parse("filter{name.in}[]=a&filter{name.in}[]=b", 100).unwrap();
        assert_eq!(query.filters[0].values, ["a", "b"]);
        assert!(QueryFeatures::parse("combine.total.amount=principal", 100).is_err());
    }

    #[test]
    fn matches_exclude_count_value_and_exclude_links_presence_semantics() {
        let query = QueryFeatures::parse("exclude_count=false&exclude_links=false", 100).unwrap();
        assert!(query.exclude_count);
        assert!(query.exclude_links);

        let query = QueryFeatures::parse("exclude_count=&exclude_links=", 100).unwrap();
        assert!(!query.exclude_count);
        assert!(query.exclude_links);
    }

    #[test]
    fn rejects_malformed_filter() {
        assert!(QueryFeatures::parse("filter{status=late", 100).is_err());
    }
}
