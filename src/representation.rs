use serde_json::{Map, Value};

use crate::{Field, FieldKind};

pub(crate) const IDENTITY_KEY: &str = "_meta";

/// Attach identity used by the sideloading processor. The marker is an
/// implementation detail and is removed from every serialized response.
pub fn tag_resource(object: &mut Map<String, Value>, resource_type: impl Into<String>, id: &Value) {
    object.insert(
        IDENTITY_KEY.into(),
        serde_json::json!({"id": id.clone(), "type": resource_type.into()}),
    );
}

/// Render database/adapter values according to Dynamic REST field behavior.
#[must_use]
pub fn normalize_field_value(field: &Field, value: Value) -> Value {
    if matches!(field.kind, FieldKind::File) && value.as_str().is_some_and(str::is_empty) {
        return Value::Null;
    }
    if matches!(field.kind, FieldKind::DateTime) {
        if let Value::String(value) = value {
            return Value::String(normalize_datetime(&value));
        }
    }
    if matches!(field.kind, FieldKind::Decimal | FieldKind::Money) {
        if value.is_null() {
            return value;
        }
        let scale = field
            .decimal_places
            .unwrap_or(if matches!(field.kind, FieldKind::Money) {
                2
            } else {
                0
            });
        if let Some(rendered) = fixed_decimal(&value, scale) {
            return Value::String(rendered);
        }
    }
    value
}

fn fixed_decimal(value: &Value, scale: u32) -> Option<String> {
    let precision = usize::try_from(scale).ok()?;
    match value {
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                return Some(if precision == 0 {
                    integer.to_string()
                } else {
                    format!("{integer}.{zero:0<precision$}", zero = "")
                });
            }
            let number = number.as_f64()?;
            Some(format!("{number:.precision$}"))
        }
        Value::String(value) => value.parse::<f64>().ok().map(|number| {
            if precision == 0 {
                format!("{number:.0}")
            } else {
                format!("{number:.precision$}")
            }
        }),
        _ => None,
    }
}

/// Remove all internal Dynamic REST identity markers from arbitrary JSON.
#[must_use]
pub fn sanitize(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(sanitize).collect()),
        Value::Object(object) => Value::Object(
            object
                .iter()
                .filter(|(name, _)| name.as_str() != IDENTITY_KEY)
                .map(|(name, value)| (name.clone(), sanitize(value)))
                .collect(),
        ),
        value => value.clone(),
    }
}

fn normalize_datetime(value: &str) -> String {
    let (body, suffix) = if let Some(body) = value.strip_suffix("+00:00") {
        (body, "Z")
    } else if let Some(body) = value.strip_suffix("+00") {
        (body, "Z")
    } else if let Some(body) = value.strip_suffix('Z') {
        (body, "Z")
    } else {
        (value, "")
    };
    let Some((whole, fraction)) = body.rsplit_once('.') else {
        return format!("{body}{suffix}");
    };
    if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return format!("{body}{suffix}");
    }
    let padded = if fraction.len() < 6 {
        format!("{fraction:0<6}")
    } else {
        fraction.to_owned()
    };
    format!("{whole}.{padded}{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(kind: FieldKind, decimal_places: Option<u32>) -> Field {
        Field {
            name: "value".into(),
            label: None,
            description: None,
            source: "value".into(),
            column: Some("value".into()),
            kind,
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
            decimal_places,
            related_table: None,
            related_pk_column: None,
            reverse_column: None,
            through_table: None,
            through_source_column: None,
            through_target_column: None,
            related_resource: None,
            relation_order: Vec::new(),
            link: crate::RelationLink::Default,
        }
    }

    #[test]
    fn matches_drf_datetime_microsecond_and_utc_rendering() {
        assert_eq!(
            normalize_field_value(
                &field(FieldKind::DateTime, None),
                Value::String("2026-09-08T12:34:56.39012+00:00".into())
            ),
            Value::String("2026-09-08T12:34:56.390120Z".into())
        );
        assert_eq!(
            normalize_field_value(
                &field(FieldKind::DateTime, None),
                Value::String("2026-09-08T12:34:56+00:00".into())
            ),
            Value::String("2026-09-08T12:34:56Z".into())
        );
    }

    #[test]
    fn converts_empty_file_to_null() {
        assert_eq!(
            normalize_field_value(&field(FieldKind::File, None), Value::String(String::new())),
            Value::Null
        );
    }

    #[test]
    fn renders_decimal_and_money_with_fixed_scale() {
        assert_eq!(
            normalize_field_value(
                &field(FieldKind::Money, Some(2)),
                serde_json::json!(200_000)
            ),
            Value::String("200000.00".into())
        );
        assert_eq!(
            normalize_field_value(
                &field(FieldKind::Decimal, Some(6)),
                serde_json::json!(30000.0)
            ),
            Value::String("30000.000000".into())
        );
    }
}
