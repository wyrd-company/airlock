//! Plain JSON documents checked against an embedded schema catalog.
//
// relationships:
//   implements: release-process-conformance

use jsonschema::{Draft, Validator};
use serde_json::Value;
use std::sync::LazyLock;

pub(crate) const MODEL_ID: &str = "https://intentional.foo/schemas/release-model/1";
const MODEL: &str = include_str!("../schemas/intentional/release-model-1.schema.yml");
const TAG: &str = include_str!("../schemas/intentional/tag-record.schema.yml");
const PLAN: &str = include_str!("../schemas/intentional/release-plan.schema.yml");
const CONFIG: &str = include_str!("../schemas/intentional/release-workspace.schema.yml");

fn schema(text: &str) -> Value {
    serde_norway::from_str(text).expect("embedded schema is JSON-compatible YAML")
}

fn validator(text: &str) -> Validator {
    let mut registry = jsonschema::Registry::new();
    for source in [MODEL, TAG, PLAN, CONFIG] {
        let value = schema(source);
        let id = value["$id"]
            .as_str()
            .expect("embedded schema identity")
            .to_owned();
        registry = registry.add(id, value).expect("embedded schema registers");
    }
    let registry = registry.prepare().expect("embedded catalog resolves");
    jsonschema::options()
        .offline()
        .with_draft(Draft::Draft202012)
        .with_registry(&registry)
        .build(&schema(text))
        .expect("embedded schema compiles")
}

static MODEL_VALIDATOR: LazyLock<Validator> = LazyLock::new(|| validator(MODEL));
static TAG_VALIDATOR: LazyLock<Validator> = LazyLock::new(|| validator(TAG));

#[derive(Debug)]
pub(crate) enum DocumentError {
    Identity(String),
    Invalid(String),
}

pub(crate) fn model(bytes: &[u8]) -> Result<Value, DocumentError> {
    read(bytes, MODEL_ID, &MODEL_VALIDATOR)
}

pub(crate) fn read(
    bytes: &[u8],
    expected: &str,
    validator: &Validator,
) -> Result<Value, DocumentError> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| DocumentError::Invalid(format!("JSON syntax: {error}")))?;
    if value.get("$schema").and_then(Value::as_str) != Some(expected) {
        return Err(DocumentError::Identity(format!(
            "expected {expected}; found {}",
            value.get("$schema").unwrap_or(&Value::Null)
        )));
    }
    validate(validator, &value).map_err(DocumentError::Invalid)?;
    Ok(value)
}

fn validate(validator: &Validator, value: &Value) -> Result<(), String> {
    validator.validate(value).map_err(|error| {
        format!(
            "{}: {} ({error})",
            error.instance_path(),
            error.schema_path()
        )
    })
}

/// Project the line protocol onto its schema, preserving ordering and uniqueness.
pub(crate) fn tag(message: &str) -> Result<Value, String> {
    const FIELDS: &[&str] = &[
        "contract",
        "generator",
        "plan-digest",
        "tag-id",
        "tag-role",
        "version",
        "target",
        "baseline",
    ];
    let body = message
        .strip_prefix("intentional release record\n\n")
        .ok_or("not-a-tag-record")?;
    let mut result = serde_json::Map::new();
    let mut previous = None;
    let mut prerequisites = Vec::new();
    let mut prior_id: Option<&str> = None;
    for line in body.strip_suffix('\n').unwrap_or(body).split('\n') {
        let (key, text) = line.split_once(": ").ok_or("malformed-field")?;
        if key == "prerequisite" {
            let (id, object) = text.split_once(' ').ok_or("malformed-prerequisite")?;
            if prior_id.is_some_and(|prior| prior >= id) {
                return Err("prerequisites-not-sorted-unique".into());
            }
            prior_id = Some(id);
            prerequisites.push(serde_json::json!({"tag-id": id, "tag-object": object}));
            continue;
        }
        let index = FIELDS
            .iter()
            .position(|field| *field == key)
            .ok_or("unknown-field")?;
        if !prerequisites.is_empty() || previous.is_some_and(|prior| prior >= index) {
            return Err("fields-not-in-schema-order".into());
        }
        previous = Some(index);
        let value = if key == "baseline" {
            match text {
                "true" => Value::Bool(true),
                "false" => Value::Bool(false),
                _ => return Err("malformed-baseline".into()),
            }
        } else {
            Value::String(text.to_owned())
        };
        result.insert(key.to_owned(), value);
    }
    if !prerequisites.is_empty() {
        result.insert("prerequisites".into(), Value::Array(prerequisites));
    }
    let value = Value::Object(result);
    validate(&TAG_VALIDATOR, &value)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn embedded_schema_provenance_matches_bytes_and_identities() {
        let provenance: Value =
            serde_json::from_str(include_str!("../schemas/intentional/provenance.json")).unwrap();
        for (entry, bytes) in provenance
            .as_array()
            .unwrap()
            .iter()
            .zip([MODEL, TAG, PLAN, CONFIG])
        {
            assert_eq!(
                entry["sha256"],
                hex::encode(Sha256::digest(bytes.as_bytes()))
            );
            assert_eq!(entry["repository"], "github.com/wyrd-company/intentional");
            assert_eq!(entry["commit"].as_str().unwrap().len(), 40);
            assert_eq!(entry["schema_id"], schema(bytes)["$id"]);
            assert!(schema(bytes)["$id"]
                .as_str()
                .unwrap()
                .starts_with("https://intentional.foo/schemas/"));
        }
        assert_eq!(schema(MODEL)["$id"], MODEL_ID);
    }

    #[test]
    fn reader_uses_exact_identity_and_schema_keyword_without_network() {
        let validator = jsonschema::options().offline().build(&serde_json::json!({"type":"object", "required":["items"], "properties":{"items":{"type":"array"}}})).unwrap();
        assert!(matches!(
            read(
                br#"{"$schema":"https://example.test/model"}"#,
                MODEL_ID,
                &validator
            ),
            Err(DocumentError::Identity(_))
        ));
        for bytes in [
            br#"{"$schema":"https://intentional.foo/schemas/release-model/1"}"#.as_slice(),
            br#"{"$schema":"https://intentional.foo/schemas/release-model/1","items":true}"#,
        ] {
            let Err(DocumentError::Invalid(message)) = read(bytes, MODEL_ID, &validator) else {
                panic!("validation required");
            };
            assert!(
                message.contains("required") || message.contains("/items/type"),
                "{message}"
            );
        }
        assert!(read(b"$schema: value", MODEL_ID, &validator).is_err());
    }
}

#[cfg(test)]
mod projection_tests {
    use super::*;
    #[test]
    fn vendored_line_one_requires_generic_on_every_projection() {
        let mut model: Value =
            serde_json::from_str(include_str!("../schemas/intentional/model-fixture.json"))
                .unwrap();
        assert!(super::model(model.to_string().as_bytes()).is_ok());
        model["release_units"]["sample"]["projections"][0]
            .as_object_mut()
            .unwrap()
            .remove("generic");
        assert!(matches!(
            super::model(model.to_string().as_bytes()),
            Err(DocumentError::Invalid(_))
        ));
    }
}
