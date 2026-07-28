//! Hardened YAML loading.
//!
//! Every YAML document airlock reads — the policy, suppression requests,
//! taskfiles, workflows, declared repository settings — is attacker
//! influenceable. The loader here materialises documents into a closed value
//! type under an explicit budget, and rejects the constructs that make YAML a
//! hazard: custom tags, non-string keys, duplicate keys, unbounded nesting,
//! and alias expansion.
//!
//! Alias expansion is bounded rather than forbidden. The underlying parser
//! expands an alias into real nodes, so a node budget spent during
//! materialisation stops an expansion bomb before it costs anything.

use std::cell::RefCell;
use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

use crate::limits::YamlLimits;

/// Why a YAML document was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum YamlError {
    /// The document is larger than the configured byte budget.
    #[error("document is {actual} bytes, over the {limit} byte limit")]
    TooLarge {
        /// Size of the offered document.
        actual: usize,
        /// The configured limit.
        limit: usize,
    },

    /// The document nests deeper than the configured depth budget.
    #[error("document nests deeper than the {limit} level limit")]
    TooDeep {
        /// The configured limit.
        limit: usize,
    },

    /// The document materialises more nodes than the configured budget.
    #[error("document expands to more than the {limit} node limit")]
    TooManyNodes {
        /// The configured limit.
        limit: usize,
    },

    /// A mapping declared the same key twice.
    #[error("duplicate mapping key `{key}`")]
    DuplicateKey {
        /// The repeated key.
        key: String,
    },

    /// A mapping key was not a string.
    #[error("mapping keys must be strings")]
    NonStringKey,

    /// The document carried a tag.
    #[error("tagged values are not accepted")]
    Tagged,

    /// The parser rejected the document.
    #[error("invalid yaml: {0}")]
    Parse(String),
}

/// A YAML document, materialised into a closed value type.
#[derive(Debug, Clone, PartialEq)]
pub enum Yaml {
    /// An explicit or implicit null.
    Null,
    /// A boolean.
    Bool(bool),
    /// An integer.
    Int(i64),
    /// A floating point number.
    Float(f64),
    /// A string scalar.
    String(String),
    /// A sequence, in document order.
    Seq(Vec<Yaml>),
    /// A mapping, in document order, with string keys and no duplicates.
    Map(Vec<(String, Yaml)>),
}

impl Yaml {
    /// The value as a string scalar, if it is one.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Yaml::String(value) => Some(value),
            _ => None,
        }
    }

    /// The value as a boolean, if it is one.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Yaml::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// The value as an integer, if it is one.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Yaml::Int(value) => Some(*value),
            _ => None,
        }
    }

    /// The value as a sequence, if it is one.
    #[must_use]
    pub fn as_seq(&self) -> Option<&[Yaml]> {
        match self {
            Yaml::Seq(values) => Some(values),
            _ => None,
        }
    }

    /// The value as a mapping, if it is one.
    #[must_use]
    pub fn as_map(&self) -> Option<&[(String, Yaml)]> {
        match self {
            Yaml::Map(entries) => Some(entries),
            _ => None,
        }
    }

    /// The value stored under `key`, if this is a mapping that has one.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Yaml> {
        self.as_map()?
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    /// The mapping's keys, in document order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.as_map()
            .into_iter()
            .flat_map(|entries| entries.iter().map(|(key, _)| key.as_str()))
    }

    /// A short name for the value's shape, for error messages.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Yaml::Null => "null",
            Yaml::Bool(_) => "boolean",
            Yaml::Int(_) => "integer",
            Yaml::Float(_) => "number",
            Yaml::String(_) => "string",
            Yaml::Seq(_) => "sequence",
            Yaml::Map(_) => "mapping",
        }
    }

    /// Walk the document looking for any string scalar satisfying `predicate`.
    #[must_use]
    pub fn any_string(&self, predicate: &dyn Fn(&str) -> bool) -> bool {
        match self {
            Yaml::String(value) => predicate(value),
            Yaml::Seq(values) => values.iter().any(|value| value.any_string(predicate)),
            Yaml::Map(entries) => entries
                .iter()
                .any(|(key, value)| predicate(key) || value.any_string(predicate)),
            _ => false,
        }
    }
}

/// Parse one YAML document under `limits`.
///
/// # Errors
///
/// Returns a [`YamlError`] when the document exceeds a budget, uses a rejected
/// construct, or is not valid YAML.
pub fn parse(source: &str, limits: YamlLimits) -> Result<Yaml, YamlError> {
    if source.len() > limits.max_bytes {
        return Err(YamlError::TooLarge {
            actual: source.len(),
            limit: limits.max_bytes,
        });
    }

    let state = RefCell::new(State {
        nodes: 0,
        limits,
        refusal: None,
    });
    let deserializer = serde_norway::Deserializer::from_str(source);
    let seed = Seed {
        state: &state,
        depth: 0,
    };
    let parsed = seed.deserialize(deserializer);

    // A refusal recorded by the visitor is more precise than whatever the
    // parser wrapped it in, so it wins.
    if let Some(refusal) = state.borrow_mut().refusal.take() {
        return Err(refusal);
    }
    parsed.map_err(|error| YamlError::Parse(error.to_string()))
}

/// Parse a document that must be a mapping at its root.
///
/// # Errors
///
/// Returns a [`YamlError`] on any parse failure, or when the root is not a
/// mapping.
pub fn parse_mapping(source: &str, limits: YamlLimits) -> Result<Yaml, YamlError> {
    let document = parse(source, limits)?;
    match document {
        Yaml::Map(_) => Ok(document),
        // An empty document is an empty mapping, which is the useful reading
        // for every file airlock parses.
        Yaml::Null => Ok(Yaml::Map(Vec::new())),
        other => Err(YamlError::Parse(format!(
            "expected a mapping at the document root, found {}",
            other.kind()
        ))),
    }
}

struct State {
    nodes: usize,
    limits: YamlLimits,
    refusal: Option<YamlError>,
}

impl State {
    fn record_node(&mut self) -> Option<YamlError> {
        self.nodes += 1;
        if self.nodes > self.limits.max_nodes {
            let error = YamlError::TooManyNodes {
                limit: self.limits.max_nodes,
            };
            self.refusal.get_or_insert(error.clone());
            return Some(error);
        }
        None
    }

    fn refuse(&mut self, error: YamlError) -> YamlError {
        self.refusal.get_or_insert(error.clone());
        error
    }
}

struct Seed<'a> {
    state: &'a RefCell<State>,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Yaml;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'a> Seed<'a> {
    fn nested(&self) -> Seed<'a> {
        Seed {
            state: self.state,
            depth: self.depth + 1,
        }
    }

    fn count<E: de::Error>(&self) -> Result<(), E> {
        match self.state.borrow_mut().record_node() {
            Some(error) => Err(E::custom(error.to_string())),
            None => Ok(()),
        }
    }

    fn descend<E: de::Error>(&self) -> Result<(), E> {
        let limit = self.state.borrow().limits.max_depth;
        if self.depth >= limit {
            let error = self.state.borrow_mut().refuse(YamlError::TooDeep { limit });
            return Err(E::custom(error.to_string()));
        }
        Ok(())
    }

    fn refuse<E: de::Error>(&self, error: YamlError) -> E {
        let error = self.state.borrow_mut().refuse(error);
        E::custom(error.to_string())
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Yaml;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a yaml value")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Yaml, E> {
        self.count()?;
        Ok(Yaml::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Yaml, E> {
        self.count()?;
        Ok(Yaml::Int(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Yaml, E> {
        self.count()?;
        Ok(i64::try_from(value).map_or(Yaml::Float(value as f64), Yaml::Int))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Yaml, E> {
        self.count()?;
        Ok(Yaml::Float(value))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Yaml, E> {
        self.count()?;
        Ok(Yaml::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Yaml, E> {
        self.count()?;
        Ok(Yaml::String(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Yaml, E> {
        self.count()?;
        Ok(Yaml::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Yaml, E> {
        self.count()?;
        Ok(Yaml::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Yaml, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }

    fn visit_seq<A>(self, mut access: A) -> Result<Yaml, A::Error>
    where
        A: SeqAccess<'de>,
    {
        self.count()?;
        self.descend()?;
        let mut values = Vec::new();
        while let Some(value) = access.next_element_seed(self.nested())? {
            values.push(value);
        }
        Ok(Yaml::Seq(values))
    }

    fn visit_map<A>(self, mut access: A) -> Result<Yaml, A::Error>
    where
        A: MapAccess<'de>,
    {
        self.count()?;
        self.descend()?;
        let mut entries: Vec<(String, Yaml)> = Vec::new();
        while let Some(key) = access.next_key_seed(KeySeed { owner: &self })? {
            if entries.iter().any(|(existing, _)| existing == &key) {
                return Err(self.refuse(YamlError::DuplicateKey { key }));
            }
            let value = access.next_value_seed(self.nested())?;
            entries.push((key, value));
        }
        Ok(Yaml::Map(entries))
    }

    fn visit_enum<A>(self, _access: A) -> Result<Yaml, A::Error>
    where
        A: de::EnumAccess<'de>,
    {
        // The underlying parser surfaces a tagged scalar as an enum. Airlock
        // accepts no tags at all, so this is always a refusal.
        Err(self.refuse(YamlError::Tagged))
    }
}

struct KeySeed<'a, 'b> {
    owner: &'b Seed<'a>,
}

impl<'de> DeserializeSeed<'de> for KeySeed<'_, '_> {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for KeySeed<'_, '_> {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string mapping key")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<String, E> {
        self.owner.count()?;
        Ok(value.to_owned())
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<String, E> {
        self.owner.count()?;
        Ok(value)
    }

    fn visit_bool<E: de::Error>(self, _value: bool) -> Result<String, E> {
        Err(self.owner.refuse(YamlError::NonStringKey))
    }

    fn visit_i64<E: de::Error>(self, _value: i64) -> Result<String, E> {
        Err(self.owner.refuse(YamlError::NonStringKey))
    }

    fn visit_u64<E: de::Error>(self, _value: u64) -> Result<String, E> {
        Err(self.owner.refuse(YamlError::NonStringKey))
    }

    fn visit_f64<E: de::Error>(self, _value: f64) -> Result<String, E> {
        Err(self.owner.refuse(YamlError::NonStringKey))
    }

    fn visit_unit<E: de::Error>(self) -> Result<String, E> {
        Err(self.owner.refuse(YamlError::NonStringKey))
    }

    fn visit_seq<A>(self, _access: A) -> Result<String, A::Error>
    where
        A: SeqAccess<'de>,
    {
        Err(self.owner.refuse(YamlError::NonStringKey))
    }

    fn visit_map<A>(self, _access: A) -> Result<String, A::Error>
    where
        A: MapAccess<'de>,
    {
        Err(self.owner.refuse(YamlError::NonStringKey))
    }

    fn visit_enum<A>(self, _access: A) -> Result<String, A::Error>
    where
        A: de::EnumAccess<'de>,
    {
        Err(self.owner.refuse(YamlError::Tagged))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> YamlLimits {
        YamlLimits::default()
    }

    #[test]
    fn parses_a_mapping_in_document_order() {
        let document = parse("b: 2\na: 1\n", limits()).unwrap();
        assert_eq!(document.keys().collect::<Vec<_>>(), vec!["b", "a"]);
        assert_eq!(document.get("a").and_then(Yaml::as_i64), Some(1));
    }

    #[test]
    fn parses_nested_sequences_and_scalars() {
        let document = parse("items:\n  - one\n  - true\n  - 3\n", limits()).unwrap();
        let items = document.get("items").and_then(Yaml::as_seq).unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].as_str(), Some("one"));
        assert_eq!(items[1].as_bool(), Some(true));
        assert_eq!(items[2].as_i64(), Some(3));
    }

    #[test]
    fn rejects_a_document_over_the_byte_budget() {
        let budget = YamlLimits {
            max_bytes: 8,
            ..limits()
        };
        let error = parse("key: a-much-longer-value\n", budget).unwrap_err();
        assert!(matches!(error, YamlError::TooLarge { limit: 8, .. }));
    }

    #[test]
    fn rejects_duplicate_keys() {
        let error = parse("name: one\nname: two\n", limits()).unwrap_err();
        assert_eq!(
            error,
            YamlError::DuplicateKey {
                key: "name".to_owned()
            }
        );
    }

    #[test]
    fn rejects_non_string_keys() {
        let error = parse("1: one\n", limits()).unwrap_err();
        assert_eq!(error, YamlError::NonStringKey);
    }

    #[test]
    fn rejects_custom_tags() {
        let error = parse("value: !secret hunter2\n", limits()).unwrap_err();
        assert_eq!(error, YamlError::Tagged);
    }

    #[test]
    fn rejects_documents_deeper_than_the_depth_budget() {
        let budget = YamlLimits {
            max_depth: 3,
            ..limits()
        };
        let error = parse("a:\n  b:\n    c:\n      d: 1\n", budget).unwrap_err();
        assert_eq!(error, YamlError::TooDeep { limit: 3 });
    }

    #[test]
    fn rejects_an_alias_expansion_bomb() {
        // The classic billion-laughs shape. The node budget is spent long
        // before the expansion is materialised.
        let bomb = "\
a: &a [x, x, x, x, x, x, x, x, x]
b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]
c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]
d: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c]
e: &e [*d, *d, *d, *d, *d, *d, *d, *d, *d]
f: [*e, *e, *e, *e, *e, *e, *e, *e, *e]
";
        let budget = YamlLimits {
            max_nodes: 5_000,
            ..limits()
        };
        let error = parse(bomb, budget).unwrap_err();
        assert_eq!(error, YamlError::TooManyNodes { limit: 5_000 });
    }

    #[test]
    fn accepts_a_modest_alias() {
        let document = parse("base: &base one\nalso: *base\n", limits()).unwrap();
        assert_eq!(document.get("also").and_then(Yaml::as_str), Some("one"));
    }

    #[test]
    fn parse_mapping_rejects_a_sequence_root() {
        let error = parse_mapping("- one\n", limits()).unwrap_err();
        assert!(matches!(error, YamlError::Parse(_)));
    }

    #[test]
    fn parse_mapping_reads_an_empty_document_as_an_empty_mapping() {
        assert_eq!(parse_mapping("", limits()).unwrap(), Yaml::Map(Vec::new()));
    }

    #[test]
    fn any_string_walks_the_whole_document() {
        let document = parse("jobs:\n  build:\n    uses: owner/repo@main\n", limits()).unwrap();
        assert!(document.any_string(&|value| value.contains("owner/repo")));
        assert!(!document.any_string(&|value| value.contains("nothing-here")));
    }
}
