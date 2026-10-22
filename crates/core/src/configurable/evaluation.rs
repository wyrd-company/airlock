// ---
// relationships:
//   implements: configurable-rules
// ---

//! Pure evaluation registry. An evaluator receives one probe output and a
//! batch of selections and expected values, in order. No probe/evaluation pairing is built in.

use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct Decision {
    pub passed: bool,
    pub reason: String,
}

pub struct EvaluationInput {
    pub pointer: String,
    pub expected: Value,
}

pub trait Evaluation: Send + Sync {
    fn input_schema(&self) -> Value;
    fn batch_capable(&self) -> bool {
        false
    }
    fn validate_input(&self, _value: &Value) -> Result<(), String> {
        Ok(())
    }
    fn evaluate(
        &self,
        observed: &Value,
        requests: &[EvaluationInput],
    ) -> Vec<Result<Decision, String>>;
    /// Whether child replaces parent with a weaker condition. None is
    /// incomparable, and leads to a conservative replacement warning.
    fn relaxes(&self, parent: &Value, child: &Value) -> Option<bool>;
}

#[derive(Default)]
pub struct Evaluations {
    entries: BTreeMap<String, Box<dyn Evaluation>>,
}

impl Evaluations {
    pub fn built_in() -> Self {
        let mut result = Self::default();
        for kind in ["equal", "minimum", "maximum", "contains-all", "glob"] {
            result.register(kind, Box::new(Comparison(kind)));
        }
        result
    }
    pub fn register(&mut self, kind: &str, evaluation: Box<dyn Evaluation>) {
        self.entries.insert(kind.to_owned(), evaluation);
    }
    pub fn get(&self, kind: &str) -> Option<&dyn Evaluation> {
        self.entries.get(kind).map(Box::as_ref)
    }
}

struct Comparison(&'static str);

impl Evaluation for Comparison {
    fn input_schema(&self) -> Value {
        match self.0 {
            "minimum" | "maximum" => json!({"type":"integer"}),
            "contains-all" => json!({"type":"array", "uniqueItems":true}),
            "glob" => json!({"type":"string"}),
            _ => json!({}),
        }
    }
    fn batch_capable(&self) -> bool {
        true
    }
    fn validate_input(&self, value: &Value) -> Result<(), String> {
        if matches!(self.0, "minimum" | "maximum")
            && value.as_i64().is_none()
            && value.as_u64().is_none()
        {
            return Err("ordered comparison input must be a JSON integer".into());
        }
        if self.0 == "glob" {
            globset::Glob::new(value.as_str().ok_or("glob expected a string")?)
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
    fn evaluate(
        &self,
        observed: &Value,
        requests: &[EvaluationInput],
    ) -> Vec<Result<Decision, String>> {
        requests
            .iter()
            .map(|request| {
                let expected = &request.expected;
                let observed = observed
                    .pointer(&request.pointer)
                    .ok_or("unobserved selected field")?;
                let passed = match self.0 {
                    "equal" => observed == expected,
                    "minimum" | "maximum" => {
                        // Numeric ordering uses JSON numbers through serde_json's
                        // integer representations without converting through floats.
                        let order = number_order(observed, expected)
                            .ok_or("comparison needs JSON integers")?;
                        if self.0 == "minimum" {
                            !order.is_lt()
                        } else {
                            !order.is_gt()
                        }
                    }
                    "contains-all" => {
                        let actual = observed.as_array().ok_or("contains-all needs an array")?;
                        expected
                            .as_array()
                            .ok_or("contains-all expected an array")?
                            .iter()
                            .all(|v| actual.contains(v))
                    }
                    "glob" => {
                        let actual = observed.as_str().ok_or("glob needs a string")?;
                        let pattern = expected.as_str().ok_or("glob expected a string")?;
                        globset::Glob::new(pattern)
                            .map_err(|e| e.to_string())?
                            .compile_matcher()
                            .is_match(actual)
                    }
                    _ => unreachable!(),
                };
                Ok(Decision {
                    passed,
                    reason: if passed {
                        "condition passed"
                    } else {
                        "observed value does not meet condition"
                    }
                    .into(),
                })
            })
            .collect()
    }
    fn relaxes(&self, parent: &Value, child: &Value) -> Option<bool> {
        if parent == child {
            return Some(false);
        }
        match self.0 {
            "minimum" => Some(number_order(child, parent)?.is_lt()),
            "maximum" => Some(number_order(child, parent)?.is_gt()),
            "contains-all" => {
                let parent = parent.as_array()?;
                let child = child.as_array()?;
                if parent.iter().all(|v| child.contains(v)) {
                    Some(false)
                } else if child.iter().all(|v| parent.contains(v)) {
                    Some(true)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

fn number_order(a: &Value, b: &Value) -> Option<std::cmp::Ordering> {
    if let (Some(a), Some(b)) = (a.as_i64(), b.as_i64()) {
        return Some(a.cmp(&b));
    }
    if let (Some(a), Some(b)) = (a.as_u64(), b.as_u64()) {
        return Some(a.cmp(&b));
    }
    if let (Some(a), Some(b)) = (a.as_i64(), b.as_u64()) {
        return Some(if a < 0 {
            std::cmp::Ordering::Less
        } else {
            (a as u64).cmp(&b)
        });
    }
    if let (Some(a), Some(b)) = (a.as_u64(), b.as_i64()) {
        return Some(if b < 0 {
            std::cmp::Ordering::Greater
        } else {
            a.cmp(&(b as u64))
        });
    }
    None
}
