//! Organization-owned classification inputs, separate from repository files and maturity.
//
// relationships:
//   implements: classification
//   references: release-process-conformance

use crate::github::{CustomPropertyValue, CustomPropertyValueKind};

/// One declaration maintained by the operator on the organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Property {
    Audience,
    Family,
    Category,
}

impl Property {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Audience => "audience",
            Self::Family => "family",
            Self::Category => "category",
        }
    }

    #[must_use]
    pub const fn undeclared_code(self) -> &'static str {
        match self {
            Self::Audience => "classification_audience_undeclared",
            Self::Family => "classification_family_undeclared",
            Self::Category => "classification_category_undeclared",
        }
    }

    /// The compiled declaration required by an undeclared work-queue row.
    #[must_use]
    pub fn from_undeclared_code(code: &str) -> Option<Self> {
        [Self::Audience, Self::Family, Self::Category]
            .into_iter()
            .find(|property| property.undeclared_code() == code)
    }

    /// Declarations consumed by the seven classification comparisons.
    #[must_use]
    pub fn required_by(rule: &str) -> &'static [Self] {
        match rule {
            "REPO-ORG-01" | "REPO-ORG-02" => &[Self::Audience],
            "REPO-NAME-02" | "REPO-LIC-02" => &[Self::Category],
            "REPO-NAME-03" | "REPO-NAME-04" | "REPO-META-08" => &[Self::Family],
            _ => &[],
        }
    }

    /// Read a scalar without treating malformed or duplicate input as absent.
    ///
    /// # Errors
    /// Returns a diagnostic for repeated properties or a non-scalar value.
    pub fn read(self, values: &[CustomPropertyValue]) -> Result<Option<&str>, String> {
        let mut matching = values.iter().filter(|row| row.property_name == self.name());
        let first = matching.next();
        if matching.next().is_some() {
            return Err(format!(
                "organization property `{}` occurs more than once",
                self.name()
            ));
        }
        match first.map(|row| &row.value) {
            None | Some(CustomPropertyValueKind::Null) => Ok(None),
            Some(CustomPropertyValueKind::String(value)) if value.trim().is_empty() => Ok(None),
            Some(CustomPropertyValueKind::String(value)) => Ok(Some(value)),
            Some(CustomPropertyValueKind::Strings(_)) => Err(format!(
                "organization property `{}` must be a single value",
                self.name()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, value: CustomPropertyValueKind) -> CustomPropertyValue {
        CustomPropertyValue {
            property_name: name.to_owned(),
            value,
        }
    }

    #[test]
    fn missing_null_and_blank_are_undeclared() {
        for values in [
            vec![],
            vec![row("audience", CustomPropertyValueKind::Null)],
            vec![row("audience", CustomPropertyValueKind::String(" ".into()))],
        ] {
            assert_eq!(Property::Audience.read(&values), Ok(None));
        }
    }

    #[test]
    fn duplicate_and_multiselect_classification_are_errors() {
        let value = row("family", CustomPropertyValueKind::String("sample".into()));
        assert!(Property::Family
            .read(&[value.clone(), value])
            .unwrap_err()
            .contains("more than once"));
        assert!(Property::Family
            .read(&[row(
                "family",
                CustomPropertyValueKind::Strings(vec!["sample".into()])
            )])
            .unwrap_err()
            .contains("single value"));
    }

    #[test]
    fn unrelated_shapes_do_not_change_the_requested_declaration() {
        let values = [
            row("unrelated", CustomPropertyValueKind::Strings(vec![])),
            row("other", CustomPropertyValueKind::Null),
            row("family", CustomPropertyValueKind::String("sample".into())),
        ];
        assert_eq!(Property::Family.read(&values), Ok(Some("sample")));
        assert_eq!(Property::Audience.read(&values), Ok(None));
    }

    #[test]
    fn only_compiled_undeclared_codes_select_a_property() {
        for property in [Property::Audience, Property::Family, Property::Category] {
            assert_eq!(
                Property::from_undeclared_code(property.undeclared_code()),
                Some(property)
            );
        }
        assert_eq!(Property::from_undeclared_code("out-of-scope"), None);
    }
}
