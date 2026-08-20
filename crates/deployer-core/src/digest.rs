use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{CoreError, Result};

/// An exact SHA-256 plan approval, formatted as `sha256:<lowercase hex>`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlanDigest(String);

impl PlanDigest {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
    }
}

impl fmt::Display for PlanDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for PlanDigest {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self> {
        let Some(hex) = value.strip_prefix("sha256:") else {
            return Err(CoreError::InvalidPlanDigest);
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CoreError::InvalidPlanDigest);
        }
        Ok(Self(value.to_owned()))
    }
}

impl Serialize for PlanDigest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PlanDigest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Serializes a value as deterministic JSON with recursively sorted keys.
///
/// This is the canonical byte representation used for plan approvals and
/// state integrity. Non-finite floats are rejected by `serde_json`.
///
/// # Errors
///
/// Returns [`CoreError::CanonicalSerialization`] if `value` cannot be
/// represented as JSON.
pub fn canonical_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let inspected = serde_value::to_value(value).map_err(|_| CoreError::CanonicalSerialization)?;
    if contains_non_finite(&inspected) {
        return Err(CoreError::CanonicalSerialization);
    }
    let value = serde_json::to_value(value).map_err(|_| CoreError::CanonicalSerialization)?;
    let canonical = canonicalize(value);
    serde_json::to_vec(&canonical).map_err(|_| CoreError::CanonicalSerialization)
}

fn contains_non_finite(value: &serde_value::Value) -> bool {
    use serde_value::Value;

    match value {
        Value::F32(number) => !number.is_finite(),
        Value::F64(number) => !number.is_finite(),
        Value::Option(Some(value)) | Value::Newtype(value) => contains_non_finite(value),
        Value::Seq(values) => values.iter().any(contains_non_finite),
        Value::Map(entries) => entries
            .iter()
            .any(|(key, value)| contains_non_finite(key) || contains_non_finite(value)),
        Value::Bool(_)
        | Value::U8(_)
        | Value::U16(_)
        | Value::U32(_)
        | Value::U64(_)
        | Value::I8(_)
        | Value::I16(_)
        | Value::I32(_)
        | Value::I64(_)
        | Value::Char(_)
        | Value::String(_)
        | Value::Unit
        | Value::Option(None)
        | Value::Bytes(_) => false,
    }
}

/// Computes the approval digest for the complete, canonical deployment plan.
///
/// # Errors
///
/// Returns [`CoreError::CanonicalSerialization`] if `plan` cannot be
/// represented as canonical JSON.
pub fn canonical_plan_digest<T: Serialize + ?Sized>(plan: &T) -> Result<PlanDigest> {
    Ok(PlanDigest::from_bytes(&canonical_json(plan)?))
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        Value::Object(values) => {
            let mut entries: Vec<_> = values.into_iter().collect();
            entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, canonicalize(value)))
                    .collect(),
            )
        }
        scalar => scalar,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use serde_json::json;

    use super::*;

    #[test]
    fn canonical_hash_is_independent_of_map_insertion_order() {
        let mut first = HashMap::new();
        first.insert("z", json!({"b": 2, "a": 1}));
        first.insert("a", json!([3, 4]));
        let mut second = BTreeMap::new();
        second.insert("a", json!([3, 4]));
        second.insert("z", json!({"a": 1, "b": 2}));
        assert_eq!(
            canonical_plan_digest(&first).unwrap(),
            canonical_plan_digest(&second).unwrap()
        );
    }

    #[test]
    fn hash_has_stable_known_answer() {
        let digest = canonical_plan_digest(&json!({"b": 2, "a": 1})).unwrap();
        assert_eq!(
            digest.as_str(),
            "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
        );
    }

    #[test]
    fn plan_digest_parser_is_exact() {
        let valid = "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777";
        assert_eq!(valid.parse::<PlanDigest>().unwrap().as_str(), valid);
        assert!(valid.to_uppercase().parse::<PlanDigest>().is_err());
        assert!(
            valid
                .trim_start_matches("sha256:")
                .parse::<PlanDigest>()
                .is_err()
        );
    }

    #[test]
    fn canonical_json_rejects_non_finite_numbers() {
        assert!(canonical_json(&f64::NAN).is_err());
        assert!(canonical_json(&f64::INFINITY).is_err());
    }
}
