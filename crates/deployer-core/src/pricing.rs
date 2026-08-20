use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{CoreError, Result};

/// Currency supported by the v0.1 GCP cost gate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PricingCurrency {
    Usd,
}

/// A positive reduced rational number, avoiding floating-point quantities.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RationalQuantity {
    pub numerator: u64,
    pub denominator: u64,
}

impl RationalQuantity {
    fn validate(self) -> Result<()> {
        if self.numerator == 0
            || self.denominator == 0
            || greatest_common_divisor(self.numerator, self.denominator) != 1
        {
            return Err(CoreError::InvalidPlan(
                "pricing quantity is not a positive reduced rational",
            ));
        }
        Ok(())
    }
}

/// One normalized GCP SKU/tier line. `unit_price_nanos` is USD nanos per
/// pricing unit; the exact calculation inputs and resulting micro-USD subtotal
/// are both approval-bound.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PricingLine {
    pub sku_id: String,
    pub tier_start_base_units: u64,
    pub usage_unit: String,
    pub base_unit: String,
    pub base_unit_conversion: RationalQuantity,
    pub usage_quantity: RationalQuantity,
    pub unit_price_nanos: u64,
    pub subtotal_microusd: u64,
}

impl PricingLine {
    fn validate(&self) -> Result<()> {
        if !safe_pricing_token(&self.sku_id)
            || !safe_pricing_token(&self.usage_unit)
            || !safe_pricing_token(&self.base_unit)
            || self.unit_price_nanos == 0
            || self.subtotal_microusd == 0
        {
            return Err(CoreError::InvalidPlan("pricing line is incomplete"));
        }
        self.base_unit_conversion.validate()?;
        self.usage_quantity.validate()
    }
}

/// Costs intentionally excluded from the estimate and displayed to operators.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnpricedExclusion {
    NetworkEgress,
    CloudDnsQueries,
    BackupAndSnapshotStorage,
    Support,
    Taxes,
}

/// Canonical float-free pricing quote bound into a deployment Plan ID.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PricingQuote {
    pub currency: PricingCurrency,
    /// `BTreeSet` gives canonical line ordering independent of API response
    /// order and rejects byte-identical duplicates.
    pub lines: BTreeSet<PricingLine>,
    pub unpriced_exclusions: BTreeSet<UnpricedExclusion>,
    pub total_microusd: u64,
}

impl PricingQuote {
    /// Validates normalized pricing inputs, uniqueness, exact sum, and budget.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidPlan`] for malformed lines, repeated
    /// SKU/tier units, arithmetic overflow, sum mismatch, or budget excess.
    pub fn validate(&self, maximum_monthly_microusd: u64) -> Result<()> {
        if self.lines.is_empty() || self.total_microusd == 0 {
            return Err(CoreError::InvalidPlan("pricing quote is empty"));
        }
        let mut keys = BTreeSet::new();
        let mut total = 0_u64;
        for line in &self.lines {
            line.validate()?;
            if !keys.insert((
                line.sku_id.as_str(),
                line.tier_start_base_units,
                line.usage_unit.as_str(),
                line.base_unit.as_str(),
            )) {
                return Err(CoreError::InvalidPlan("pricing SKU tier is repeated"));
            }
            total = total
                .checked_add(line.subtotal_microusd)
                .ok_or(CoreError::InvalidPlan("pricing total overflow"))?;
        }
        if total != self.total_microusd || total > maximum_monthly_microusd {
            return Err(CoreError::InvalidPlan(
                "pricing total differs from lines or exceeds budget",
            ));
        }
        Ok(())
    }
}

fn safe_pricing_token(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
}

const fn greatest_common_divisor(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(sku_id: &str, subtotal_microusd: u64) -> PricingLine {
        PricingLine {
            sku_id: sku_id.to_owned(),
            tier_start_base_units: 0,
            usage_unit: "h".to_owned(),
            base_unit: "s".to_owned(),
            base_unit_conversion: RationalQuantity {
                numerator: 3_600,
                denominator: 1,
            },
            usage_quantity: RationalQuantity {
                numerator: 730,
                denominator: 1,
            },
            unit_price_nanos: 10_000_000,
            subtotal_microusd,
        }
    }

    #[test]
    fn quote_requires_exact_sum_and_reduced_quantities() {
        let mut quote = PricingQuote {
            currency: PricingCurrency::Usd,
            lines: BTreeSet::from([line("SKU-VM", 7_300_000)]),
            unpriced_exclusions: BTreeSet::from([UnpricedExclusion::NetworkEgress]),
            total_microusd: 7_300_000,
        };
        assert!(quote.validate(8_000_000).is_ok());
        quote.total_microusd += 1;
        assert!(quote.validate(8_000_000).is_err());
        quote.total_microusd -= 1;
        let mut invalid = line("SKU-DISK", 1);
        invalid.usage_quantity = RationalQuantity {
            numerator: 2,
            denominator: 2,
        };
        quote.lines.insert(invalid);
        assert!(quote.validate(8_000_000).is_err());
    }

    #[test]
    fn quote_rejects_budget_excess_and_repeated_sku_tiers() {
        let mut quote = PricingQuote {
            currency: PricingCurrency::Usd,
            lines: BTreeSet::from([line("SKU-VM", 7_300_000)]),
            unpriced_exclusions: BTreeSet::new(),
            total_microusd: 7_300_000,
        };
        assert!(matches!(
            quote.validate(7_299_999),
            Err(CoreError::InvalidPlan(
                "pricing total differs from lines or exceeds budget"
            ))
        ));

        let mut repeated = line("SKU-VM", 700_000);
        repeated.unit_price_nanos += 1;
        quote.lines.insert(repeated);
        quote.total_microusd = 8_000_000;
        assert!(matches!(
            quote.validate(8_000_000),
            Err(CoreError::InvalidPlan("pricing SKU tier is repeated"))
        ));
    }

    #[test]
    fn quote_is_stable_across_response_ordering() {
        let quote = PricingQuote {
            currency: PricingCurrency::Usd,
            lines: BTreeSet::from([line("SKU-VM", 7_300_000), line("SKU-DISK", 1_000_000)]),
            unpriced_exclusions: BTreeSet::from([
                UnpricedExclusion::Taxes,
                UnpricedExclusion::NetworkEgress,
            ]),
            total_microusd: 8_300_000,
        };
        let canonical = serde_json::to_value(&quote).unwrap();
        let mut reordered = canonical.clone();
        reordered["lines"].as_array_mut().unwrap().reverse();
        reordered["unpriced_exclusions"]
            .as_array_mut()
            .unwrap()
            .reverse();
        let decoded: PricingQuote = serde_json::from_value(reordered).unwrap();
        assert_eq!(decoded, quote);
        assert_eq!(serde_json::to_value(decoded).unwrap(), canonical);
    }
}
