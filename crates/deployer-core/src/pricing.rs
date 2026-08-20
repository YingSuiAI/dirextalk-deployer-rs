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
/// `usage_unit`, and `usage_quantity` is the chargeable quantity in that same
/// unit. `tier_start_base_units` is the source tier threshold converted
/// exactly to an integer number of `base_unit`s.
///
/// GCP's base-unit conversion is approval-bound provenance and is used by the
/// quote producer to normalize the tier threshold; it does not enter the cost
/// formula because both price and quantity use `usage_unit`. GCP's
/// `display_quantity` is deliberately absent because the API defines it as
/// display-only and says that it does not affect the pricing formula.
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
        self.usage_quantity.validate()?;
        if self.conservative_subtotal_microusd()? != self.subtotal_microusd {
            return Err(CoreError::InvalidPlan(
                "pricing line subtotal is not derived from price and usage",
            ));
        }
        Ok(())
    }

    /// Computes the line subtotal with exact integer arithmetic, conservatively
    /// rounded up to the next micro-USD:
    ///
    /// `ceil(unit_price_nanos * usage_numerator / (1000 * usage_denominator))`.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidPlan`] when the price or quantity is invalid
    /// or the rounded subtotal does not fit in `u64` micro-USD.
    pub fn conservative_subtotal_microusd(&self) -> Result<u64> {
        if self.unit_price_nanos == 0 {
            return Err(CoreError::InvalidPlan("pricing line price is invalid"));
        }
        self.usage_quantity.validate()?;
        let numerator = u128::from(self.unit_price_nanos)
            .checked_mul(u128::from(self.usage_quantity.numerator))
            .ok_or(CoreError::InvalidPlan("pricing subtotal overflow"))?;
        let denominator = u128::from(self.usage_quantity.denominator)
            .checked_mul(1_000)
            .ok_or(CoreError::InvalidPlan("pricing subtotal overflow"))?;
        let quotient = numerator / denominator;
        let rounded_up = quotient
            .checked_add(u128::from(numerator % denominator != 0))
            .ok_or(CoreError::InvalidPlan("pricing subtotal overflow"))?;
        rounded_up
            .try_into()
            .map_err(|_| CoreError::InvalidPlan("pricing subtotal overflow"))
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
    /// Returns [`CoreError::InvalidPlan`] for malformed or underquoted lines,
    /// unsupported multi-tier SKUs, arithmetic overflow, sum mismatch, or
    /// budget excess.
    pub fn validate(&self, maximum_monthly_microusd: u64) -> Result<()> {
        if self.lines.is_empty() || self.total_microusd == 0 {
            return Err(CoreError::InvalidPlan("pricing quote is empty"));
        }
        let mut skus = BTreeSet::new();
        let mut total = 0_u64;
        for line in &self.lines {
            line.validate()?;
            if !skus.insert(line.sku_id.as_str()) {
                return Err(CoreError::InvalidPlan(
                    "pricing SKU has an unsupported multi-tier shape",
                ));
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
    fn quote_rejects_underquoted_line_subtotal() {
        let mut underquoted = line("SKU-VM", 7_299_999);
        assert_eq!(
            underquoted.conservative_subtotal_microusd().unwrap(),
            7_300_000
        );
        let quote = PricingQuote {
            currency: PricingCurrency::Usd,
            lines: BTreeSet::from([underquoted.clone()]),
            unpriced_exclusions: BTreeSet::new(),
            total_microusd: underquoted.subtotal_microusd,
        };
        assert!(matches!(
            quote.validate(8_000_000),
            Err(CoreError::InvalidPlan(
                "pricing line subtotal is not derived from price and usage"
            ))
        ));

        underquoted.subtotal_microusd = 7_300_001;
        assert!(matches!(
            underquoted.validate(),
            Err(CoreError::InvalidPlan(
                "pricing line subtotal is not derived from price and usage"
            ))
        ));
    }

    #[test]
    fn subtotal_rounds_fractional_microusd_up() {
        let fractional = PricingLine {
            usage_quantity: RationalQuantity {
                numerator: 1,
                denominator: 3,
            },
            unit_price_nanos: 1,
            subtotal_microusd: 1,
            ..line("SKU-FRACTIONAL", 1)
        };
        assert_eq!(fractional.conservative_subtotal_microusd().unwrap(), 1);
        assert!(fractional.validate().is_ok());
    }

    #[test]
    fn subtotal_rejects_values_that_do_not_fit_microusd() {
        let overflow = PricingLine {
            usage_quantity: RationalQuantity {
                numerator: u64::MAX,
                denominator: 1,
            },
            unit_price_nanos: u64::MAX,
            subtotal_microusd: u64::MAX,
            ..line("SKU-OVERFLOW", u64::MAX)
        };
        assert!(matches!(
            overflow.conservative_subtotal_microusd(),
            Err(CoreError::InvalidPlan("pricing subtotal overflow"))
        ));
    }

    #[test]
    fn quote_rejects_budget_excess_and_unsupported_multi_tiers() {
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
        repeated.tier_start_base_units = 3_600;
        repeated.usage_quantity = RationalQuantity {
            numerator: 70,
            denominator: 1,
        };
        quote.lines.insert(repeated);
        quote.total_microusd = 8_000_000;
        assert!(matches!(
            quote.validate(8_000_000),
            Err(CoreError::InvalidPlan(
                "pricing SKU has an unsupported multi-tier shape"
            ))
        ));
    }

    #[test]
    fn one_exactly_normalized_nonzero_tier_is_supported() {
        let mut priced_after_free_allowance = line("SKU-TIERED", 7_300_000);
        priced_after_free_allowance.tier_start_base_units = 36_000;
        priced_after_free_allowance.base_unit_conversion = RationalQuantity {
            numerator: 3_600,
            denominator: 1,
        };
        let quote = PricingQuote {
            currency: PricingCurrency::Usd,
            lines: BTreeSet::from([priced_after_free_allowance]),
            unpriced_exclusions: BTreeSet::new(),
            total_microusd: 7_300_000,
        };
        assert!(quote.validate(8_000_000).is_ok());

        let mut noncanonical = quote;
        let mut line = noncanonical.lines.pop_first().unwrap();
        line.base_unit_conversion = RationalQuantity {
            numerator: 7_200,
            denominator: 2,
        };
        noncanonical.lines.insert(line);
        assert!(matches!(
            noncanonical.validate(8_000_000),
            Err(CoreError::InvalidPlan(
                "pricing quantity is not a positive reduced rational"
            ))
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
