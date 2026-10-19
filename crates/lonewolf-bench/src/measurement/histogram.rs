// SPDX-License-Identifier: Apache-2.0

use super::invalid;
use crate::{
    error::BenchResult,
    report::{HistogramBucket, HistogramReport, Microseconds},
};
use hdrhistogram::Histogram;
use std::time::Duration;

pub struct LatencyHistogram {
    histogram: Histogram<u64>,
    max_us: u64,
    sum_us: u64,
    minimum: Option<u64>,
    maximum: Option<u64>,
}

fn micros(duration: Duration) -> BenchResult<u64> {
    duration
        .as_nanos()
        .div_ceil(1000)
        .try_into()
        .map_err(|_| invalid("histogram duration overflow"))
}

impl LatencyHistogram {
    pub fn new(max: Duration) -> BenchResult<Self> {
        let max_us = micros(max)?;
        if max_us == 0 {
            return Err(invalid("histogram maximum is zero"));
        }
        let mut histogram = Histogram::new_with_bounds(1, max_us.max(2), 3)
            .map_err(|_| invalid("histogram allocation failed"))?;
        histogram.auto(false);
        Ok(Self {
            histogram,
            max_us,
            sum_us: 0,
            minimum: None,
            maximum: None,
        })
    }

    pub fn record(&mut self, duration: Duration) -> BenchResult<()> {
        let value = micros(duration)?;
        if value > self.max_us || self.histogram.len() == u64::MAX {
            return Err(invalid("histogram sample overflow"));
        }
        let sum = self
            .sum_us
            .checked_add(value)
            .ok_or_else(|| invalid("histogram sum overflow"))?;
        self.histogram
            .record(value)
            .map_err(|_| invalid("histogram sample out of range"))?;
        self.sum_us = sum;
        self.minimum = Some(self.minimum.map_or(value, |v| v.min(value)));
        self.maximum = Some(self.maximum.map_or(value, |v| v.max(value)));
        Ok(())
    }

    pub fn report(&self) -> HistogramReport {
        let count = self.histogram.len();
        let quantile = |q| (count > 0).then(|| self.histogram.value_at_quantile(q));
        HistogramReport {
            unit: Microseconds::Microseconds,
            significant_figures: 3,
            count,
            min_us: self.minimum,
            mean_us: (count > 0).then(|| self.sum_us as f64 / count as f64),
            p50_us: quantile(0.5),
            p95_us: quantile(0.95),
            p99_us: quantile(0.99),
            max_us: self.maximum,
            sum_us: self.sum_us,
            buckets: self
                .histogram
                .iter_recorded()
                .map(|v| HistogramBucket {
                    upper_bound_us: v.value_iterated_to(),
                    count: v.count_at_value(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sum_overflow_returns_error_without_adding_a_sample() {
        let mut histogram = LatencyHistogram::new(Duration::from_secs(1)).unwrap();
        histogram.sum_us = u64::MAX;
        assert!(histogram.record(Duration::from_nanos(1)).is_err());
        assert_eq!(histogram.report().count, 0);
    }
}
