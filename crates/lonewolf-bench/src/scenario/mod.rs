// SPDX-License-Identifier: Apache-2.0

pub mod idle;

use crate::{
    config::ScenarioConfig,
    error::{BenchError, BenchResult},
};

pub fn validate_supported(scenario: &ScenarioConfig) -> BenchResult<()> {
    match scenario {
        ScenarioConfig::Idle { .. } => Ok(()),
        ScenarioConfig::Messages { .. } | ScenarioConfig::Churn { .. } => Err(BenchError::staged()),
    }
}

#[cfg(test)]
mod tests;
