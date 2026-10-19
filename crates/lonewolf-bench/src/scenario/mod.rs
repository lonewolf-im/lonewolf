// SPDX-License-Identifier: Apache-2.0

pub mod idle;
pub mod messages;

use crate::{
    config::ScenarioConfig,
    error::{BenchError, BenchResult},
};

pub fn validate_supported(scenario: &ScenarioConfig) -> BenchResult<()> {
    match scenario {
        ScenarioConfig::Idle { .. } | ScenarioConfig::Messages { .. } => Ok(()),
        ScenarioConfig::Churn { .. } => Err(BenchError::staged()),
    }
}

#[cfg(test)]
mod tests;
