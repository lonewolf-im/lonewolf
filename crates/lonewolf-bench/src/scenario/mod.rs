// SPDX-License-Identifier: Apache-2.0

pub mod churn;
pub mod idle;
pub mod messages;

use crate::{config::ScenarioConfig, error::BenchResult};

pub fn validate_supported(scenario: &ScenarioConfig) -> BenchResult<()> {
    match scenario {
        ScenarioConfig::Idle { .. }
        | ScenarioConfig::Messages { .. }
        | ScenarioConfig::Churn { .. } => Ok(()),
    }
}

#[cfg(test)]
mod tests;
