// SPDX-License-Identifier: Apache-2.0

pub const NAME: &str = "carbons";
pub const NAMESPACE: &str = "urn:xmpp:carbons:2";
pub const RULES_FEATURE: &str = "urn:xmpp:carbons:rules:0";
pub const FORWARD_NAMESPACE: &str = "urn:xmpp:forward:0";

pub mod copy;
pub mod rules;

#[cfg(test)]
mod tests;
