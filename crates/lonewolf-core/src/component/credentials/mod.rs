// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;

use lonewolf_auth::component::ComponentSecret;

use crate::RunError;
use crate::config::{ComponentSecretSource, ComponentsConfig};

pub(crate) fn load(
    config: &ComponentsConfig,
) -> Result<BTreeMap<Box<str>, ComponentSecret>, RunError> {
    config.domains.iter().map(|(domain, component)| {
        let secret = match &component.secret {
            ComponentSecretSource::Inline(secret) => secret.clone(),
            ComponentSecretSource::File(path) => {
                let read = || -> Result<ComponentSecret, io::Error> {
                    let mut value = fs::read_to_string(path)?;
                    let mode = fs::metadata(path)?.permissions().mode();
                    if mode & 0o077 != 0 {
                        tracing::warn!(component_domain = %domain, "component secret file is accessible to other users");
                    }
                    if value.ends_with("\r\n") {
                        value.truncate(value.len() - 2);
                    } else if value.ends_with('\n') {
                        value.pop();
                    }
                    ComponentSecret::new(&value).map_err(|_| io::Error::new(
                        io::ErrorKind::InvalidData,
                        "component secret must be 16 to 1024 bytes",
                    ))
                };
                read().map_err(|source| RunError::ComponentSecret { domain: domain.clone(), source })?
            }
        };
        Ok((domain.as_str().into(), secret))
    }).collect()
}

#[cfg(test)]
mod tests;
