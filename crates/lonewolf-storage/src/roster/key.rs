// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use lonewolf_xmpp::jid::JidRef;

use crate::account::AccountKey;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RosterJid {
    text: Box<str>,
}

impl RosterJid {
    pub fn domain(&self) -> &str {
        let bare = self
            .text
            .split_once('/')
            .map_or(self.as_str(), |(bare, _)| bare);
        bare.split_once('@').map_or(bare, |(_, domain)| domain)
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl From<JidRef<'_>> for RosterJid {
    fn from(jid: JidRef<'_>) -> Self {
        Self {
            text: Box::from(jid.as_str()),
        }
    }
}

impl From<&AccountKey> for RosterJid {
    fn from(key: &AccountKey) -> Self {
        Self {
            text: Box::from(key.as_str()),
        }
    }
}

impl fmt::Debug for RosterJid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RosterJid").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lonewolf_util::arena::Arena;
    use lonewolf_xmpp::jid::Jid;

    #[test]
    fn domain_excludes_the_localpart_and_resource() -> Result<(), Box<dyn std::error::Error>> {
        let mut arena = Arena::try_new(Default::default())?;
        for text in [
            "irc.example.test",
            "irc-server.example.test@irc.example.test",
            "irc-server.example.test@irc.example.test/console",
            "irc.example.test/console@elsewhere.test",
        ] {
            let parsed = Jid::parse_in(text, &mut arena)?;
            let jid = RosterJid::from(parsed.resolve(&arena)?);
            assert_eq!(jid.domain(), "irc.example.test");
            assert_eq!(jid.as_str(), text);
        }
        Ok(())
    }
}
