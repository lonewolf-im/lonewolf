// SPDX-License-Identifier: Apache-2.0

use ::redb::{ReadableTable, TableDefinition, WriteTransaction};
use lonewolf_xmpp::jid::{JidRef, MAX_JID_LEN};

use super::{
    BlockChange, BlockDelta, BlockError, BlockingReads, BlockingWrites, MAX_BLOCKLIST_ITEM_BYTES,
    MAX_BLOCKLIST_ITEMS,
};
use crate::StorageError;
use crate::account::AccountKey;
use crate::account::redb::account_exists;
use crate::redb::{RedbRead, RedbWrite, storage_error, with_canonical_jid};
use crate::roster::RosterJid;

pub(crate) const ITEMS: TableDefinition<(&str, &str), ()> =
    TableDefinition::new("lonewolf_blocklist");

pub(crate) fn initialize(transaction: &WriteTransaction) -> Result<(), StorageError> {
    transaction.open_table(ITEMS).map_err(storage_error)?;
    Ok(())
}

struct LookupJid {
    text: Box<str>,
    bare_end: usize,
    domain_start: usize,
}

impl LookupJid {
    fn new(jid: JidRef<'_>) -> Self {
        let bare_end = jid.bare().as_str().len();
        Self {
            text: Box::from(jid.as_str()),
            bare_end,
            domain_start: bare_end - jid.domainpart().len(),
        }
    }

    fn is_blocked(
        &self,
        table: &impl ReadableTable<(&'static str, &'static str), ()>,
        owner: &str,
    ) -> Result<bool, StorageError> {
        let full = self.text.as_ref();
        let bare = &full[..self.bare_end];
        let domain = &bare[self.domain_start..];
        if table.get((owner, full)).map_err(storage_error)?.is_some() {
            return Ok(true);
        }
        if full != bare && table.get((owner, bare)).map_err(storage_error)?.is_some() {
            return Ok(true);
        }
        Ok(bare != domain && table.get((owner, domain)).map_err(storage_error)?.is_some())
    }
}

macro_rules! blocking_reads {
    ($handle:ty) => {
        impl BlockingReads for $handle {
            async fn blocklist(&self, owner: &AccountKey) -> Result<Vec<RosterJid>, BlockError> {
                let owner = owner.clone();
                self.run(move |transaction| {
                    let table = transaction.open_table(ITEMS).map_err(storage_error)?;
                    load_rules(&table, owner.as_str()).map_err(BlockError::from)
                })
                .await
            }

            async fn is_blocked(
                &self,
                owner: &AccountKey,
                peer: JidRef<'_>,
            ) -> Result<bool, BlockError> {
                let owner = owner.clone();
                let peer = LookupJid::new(peer);
                self.run(move |transaction| {
                    let table = transaction.open_table(ITEMS).map_err(storage_error)?;
                    peer.is_blocked(&table, owner.as_str())
                        .map_err(BlockError::from)
                })
                .await
            }
        }
    };
}

blocking_reads!(RedbRead);
blocking_reads!(RedbWrite);

enum OwnedChange {
    Block(Vec<RosterJid>),
    Unblock(Vec<RosterJid>),
    Clear,
}

impl BlockingWrites for RedbWrite {
    async fn change_blocklist(
        &mut self,
        owner: &AccountKey,
        change: BlockChange<'_>,
    ) -> Result<BlockDelta, BlockError> {
        let owner = owner.clone();
        let change = match change {
            BlockChange::Block(items) => OwnedChange::Block(items.to_vec()),
            BlockChange::Unblock(items) => OwnedChange::Unblock(items.to_vec()),
            BlockChange::Clear => OwnedChange::Clear,
        };
        self.run(move |transaction| update(transaction, owner.as_str(), change))
            .await
    }
}

fn load_rules(
    table: &impl ReadableTable<(&'static str, &'static str), ()>,
    owner: &str,
) -> Result<Vec<RosterJid>, StorageError> {
    // Canonical JIDs cannot contain NUL, so this range includes only this owner.
    let end = format!("{owner}\0");
    table
        .range((owner, "")..(end.as_str(), ""))
        .map_err(storage_error)?
        .map(|entry| {
            let (key, _) = entry.map_err(storage_error)?;
            let (_, text) = key.value();
            with_canonical_jid(text, MAX_JID_LEN, |jid| Ok(RosterJid::from(jid)))
        })
        .collect()
}

fn update(
    transaction: &WriteTransaction,
    owner: &str,
    change: OwnedChange,
) -> Result<BlockDelta, BlockError> {
    if matches!(change, OwnedChange::Block(_)) && !account_exists(transaction, owner)? {
        return Err(BlockError::NoAccount);
    }
    let mut table = transaction.open_table(ITEMS).map_err(storage_error)?;
    let mut unchanged = load_rules(&table, owner)?;
    let mut delta = BlockDelta::default();
    match change {
        OwnedChange::Block(mut items) => {
            items.sort_unstable();
            items.dedup();
            items.retain(|item| unchanged.binary_search(item).is_err());
            let count = unchanged.len() + items.len();
            if !items.is_empty()
                && (count > MAX_BLOCKLIST_ITEMS
                    || unchanged
                        .iter()
                        .chain(&items)
                        .map(item_bytes)
                        .sum::<usize>()
                        > MAX_BLOCKLIST_ITEM_BYTES)
            {
                return Err(BlockError::QuotaExceeded);
            }
            delta.inserted = items;
        }
        OwnedChange::Unblock(mut items) => {
            items.sort_unstable();
            delta.removed = unchanged
                .extract_if(.., |item| items.binary_search(item).is_ok())
                .collect();
        }
        OwnedChange::Clear => delta.removed = std::mem::take(&mut unchanged),
    }
    for item in &delta.inserted {
        table
            .insert((owner, item.as_str()), ())
            .map_err(storage_error)?;
    }
    for item in &delta.removed {
        table
            .remove((owner, item.as_str()))
            .map_err(storage_error)?;
    }
    delta.unchanged = unchanged;
    Ok(delta)
}

fn item_bytes(item: &RosterJid) -> usize {
    let text = item.as_str();
    // Match the stanza writer's escaping for double-quoted attributes.
    let escaped_bytes = text
        .bytes()
        .map(|byte| match byte {
            b'&' | b'\t' | b'\n' | b'\r' => 4,
            b'<' | b'>' => 3,
            b'"' => 5,
            _ => 0,
        })
        .sum::<usize>();
    br#"<item jid=""/>"#.len() + text.len() + escaped_bytes
}
