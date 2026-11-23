// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::num::NonZeroUsize;

use lonewolf_auth::scram::{ScramCredentials, ScramHash, ScramVerifier};

use super::{CachedRead, CachedWrite};
use crate::account::{Account, AccountError, AccountKey, AccountReads, AccountWrites, NewAccount};
use crate::offline::{
    OfflineError, OfflinePage, OfflineReads, OfflineSequence, OfflineWrites, StoredMessage,
};
use crate::private::{
    PrivateXmlChange, PrivateXmlError, PrivateXmlQuota, PrivateXmlReads, PrivateXmlWrites,
    StoredPrivateXml,
};
use crate::roster::{
    PendingPage, PendingSubscription, RosterError, RosterItem, RosterJid, RosterMutation,
    RosterQuota, RosterReads, RosterSnapshot, RosterSubscription, RosterVersion, RosterWrites,
};
use crate::vcard::{StoredVCard, VCardError, VCardQuota, VCardReads, VCardWrites};

macro_rules! forward_reads {
    ($trait:ident { $(
        fn $method:ident(&$self:ident $(, $arg:ident: $type:ty)* $(,)?)
            -> $result:ty;
    )* }) => {
        impl<T: $trait> $trait for CachedRead<T> {
            $(fn $method(&$self $(, $arg: $type)*) -> impl Future<Output = $result> + Send {
                $self.inner.$method($($arg),*)
            })*
        }

        impl<T: $trait> $trait for CachedWrite<T> {
            $(fn $method(&$self $(, $arg: $type)*) -> impl Future<Output = $result> + Send {
                $self.inner.$method($($arg),*)
            })*
        }
    };
}

forward_reads! {
    AccountReads {
        fn account(&self, key: &AccountKey) -> Result<Option<Account>, AccountError>;
        fn scram(&self, key: &AccountKey, hash: ScramHash) -> Result<Option<ScramVerifier>, AccountError>;
        fn accounts_after(&self, after: Option<&AccountKey>, limit: NonZeroUsize) -> Result<Vec<Account>, AccountError>;
    }
}

impl<T: AccountWrites> AccountWrites for CachedWrite<T> {
    fn create_account(
        &mut self,
        account: NewAccount,
    ) -> impl Future<Output = Result<(), AccountError>> + Send {
        self.inner.create_account(account)
    }

    fn delete_account(
        &mut self,
        key: &AccountKey,
    ) -> impl Future<Output = Result<(), AccountError>> + Send {
        self.inner.delete_account(key)
    }

    fn replace_credentials(
        &mut self,
        key: &AccountKey,
        credentials: ScramCredentials,
    ) -> impl Future<Output = Result<(), AccountError>> + Send {
        self.inner.replace_credentials(key, credentials)
    }
}

forward_reads! {
    OfflineReads {
        fn offline_messages(&self, owner: &AccountKey) -> Result<Vec<StoredMessage>, OfflineError>;
        fn last_offline_sequence(&self, owner: &AccountKey) -> Result<Option<OfflineSequence>, OfflineError>;
        fn offline_page(&self, owner: &AccountKey, after: Option<OfflineSequence>, through: OfflineSequence, max_bytes: NonZeroUsize, page: OfflinePage) -> Result<OfflinePage, OfflineError>;
        fn contains_offline_message(&self, owner: &AccountKey, sequence: OfflineSequence) -> Result<bool, OfflineError>;
        fn offline_count(&self, owner: &AccountKey) -> Result<usize, OfflineError>;
    }
}

impl<T: OfflineWrites> OfflineWrites for CachedWrite<T> {
    fn push_offline_message(
        &mut self,
        owner: &AccountKey,
        stored_at: u64,
        stanza: &[u8],
    ) -> impl Future<Output = Result<OfflineSequence, OfflineError>> + Send {
        self.inner.push_offline_message(owner, stored_at, stanza)
    }

    fn remove_offline_messages_through(
        &mut self,
        owner: &AccountKey,
        through: OfflineSequence,
    ) -> impl Future<Output = Result<usize, OfflineError>> + Send {
        self.inner.remove_offline_messages_through(owner, through)
    }

    fn remove_offline_message(
        &mut self,
        owner: &AccountKey,
        sequence: OfflineSequence,
    ) -> impl Future<Output = Result<bool, OfflineError>> + Send {
        self.inner.remove_offline_message(owner, sequence)
    }

    fn clear_offline_messages(
        &mut self,
        owner: &AccountKey,
    ) -> impl Future<Output = Result<(), OfflineError>> + Send {
        self.inner.clear_offline_messages(owner)
    }
}

forward_reads! {
    PrivateXmlReads {
        fn private_xml(&self, owner: &AccountKey, namespace: &str, name: &str) -> Result<Option<StoredPrivateXml>, PrivateXmlError>;
    }
}

impl<T: PrivateXmlWrites> PrivateXmlWrites for CachedWrite<T> {
    fn update_private_xml(
        &mut self,
        owner: &AccountKey,
        changes: &[PrivateXmlChange<'_>],
        quota: PrivateXmlQuota,
    ) -> impl Future<Output = Result<(), PrivateXmlError>> + Send {
        self.inner.update_private_xml(owner, changes, quota)
    }

    fn clear_private_xml(
        &mut self,
        owner: &AccountKey,
    ) -> impl Future<Output = Result<(), PrivateXmlError>> + Send {
        self.inner.clear_private_xml(owner)
    }
}

forward_reads! {
    RosterReads {
        fn roster(&self, owner: &AccountKey, quota: RosterQuota) -> Result<RosterSnapshot, RosterError>;
        fn roster_item(&self, owner: &AccountKey, jid: &RosterJid, quota: RosterQuota) -> Result<Option<RosterItem>, RosterError>;
        fn roster_version(&self, owner: &AccountKey) -> Result<RosterVersion, RosterError>;
        fn roster_subscription(&self, owner: &AccountKey, jid: &RosterJid) -> Result<Option<RosterSubscription>, RosterError>;
        fn next_roster_subscription(&self, owner: &AccountKey, after: Option<&RosterJid>) -> Result<Option<(RosterJid, RosterSubscription)>, RosterError>;
        fn next_pending_sender(&self, owner: &AccountKey, after: Option<&RosterJid>) -> Result<Option<RosterJid>, RosterError>;
        fn pending_request_exists(&self, owner: &AccountKey, sender: &RosterJid) -> Result<bool, RosterError>;
        fn pending_page(&self, owner: &AccountKey, after: Option<&RosterJid>, max_bytes: NonZeroUsize, page: PendingPage) -> Result<PendingPage, RosterError>;
        fn pending_requests(&self, owner: &AccountKey) -> Result<Vec<PendingSubscription>, RosterError>;
        fn pending_request(&self, owner: &AccountKey, sender: &RosterJid) -> Result<Option<PendingSubscription>, RosterError>;
    }
}

impl<T: RosterWrites> RosterWrites for CachedWrite<T> {
    type Snapshot = CachedRead<T::Snapshot>;

    fn put_roster_item(
        &mut self,
        owner: &AccountKey,
        item: &RosterItem,
        quota: RosterQuota,
    ) -> impl Future<Output = Result<RosterVersion, RosterError>> + Send {
        self.inner.put_roster_item(owner, item, quota)
    }

    fn set_roster_subscription(
        &mut self,
        before: &Self::Snapshot,
        owner: &AccountKey,
        jid: &RosterJid,
        subscription: RosterSubscription,
    ) -> impl Future<Output = Result<Option<RosterVersion>, RosterError>> + Send {
        self.inner
            .set_roster_subscription(before.inner(), owner, jid, subscription)
    }

    fn transition_roster_subscription(
        &mut self,
        owner: &AccountKey,
        jid: &RosterJid,
        expected: RosterSubscription,
        subscription: RosterSubscription,
    ) -> impl Future<Output = Result<Option<RosterVersion>, RosterError>> + Send {
        self.inner
            .transition_roster_subscription(owner, jid, expected, subscription)
    }

    fn remove_roster_subscription(
        &mut self,
        owner: &AccountKey,
        jid: &RosterJid,
    ) -> impl Future<Output = Result<Option<RosterMutation<RosterSubscription>>, RosterError>> + Send
    {
        self.inner.remove_roster_subscription(owner, jid)
    }

    fn remove_roster_item(
        &mut self,
        owner: &AccountKey,
        jid: &RosterJid,
    ) -> impl Future<Output = Result<Option<RosterMutation<RosterItem>>, RosterError>> + Send {
        self.inner.remove_roster_item(owner, jid)
    }

    fn put_pending_request(
        &mut self,
        owner: &AccountKey,
        request: PendingSubscription,
        max_pending_subscription_requests: NonZeroUsize,
    ) -> impl Future<Output = Result<(), RosterError>> + Send {
        self.inner
            .put_pending_request(owner, request, max_pending_subscription_requests)
    }

    fn remove_pending_request(
        &mut self,
        owner: &AccountKey,
        sender: &RosterJid,
    ) -> impl Future<Output = Result<bool, RosterError>> + Send {
        self.inner.remove_pending_request(owner, sender)
    }

    fn clear_roster(
        &mut self,
        owner: &AccountKey,
    ) -> impl Future<Output = Result<(), RosterError>> + Send {
        self.inner.clear_roster(owner)
    }
}

forward_reads! {
    VCardReads {
        fn vcard(&self, owner: &AccountKey) -> Result<Option<StoredVCard>, VCardError>;
    }
}

impl<T: VCardWrites> VCardWrites for CachedWrite<T> {
    fn replace_vcard(
        &mut self,
        owner: &AccountKey,
        xml: &str,
        quota: VCardQuota,
    ) -> impl Future<Output = Result<(), VCardError>> + Send {
        self.inner.replace_vcard(owner, xml, quota)
    }

    fn delete_vcard(
        &mut self,
        owner: &AccountKey,
    ) -> impl Future<Output = Result<(), VCardError>> + Send {
        self.inner.delete_vcard(owner)
    }
}
