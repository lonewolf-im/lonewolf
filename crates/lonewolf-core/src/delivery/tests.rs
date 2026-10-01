// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::error::Error;
use std::rc::Rc;
use std::time::Duration;

use compio::runtime::Runtime;
use lonewolf_extension::Deliver;
use lonewolf_extension::delivery::{
    Delivery, DeliveryError, DeliveryFuture, HostLookup, SessionTag, StanzaFactory,
};
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::RoutedStanza;

use super::deliver_committed;
use crate::order::Order;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct NoDelivery;

impl HostLookup for NoDelivery {
    fn is_local_host(&self, _: &str) -> bool {
        true
    }
}

impl Delivery<GlobalChunkAllocator> for NoDelivery {
    fn arena(&self) -> Result<Arena<GlobalChunkAllocator>, DeliveryError> {
        Arena::try_new(ArenaConfig::default()).map_err(|_| DeliveryError)
    }

    fn tag_session<'a>(&'a self, _: SessionTag, _: u64) -> DeliveryFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn to_available<'a>(&'a self, _: RoutedStanza<GlobalChunkAllocator>) -> DeliveryFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn to_tagged<'a>(
        &'a self,
        _: SessionTag,
        _: RoutedStanza<GlobalChunkAllocator>,
    ) -> DeliveryFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn push_to_tagged<'a>(
        &'a self,
        _: &'a AccountKey,
        _: SessionTag,
        _: StanzaFactory<GlobalChunkAllocator>,
    ) -> DeliveryFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn current_presence<'a>(&'a self, _: &'a AccountKey, _: &'a AccountKey) -> DeliveryFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn unavailable_presence<'a>(
        &'a self,
        _: &'a AccountKey,
        _: &'a AccountKey,
    ) -> DeliveryFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

fn account(value: &str) -> TestResult<AccountKey> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in(value, &mut arena)?;
    Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
}

#[test]
fn committed_effects_run_after_the_caller_is_gone() -> TestResult {
    Runtime::new()?.block_on(async {
        let order = Order::new();
        let alice = account("alice@example.com")?;
        let ((), ahead) = order
            .fix(vec![alice.clone()], async { Ok::<_, DeliveryError>(()) })
            .await?;
        let ((), ticket) = order
            .fix(vec![alice], async { Ok::<_, DeliveryError>(()) })
            .await?;
        let ran = Rc::new(Cell::new(false));
        let flag = Rc::clone(&ran);
        let deliver: Deliver<GlobalChunkAllocator> = Box::new(move |_| {
            Box::pin(async move {
                flag.set(true);
                Ok(())
            })
        });
        let committed = deliver_committed(ticket, deliver, NoDelivery, None);
        drop(committed);
        compio::time::sleep(Duration::from_millis(20)).await;
        assert!(!ran.get(), "effects ran before their turn");

        drop(ahead);
        for _ in 0..50 {
            if ran.get() {
                break;
            }
            compio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(ran.get(), "effects were lost with their caller");
        Ok(())
    })
}
