// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::error::Error;
use std::rc::Rc;
use std::time::Duration;

use compio::runtime::Runtime;
use lonewolf_extension::delivery::DeliveryError;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::RoutedStanza;

use super::after_turn;
use crate::order::Order;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn account(value: &str) -> TestResult<AccountKey> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in(value, &mut arena)?;
    Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
}

#[test]
fn work_after_a_turn_runs_once_the_caller_is_gone() -> TestResult {
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
        let pending = after_turn(
            ticket,
            None,
            move |_: Vec<RoutedStanza<GlobalChunkAllocator>>| async move { flag.set(true) },
        );
        drop(pending);
        compio::time::sleep(Duration::from_millis(20)).await;
        assert!(!ran.get(), "work ran before its turn");

        drop(ahead);
        for _ in 0..50 {
            if ran.get() {
                break;
            }
            compio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(ran.get(), "work was lost with its caller");
        Ok(())
    })
}
