// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::future::Future;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use compio::runtime::Runtime;
use futures_channel::oneshot;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::Jid;

use super::{Order, Ticket};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn account(value: &str) -> TestResult<AccountKey> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in(value, &mut arena)?;
    Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
}

fn admit(order: &Arc<Order>, accounts: &[&AccountKey]) -> Ticket {
    order.admit(accounts.iter().map(|account| (*account).clone()).collect())
}

fn block_on<F: Future>(future: F) -> TestResult<F::Output> {
    Ok(Runtime::new()?.block_on(future))
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn is_ready(ticket: &mut Ticket) -> bool {
    poll_once(pin!(ticket.turn())).is_ready()
}

#[test]
fn tickets_for_one_account_turn_in_admission_order() -> TestResult {
    let order = Order::new();
    let alice = account("alice@example.com")?;
    let mut first = admit(&order, &[&alice]);
    let mut second = admit(&order, &[&alice]);
    assert!(is_ready(&mut first));
    assert!(!is_ready(&mut second));
    drop(first);
    assert!(is_ready(&mut second));
    Ok(())
}

#[test]
fn tickets_for_different_accounts_do_not_wait_for_each_other() -> TestResult {
    let order = Order::new();
    let alice = account("alice@example.com")?;
    let bob = account("bob@example.com")?;
    let _alice_only = admit(&order, &[&alice]);
    let mut bob_only = admit(&order, &[&bob]);
    assert!(is_ready(&mut bob_only));
    Ok(())
}

#[test]
fn a_ticket_waits_for_every_account_it_names() -> TestResult {
    let order = Order::new();
    let alice = account("alice@example.com")?;
    let bob = account("bob@example.com")?;
    let alice_only = admit(&order, &[&alice]);
    let bob_only = admit(&order, &[&bob]);
    let mut both = admit(&order, &[&alice, &bob]);
    assert!(!is_ready(&mut both));
    drop(alice_only);
    assert!(!is_ready(&mut both));
    drop(bob_only);
    assert!(is_ready(&mut both));
    Ok(())
}

#[test]
fn a_later_ticket_does_not_overtake_a_waiting_one() -> TestResult {
    let order = Order::new();
    let alice = account("alice@example.com")?;
    let bob = account("bob@example.com")?;
    let first = admit(&order, &[&alice]);
    let mut second = admit(&order, &[&alice, &bob]);
    let mut third = admit(&order, &[&bob]);
    assert!(
        !is_ready(&mut third),
        "bob's line starts behind the waiting ticket"
    );
    drop(first);
    assert!(is_ready(&mut second));
    assert!(!is_ready(&mut third));
    drop(second);
    assert!(is_ready(&mut third));
    Ok(())
}

#[test]
fn a_ticket_without_accounts_turns_immediately() -> TestResult {
    let order = Order::new();
    let alice = account("alice@example.com")?;
    let _held = admit(&order, &[&alice]);
    let mut free = admit(&order, &[]);
    assert!(is_ready(&mut free));
    Ok(())
}

#[test]
fn dropping_a_waiting_ticket_gives_its_place_to_the_next() -> TestResult {
    let order = Order::new();
    let alice = account("alice@example.com")?;
    let first = admit(&order, &[&alice]);
    let second = admit(&order, &[&alice]);
    let mut third = admit(&order, &[&alice]);
    drop(second);
    assert!(!is_ready(&mut third));
    drop(first);
    assert!(is_ready(&mut third));
    Ok(())
}

#[test]
fn a_dropped_turn_keeps_the_place() -> TestResult {
    let order = Order::new();
    let alice = account("alice@example.com")?;
    let first = admit(&order, &[&alice]);
    let mut second = admit(&order, &[&alice]);
    let mut third = admit(&order, &[&alice]);
    assert!(!is_ready(&mut second));
    drop(first);
    assert!(is_ready(&mut second));
    assert!(!is_ready(&mut third));
    drop(second);
    assert!(is_ready(&mut third));
    Ok(())
}

#[test]
fn released_tickets_leave_no_lines_behind() -> TestResult {
    let order = Order::new();
    let alice = account("alice@example.com")?;
    let bob = account("bob@example.com")?;
    let first = admit(&order, &[&alice, &bob]);
    let second = admit(&order, &[&alice]);
    drop(first);
    drop(second);
    let lines = order.lines.lock();
    assert!(lines.queues.is_empty());
    assert!(lines.waiting.is_empty());
    Ok(())
}

#[test]
fn a_view_that_cannot_be_fixed_takes_no_ticket() -> TestResult {
    let order = Order::new();
    let alice = account("alice@example.com")?;
    let failed = block_on(order.fix(vec![alice.clone()], async { Err::<(), &str>("no view") }))?;
    assert!(matches!(failed, Err("no view")));
    {
        let lines = order.lines.lock();
        assert!(lines.queues.is_empty());
        assert!(lines.waiting.is_empty());
    }
    let (value, mut ticket) = block_on(order.fix(vec![alice], async { Ok::<_, &str>(7) }))??;
    assert_eq!(value, 7);
    assert!(is_ready(&mut ticket));
    Ok(())
}

#[test]
fn tickets_follow_the_order_in_which_views_are_fixed() -> TestResult {
    let order = Order::new();
    let alice = account("alice@example.com")?;
    let (release, gate) = oneshot::channel::<()>();
    let mut slow = pin!(order.fix(vec![alice.clone()], async {
        gate.await.map_err(|_| "gate dropped")
    }));
    let mut fast = pin!(order.fix(vec![alice], async { Ok::<(), &str>(()) }));
    assert!(poll_once(slow.as_mut()).is_pending());
    assert!(
        poll_once(fast.as_mut()).is_pending(),
        "a view fixes only once the earlier one has its ticket"
    );
    release.send(()).map_err(|_| "gate closed")?;
    let ((), mut slow_ticket) = block_on(slow)??;
    let ((), mut fast_ticket) = block_on(fast)??;
    assert!(is_ready(&mut slow_ticket));
    assert!(!is_ready(&mut fast_ticket));
    drop(slow_ticket);
    assert!(is_ready(&mut fast_ticket));
    Ok(())
}
