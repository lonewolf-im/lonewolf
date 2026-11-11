// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::future::Either;

pin_project_lite::pin_project! {
    #[must_use = "futures do nothing unless polled"]
    pub struct Race<A, B> {
        // Fields drop in declaration order, so this matches dropping pinned temporaries in reverse.
        #[pin]
        second: B,
        #[pin]
        first: A,
    }
}

/// Polls `first` before `second` and resolves with the output of whichever completes first.
///
/// Each input is stored once, while an `async fn` that pins its future argument stores it twice.
pub fn race<A: Future, B: Future>(first: A, second: B) -> Race<A, B> {
    Race { second, first }
}

impl<A: Future, B: Future> Future for Race<A, B> {
    type Output = Either<A::Output, B::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        if let Poll::Ready(output) = this.first.poll(cx) {
            return Poll::Ready(Either::Left(output));
        }
        this.second.poll(cx).map(Either::Right)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::future::{pending, ready};
    use std::mem::size_of_val;
    use std::rc::Rc;

    use futures_util::FutureExt as _;
    use futures_util::future::Either;

    use super::race;

    struct Recorder(&'static str, Rc<RefCell<Vec<&'static str>>>);

    impl Drop for Recorder {
        fn drop(&mut self) {
            self.1.borrow_mut().push(self.0);
        }
    }

    #[test]
    fn first_wins_when_both_are_ready() {
        let output = race(ready(1), ready("two")).now_or_never();
        assert!(matches!(output, Some(Either::Left(1))));
    }

    #[test]
    fn second_resolves_while_first_is_pending() {
        let output = race(pending::<()>(), ready(2)).now_or_never();
        assert!(matches!(output, Some(Either::Right(2))));
    }

    #[test]
    fn stays_pending_until_either_completes() {
        let output = race(pending::<()>(), pending::<()>()).now_or_never();
        assert!(output.is_none());
    }

    #[test]
    fn drops_second_before_first() {
        let order = Rc::new(RefCell::new(Vec::new()));
        let first = Recorder("first", Rc::clone(&order));
        let second = Recorder("second", Rc::clone(&order));
        drop(race(
            async move {
                let _first = first;
                pending::<()>().await
            },
            async move {
                let _second = second;
                pending::<()>().await
            },
        ));
        assert_eq!(*order.borrow(), ["second", "first"]);
    }

    #[test]
    fn stores_each_input_once() {
        let first = async {
            let buffer = [0_u8; 4096];
            pending::<()>().await;
            buffer.len()
        };
        let second = pending::<()>();
        let expected = size_of_val(&first) + size_of_val(&second);
        assert_eq!(size_of_val(&race(first, second)), expected);
    }
}
