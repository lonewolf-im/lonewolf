// SPDX-License-Identifier: Apache-2.0

use std::time::Instant;

pub(crate) fn now() -> Instant {
    #[cfg(test)]
    if let Some(now) = FROZEN_NOW.with_borrow(|clock| clock.as_ref().map(|time| *time.borrow())) {
        return now;
    }
    #[cfg(feature = "test-support")]
    if let Some(clock) = crate::test_support::ManualClock::current() {
        return clock.now();
    }
    Instant::now()
}

pub(crate) fn wall_now() -> std::time::SystemTime {
    #[cfg(feature = "test-support")]
    if let Some(clock) = crate::test_support::ManualClock::current() {
        return clock.wall_now();
    }
    std::time::SystemTime::now()
}

pub(crate) fn unix_now() -> rustls::pki_types::UnixTime {
    #[cfg(feature = "test-support")]
    if let Some(clock) = crate::test_support::ManualClock::current() {
        return rustls::pki_types::UnixTime::since_unix_epoch(
            clock
                .wall_now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("fixture time starts after the Unix epoch"),
        );
    }
    rustls::pki_types::UnixTime::now()
}

pub(crate) fn sleep(duration: std::time::Duration) -> impl std::future::Future<Output = ()> {
    sleep_until(now() + duration)
}

pub(crate) async fn sleep_until(deadline: Instant) {
    #[cfg(test)]
    if let Some(mut time) =
        FROZEN_NOW.with_borrow(|clock| clock.as_ref().map(tokio::sync::watch::Sender::subscribe))
    {
        let _ = time.wait_for(|now| *now >= deadline).await;
        return;
    }
    #[cfg(feature = "test-support")]
    if let Some(clock) = crate::test_support::ManualClock::current() {
        clock.sleep_until(deadline).await;
        return;
    }
    compio::time::sleep_until(deadline).await;
}

/// Races `future` against `deadline` while storing `future` once.
pub(crate) fn timeout_at<F: std::future::Future>(
    deadline: Instant,
    future: F,
) -> impl std::future::Future<Output = Result<F::Output, ()>> {
    use futures_util::FutureExt as _;
    use futures_util::future::Either;
    #[cfg(any(test, feature = "test-support"))]
    if is_controlled() {
        return lonewolf_util::race::race(sleep_until(deadline), future)
            .map(|result| match result {
                Either::Left(()) => Err(()),
                Either::Right(output) => Ok(output),
            })
            .left_future();
    }
    let raced =
        lonewolf_util::race::race(future, compio::time::sleep_until(deadline)).map(|result| {
            match result {
                Either::Left(output) => Ok(output),
                Either::Right(()) => Err(()),
            }
        });
    #[cfg(any(test, feature = "test-support"))]
    let raced = raced.right_future();
    raced
}

#[cfg(any(test, feature = "test-support"))]
fn is_controlled() -> bool {
    #[cfg(test)]
    if FROZEN_NOW.with_borrow(Option::is_some) {
        return true;
    }
    #[cfg(feature = "test-support")]
    {
        crate::test_support::ManualClock::current().is_some()
    }
    #[cfg(not(feature = "test-support"))]
    {
        false
    }
}

#[cfg(test)]
thread_local! {
    static FROZEN_NOW: std::cell::RefCell<Option<tokio::sync::watch::Sender<Instant>>> = const { std::cell::RefCell::new(None) };
}

/// Holds [`now`] at a fixed instant on this thread until dropped, so a test decides when time passes.
#[cfg(test)]
pub(crate) struct FrozenClock(Option<tokio::sync::watch::Sender<Instant>>);

#[cfg(test)]
impl FrozenClock {
    pub(crate) fn start() -> Self {
        Self(FROZEN_NOW.replace(Some(tokio::sync::watch::channel(Instant::now()).0)))
    }

    pub(crate) fn now(&self) -> Instant {
        now()
    }

    pub(crate) fn advance(&self, duration: std::time::Duration) {
        FROZEN_NOW.with_borrow(|clock| {
            clock
                .as_ref()
                .expect("frozen clock")
                .send_modify(|now| *now += duration)
        });
    }
}

#[cfg(test)]
impl Drop for FrozenClock {
    fn drop(&mut self) {
        FROZEN_NOW.replace(self.0.take());
    }
}
