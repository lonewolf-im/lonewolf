// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use compio::runtime::Runtime;
use compio::time::timeout;
use futures_util::future::poll_fn;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncReadExt, ReadBuf};

use super::*;

struct SliceReader<'a> {
    bytes: &'a [u8],
}

impl AsyncBufRead for SliceReader<'_> {
    fn poll_fill_buf(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        Poll::Ready(Ok(self.get_mut().bytes))
    }

    fn consume(self: Pin<&mut Self>, amount: usize) {
        let this = self.get_mut();
        this.bytes = &this.bytes[amount..];
    }
}

impl AsyncRead for SliceReader<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let available = match self.as_mut().poll_fill_buf(cx) {
            Poll::Ready(Ok(available)) => available,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        };
        let amount = available.len().min(output.remaining());
        output.put_slice(&available[..amount]);
        self.consume(amount);
        Poll::Ready(Ok(()))
    }
}

#[test]
fn burst_then_refill_paces_all_bytes() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        let mut reader = RateLimitedReader::new(
            SliceReader { bytes: b"abcde" },
            NonZeroUsize::new(20).ok_or("invalid rate")?,
            NonZeroUsize::new(3).ok_or("invalid burst")?,
        );
        let mut first = [0; 3];
        reader.read_exact(&mut first).await?;
        assert_eq!(&first, b"abc");
        let mut fourth = [0; 1];
        assert!(
            timeout(Duration::from_millis(10), reader.read_exact(&mut fourth))
                .await
                .is_err()
        );
        timeout(Duration::from_millis(200), reader.read_exact(&mut fourth)).await??;
        assert_eq!(&fourth, b"d");
        let mut fifth = [0; 1];
        timeout(Duration::from_millis(200), reader.read_exact(&mut fifth)).await??;
        assert_eq!(&fifth, b"e");
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn transport_upgrade_keeps_rate_allowance() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        let mut before = RateLimitedReader::new(
            SliceReader { bytes: b"ab" },
            NonZeroUsize::new(10).ok_or("invalid rate")?,
            NonZeroUsize::new(2).ok_or("invalid burst")?,
        );
        let mut initial = [0; 2];
        before.read_exact(&mut initial).await?;
        let mut after =
            RateLimitedReader::from_state(SliceReader { bytes: b"c" }, before.into_state());
        let mut next = [0; 1];
        assert!(
            timeout(Duration::from_millis(20), after.read_exact(&mut next))
                .await
                .is_err()
        );
        timeout(Duration::from_millis(200), after.read_exact(&mut next)).await??;
        assert_eq!(&next, b"c");
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn transport_upgrade_keeps_an_already_pending_refill_timer() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        let mut before = RateLimitedReader::new(
            SliceReader { bytes: b"ab" },
            NonZeroUsize::new(2).ok_or("invalid rate")?,
            NonZeroUsize::MIN,
        );
        let mut initial = [0; 1];
        before.read_exact(&mut initial).await?;
        assert_eq!(&initial, b"a");
        poll_fn(|cx| {
            assert!(Pin::new(&mut before).poll_fill_buf(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let timer = before
            .state
            .refill_wait
            .as_ref()
            .ok_or("missing pending timer")?
            .as_ref()
            .get_ref() as *const dyn Future<Output = ()>;
        let delay = before
            .state
            .bucket
            .refill_delay(before.state.bytes_per_second);
        let state = before.into_state();
        assert_eq!(state.bucket.available(), 0);
        let mut after = RateLimitedReader::from_state(SliceReader { bytes: b"c" }, state);
        assert_eq!(after.state.bucket.available(), 0);
        assert_eq!(
            after
                .state
                .bucket
                .refill_delay(after.state.bytes_per_second),
            delay
        );
        assert!(std::ptr::eq(
            timer,
            after
                .state
                .refill_wait
                .as_ref()
                .ok_or("missing transferred timer")?
                .as_ref()
                .get_ref()
        ));
        let mut next = [0; 1];
        timeout(Duration::from_secs(1), after.read_exact(&mut next)).await??;
        assert_eq!(&next, b"c");
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
#[should_panic]
fn consuming_more_than_the_reader_allowance_panics() {
    let mut reader = RateLimitedReader::new(
        SliceReader { bytes: b"ab" },
        NonZeroUsize::MIN,
        NonZeroUsize::MIN,
    );
    Pin::new(&mut reader).consume(2);
}
