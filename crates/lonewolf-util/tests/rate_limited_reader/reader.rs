// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use compio::runtime::Runtime;
use compio::time::timeout;
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
fn refill_keeps_fractional_credit_and_caps_at_burst() {
    let mut reader = RateLimitedReader::new(
        SliceReader { bytes: b"" },
        NonZeroUsize::new(3).unwrap(),
        NonZeroUsize::new(2).unwrap(),
    );
    reader.tokens = 0;
    let start = reader.updated_at;
    reader.replenish(start + Duration::from_millis(100));
    assert_eq!(reader.tokens, 0);
    assert_eq!(reader.remainder, 300_000_000);
    reader.replenish(start + Duration::from_millis(400));
    assert_eq!(reader.tokens, 1);
    assert_eq!(reader.remainder, 200_000_000);
    reader.replenish(start + Duration::from_secs(2));
    assert_eq!(reader.tokens, 2);
    assert_eq!(reader.remainder, 0);
    assert_eq!(reader.refill_delay(), Duration::from_nanos(333_333_334));
}

#[test]
fn high_rate_with_small_burst_waits_at_least_one_nanosecond() {
    let mut reader = RateLimitedReader::new(
        SliceReader { bytes: b"" },
        NonZeroUsize::new(usize::MAX).unwrap(),
        NonZeroUsize::MIN,
    );
    reader.tokens = 0;
    reader.replenish(Instant::now());
    assert_eq!(reader.refill_delay(), Duration::from_nanos(1));
}
