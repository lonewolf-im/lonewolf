// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::task::Waker;
use std::time::Instant;

use super::*;
use crate::s2s::metrics::{Direction, S2sMetrics};
use crate::s2s::stream::traffic::{ConnectionActivity, S2sByteObserver};
use crate::test_allocator::allocations_during;

struct Io;
impl AsyncRead for Io {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        output.fill(0);
        Poll::Ready(Ok(output.len()))
    }
}
impl AsyncWrite for Io {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(input.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn check(observer: impl TrafficObserver + Unpin) {
    let mut io = ObservedIo::new(Io, observer);
    let mut cx = Context::from_waker(Waker::noop());
    let mut bytes = [0; 8];
    let allocations = allocations_during(|| {
        for _ in 0..32 {
            let mut result = Pin::new(&mut io).poll_read(&mut cx, &mut bytes);
            if result.is_pending() {
                result = Pin::new(&mut io).poll_read(&mut cx, &mut bytes);
            }
            assert!(matches!(result, Poll::Ready(Ok(8))));
            assert!(matches!(
                Pin::new(&mut io).poll_write(&mut cx, &bytes),
                Poll::Ready(Ok(8))
            ));
            assert!(matches!(
                Pin::new(&mut io).poll_read(&mut cx, &mut []),
                Poll::Ready(Ok(0))
            ));
            assert!(matches!(
                Pin::new(&mut io).poll_write(&mut cx, &[]),
                Poll::Ready(Ok(0))
            ));
            assert!(matches!(
                Pin::new(&mut io).poll_flush(&mut cx),
                Poll::Ready(Ok(()))
            ));
            assert!(matches!(
                Pin::new(&mut io).poll_close(&mut cx),
                Poll::Ready(Ok(()))
            ));
        }
    });
    assert_eq!(allocations, 0);
}

#[test]
fn observed_io_does_not_allocate_after_observer_construction() {
    check(S2sByteObserver::new(S2sMetrics::new(1), Direction::Inbound));
    check(ConnectionActivity::new(Instant::now()));
}

#[derive(Clone, Default)]
struct Observer(std::rc::Rc<Counts>);

#[derive(Default)]
struct Counts {
    read: std::cell::Cell<(usize, usize)>,
    written: std::cell::Cell<(usize, usize)>,
}

impl TrafficObserver for Observer {
    fn received(&self, bytes: usize) {
        let (calls, total) = self.0.read.get();
        self.0.read.set((calls + 1, total + bytes));
    }
    fn sent(&self, bytes: usize) {
        let (calls, total) = self.0.written.get();
        self.0.written.set((calls + 1, total + bytes));
    }
}

struct OwnedIo {
    result: Result<usize, io::ErrorKind>,
    pending: bool,
    vectored_reads: usize,
    vectored_writes: usize,
    flushes: usize,
    shutdowns: usize,
}

impl OwnedIo {
    fn new() -> Self {
        Self {
            result: Ok(3),
            pending: false,
            vectored_reads: 0,
            vectored_writes: 0,
            flushes: 0,
            shutdowns: 0,
        }
    }
}

impl compio::io::AsyncRead for OwnedIo {
    async fn read<B: compio::buf::IoBufMut>(&mut self, buf: B) -> compio::BufResult<usize, B> {
        if self.pending {
            std::future::pending::<()>().await;
        }
        match self.result {
            Ok(limit) => compio::io::AsyncRead::read(&mut &b"abc"[..limit], buf).await,
            Err(error) => compio::BufResult(Err(error.into()), buf),
        }
    }
    async fn read_vectored<B: compio::buf::IoVectoredBufMut>(
        &mut self,
        buf: B,
    ) -> compio::BufResult<usize, B> {
        self.vectored_reads += 1;
        if self.pending {
            std::future::pending::<()>().await;
        }
        match self.result {
            Ok(limit) => compio::io::AsyncRead::read_vectored(&mut &b"abc"[..limit], buf).await,
            Err(error) => compio::BufResult(Err(error.into()), buf),
        }
    }
}

impl compio::io::AsyncWrite for OwnedIo {
    async fn write<B: compio::buf::IoBuf>(&mut self, buf: B) -> compio::BufResult<usize, B> {
        if self.pending {
            std::future::pending::<()>().await;
        }
        compio::BufResult(
            self.result
                .map(|count| count.min(buf.buf_len()))
                .map_err(Into::into),
            buf,
        )
    }
    async fn write_vectored<B: compio::buf::IoVectoredBuf>(
        &mut self,
        buf: B,
    ) -> compio::BufResult<usize, B> {
        self.vectored_writes += 1;
        if self.pending {
            std::future::pending::<()>().await;
        }
        compio::BufResult(
            self.result
                .map(|count| count.min(buf.total_len()))
                .map_err(Into::into),
            buf,
        )
    }
    async fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        Err(io::ErrorKind::BrokenPipe.into())
    }
    async fn shutdown(&mut self) -> io::Result<()> {
        self.shutdowns += 1;
        Err(io::ErrorKind::ConnectionReset.into())
    }
}

#[test]
fn owned_buffer_io_preserves_partial_vectored_zero_and_error_results()
-> Result<(), Box<dyn std::error::Error>> {
    use compio::BufResult;
    use compio::io::{AsyncRead as _, AsyncWrite as _};
    let observer = Observer::default();
    let mut stream = ObservedIo::new(OwnedIo::new(), observer.clone());
    let mut cx = Context::from_waker(Waker::noop());
    for limit in [3, 0] {
        stream.inner_mut().result = Ok(limit);
        let buffer = Vec::with_capacity(8);
        let pointer = buffer.as_ptr();
        let Poll::Ready(BufResult(result, buffer)) =
            std::pin::pin!(stream.read(buffer)).poll(&mut cx)
        else {
            panic!("read pending");
        };
        assert_eq!(result?, limit);
        assert_eq!(buffer.as_ptr(), pointer);
        assert_eq!(buffer, &b"abc"[..limit]);
        let buffers = [Vec::with_capacity(2), Vec::with_capacity(2)];
        let pointers = buffers.each_ref().map(|buffer| buffer.as_ptr());
        let Poll::Ready(BufResult(result, buffers)) =
            std::pin::pin!(stream.read_vectored(buffers)).poll(&mut cx)
        else {
            panic!("vectored read pending");
        };
        assert_eq!(result?, limit);
        assert_eq!(buffers.each_ref().map(|buffer| buffer.as_ptr()), pointers);
        assert_eq!(buffers[0], &b"ab"[..limit.min(2)]);
        assert_eq!(
            buffers[1],
            if limit == 3 {
                b"c".as_slice()
            } else {
                b"".as_slice()
            }
        );
        let buffer = b"outbound".to_vec();
        let pointer = buffer.as_ptr();
        let Poll::Ready(BufResult(result, buffer)) =
            std::pin::pin!(stream.write(buffer)).poll(&mut cx)
        else {
            panic!("write pending");
        };
        assert_eq!(result?, limit);
        assert_eq!(buffer.as_ptr(), pointer);
        assert_eq!(buffer, b"outbound");
        let buffers = [b"ab".to_vec(), b"cd".to_vec()];
        let pointers = buffers.each_ref().map(|buffer| buffer.as_ptr());
        let Poll::Ready(BufResult(result, buffers)) =
            std::pin::pin!(stream.write_vectored(buffers)).poll(&mut cx)
        else {
            panic!("vectored write pending");
        };
        assert_eq!(result?, limit);
        assert_eq!(buffers.each_ref().map(|buffer| buffer.as_ptr()), pointers);
        assert_eq!(buffers, [b"ab".to_vec(), b"cd".to_vec()]);
    }
    assert_eq!(observer.0.read.get(), (4, 6));
    assert_eq!(observer.0.written.get(), (4, 6));
    stream.inner_mut().result = Err(io::ErrorKind::ConnectionReset);
    let Poll::Ready(BufResult(result, buffer)) =
        std::pin::pin!(stream.read(vec![8; 4])).poll(&mut cx)
    else {
        panic!("read pending");
    };
    assert_eq!(
        result.expect_err("read error").kind(),
        io::ErrorKind::ConnectionReset
    );
    assert_eq!(buffer, [8; 4]);
    let Poll::Ready(BufResult(result, buffer)) =
        std::pin::pin!(stream.read_vectored([vec![9; 2], vec![7; 2]])).poll(&mut cx)
    else {
        panic!("vectored read pending");
    };
    assert_eq!(
        result.expect_err("read error").kind(),
        io::ErrorKind::ConnectionReset
    );
    assert_eq!(buffer, [vec![9; 2], vec![7; 2]]);
    let Poll::Ready(BufResult(result, buffer)) =
        std::pin::pin!(stream.write(vec![6; 4])).poll(&mut cx)
    else {
        panic!("write pending");
    };
    assert_eq!(
        result.expect_err("write error").kind(),
        io::ErrorKind::ConnectionReset
    );
    assert_eq!(buffer, [6; 4]);
    let Poll::Ready(BufResult(result, buffer)) =
        std::pin::pin!(stream.write_vectored([vec![5; 2], vec![4; 2]])).poll(&mut cx)
    else {
        panic!("vectored write pending");
    };
    assert_eq!(
        result.expect_err("write error").kind(),
        io::ErrorKind::ConnectionReset
    );
    assert_eq!(buffer, [vec![5; 2], vec![4; 2]]);
    assert!(
        matches!(std::pin::pin!(stream.flush()).poll(&mut cx), Poll::Ready(Err(error)) if error.kind()==io::ErrorKind::BrokenPipe)
    );
    assert!(
        matches!(std::pin::pin!(stream.shutdown()).poll(&mut cx), Poll::Ready(Err(error)) if error.kind()==io::ErrorKind::ConnectionReset)
    );
    assert_eq!(stream.inner_mut().flushes, 1);
    assert_eq!(stream.inner_mut().shutdowns, 1);
    assert_eq!(stream.inner_mut().vectored_reads, 3);
    assert_eq!(stream.inner_mut().vectored_writes, 3);
    assert_eq!(observer.0.read.get(), (4, 6));
    assert_eq!(observer.0.written.get(), (4, 6));
    Ok(())
}

#[test]
fn abandoned_owned_operation_does_not_report_an_unreturned_result() {
    use compio::io::AsyncWrite as _;
    let observer = Observer::default();
    let mut socket = OwnedIo::new();
    socket.pending = true;
    let mut stream = ObservedIo::new(socket, observer.clone());
    let buffer = std::rc::Rc::new(b"pending".to_vec());
    let mut cx = Context::from_waker(Waker::noop());
    {
        let mut operation = std::pin::pin!(stream.write(std::rc::Rc::clone(&buffer)));
        assert!(operation.as_mut().poll(&mut cx).is_pending());
        assert_eq!(std::rc::Rc::strong_count(&buffer), 2);
        assert_eq!(observer.0.written.get(), (0, 0));
    }
    assert_eq!(std::rc::Rc::strong_count(&buffer), 1);
    assert_eq!(observer.0.written.get(), (0, 0));
}

#[test]
fn splitting_owned_io_reuses_the_observer_without_allocation()
-> Result<(), Box<dyn std::error::Error>> {
    use compio::io::util::Splittable;
    use compio::io::{AsyncRead as _, AsyncWrite as _};
    let observer = Observer::default();
    let stream = ObservedIo::new((OwnedIo::new(), OwnedIo::new()), observer.clone());
    let mut halves = None;
    let allocations = allocations_during(|| {
        halves = Some(stream.split());
    });
    assert_eq!(allocations, 0);
    let (mut read, mut write) = halves.ok_or("missing split halves")?;
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        std::pin::pin!(read.read([0; 8])).poll(&mut cx),
        Poll::Ready(compio::BufResult(Ok(3), _))
    ));
    assert!(matches!(
        std::pin::pin!(write.write([0; 8])).poll(&mut cx),
        Poll::Ready(compio::BufResult(Ok(3), _))
    ));
    assert_eq!(observer.0.read.get(), (1, 3));
    assert_eq!(observer.0.written.get(), (1, 3));
    Ok(())
}

#[test]
fn owned_buffer_observation_does_not_allocate_per_operation() {
    use compio::io::{AsyncRead as _, AsyncWrite as _};
    let mut stream = ObservedIo::new(
        OwnedIo::new(),
        S2sByteObserver::new(S2sMetrics::new(1), Direction::Inbound),
    );
    let mut cx = Context::from_waker(Waker::noop());
    let allocations = allocations_during(|| {
        for _ in 0..32 {
            assert!(matches!(
                std::pin::pin!(stream.read([0; 8])).poll(&mut cx),
                Poll::Ready(compio::BufResult(Ok(3), _))
            ));
            assert!(matches!(
                std::pin::pin!(stream.write([0; 8])).poll(&mut cx),
                Poll::Ready(compio::BufResult(Ok(3), _))
            ));
            assert!(matches!(
                std::pin::pin!(stream.read_vectored([[0; 2]; 2])).poll(&mut cx),
                Poll::Ready(compio::BufResult(Ok(3), _))
            ));
            assert!(matches!(
                std::pin::pin!(stream.write_vectored([[0; 2]; 2])).poll(&mut cx),
                Poll::Ready(compio::BufResult(Ok(3), _))
            ));
        }
    });
    assert_eq!(allocations, 0);
}
