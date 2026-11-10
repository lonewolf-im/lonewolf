// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, Cursor};

use crate::c2s::metrics::C2sMetrics;
use crate::xml_stream::traffic::ObservedIo;

#[test]
fn reads_and_writes_are_counted() -> Result<(), Box<dyn std::error::Error>> {
    compio::runtime::Runtime::new()?.block_on(async {
        let metrics = C2sMetrics::detached();
        let mut input = ObservedIo::new(Cursor::new(b"hello"), metrics.worker(0, 0));
        let mut buffer = [0; 3];
        assert_eq!(input.read(&mut buffer).await?, 3);
        assert_eq!(input.read(&mut buffer).await?, 2);
        assert_eq!(input.read(&mut buffer).await?, 0);
        assert_eq!(input.read(&mut []).await?, 0);
        let mut output = ObservedIo::new(Vec::new(), metrics.worker(0, 0));
        output.write_all(b"goodbye").await?;
        assert_eq!(output.write(&[]).await?, 0);
        output.flush().await?;
        output.close().await?;
        assert_eq!(*output.inner_mut(), b"goodbye");
        let body = metrics.render()?;
        assert!(
            body.contains("lonewolf_c2s_received_bytes_total{listener=\"0\"} 5\n"),
            "{body}"
        );
        assert!(
            body.contains("lonewolf_c2s_sent_bytes_total{listener=\"0\"} 7\n"),
            "{body}"
        );
        Ok(())
    })
}
struct ControlledIo {
    result: Poll<io::Result<usize>>,
    flushes: usize,
    closes: usize,
}

impl AsyncRead for ControlledIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let result = std::mem::replace(&mut self.result, Poll::Pending);
        if let Poll::Ready(Ok(count)) = result {
            output[..count].fill(0);
        }
        result
    }
}

impl AsyncWrite for ControlledIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<io::Result<usize>> {
        std::mem::replace(&mut self.result, Poll::Pending)
    }

    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flushes += 1;
        Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closes += 1;
        Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
    }
}

#[test]
fn pending_errors_and_partial_operations_preserve_actual_byte_counts()
-> Result<(), Box<dyn std::error::Error>> {
    let metrics = C2sMetrics::detached();
    let mut io = ObservedIo::new(
        ControlledIo {
            result: Poll::Pending,
            flushes: 0,
            closes: 0,
        },
        metrics.worker(0, 0),
    );
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
    let mut buffer = [0; 8];
    assert!(
        Pin::new(&mut io)
            .poll_read(&mut cx, &mut buffer)
            .is_pending()
    );
    assert!(Pin::new(&mut io).poll_write(&mut cx, &buffer).is_pending());
    io.inner_mut().result = Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
    assert!(matches!(
        Pin::new(&mut io).poll_read(&mut cx, &mut buffer),
        Poll::Ready(Err(_))
    ));
    io.inner_mut().result = Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
    assert!(matches!(
        Pin::new(&mut io).poll_write(&mut cx, &buffer),
        Poll::Ready(Err(_))
    ));
    io.inner_mut().result = Poll::Ready(Ok(2));
    assert!(matches!(
        Pin::new(&mut io).poll_read(&mut cx, &mut buffer),
        Poll::Ready(Ok(2))
    ));
    io.inner_mut().result = Poll::Ready(Ok(3));
    assert!(matches!(
        Pin::new(&mut io).poll_write(&mut cx, &buffer),
        Poll::Ready(Ok(3))
    ));
    assert!(matches!(
        Pin::new(&mut io).poll_flush(&mut cx),
        Poll::Ready(Err(_))
    ));
    assert!(matches!(
        Pin::new(&mut io).poll_close(&mut cx),
        Poll::Ready(Err(_))
    ));
    assert_eq!(io.inner_mut().flushes, 1);
    assert_eq!(io.inner_mut().closes, 1);
    let body = metrics.render()?;
    assert!(
        body.contains("lonewolf_c2s_received_bytes_total{listener=\"0\"} 2\n"),
        "{body}"
    );
    assert!(
        body.contains("lonewolf_c2s_sent_bytes_total{listener=\"0\"} 3\n"),
        "{body}"
    );
    Ok(())
}

#[test]
fn socket_observation_excludes_discarded_buffers_and_counts_returned_writes()
-> Result<(), Box<dyn std::error::Error>> {
    compio::runtime::Runtime::new()?.block_on(async {
        for flush in [false, true] {
            let listener = compio::net::TcpListener::bind("127.0.0.1:0").await?;
            let (client, server) = futures_util::future::join(
                compio::net::TcpStream::connect(listener.local_addr()?),
                listener.accept(),
            )
            .await;
            let mut client = client?;
            let (server, _) = server?;
            let metrics = C2sMetrics::detached();
            let mut adapter = Box::pin(compio::io::compat::AsyncStream::new(ObservedIo::new(
                server,
                metrics.worker(0, 0),
            )));
            adapter.write_all(b"discard").await?;
            let before = metrics.render()?;
            assert!(
                before.contains("lonewolf_c2s_sent_bytes_total{listener=\"0\"} 0\n"),
                "{before}"
            );
            if flush {
                adapter.flush().await?;
            }
            drop(adapter);
            let compio::BufResult(result, _) =
                compio::io::AsyncRead::read(&mut client, [0; 8]).await;
            assert_eq!(result?, if flush { 7 } else { 0 });
            let body = metrics.render()?;
            assert!(
                body.contains(&format!(
                    "lonewolf_c2s_sent_bytes_total{{listener=\"0\"}} {}\n",
                    if flush { 7 } else { 0 }
                )),
                "{body}"
            );
        }
        Ok(())
    })
}
