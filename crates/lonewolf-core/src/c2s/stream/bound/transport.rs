// SPDX-License-Identifier: Apache-2.0

use std::pin::pin;

use futures_util::future::{Either, join, select};
use lonewolf_util::arena::ChunkAllocator;

use super::super::certificate::CertificateMonitor;
use super::super::close::{self, CloseContext};
use super::super::session::{Reader, Writer};
use super::CloseOutcome;
use super::link::LinkTransport;

pub(super) struct Transport<A: ChunkAllocator> {
    pub(super) reader: Reader<A>,
    pub(super) writer: Writer,
    pub(super) close: CloseContext,
    pub(super) monitor: Option<CertificateMonitor>,
    pub(super) link: LinkTransport<A>,
}

impl<A: ChunkAllocator + Clone> Transport<A> {
    pub(super) async fn run(&mut self) -> CloseOutcome {
        let Self {
            reader,
            writer,
            close,
            monitor,
            link,
        } = self;
        let link = &*link;
        let close = &*close;
        let monitor = monitor.as_ref();
        let reading = async {
            let read = async {
                link.read(reader, monitor).await;
                Ok(())
            };
            let result = match monitor {
                Some(monitor) => monitor.interrupt(read).await,
                None => read.await,
            };
            if let Err(outcome) = result {
                link.fail(outcome);
            }
        };
        let writing = async {
            let mut write = pin!(link.write(writer, monitor));
            match select(write.as_mut(), pin!(link.stopped())).await {
                Either::Left((outcome, _)) => (outcome, close.deadline()),
                Either::Right(((), _)) => {
                    let deadline = close.deadline();
                    (close.cleanup(deadline, write).await, deadline)
                }
            }
        };
        let ((), (outcome, deadline)) = join(reading, writing).await;
        close::finish(reader, writer, outcome.into(), close, deadline).await
    }
}
