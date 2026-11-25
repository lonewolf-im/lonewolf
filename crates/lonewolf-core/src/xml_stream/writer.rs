// SPDX-License-Identifier: Apache-2.0

use std::io;

use futures_util::io::{AsyncWrite, AsyncWriteExt as _, BufWriter};
use lonewolf_util::arena::ArenaRead;
use lonewolf_xmpp::stanza::{AsyncWriteError, StanzaNamespace, StanzaRef};
use lonewolf_xmpp::stream::StreamErrorCondition;

use super::{STREAM_FOOTER, stream_error_xml};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Unopened,
    Open,
    Ended,
}

/// Writes one side of an XML stream and tracks what the peer may already have received.
///
/// Each operation updates the state before its first write, because a cancelled write can still deliver buffered bytes.
pub(crate) struct StreamWriter<W> {
    output: Option<BufWriter<W>>,
    phase: Phase,
    intact: bool,
}

impl<W: AsyncWrite + Unpin> StreamWriter<W> {
    pub(crate) fn new(output: W, capacity: usize) -> Self {
        Self {
            output: Some(BufWriter::with_capacity(capacity, output)),
            phase: Phase::Unopened,
            intact: true,
        }
    }

    #[cfg(test)]
    pub(crate) fn opened(output: W, capacity: usize) -> Self {
        Self {
            phase: Phase::Open,
            ..Self::new(output, capacity)
        }
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn get_mut(&mut self) -> Option<&mut W> {
        self.output.as_mut().map(BufWriter::get_mut)
    }

    /// Discards unflushed output.
    pub(crate) fn take_output(&mut self) -> Option<W> {
        self.output.take().map(BufWriter::into_inner)
    }

    /// True while the stream header is queued, the stream has not ended, and no write was torn.
    pub(crate) fn is_open(&self) -> bool {
        self.phase == Phase::Open && self.intact
    }

    #[cfg(test)]
    pub(crate) fn is_intact(&self) -> bool {
        self.intact
    }

    /// True when the current stream needs its header before an error or footer.
    pub(crate) fn needs_header(&self) -> bool {
        self.phase == Phase::Unopened && self.intact
    }

    /// Requires a new header after the stream restarts on the same transport.
    pub(crate) fn restart(&mut self) {
        if self.phase == Phase::Open {
            self.phase = Phase::Unopened;
        }
    }

    pub(crate) async fn send_header(&mut self, xml: &str) -> io::Result<()> {
        self.phase = Phase::Open;
        self.send(xml).await
    }

    /// `xml` must be complete elements that keep the current stream, so a stream error may follow a cancelled flush.
    pub(crate) async fn send(&mut self, xml: &str) -> io::Result<()> {
        self.queue(xml).await?;
        self.flush().await
    }

    /// Use for an element after which the peer leaves the current XML stream.
    pub(crate) async fn send_protocol_switch(&mut self, xml: &str) -> io::Result<()> {
        self.intact = false;
        self.output()?.write_all(xml.as_bytes()).await?;
        self.flush().await?;
        self.intact = true;
        Ok(())
    }

    /// The caller must flush buffered output.
    pub(crate) async fn write_stanza<R: ArenaRead>(
        &mut self,
        stanza: &StanzaRef<'_, R>,
        namespace: StanzaNamespace,
    ) -> Result<(), AsyncWriteError> {
        self.intact = false;
        let output = self.output().map_err(AsyncWriteError::Output)?;
        stanza.write_xml_async_as(namespace, output).await?;
        self.intact = true;
        Ok(())
    }

    pub(crate) async fn flush(&mut self) -> io::Result<()> {
        let flushed = self.output()?.flush().await;
        if flushed.is_err() {
            self.intact = false;
        }
        flushed
    }

    /// Ends an open, intact stream with a stream error or a footer and reports whether it wrote one.
    pub(crate) async fn close(
        &mut self,
        condition: Option<StreamErrorCondition>,
    ) -> io::Result<bool> {
        if !self.is_open() {
            return Ok(false);
        }
        self.phase = Phase::Ended;
        match condition {
            Some(condition) => self.send(&stream_error_xml(condition)).await?,
            None => self.send(STREAM_FOOTER).await?,
        }
        Ok(true)
    }

    pub(crate) async fn shutdown(&mut self) -> io::Result<()> {
        self.output()?.close().await
    }

    async fn queue(&mut self, xml: &str) -> io::Result<()> {
        self.intact = false;
        self.output()?.write_all(xml.as_bytes()).await?;
        self.intact = true;
        Ok(())
    }

    fn output(&mut self) -> io::Result<&mut BufWriter<W>> {
        self.output
            .as_mut()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))
    }
}

#[cfg(test)]
#[path = "tests/writer.rs"]
mod tests;
