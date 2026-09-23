// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;
use std::pin::pin;

use compio::io::compat::AsyncReadStream;
use compio::net::TcpStream;
use lonewolf_util::arena::{ArenaConfig, ChunkAllocator};
use lonewolf_xmpp::parser::{ParseError, ParserConfig, StreamEvent, XmppParser, compio_reader};

use super::connection_limit::ConnectionPermit;

const READ_BUFFER_BYTES: usize = 1_024;

pub(super) struct XmppStream<A: ChunkAllocator> {
    transport: TcpStream,
    permit: ConnectionPermit,
    settings: StreamSettings<A>,
}

#[derive(Clone)]
pub(super) struct StreamSettings<A: ChunkAllocator> {
    max_stanza_bytes: NonZeroUsize,
    allocator: A,
}

impl<A: ChunkAllocator> StreamSettings<A> {
    pub(super) fn new(max_stanza_bytes: NonZeroUsize, allocator: A) -> Self {
        Self {
            max_stanza_bytes,
            allocator,
        }
    }
}

impl<A: ChunkAllocator + Clone> XmppStream<A> {
    pub(super) fn new(
        transport: TcpStream,
        permit: ConnectionPermit,
        settings: StreamSettings<A>,
    ) -> Self {
        Self {
            transport,
            permit,
            settings,
        }
    }

    pub(super) async fn run(self) -> CloseOutcome {
        let Self {
            transport,
            permit,
            settings,
        } = self;
        let outcome = {
            let mut input = pin!(AsyncReadStream::with_capacity(READ_BUFFER_BYTES, transport));
            let mut parser = XmppParser::new(
                compio_reader(input.as_mut()),
                ParserConfig {
                    max_stanza_bytes: settings.max_stanza_bytes,
                    arena: ArenaConfig::default(),
                },
                settings.allocator,
            );
            loop {
                match parser.next_event().await {
                    Ok(Some(StreamEvent::StreamStart(_))) => {}
                    Ok(Some(StreamEvent::StreamEnd) | None) => break CloseOutcome::StreamEnd,
                    Ok(Some(StreamEvent::Stanza(_) | StreamEvent::Element(_))) => {
                        break CloseOutcome::UnsupportedInput;
                    }
                    Err(ParseError::UnexpectedEof) => break CloseOutcome::Eof,
                    Err(ParseError::SizeLimitExceeded { .. }) => {
                        break CloseOutcome::SizeLimitExceeded;
                    }
                    Err(_) => break CloseOutcome::ParserError,
                }
            }
        };
        drop(permit);
        outcome
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum CloseOutcome {
    StreamEnd,
    Eof,
    UnsupportedInput,
    SizeLimitExceeded,
    ParserError,
}

impl CloseOutcome {
    pub(super) fn as_str(&self) -> &'static str {
        match self {
            Self::StreamEnd => "stream_end",
            Self::Eof => "eof",
            Self::UnsupportedInput => "unsupported_input",
            Self::SizeLimitExceeded => "size_limit_exceeded",
            Self::ParserError => "parser_error",
        }
    }
}

#[cfg(test)]
#[path = "../../tests/c2s/stream.rs"]
mod tests;
