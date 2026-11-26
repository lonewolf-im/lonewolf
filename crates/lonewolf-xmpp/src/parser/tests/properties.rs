// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::io;

use futures_util::{TryStreamExt, stream};
use lonewolf_util::arena::GlobalChunkAllocator;
use proptest::prelude::*;
use tokio::io::AsyncBufRead;
use tokio_util::compat::FuturesAsyncReadCompatExt;

use super::{CLOSE, OPEN, TestResult, config, open, stanza};
use crate::parser::{ParseError, StreamEvent, XmppParser};

fn stream_cases() -> impl Strategy<Value = (String, usize, BTreeSet<usize>)> {
    let body = r"(?:[A-Za-z0-9 é李🐺]|&amp;|&#13;|\r\n|<!\[CDATA\[<&\]\]>){0,12}";
    let stanza = prop_oneof![
        body.prop_map(|text| format!("<message><body>{text}</body></message>")),
        "[a-z]{0,8}".prop_map(|id| format!("<presence id='{id}'/>")),
        "[A-Zé]{1,8}".prop_map(|key| format!("<iq type='get' id='{key}'><q xmlns='urn:q'/></iq>")),
    ];
    (prop::collection::vec(stanza, 1..=4), any::<bool>()).prop_flat_map(|(stanzas, closed)| {
        let footer = if closed { CLOSE } else { "" };
        let wire = format!("{OPEN}{}{footer}", stanzas.join("\n"));
        let splits = prop::collection::btree_set(1..wire.len(), 1..=16);
        (Just(wire), Just(stanzas.len()), splits)
    })
}

async fn read_stanzas(
    reader: impl AsyncBufRead + Unpin,
    count: usize,
    closed: bool,
) -> TestResult<Vec<String>> {
    let mut parser = XmppParser::new(reader, config(4096)?, GlobalChunkAllocator);
    open(&mut parser).await?;
    let mut stanzas = Vec::with_capacity(count);
    for _ in 0..count {
        let parsed = stanza(&mut parser).await?;
        let mut xml = String::new();
        parsed
            .value()
            .resolve(parsed.arena())?
            .write_xml(&mut xml)?;
        stanzas.push(xml);
    }
    if closed {
        assert!(matches!(
            parser.next_event().await?,
            Some(StreamEvent::StreamEnd)
        ));
        assert!(parser.next_event().await?.is_none());
    } else {
        assert!(matches!(
            parser.next_event().await,
            Err(ParseError::UnexpectedEof)
        ));
    }
    Ok(stanzas)
}

proptest! {
    #[test]
    #[ignore = "runs in the XMPP property workflow"]
    fn property_xml_chunking((wire, count, splits) in stream_cases()) {
        let bytes = wire.as_bytes();
        let closed = wire.ends_with(CLOSE);
        let mut start = 0;
        let chunks = splits.iter().copied().chain([bytes.len()]).map(|end| {
            let chunk = &bytes[start..end];
            start = end;
            Ok::<_, io::Error>(chunk)
        });
        let fragmented = stream::iter(chunks).into_async_read().compat();
        let contiguous = futures_executor::block_on(read_stanzas(bytes, count, closed))
            .expect("generated stanzas must parse from a contiguous buffer");
        let actual = futures_executor::block_on(read_stanzas(fragmented, count, closed))
            .expect("generated stanzas must parse across chunk boundaries");
        prop_assert_eq!(actual, contiguous);
    }
}
