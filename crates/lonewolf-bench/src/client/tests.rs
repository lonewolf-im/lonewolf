// SPDX-License-Identifier: Apache-2.0

use std::{
    error::Error,
    future::Future,
    io,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use lonewolf_util::blocking::BlockingExecutor;
use lonewolf_xmpp::parser::StreamEvent;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::{Instant, timeout};

use super::{
    scram::Exchange,
    transport::{Retirement, SessionReader, Writer, shutdown_parts},
    xml, *,
};

type TestResult = Result<(), Box<dyn Error>>;
const HEADER: &str = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' from='example.test' version='1.0'>";
const NONCE: &str = "rOprNGfwEbeRWgbNEkqO";
const CHALLENGE: &str =
    "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
const SERVER_PROOF: &str = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

fn account() -> BenchResult<PreparedAccount> {
    PreparedAccount::new("user@example.test", "pencil".to_owned())
}
fn cpu() -> BlockingExecutor {
    BlockingExecutor::new(NonZeroUsize::MIN)
}
fn id() -> CorrelationId {
    CorrelationId {
        run_nonce: [1; 16],
        phase: TrafficPhase::Measurement,
        sequence: 7,
    }
}
fn command() -> WriteCommand {
    WriteCommand::Message(MessageCommand {
        operation: id(),
        scheduled_at: Instant::now(),
        route_index: 0,
        phase: TrafficPhase::Measurement,
    })
}
fn sink(capacity: usize) -> (EventSink, tokio::sync::mpsc::Receiver<WriterEvent>) {
    EventSink::bounded(
        NonZeroUsize::new(capacity).unwrap(),
        Arc::new(AtomicBool::new(false)),
    )
}
fn configure<W: AsyncWrite + Unpin>(writer: &mut Writer<W>) -> BenchResult<()> {
    writer.configure_messages(
        Arc::from([MessageRoute {
            to: "receiver@example.test/resource".to_owned(),
        }]),
        Arc::from("xxx"),
    )
}

#[tokio::test]
async fn scram_rfc7677_vector_prime_reuse_and_signature_verification() -> TestResult {
    let mut account = account()?;
    let exchange = Exchange::with_nonce(&account, NONCE.to_owned())?;
    let challenge = exchange.challenge(&STANDARD.encode(CHALLENGE))?;
    let proof = exchange
        .respond(&mut account, challenge, KeyMode::Prime, &cpu())
        .await?;
    assert_eq!(
        String::from_utf8(STANDARD.decode(proof.response.as_bytes())?)?,
        "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
    );
    proof.verify(&STANDARD.encode(SERVER_PROOF))?;
    let exchange = Exchange::with_nonce(&account, NONCE.to_owned())?;
    let challenge = exchange.challenge(&STANDARD.encode(CHALLENGE))?;
    let proof = exchange
        .respond(&mut account, challenge, KeyMode::Reuse, &cpu())
        .await?;
    proof.verify(&STANDARD.encode(SERVER_PROOF))?;
    Ok(())
}

#[tokio::test]
async fn scram_rejects_cache_mismatch_unprimed_reuse_and_bad_server_signatures() -> TestResult {
    let mut account = account()?;
    let exchange = Exchange::with_nonce(&account, NONCE.to_owned())?;
    let challenge = exchange.challenge(&STANDARD.encode(CHALLENGE))?;
    assert!(
        exchange
            .respond(&mut account, challenge, KeyMode::Reuse, &cpu())
            .await
            .is_err()
    );
    let exchange = Exchange::with_nonce(&account, NONCE.to_owned())?;
    let challenge = exchange.challenge(&STANDARD.encode(CHALLENGE))?;
    let proof = exchange
        .respond(&mut account, challenge, KeyMode::Prime, &cpu())
        .await?;
    assert_eq!(
        proof
            .verify(&STANDARD.encode(format!("v={}", STANDARD.encode([0; 32]))))
            .unwrap_err()
            .context(),
        "scram_server_signature"
    );
    for message in [
        CHALLENGE.replace("4096", "4097"),
        CHALLENGE.replace("W22ZaJ0SNY7soEsUEjb6gQ==", "YWJj"),
    ] {
        let exchange = Exchange::with_nonce(&account, NONCE.to_owned())?;
        let challenge = exchange.challenge(&STANDARD.encode(message))?;
        assert_eq!(
            exchange
                .respond(&mut account, challenge, KeyMode::Reuse, &cpu())
                .await
                .err()
                .ok_or("accepted mismatch")?
                .context(),
            "scram_parameters_changed"
        );
    }
    Ok(())
}

#[test]
fn scram_bounds_duplicates_extensions_nonce_and_base64_are_rejected() -> TestResult {
    let account = account()?;
    for message in [
        format!("{CHALLENGE},i=4096"),
        format!("m=required,{CHALLENGE}"),
        CHALLENGE.replace("4096", "4095"),
        CHALLENGE.replace("4096", "1000001"),
        CHALLENGE.replace("4096", "04096"),
        CHALLENGE.replace("W22ZaJ0SNY7soEsUEjb6gQ==", &STANDARD.encode([0; 65])),
        CHALLENGE.replace("W22ZaJ0SNY7soEsUEjb6gQ==", "!!!"),
        format!("r={NONCE},s=YWJj,i=4096"),
        "r=wrongnonce,s=YWJj,i=4096".to_owned(),
        format!("r={}z,s=YWJj,i=4096", "x".repeat(1024)),
        "x".repeat(4097),
    ] {
        let exchange = Exchange::with_nonce(&account, NONCE.to_owned())?;
        assert!(exchange.challenge(&STANDARD.encode(message)).is_err());
    }
    let exchange = Exchange::new(&account)?;
    let first = String::from_utf8(STANDARD.decode(exchange.first.as_bytes())?)?;
    let nonce = first.rsplit_once("r=").ok_or("missing nonce")?.1;
    assert_eq!(STANDARD.decode(nonce)?.len(), 24);
    assert!(Exchange::new(&account)?.first != exchange.first);
    Ok(())
}

#[test]
fn passwords_are_saslprepped_usernames_escaped_and_debug_errors_redacted() -> TestResult {
    let account = PreparedAccount::new("a,b=c@example.test", "I\u{ad}X".to_owned())?;
    let exchange = Exchange::with_nonce(&account, "nonce".to_owned())?;
    assert_eq!(
        String::from_utf8(STANDARD.decode(exchange.first.as_bytes())?)?,
        "n,,n=a=2Cb=3Dc,r=nonce"
    );
    let debug = format!("{account:?}");
    assert!(!debug.contains("example.test"));
    assert!(!debug.contains("IX"));
    assert!(PreparedAccount::new("user@example.test/resource", "secret".to_owned()).is_err());
    let error = exchange
        .challenge("secret%%%peerxml")
        .err()
        .ok_or("accepted invalid base64")?;
    assert!(!format!("{error:?} {error}").contains("secret"));
    Ok(())
}

#[tokio::test]
async fn fragmented_coalesced_parser_restart_retains_buffer_and_limits_xml() -> TestResult {
    let (input, mut output) = tokio::io::duplex(16_384);
    let mut parser = xml::parser(input);
    output.write_all(HEADER.as_bytes()).await?;
    assert!(matches!(
        xml::next(&mut parser).await?,
        StreamEvent::StreamStart { .. }
    ));
    output
        .write_all(b"<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>YW")
        .await?;
    let mut pending = Box::pin(xml::sasl(&mut parser, "challenge"));
    assert!(
        pending
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    output
        .write_all(
            b"Jj</challenge><success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>eA==</success>",
        )
        .await?;
    assert_eq!(&*pending.await?, "YWJj");
    output.write_all(HEADER.as_bytes()).await?;
    assert_eq!(&*xml::sasl(&mut parser, "success").await?, "eA==");
    parser = parser.restart().map_err(|_| "restart failed")?;
    assert!(matches!(
        xml::next(&mut parser).await?,
        StreamEvent::StreamStart { .. }
    ));
    let bytes = format!(
        "{HEADER}<message><body>{}</body></message>",
        "x".repeat(262_144)
    );
    let mut parser = xml::parser(bytes.as_bytes());
    xml::next(&mut parser).await?;
    assert_eq!(
        xml::next(&mut parser)
            .await
            .err()
            .ok_or("accepted oversized XML")?
            .context(),
        "xml_protocol"
    );
    Ok(())
}

#[tokio::test]
async fn parser_rejects_duplicate_attributes_and_binding_identity_or_structure() -> TestResult {
    for stanza in [
        "<message id='a' id='b'/>",
        "<message from='a@example.test' from='b@example.test'/>",
    ] {
        let text = format!("{HEADER}{stanza}");
        let mut parser = xml::parser(text.as_bytes());
        xml::next(&mut parser).await?;
        assert!(xml::next(&mut parser).await.is_err());
    }
    for jid in [
        "user@example.test/other",
        "other@example.test/resource",
        "user@example.test",
    ] {
        let text = format!(
            "{HEADER}<iq type='result' id='bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>{jid}</jid></bind></iq>"
        );
        let mut parser = xml::parser(text.as_bytes());
        xml::next(&mut parser).await?;
        assert!(
            xml::binding(&mut parser, "user@example.test/resource")
                .await
                .is_err()
        );
    }
    let text = format!(
        "{HEADER}<iq type='result' id='bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>USER@example.test/resource</jid></bind></iq>"
    );
    let mut parser = xml::parser(text.as_bytes());
    xml::next(&mut parser).await?;
    assert_eq!(
        xml::binding(&mut parser, "user@example.test/resource").await?,
        "user@example.test/resource"
    );
    Ok(())
}

#[test]
fn correlation_parser_is_bounded_canonical_and_redacted() {
    assert_eq!(CorrelationId::parse(&id().to_string()), Some(id()));
    for value in [
        "x".repeat(4096),
        format!("{}.m.10000000", "00".repeat(16)),
        format!("{}.m.00", "00".repeat(16)),
        format!("{}.q.1", "00".repeat(16)),
        format!("{}.m.1", "ZZ".repeat(16)),
    ] {
        assert!(CorrelationId::parse(&value).is_none());
    }
    assert!(!format!("{:?}", id()).contains("010101"));
}

fn chat() -> String {
    format!(
        "<message type='chat' from='sender@example.test/resource' to='receiver@example.test/resource' id='{}'><body>xxx</body></message>",
        id()
    )
}

#[tokio::test(start_paused = true)]
async fn sends_and_cancelled_receipt_waits_do_not_cancel_persistent_parser_read() -> TestResult {
    let (input, mut output) = tokio::io::duplex(8192);
    let retirement = Retirement::new();
    let mut reader = SessionReader::start(
        xml::parser(input),
        "receiver@example.test/resource".to_owned(),
        Some(ReceiveRoute {
            from: "sender@example.test/resource".to_owned(),
            body_bytes: 3,
        }),
        retirement.clone(),
        NonZeroUsize::new(8).unwrap(),
    );
    output.write_all(HEADER.as_bytes()).await?;
    assert!(matches!(
        reader.next().await?.kind,
        ReceivedKind::Unexpected
    ));
    output.write_all(b"<message type='chat'").await?;
    assert!(
        timeout(Duration::from_millis(1), reader.next())
            .await
            .is_err()
    );
    let mut writer = Writer::new(tokio::io::sink(), retirement);
    configure(&mut writer)?;
    let (events, mut notices) = sink(8);
    writer.send(&command(), &events).await?;
    assert!(matches!(
        notices.try_recv()?,
        WriterEvent::WriteStarted { .. }
    ));
    assert!(matches!(
        notices.try_recv()?,
        WriterEvent::WriteCompleted { .. }
    ));
    let chat = chat();
    output.write_all(&chat.as_bytes()[20..]).await?;
    let event = reader.next().await?;
    assert!(matches!(
        event.kind,
        ReceivedKind::Chat {
            route_valid: true,
            correlation: Some(_),
            body: BodyValidation {
                bytes: 3,
                ascii_x: true
            },
            ..
        }
    ));
    writer.retire();
    reader.retire().await?;
    Ok(())
}

#[tokio::test]
async fn receipts_validate_route_payload_without_retaining_content() -> TestResult {
    for (stanza, valid) in [
        (chat(), true),
        (chat().replace("sender@", "wrong@"), false),
        (chat().replace("receiver@", "wrong@"), false),
        (chat().replace("xxx", "xxy"), false),
        (chat().replace("xxx", "xx"), false),
        (chat().replace("</body>", "</body><body>xxx</body>"), false),
    ] {
        let text = format!("{HEADER}{stanza}");
        let mut parser = xml::parser(text.as_bytes());
        xml::next(&mut parser).await?;
        let event = xml::received(
            xml::next(&mut parser).await?,
            "receiver@example.test/resource",
            Some(&ReceiveRoute {
                from: "sender@example.test/resource".to_owned(),
                body_bytes: 3,
            }),
        )?;
        assert!(
            matches!(event.kind, ReceivedKind::Chat { route_valid, .. } if route_valid == valid)
        );
    }
    Ok(())
}

struct ProbeWriter {
    bytes: Arc<Mutex<Vec<u8>>>,
    dropped: Arc<AtomicBool>,
    fail_after: Option<usize>,
    pending_flush: bool,
}
impl Drop for ProbeWriter {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}
impl AsyncWrite for ProbeWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut bytes = self.bytes.lock().unwrap();
        if self.fail_after.is_some_and(|limit| bytes.len() >= limit) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let count = self
            .fail_after
            .map_or(data.len(), |limit| data.len().min(limit - bytes.len()));
        bytes.extend_from_slice(&data[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_flush {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
fn probe(fail_after: Option<usize>, pending_flush: bool) -> (ProbeWriter, Arc<AtomicBool>) {
    let dropped = Arc::new(AtomicBool::new(false));
    (
        ProbeWriter {
            bytes: Arc::new(Mutex::new(Vec::new())),
            dropped: dropped.clone(),
            fail_after,
            pending_flush,
        },
        dropped,
    )
}

#[tokio::test(start_paused = true)]
async fn partial_failure_and_cancelled_flush_retire_writer_without_retry() -> TestResult {
    for (fail_after, pending_flush) in [(Some(4), false), (None, true)] {
        let (transport, dropped) = probe(fail_after, pending_flush);
        let mut writer = Writer::new(transport, Retirement::new());
        configure(&mut writer)?;
        let (sink, mut events) = sink(8);
        assert!(!matches!(
            timeout(Duration::from_millis(1), writer.send(&command(), &sink)).await,
            Ok(Ok(()))
        ));
        assert!(dropped.load(Ordering::Acquire));
        assert!(writer.send(&command(), &sink).await.is_err());
        assert!(matches!(
            events.try_recv()?,
            WriterEvent::WriteStarted { .. }
        ));
    }
    Ok(())
}

#[tokio::test]
async fn event_overflow_is_visible_and_retires_write_owner() -> TestResult {
    let (transport, dropped) = probe(None, false);
    let mut writer = Writer::new(transport, Retirement::new());
    configure(&mut writer)?;
    let (sink, _) = sink(1);
    assert!(writer.send(&command(), &sink).await.is_err());
    assert!(sink.run_invalid());
    assert!(dropped.load(Ordering::Acquire));
    Ok(())
}

struct DropReader<R> {
    inner: R,
    dropped: Arc<AtomicBool>,
}
impl<R> Drop for DropReader<R> {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}
impl<R: AsyncRead + Unpin> AsyncRead for DropReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[tokio::test(start_paused = true)]
async fn forced_shutdown_drops_both_halves_joins_parser_and_preserves_queued_events() -> TestResult
{
    let dropped = Arc::new(AtomicBool::new(false));
    let (input, mut output) = tokio::io::duplex(8192);
    let retirement = Retirement::new();
    let mut reader = SessionReader::start(
        xml::parser(DropReader {
            inner: input,
            dropped: dropped.clone(),
        }),
        "receiver@example.test/resource".to_owned(),
        None,
        retirement.clone(),
        NonZeroUsize::new(8).unwrap(),
    );
    let (transport, writer_dropped) = probe(None, false);
    let mut writer = Writer::new(transport, retirement);
    output.write_all(HEADER.as_bytes()).await?;
    output.write_all(chat().as_bytes()).await?;
    let mut observed = Vec::new();
    let result = shutdown_parts(
        &mut reader,
        &mut writer,
        Duration::from_millis(10),
        &mut |event| {
            observed.push(event);
            Ok(())
        },
    )
    .await;
    assert_eq!(result.unwrap_err().context(), "close_deadline");
    assert!(dropped.load(Ordering::Acquire));
    assert!(writer_dropped.load(Ordering::Acquire));
    assert!(
        observed
            .iter()
            .any(|event| matches!(event.kind, ReceivedKind::Chat { .. }))
    );
    Ok(())
}

#[tokio::test]
async fn bounded_reader_overflow_and_failed_read_terminate_owner() -> TestResult {
    for input in [
        format!("{HEADER}{}{}", chat(), chat()),
        format!("{HEADER}<message"),
    ] {
        let dropped = Arc::new(AtomicBool::new(false));
        let (read, mut write) = tokio::io::duplex(8192);
        let retirement = Retirement::new();
        let mut reader = SessionReader::start(
            xml::parser(DropReader {
                inner: read,
                dropped: dropped.clone(),
            }),
            "receiver@example.test/resource".to_owned(),
            None,
            retirement,
            NonZeroUsize::MIN,
        );
        write.write_all(input.as_bytes()).await?;
        drop(write);
        for _ in 0..100 {
            if dropped.load(Ordering::Acquire) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(dropped.load(Ordering::Acquire));
        if input.ends_with("</message>") {
            assert!(reader.run_invalid());
        }
        assert!(reader.retire().await.is_err());
    }
    Ok(())
}

#[tokio::test]
async fn cpu_admission_remains_bounded_after_caller_cancellation() -> TestResult {
    let cpu = cpu();
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let (release, gate) = std::sync::mpsc::channel();
    let (entered, started) = tokio::sync::oneshot::channel();
    let first_cpu = cpu.clone();
    let first_active = active.clone();
    let first_max = maximum.clone();
    let first = tokio::spawn(async move {
        first_cpu
            .run(move || {
                let running = first_active.fetch_add(1, Ordering::AcqRel) + 1;
                first_max.fetch_max(running, Ordering::AcqRel);
                let _ = entered.send(());
                let _ = gate.recv_timeout(Duration::from_secs(5));
                first_active.fetch_sub(1, Ordering::AcqRel);
            })
            .await
    });
    started.await?;
    first.abort();
    let _ = first.await;
    let next_active = active.clone();
    let next_max = maximum.clone();
    let mut second = Box::pin(cpu.run(move || {
        let running = next_active.fetch_add(1, Ordering::AcqRel) + 1;
        next_max.fetch_max(running, Ordering::AcqRel);
        next_active.fetch_sub(1, Ordering::AcqRel);
    }));
    assert!(
        second
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert_eq!(maximum.load(Ordering::Acquire), 1);
    release.send(())?;
    second.await;
    assert_eq!(maximum.load(Ordering::Acquire), 1);
    Ok(())
}

#[tokio::test]
async fn required_features_identity_and_sasl_failures_have_static_errors() -> TestResult {
    for (header, features, expected) in [
        (
            HEADER.to_owned(),
            "<stream:features/>",
            "required_feature_missing",
        ),
        (
            HEADER.replace("example.test", "wrong.test"),
            "<stream:features/>",
            "stream_identity",
        ),
        (
            HEADER.to_owned(),
            "<stream:error><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>",
            "stream_features",
        ),
        (
            HEADER.to_owned(),
            "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms></stream:features>",
            "required_feature_missing",
        ),
    ] {
        let text = format!("{header}{features}");
        let mut parser = xml::parser(text.as_bytes());
        assert_eq!(
            xml::features(&mut parser, "example.test", "starttls", xml::TLS_NS)
                .await
                .unwrap_err()
                .context(),
            expected
        );
    }
    let text = format!(
        "{HEADER}<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms></stream:features>"
    );
    let mut parser = xml::parser(text.as_bytes());
    assert_eq!(
        xml::features(&mut parser, "example.test", "mechanisms", xml::SASL_NS)
            .await
            .unwrap_err()
            .context(),
        "scram_mechanism_missing"
    );
    let text = format!(
        "{HEADER}<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>"
    );
    let mut parser = xml::parser(text.as_bytes());
    xml::next(&mut parser).await?;
    assert_eq!(
        xml::sasl(&mut parser, "success")
            .await
            .unwrap_err()
            .context(),
        "authentication_failed"
    );
    Ok(())
}

#[tokio::test]
async fn proceed_boundary_exposes_buffered_plaintext_and_requires_empty_element() -> TestResult {
    let text = format!("{HEADER}<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>plaintext");
    let mut parser = xml::parser(text.as_bytes());
    xml::next(&mut parser).await?;
    xml::proceed(&mut parser).await?;
    assert_eq!(parser.into_inner().buffer(), b"plaintext");
    let text = format!("{HEADER}<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'>text</proceed>");
    let mut parser = xml::parser(text.as_bytes());
    xml::next(&mut parser).await?;
    assert!(xml::proceed(&mut parser).await.is_err());
    Ok(())
}

#[tokio::test]
async fn malformed_server_final_bounds_and_duplicate_verifier_are_rejected() -> TestResult {
    let mut account = account()?;
    for final_message in [
        format!("{SERVER_PROOF},{SERVER_PROOF}"),
        "v=invalid%%%".to_owned(),
        "e=invalid-proof".to_owned(),
        format!("m=unsupported,{SERVER_PROOF}"),
        format!("v={}", STANDARD.encode([0; 33])),
    ] {
        let exchange = Exchange::with_nonce(&account, NONCE.to_owned())?;
        let challenge = exchange.challenge(&STANDARD.encode(CHALLENGE))?;
        let proof = exchange
            .respond(&mut account, challenge, KeyMode::Prime, &cpu())
            .await?;
        assert!(proof.verify(&STANDARD.encode(final_message)).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn graceful_close_uses_existing_reader_and_retains_receipt_timestamp() -> TestResult {
    let (input, mut output) = tokio::io::duplex(8192);
    let retirement = Retirement::new();
    let mut reader = SessionReader::start(
        xml::parser(input),
        "receiver@example.test/resource".to_owned(),
        None,
        retirement.clone(),
        NonZeroUsize::new(8).unwrap(),
    );
    let (transport, dropped) = probe(None, false);
    let bytes = transport.bytes.clone();
    let mut writer = Writer::new(transport, retirement);
    output
        .write_all(format!("{HEADER}{}", chat()).as_bytes())
        .await?;
    reader.next().await?;
    let received = reader.next().await?;
    let after = Instant::now();
    assert!(received.at <= after);
    output.write_all(b"</stream:stream>").await?;
    let mut observed = Vec::new();
    shutdown_parts(
        &mut reader,
        &mut writer,
        Duration::from_secs(1),
        &mut |event| {
            observed.push(event);
            Ok(())
        },
    )
    .await?;
    assert!(
        observed
            .iter()
            .any(|event| matches!(event.kind, ReceivedKind::StreamEnd))
    );
    assert_eq!(&*bytes.lock().unwrap(), b"</stream:stream>");
    assert!(dropped.load(Ordering::Acquire));
    Ok(())
}

#[test]
fn tls_helpers_reject_invalid_roots_and_disable_early_data() -> TestResult {
    let config = remote_tls_config(None)?;
    assert!(!config.enable_early_data);
    assert!(config.enable_sni);
    assert!(remote_tls_config(Some(b"not a PEM certificate")).is_err());
    assert!(local_tls_config(rustls::pki_types::CertificateDer::from(vec![1, 2, 3])).is_err());
    Ok(())
}

#[tokio::test]
async fn write_start_precedes_write_poll_and_completion_waits_for_flush() -> TestResult {
    let (transport, _) = probe(None, true);
    let bytes = transport.bytes.clone();
    let mut writer = Writer::new(transport, Retirement::new());
    configure(&mut writer)?;
    let (sink, mut events) = sink(8);
    let command = command();
    let mut send = Box::pin(writer.send(&command, &sink));
    assert!(
        send.as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert!(!bytes.lock().unwrap().is_empty());
    assert!(matches!(
        events.try_recv()?,
        WriterEvent::WriteStarted { .. }
    ));
    assert!(events.try_recv().is_err());
    drop(send);
    Ok(())
}

#[tokio::test]
async fn empty_payload_rejects_nested_body_content() -> TestResult {
    for (body, valid) in [
        ("<body/>", true),
        ("<body><nested/></body>", false),
        ("<body>x<nested/></body>", false),
    ] {
        let text = format!(
            "{HEADER}<message type='chat' from='sender@example.test/resource' to='receiver@example.test/resource'>{body}</message>"
        );
        let mut parser = xml::parser(text.as_bytes());
        xml::next(&mut parser).await?;
        let event = xml::received(
            xml::next(&mut parser).await?,
            "receiver@example.test/resource",
            Some(&ReceiveRoute {
                from: "sender@example.test/resource".to_owned(),
                body_bytes: 0,
            }),
        )?;
        assert!(
            matches!(event.kind, ReceivedKind::Chat { route_valid, .. } if route_valid == valid)
        );
    }
    Ok(())
}

#[tokio::test]
async fn message_writer_escapes_attributes_omits_from_and_counts_serialized_bytes() -> TestResult {
    let (transport, _) = probe(None, false);
    let output = transport.bytes.clone();
    let mut writer = Writer::new(transport, Retirement::new());
    writer.configure_messages(
        Arc::from([MessageRoute {
            to: "receiver@example.test/r<&'\"".into(),
        }]),
        Arc::from("xxx"),
    )?;
    let (sink, mut events) = sink(2);
    writer.send(&command(), &sink).await?;
    let bytes = output.lock().map_err(|_| "output lock")?;
    let text = std::str::from_utf8(&bytes)?;
    assert!(text.contains("to='receiver@example.test/r&lt;&amp;&apos;&quot;'"));
    assert!(!text.contains("from="));
    assert!(text.ends_with("<body>xxx</body></message>"));
    assert!(matches!(
        events.try_recv()?,
        WriterEvent::WriteStarted { .. }
    ));
    assert!(
        matches!(events.try_recv()?, WriterEvent::WriteCompleted { bytes: count, .. } if count == bytes.len() && count > 3)
    );
    Ok(())
}

#[tokio::test]
async fn foreign_namespace_and_non_chat_messages_cannot_be_receipts() -> TestResult {
    for stanza in [
        chat().replacen("<message", "<message xmlns='foreign'", 1),
        chat().replace("type='chat'", "type='normal'"),
        chat().replace("<body>xxx</body>", "<body>x<nested/>xx</body>"),
    ] {
        let text = format!("{HEADER}{stanza}");
        let mut parser = xml::parser(text.as_bytes());
        xml::next(&mut parser).await?;
        let event = xml::received(
            xml::next(&mut parser).await?,
            "receiver@example.test/resource",
            Some(&ReceiveRoute {
                from: "sender@example.test/resource".into(),
                body_bytes: 3,
            }),
        )?;
        assert!(!matches!(
            event.kind,
            ReceivedKind::Chat {
                route_valid: true,
                ..
            }
        ));
    }
    Ok(())
}
