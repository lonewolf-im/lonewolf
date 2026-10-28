// SPDX-License-Identifier: Apache-2.0

use std::pin::Pin;
use std::time::SystemTime;

use compio::io::compat::AsyncStream;
use compio::net::TcpStream;
use futures_util::io::{ReadHalf, WriteHalf};
use lonewolf_util::arena::ChunkAllocator;
use tokio::io::BufReader;
use tokio_util::compat::Compat;

use super::ConnectionSocket;
use super::metrics::ConnectionGauge;
use super::stream::traffic::CountingIo;
use super::stream::{S2sReader, S2sWriter};

pub(crate) mod connect;

type ClientTlsTransport =
    CountingIo<futures_rustls::client::TlsStream<Pin<Box<AsyncStream<TcpStream>>>>>;
type ClientTlsInput = BufReader<Compat<ReadHalf<ClientTlsTransport>>>;
type ClientTlsOutput = WriteHalf<ClientTlsTransport>;

pub(crate) struct OutboundStream<A: ChunkAllocator> {
    _socket: ConnectionSocket,
    #[allow(dead_code)]
    pub(crate) reader: S2sReader<A, ClientTlsInput>,
    #[allow(dead_code)]
    pub(crate) writer: S2sWriter<ClientTlsOutput>,
    #[allow(dead_code)]
    pub(crate) valid_until: SystemTime,
    pub(crate) connection_id: u64,
    _connection_gauge: ConnectionGauge,
}
