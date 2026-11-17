// SPDX-License-Identifier: Apache-2.0

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use sha1::{Digest as _, Sha1};

use super::wire::{WireCounters, WireIo};
use super::xml::{Element, XmlStream};
use super::{C2sSuite, Client, TIMEOUT, TestResult};

pub fn tcp(address: SocketAddr) -> TestResult<TcpStream> {
    let socket = TcpStream::connect_timeout(&address, TIMEOUT)?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.set_write_timeout(Some(TIMEOUT))?;
    Ok(socket)
}

pub const NAMESPACE: &str = "jabber:component:accept";

/// Counts locally completed stanzas, including unflushed output.
pub fn completed_stanzas(metrics: &str) -> TestResult<usize> {
    let mut total = 0_usize;
    for prefix in [
        "lonewolf_component_stanzas_sent_total{kind=\"message\"} ",
        "lonewolf_component_stanzas_sent_total{kind=\"iq\"} ",
        "lonewolf_component_stanzas_sent_total{kind=\"presence\"} ",
    ] {
        let count = metrics
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .unwrap_or("0")
            .parse::<usize>()?;
        total = total
            .checked_add(count)
            .ok_or("component stanza count overflow")?;
    }
    Ok(total)
}

pub struct ResponseHeader {
    pub id: String,
    pub from: Option<String>,
    pub namespace: String,
    pub version: Option<String>,
}

pub struct ComponentClient<T = WireIo<TcpStream>> {
    stream: XmlStream<T>,
    pub counters: WireCounters,
    socket: TcpStream,
}

pub struct ComponentWriteControl {
    peer: SocketAddr,
    server: String,
}

impl ComponentWriteControl {
    fn command(&self, client: &mut Client, name: &str, attributes: &str) -> TestResult<Element> {
        let namespace = super::extensions::COMPONENT_WRITE_PROBE_NAMESPACE;
        client.send(&format!("<iq type='get' to='{}' id='component-write-control'><{name} xmlns='{namespace}' peer='{}' {attributes}/></iq>", self.server, self.peer))?;
        let reply = client.receive()?;
        reply.assert_name("jabber:client", "iq");
        assert_eq!(reply.attribute("id"), Some("component-write-control"));
        assert_eq!(reply.attribute("type"), Some("result"), "{name}: {reply:?}");
        assert_eq!(reply.attribute("from"), Some(self.server.as_str()));
        Ok(reply)
    }

    pub fn hold_after_bytes(&self, client: &mut Client, bytes: usize) -> TestResult {
        assert!(
            self.command(client, "arm", &format!("bytes='{bytes}'"))?
                .children
                .is_empty()
        );
        Ok(())
    }

    pub fn wait_held(&self, client: &mut Client) -> TestResult {
        let reply = self.command(client, "event", "")?;
        assert_eq!(reply.children.len(), 1);
        reply.children[0].assert_xml(&format!(
            "<event xmlns='{}' name='held'/>",
            super::extensions::COMPONENT_WRITE_PROBE_NAMESPACE
        ))
    }

    pub fn release_write(&self, client: &mut Client) -> TestResult {
        assert!(self.command(client, "release", "")?.children.is_empty());
        Ok(())
    }

    pub fn remove(self, client: &mut Client) -> TestResult {
        assert!(self.command(client, "remove", "")?.children.is_empty());
        Ok(())
    }
}

impl ComponentClient {
    pub fn connect(address: SocketAddr) -> TestResult<Self> {
        let socket = tcp(address)?;
        let transport = WireIo::new(socket.try_clone()?);
        let counters = transport.counters();
        Ok(Self {
            stream: XmlStream::new(transport),
            counters,
            socket,
        })
    }

    pub fn reset(self) -> TestResult {
        socket2::SockRef::from(&self.socket).set_linger(Some(std::time::Duration::ZERO))?;
        Ok(())
    }

    pub fn authenticated(suite: &C2sSuite, domain: &str, secret: &str) -> TestResult<Self> {
        let mut client = Self::connect(suite.component_address(0)?)?;
        let header = client.open(domain, None)?;
        client.send_handshake_for(secret, &header.id)?;
        client.expect_handshake()?;
        Ok(client)
    }

    pub fn authenticated_with_write_probe(
        suite: &C2sSuite,
        domain: &str,
        secret: &str,
        control: &mut Client,
    ) -> TestResult<(Self, ComponentWriteControl)> {
        let mut client = Self::connect(suite.component_address(0)?)?;
        let probe = ComponentWriteControl {
            peer: client.local_address()?,
            server: suite.domain.clone(),
        };
        assert!(probe.command(control, "install", "")?.children.is_empty());
        let header = client.open(domain, None)?;
        client.send_handshake_for(secret, &header.id)?;
        client.expect_handshake()?;
        Ok((client, probe))
    }
}

pub type TlsComponentClient = ComponentClient<StreamOwned<ClientConnection, WireIo<TcpStream>>>;

impl TlsComponentClient {
    pub fn connect_tls(
        address: SocketAddr,
        config: Arc<ClientConfig>,
        identity: ServerName<'static>,
    ) -> TestResult<Self> {
        let socket = tcp(address)?;
        let transport = WireIo::new(socket.try_clone()?);
        let counters = transport.counters();
        let mut transport = StreamOwned::new(ClientConnection::new(config, identity)?, transport);
        while transport.conn.is_handshaking() {
            transport.conn.complete_io(&mut transport.sock)?;
        }
        Ok(Self {
            stream: XmlStream::new(transport),
            counters,
            socket,
        })
    }

    pub fn tls_connection(&mut self) -> &ClientConnection {
        &self.stream.transport().conn
    }

    pub fn expect_tls_close(&mut self) -> TestResult {
        assert!(!self.stream.has_buffered_input());
        assert_eq!(self.stream.transport().read(&mut [0; 1])?, 0);
        assert_eq!(self.socket.read(&mut [0; 1])?, 0);
        Ok(())
    }
}

impl<T: Read + Write> ComponentClient<T> {
    pub fn local_address(&self) -> TestResult<SocketAddr> {
        self.socket.local_addr().map_err(Into::into)
    }

    pub fn open(&mut self, domain: &str, version: Option<&str>) -> TestResult<ResponseHeader> {
        let mut opening = format!(
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='{NAMESPACE}' to='{domain}'"
        );
        if let Some(version) = version {
            write!(opening, " version='{version}'")?;
        }
        opening.push('>');
        self.open_with(&opening)
    }

    pub fn open_with(&mut self, opening: &str) -> TestResult<ResponseHeader> {
        let header = self.stream.open_with(opening)?;
        Ok(ResponseHeader {
            id: header
                .attribute("id")
                .ok_or("component response has no stream ID")?
                .into(),
            from: header.attribute("from").map(str::to_owned),
            namespace: header
                .attribute("xmlns")
                .ok_or("component response has no namespace")?
                .into(),
            version: header.attribute("version").map(str::to_owned),
        })
    }

    pub fn send_handshake_for(&mut self, secret: &str, stream_id: &str) -> TestResult {
        let mut digest = Sha1::new();
        digest.update(stream_id.as_bytes());
        digest.update(secret.as_bytes());
        let mut xml = String::with_capacity(64);
        xml.push_str("<handshake>");
        for byte in digest.finalize() {
            write!(xml, "{byte:02x}")?;
        }
        xml.push_str("</handshake>");
        self.send(&xml)
    }

    pub fn send_raw(&mut self, xml: &str) -> TestResult {
        self.stream.send(xml)
    }
    pub fn send(&mut self, xml: &str) -> TestResult {
        self.send_raw(xml)
    }
    pub fn receive(&mut self) -> TestResult<Element> {
        self.stream.receive()
    }
    pub fn receive_or_footer(&mut self) -> TestResult<Option<Element>> {
        self.stream.receive_or_footer()
    }
    pub fn drain_to_eof(self) -> TestResult<Vec<u8>> {
        let mut input = self.stream.into_inner();
        let mut bytes = Vec::new();
        match input.read_to_end(&mut bytes) {
            Ok(_) => Ok(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => Ok(bytes),
            Err(error) => Err(error.into()),
        }
    }
    pub fn expect_xml(&mut self, xml: &str) -> TestResult {
        self.receive()?.assert_xml(xml)
    }
    pub fn expect_handshake(&mut self) -> TestResult {
        self.expect_xml("<handshake xmlns='jabber:component:accept'/>")
    }
    pub fn expect_stream_error(&mut self, condition: &str) -> TestResult {
        self.expect_xml(&format!("<stream:error xmlns:stream='http://etherx.jabber.org/streams'><{condition} xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>"))
    }
    pub fn expect_footer(&mut self) -> TestResult {
        self.stream.expect_footer()
    }
    pub fn expect_eof(&mut self) -> TestResult {
        self.stream.expect_eof()
    }
    pub fn shutdown_write(&self) -> TestResult {
        self.socket.shutdown(std::net::Shutdown::Write)?;
        Ok(())
    }

    pub fn close(&mut self) -> TestResult {
        self.send("</stream:stream>")?;
        self.expect_footer()?;
        self.shutdown_write()?;
        self.expect_eof()
    }
}
