// SPDX-License-Identifier: Apache-2.0

use std::io::{ErrorKind, Read};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit, Mac};
use quick_xml::escape::escape;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use socket2::SockRef;

use super::xml::{Element, XmlStream};
use super::{
    BIND_NAMESPACE, C2sSuite, PRE_APPROVAL_NAMESPACE, ROSTER_VERSIONING_NAMESPACE, SASL_NAMESPACE,
    TIMEOUT, TLS_NAMESPACE, TestResult,
};

pub type Client = XmlStream<StreamOwned<ClientConnection, TcpStream>>;
pub type PlainClient = XmlStream<TcpStream>;

pub struct ScramExchange {
    response: String,
    server_signature: Vec<u8>,
}

impl PlainClient {
    pub fn tcp(server: &C2sSuite) -> TestResult<Self> {
        Self::tcp_at(server.address)
    }

    fn tcp_at(address: SocketAddr) -> TestResult<Self> {
        let socket = TcpStream::connect_timeout(&address, TIMEOUT)?;
        socket.set_read_timeout(Some(TIMEOUT))?;
        socket.set_write_timeout(Some(TIMEOUT))?;
        socket.set_nodelay(true)?;
        Ok(Self::new(socket))
    }

    pub fn start_tls(mut self, server: &C2sSuite) -> TestResult<Client> {
        self.send(&format!("<starttls xmlns='{TLS_NAMESPACE}'/>"))?;
        self.receive()?.assert_name(TLS_NAMESPACE, "proceed");
        let socket = self.into_inner();
        assert!(socket.buffer().is_empty());
        let connection =
            ClientConnection::new(Arc::clone(&server.tls), ServerName::try_from("localhost")?)?;
        Ok(XmlStream::new(StreamOwned::new(
            connection,
            socket.into_inner(),
        )))
    }
}

impl Client {
    pub fn encrypted(server: &C2sSuite) -> TestResult<Self> {
        Self::encrypted_at(server, server.address)
    }

    fn encrypted_at(server: &C2sSuite, address: SocketAddr) -> TestResult<Self> {
        let mut plain = PlainClient::tcp_at(address)?;
        let features = plain.open()?;
        features
            .child(TLS_NAMESPACE, "starttls")?
            .child(TLS_NAMESPACE, "required")?;
        assert_eq!(features.children.len(), 1);
        plain.start_tls(server)
    }

    pub fn secure(server: &C2sSuite) -> TestResult<Self> {
        Self::secure_at(server, server.address)
    }

    fn secure_at(server: &C2sSuite, address: SocketAddr) -> TestResult<Self> {
        let mut client = Self::encrypted_at(server, address)?;
        client.open()?.child(SASL_NAMESPACE, "mechanisms")?;
        Ok(client)
    }

    pub fn authenticated(server: &C2sSuite, username: &str, password: &str) -> TestResult<Self> {
        Ok(Self::authenticated_with_features(server, username, password)?.0)
    }

    /// Rejects stream features outside binding and the supported roster features.
    pub fn authenticated_with_features(
        server: &C2sSuite,
        username: &str,
        password: &str,
    ) -> TestResult<(Self, Element)> {
        Self::authenticated_with_features_at(server, server.address, username, password)
    }

    fn authenticated_with_features_at(
        server: &C2sSuite,
        address: SocketAddr,
        username: &str,
        password: &str,
    ) -> TestResult<(Self, Element)> {
        let mut client = Self::secure_at(server, address)?;
        client.authenticate(username, password)?;
        let mut client = client.restart();
        let features = client.open()?;
        features.child(BIND_NAMESPACE, "bind")?;
        for feature in &features.children {
            assert!(
                matches!(
                    (feature.namespace.as_str(), feature.name.as_str()),
                    (BIND_NAMESPACE, "bind")
                        | (ROSTER_VERSIONING_NAMESPACE, "ver")
                        | (PRE_APPROVAL_NAMESPACE, "sub")
                ),
                "unexpected feature {}:{}",
                feature.namespace,
                feature.name
            );
        }
        Ok((client, features))
    }

    pub fn connect(
        server: &C2sSuite,
        username: &str,
        password: &str,
        resource: &str,
    ) -> TestResult<Self> {
        Self::connect_at(server, server.address, username, password, resource)
    }

    pub fn connect_at(
        server: &C2sSuite,
        address: SocketAddr,
        username: &str,
        password: &str,
        resource: &str,
    ) -> TestResult<Self> {
        let mut client =
            Self::authenticated_with_features_at(server, address, username, password)?.0;
        let jid = client.bind(Some(resource))?;
        assert_eq!(jid, format!("{username}@localhost/{resource}"));
        Ok(client)
    }

    pub fn send_sasl_auth(&mut self, mechanism: &str, first: &str) -> TestResult {
        self.send(&format!(
            "<auth xmlns='{SASL_NAMESPACE}' mechanism='{mechanism}'>{}</auth>",
            STANDARD.encode(first)
        ))
    }

    pub fn receive_sasl_challenge(&mut self) -> TestResult<String> {
        let reply = self.receive()?;
        reply.assert_name(SASL_NAMESPACE, "challenge");
        Ok(String::from_utf8(STANDARD.decode(reply.text)?)?)
    }

    pub fn send_sasl_response(&mut self, response: &str) -> TestResult {
        self.send(&format!(
            "<response xmlns='{SASL_NAMESPACE}'>{}</response>",
            STANDARD.encode(response)
        ))
    }

    pub fn authenticate(&mut self, username: &str, password: &str) -> TestResult {
        let reply = self.scram(username, password, "SCRAM-SHA-256", None)?;
        reply.assert_name(SASL_NAMESPACE, "success");
        Ok(())
    }

    pub fn bind(&mut self, resource: Option<&str>) -> TestResult<String> {
        let resource = resource
            .map(|value| format!("<resource>{}</resource>", escape(value)))
            .unwrap_or_default();
        self.send(&format!(
            "<iq type='set' id='bind'><bind xmlns='{BIND_NAMESPACE}'>{resource}</bind></iq>"
        ))?;
        let reply = self.receive()?;
        reply.assert_name("jabber:client", "iq");
        assert_eq!(reply.attribute("id"), Some("bind"));
        assert_eq!(reply.attribute("type"), Some("result"), "{reply:?}");
        Ok(reply
            .child(BIND_NAMESPACE, "bind")?
            .child(BIND_NAMESPACE, "jid")?
            .text
            .clone())
    }
}

impl Client {
    /// Forces a TCP reset to expose failed writes.
    pub fn reset(self) -> TestResult {
        let stream = self.into_inner().into_inner();
        SockRef::from(&stream.sock).set_linger(Some(Duration::ZERO))?;
        Ok(())
    }

    pub fn drain(&mut self) -> TestResult {
        let mut sink = [0; 4096];
        loop {
            match self.transport().read(&mut sink) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset
                    ) =>
                {
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub fn scram(
        &mut self,
        username: &str,
        password: &str,
        mechanism: &str,
        binding: Option<&str>,
    ) -> TestResult<Element> {
        let exchange = self.begin_scram(username, password, mechanism, binding, None)?;
        self.finish_scram(exchange)
    }

    pub fn begin_scram(
        &mut self,
        username: &str,
        password: &str,
        mechanism: &str,
        binding: Option<&str>,
        authzid: Option<&str>,
    ) -> TestResult<ScramExchange> {
        let flag = binding
            .map(|binding| format!("p={binding}"))
            .unwrap_or_else(|| "n".into());
        let authzid = authzid
            .map(|value| format!("a={}", value.replace('=', "=3D").replace(',', "=2C")))
            .unwrap_or_default();
        let gs2 = format!("{flag},{authzid},");
        let mut channel = gs2.as_bytes().to_vec();
        match binding {
            Some("tls-exporter") => {
                let mut exporter = [0; 32];
                self.transport().conn.export_keying_material(
                    &mut exporter,
                    b"EXPORTER-Channel-Binding",
                    None,
                )?;
                channel.extend_from_slice(&exporter);
            }
            Some("tls-server-end-point") => {
                let certificate = self
                    .transport()
                    .conn
                    .peer_certificates()
                    .and_then(|chain| chain.first())
                    .ok_or("missing peer certificate")?;
                channel.extend_from_slice(&Sha256::digest(certificate.as_ref()));
            }
            Some(_) => return Err("unsupported test channel binding".into()),
            None => {}
        }
        let sha1 = mechanism.starts_with("SCRAM-SHA-1");
        let mut random = [0; 18];
        graviola::random::fill(&mut random)?;
        let nonce = STANDARD.encode(random);
        let username = username.replace('=', "=3D").replace(',', "=2C");
        let first = format!("n={username},r={nonce}");
        self.send(&format!(
            "<auth xmlns='{SASL_NAMESPACE}' mechanism='{mechanism}'>{}</auth>",
            STANDARD.encode(format!("{gs2}{first}")),
        ))?;
        let challenge = self.receive()?;
        assert_eq!(challenge.name, "challenge", "{challenge:?}");
        assert_eq!(challenge.namespace, SASL_NAMESPACE);
        let challenge = String::from_utf8(STANDARD.decode(&challenge.text)?)?;
        let server_nonce = scram_attribute(&challenge, "r=")?;
        assert!(server_nonce.starts_with(&nonce) && server_nonce.len() > nonce.len());
        let salt = STANDARD.decode(scram_attribute(&challenge, "s=")?)?;
        let iterations = scram_attribute(&challenge, "i=")?.parse()?;
        assert!((1..=1_000_000).contains(&iterations));
        let mut salted = vec![0; if sha1 { 20 } else { 32 }];
        if sha1 {
            pbkdf2::pbkdf2_hmac::<Sha1>(password.as_bytes(), &salt, iterations, &mut salted);
        } else {
            pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iterations, &mut salted);
        }
        let final_without_proof = format!("c={},r={server_nonce}", STANDARD.encode(channel));
        let auth_message = format!("{first},{challenge},{final_without_proof}");
        let client_key = hmac(sha1, &salted, b"Client Key")?;
        let stored_key = if sha1 {
            Sha1::digest(&client_key).to_vec()
        } else {
            Sha256::digest(&client_key).to_vec()
        };
        let client_signature = hmac(sha1, &stored_key, auth_message.as_bytes())?;
        let mut proof = client_key;
        for (byte, signature) in proof.iter_mut().zip(client_signature) {
            *byte ^= signature;
        }
        let server_key = hmac(sha1, &salted, b"Server Key")?;
        Ok(ScramExchange {
            response: format!("{final_without_proof},p={}", STANDARD.encode(proof)),
            server_signature: hmac(sha1, &server_key, auth_message.as_bytes())?,
        })
    }

    pub fn finish_scram(&mut self, exchange: ScramExchange) -> TestResult<Element> {
        self.send_sasl_response(&exchange.response)?;
        let success = self.receive()?;
        if success.name != "success" || success.namespace != SASL_NAMESPACE {
            return Ok(success);
        }
        let final_message = String::from_utf8(STANDARD.decode(&success.text)?)?;
        let signature = STANDARD.decode(scram_attribute(&final_message, "v=")?)?;
        assert_eq!(
            signature, exchange.server_signature,
            "incorrect SCRAM server signature"
        );
        Ok(success)
    }
}

fn hmac(sha1: bool, key: &[u8], message: &[u8]) -> TestResult<Vec<u8>> {
    if sha1 {
        let mut mac = Hmac::<Sha1>::new_from_slice(key)?;
        mac.update(message);
        Ok(mac.finalize().into_bytes().to_vec())
    } else {
        let mut mac = Hmac::<Sha256>::new_from_slice(key)?;
        mac.update(message);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

fn scram_attribute<'a>(message: &'a str, prefix: &str) -> TestResult<&'a str> {
    message
        .split(',')
        .find_map(|part| part.strip_prefix(prefix))
        .ok_or_else(|| format!("missing SCRAM attribute {prefix}").into())
}
