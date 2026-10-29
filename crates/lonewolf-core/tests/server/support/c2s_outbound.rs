// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit, Mac};
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use sha2::{Digest, Sha256};

use crate::process::{Server, TIMEOUT};
use crate::support::{self, Fixture, Peer, Result};

pub const HEADER: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='local.test' version='1.0'>";
const SASL: &str = "urn:ietf:params:xml:ns:xmpp-sasl";

#[derive(Debug)]
pub struct Element {
    pub namespace: String,
    pub name: String,
    pub attributes: BTreeMap<String, String>,
    pub children: Vec<Element>,
    pub text: String,
}

impl Element {
    pub fn child(&self, namespace: &str, name: &str) -> Result<&Self> {
        self.children
            .iter()
            .find(|child| child.namespace == namespace && child.name == name)
            .ok_or_else(|| format!("missing {{{namespace}}}{name} in {self:?}").into())
    }
}

pub fn element(xml: &str) -> Result<Element> {
    let mut reader = quick_xml::NsReader::from_str(xml);
    reader.config_mut().expand_empty_elements = true;
    let mut stack: Vec<Element> = Vec::new();
    loop {
        let (namespace, event) = reader.read_resolved_event()?;
        match event {
            Event::Start(start) => {
                let namespace = match namespace {
                    ResolveResult::Bound(value) => value.as_ref().to_owned(),
                    ResolveResult::Unbound => String::new(),
                    ResolveResult::Unknown(_) => return Err("unbound namespace".into()),
                };
                let attributes = start
                    .attributes()
                    .map(|attribute| -> Result<_> {
                        let attribute = attribute?;
                        Ok((
                            attribute.key.as_ref().to_owned(),
                            attribute
                                .normalized_value(quick_xml::XmlVersion::Implicit1_0)?
                                .into_owned(),
                        ))
                    })
                    .collect::<Result<_>>()?;
                stack.push(Element {
                    namespace,
                    name: start.local_name().as_ref().to_owned(),
                    attributes,
                    children: Vec::new(),
                    text: String::new(),
                });
            }
            Event::End(_) => {
                let element = stack.pop().ok_or("unmatched end")?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(element);
                } else {
                    return Ok(element);
                }
            }
            Event::Text(text) => stack
                .last_mut()
                .ok_or("text outside element")?
                .text
                .push_str(&text.xml_content(quick_xml::XmlVersion::Implicit1_0)),
            Event::GeneralRef(reference) => {
                let value = format!("&{};", reference.as_ref());
                stack
                    .last_mut()
                    .ok_or("reference outside element")?
                    .text
                    .push_str(&quick_xml::escape::unescape(&value)?);
            }
            event => return Err(format!("unexpected XML event: {event:?}").into()),
        }
    }
}

fn hmac(key: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    let mut hmac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)?;
    hmac.update(input);
    Ok(hmac.finalize().into_bytes().to_vec())
}

pub fn client(fixture: &Fixture, address: SocketAddr) -> Result<Peer> {
    let password = "ephemeral-test-password";
    let mut peer = support::connect(address)?;
    peer.write_all(HEADER.as_bytes())?;
    support::until(&mut peer, "</stream:features>")?;
    peer.write_all(support::STARTTLS.as_bytes())?;
    element(&support::until(&mut peer, "/>")?)?
        .childless("urn:ietf:params:xml:ns:xmpp-tls", "proceed");
    let mut peer = rustls::StreamOwned::new(
        rustls::ClientConnection::new(
            fixture.client(None, false)?,
            rustls::pki_types::ServerName::try_from("local.test")?,
        )?,
        peer,
    );
    peer.write_all(HEADER.as_bytes())?;
    support::until(&mut peer, "</stream:features>")?;
    let mut random = [0; 18];
    graviola::random::fill(&mut random)?;
    let nonce = STANDARD.encode(random);
    let first = format!("n=alice,r={nonce}");
    write!(
        peer,
        "<auth xmlns='{SASL}' mechanism='SCRAM-SHA-256'>{}</auth>",
        STANDARD.encode(format!("n,,{first}"))
    )?;
    peer.flush()?;
    let challenge = element(&support::until(&mut peer, "</challenge>")?)?;
    assert_eq!(
        (challenge.namespace.as_str(), challenge.name.as_str()),
        (SASL, "challenge")
    );
    let challenge = String::from_utf8(STANDARD.decode(challenge.text)?)?;
    let attribute = |prefix| {
        challenge
            .split(',')
            .find_map(|part| part.strip_prefix(prefix))
            .ok_or("missing SCRAM attribute")
    };
    let server_nonce = attribute("r=")?;
    assert!(server_nonce.starts_with(&nonce) && server_nonce.len() > nonce.len());
    let salt = STANDARD.decode(attribute("s=")?)?;
    let iterations = attribute("i=")?.parse()?;
    assert!((1..=1_000_000).contains(&iterations));
    let mut salted = [0; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iterations, &mut salted);
    let final_without_proof = format!("c=biws,r={server_nonce}");
    let authentication = format!("{first},{challenge},{final_without_proof}");
    let mut proof = hmac(&salted, b"Client Key")?;
    let signature = hmac(&Sha256::digest(&proof), authentication.as_bytes())?;
    for (byte, signature) in proof.iter_mut().zip(signature) {
        *byte ^= signature;
    }
    write!(
        peer,
        "<response xmlns='{SASL}'>{}</response>",
        STANDARD.encode(format!(
            "{final_without_proof},p={}",
            STANDARD.encode(proof)
        ))
    )?;
    peer.flush()?;
    let success = element(&support::until(&mut peer, "</success>")?)?;
    assert_eq!(
        (success.namespace.as_str(), success.name.as_str()),
        (SASL, "success")
    );
    assert_eq!(
        String::from_utf8(STANDARD.decode(success.text)?)?,
        format!(
            "v={}",
            STANDARD.encode(hmac(
                &hmac(&salted, b"Server Key")?,
                authentication.as_bytes()
            )?)
        )
    );
    peer.write_all(HEADER.as_bytes())?;
    support::until(&mut peer, "</stream:features>")?;
    peer.write_all(b"<iq type='set' id='bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>")?;
    peer.flush()?;
    let reply = element(&support::until(&mut peer, "</iq>")?)?;
    assert_eq!(
        reply.attributes.get("type").map(String::as_str),
        Some("result")
    );
    assert_eq!(
        reply
            .child("urn:ietf:params:xml:ns:xmpp-bind", "bind")?
            .child("urn:ietf:params:xml:ns:xmpp-bind", "jid")?
            .text,
        "alice@local.test/desk"
    );
    Ok(peer)
}

impl Element {
    fn childless(&self, namespace: &str, name: &str) {
        assert_eq!(
            (self.namespace.as_str(), self.name.as_str()),
            (namespace, name)
        );
        assert!(self.children.is_empty());
    }
}

pub fn start(fixture: &Fixture, extra: &str) -> Result<(Server, Peer)> {
    let mut server = Server::start(&format!("{}{extra}", fixture.config), 2)?;
    let addresses = server.ready_with(|readiness| readiness.c2s)?;
    assert_eq!(addresses.len(), 1);
    let mut admin = UnixStream::connect(server.directory.path().join("run/lonewolf/admin.sock"))?;
    admin.set_read_timeout(Some(TIMEOUT))?;
    admin.set_write_timeout(Some(TIMEOUT))?;
    let body = r#"{"jid":"alice@local.test","password":"ephemeral-test-password"}"#;
    write!(
        admin,
        "POST /v1/accounts HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )?;
    let mut response = String::new();
    admin.read_to_string(&mut response)?;
    assert!(response.starts_with("HTTP/1.1 201 "), "{response}");
    let client = client(fixture, addresses[0])?;
    Ok((server, client))
}

pub fn stanza(peer: &mut Peer, name: &str) -> Result<Element> {
    element(&support::until(peer, &format!("</{name}>"))?)
}

pub fn barrier(client: &mut Peer) -> Result {
    client.write_all(b"<iq type='get' id='barrier'><query xmlns='urn:test:barrier'/></iq>")?;
    client.flush()?;
    let reply = stanza(client, "iq")?;
    assert_eq!(
        reply.attributes.get("id").map(String::as_str),
        Some("barrier")
    );
    reply
        .child("jabber:client", "error")?
        .child("urn:ietf:params:xml:ns:xmpp-stanzas", "service-unavailable")?;
    Ok(())
}

pub fn close(client: &mut Peer) -> Result {
    client.write_all(support::FOOTER.as_bytes())?;
    client.flush()?;
    assert_eq!(support::until(client, support::FOOTER)?, support::FOOTER);
    client.conn.send_close_notify();
    client.flush()?;
    assert_eq!(client.read(&mut [0; 1])?, 0);
    Ok(())
}
