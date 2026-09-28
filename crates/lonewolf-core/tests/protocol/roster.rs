// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

use crate::support::{C2sSuite, TestResult};
use compio::runtime::Runtime;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::roster::redb::RedbRosterRepository;
use lonewolf_storage::roster::{
    RosterItemUpdate, RosterJid, RosterRepository, RosterSubscription, SubscriptionState,
};
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::Jid;

fn seed_roster(directory: &Path) -> TestResult {
    fs::create_dir(directory.join("data"))?;
    let repository = RedbRosterRepository::open(directory.join("data/lonewolf.dat"))?;
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let owner = Jid::parse_in("alice@localhost", &mut arena)?;
    let contact = Jid::parse_in("bob@localhost", &mut arena)?;
    let owner = AccountKey::try_from(owner.resolve(&arena)?)?;
    let contact = RosterJid::from(contact.resolve(&arena)?);
    Runtime::new()?.block_on(async {
        repository
            .upsert(
                &owner,
                RosterItemUpdate {
                    jid: contact.clone(),
                    name: Some("Bob Smith".into()),
                    groups: vec!["Friends".into(), "Work".into()],
                },
            )
            .await?;
        repository
            .update_subscription(&owner, &contact, |_| {
                Some(RosterSubscription {
                    state: SubscriptionState::Both,
                    pending_out: true,
                    approved: true,
                })
            })
            .await?;
        Ok::<_, lonewolf_storage::roster::RosterError>(())
    })?;
    Ok(())
}

#[test]
fn enabled_roster_returns_an_empty_roster() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    alice.send("<iq type='get' id='roster'><query xmlns='jabber:iq:roster'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>")?;

    alice.close()
}

#[test]
fn roster_get_with_an_item_returns_bad_request() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    alice.send("<iq type='get' id='invalid-roster'><query xmlns='jabber:iq:roster'><item jid='bob@localhost'/></query></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='invalid-roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'><item jid='bob@localhost'/></query><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;

    alice.close()
}

#[test]
fn roster_get_returns_stored_items() -> TestResult {
    let suite = C2sSuite::with_extensions_and_setup("'roster'", seed_roster)?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    alice.send("<iq type='get' id='stored-roster'><query xmlns='jabber:iq:roster'/></iq>")?;
    alice.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='stored-roster' to='alice@localhost/desk'>
            <query xmlns='jabber:iq:roster'>
                <item jid='bob@localhost' name='Bob Smith' subscription='both' ask='subscribe' approved='true'>
                    <group>Friends</group>
                    <group>Work</group>
                </item>
            </query>
        </iq>",
    )?;

    alice.close()
}

#[test]
fn roster_get_for_another_account_returns_forbidden() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    alice.send(
        "<iq type='get' id='other-roster' to='bob@localhost'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='other-roster' from='bob@localhost' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/><error type='auth'><forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;

    alice.close()
}
