// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, ThreadId};
use std::time::Duration;

use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramVerifier, ScramVerifierData,
};
use lonewolf_storage::account::{AccountError, AccountKey};
use lonewolf_storage::{RedbDatabase, StorageErrorKind};
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::Jid;
use redb::backends::InMemoryBackend;
use redb::{Database, StorageBackend, TableDefinition};

pub type TestResult = Result<(), Box<dyn Error>>;

pub const ACCOUNTS: TableDefinition<&str, &[u8]> = TableDefinition::new("lonewolf_accounts");
pub const DECOY_SECRET: TableDefinition<&str, &[u8]> = TableDefinition::new("lonewolf_scram_decoy");
pub const DECOY_SECRET_KEY: &str = "secret";
pub const METADATA: TableDefinition<&str, u32> = TableDefinition::new("lonewolf_metadata");
pub const SCHEMA_KEY: &str = "accounts_schema";

pub fn key(input: &str) -> Result<AccountKey, Box<dyn Error>> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in(input, &mut arena)?;
    Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
}

pub fn verifier<const N: usize>(marker: u8) -> ScramVerifierData<N> {
    ScramVerifierData::new(
        [marker; 16],
        SCRAM_POLICY_ITERATIONS,
        [marker + 1; N],
        [marker + 2; N],
    )
}

pub fn credentials(marker: u8) -> ScramCredentials {
    ScramCredentials::both(verifier(marker), verifier(marker + 3))
}

pub fn assert_verifier<const N: usize>(actual: &ScramVerifierData<N>, marker: u8) {
    assert_eq!(actual.salt(), &[marker; 16]);
    assert_eq!(actual.iterations(), SCRAM_POLICY_ITERATIONS);
    assert_eq!(actual.stored_key(), &[marker + 1; N]);
    assert_eq!(actual.server_key(), &[marker + 2; N]);
}

pub fn assert_scram(actual: Option<ScramVerifier>, marker: u8) -> TestResult {
    match actual.ok_or("missing verifier")? {
        ScramVerifier::Sha1(value) => assert_verifier(&value, marker),
        ScramVerifier::Sha256(value) => assert_verifier(&value, marker),
    }
    Ok(())
}

pub fn assert_storage_error<T>(result: Result<T, AccountError>, expected: StorageErrorKind) {
    match result {
        Err(AccountError::Storage(error)) => assert_eq!(error.kind(), expected),
        _ => panic!("expected a storage error"),
    }
}

pub fn database() -> Result<RedbDatabase, redb::DatabaseError> {
    Database::builder()
        .set_cache_size(1024 * 1024)
        .create_with_backend(InMemoryBackend::new())
        .map(RedbDatabase::new)
}

pub fn insert_record(database: &Database, key: &AccountKey, bytes: &[u8]) -> TestResult {
    let transaction = database.begin_write()?;
    transaction
        .open_table(ACCOUNTS)?
        .insert(key.as_str(), bytes)?;
    transaction.commit()?;
    Ok(())
}

#[derive(Clone, Debug, Default)]
pub struct FailingSyncBackend {
    inner: Arc<InMemoryBackend>,
    fail_next_sync: Arc<AtomicBool>,
}

impl FailingSyncBackend {
    pub fn fail_next_sync(&self) {
        self.fail_next_sync.store(true, Ordering::SeqCst);
    }
}

impl StorageBackend for FailingSyncBackend {
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.inner.read(offset, out)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }

    fn sync_data(&self) -> io::Result<()> {
        self.inner.sync_data()?;
        if self.fail_next_sync.swap(false, Ordering::SeqCst) {
            Err(io::Error::other("injected sync failure"))
        } else {
            Ok(())
        }
    }

    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.inner.write(offset, data)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ObservedBackend {
    inner: Arc<InMemoryBackend>,
    threads: Arc<Mutex<Vec<ThreadId>>>,
    sync_gate: Arc<Mutex<Option<SyncGate>>>,
}

#[derive(Debug)]
struct SyncGate {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
}

impl ObservedBackend {
    pub fn take_threads(&self) -> Result<Vec<ThreadId>, Box<dyn Error>> {
        Ok(std::mem::take(
            &mut *self.threads.lock().map_err(|_| "thread log poisoned")?,
        ))
    }

    pub fn block_next_sync(
        &self,
    ) -> Result<(mpsc::Receiver<()>, mpsc::Sender<()>), Box<dyn Error>> {
        let (entered, started) = mpsc::channel();
        let (release, released) = mpsc::channel();
        *self.sync_gate.lock().map_err(|_| "sync gate poisoned")? = Some(SyncGate {
            entered,
            release: released,
        });
        Ok((started, release))
    }

    fn record_thread(&self) -> io::Result<()> {
        self.threads
            .lock()
            .map_err(|_| io::Error::other("thread log poisoned"))?
            .push(thread::current().id());
        Ok(())
    }
}

impl StorageBackend for ObservedBackend {
    fn len(&self) -> io::Result<u64> {
        self.record_thread()?;
        self.inner.len()
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.record_thread()?;
        self.inner.read(offset, out)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.record_thread()?;
        self.inner.set_len(len)
    }

    fn sync_data(&self) -> io::Result<()> {
        self.record_thread()?;
        let gate = self
            .sync_gate
            .lock()
            .map_err(|_| io::Error::other("sync gate poisoned"))?
            .take();
        if let Some(gate) = gate {
            gate.entered.send(()).map_err(io::Error::other)?;
            gate.release
                .recv_timeout(Duration::from_secs(5))
                .map_err(io::Error::other)?;
        }
        self.inner.sync_data()
    }

    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.record_thread()?;
        self.inner.write(offset, data)
    }
}
