// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::Arc;

use compio::runtime::Runtime;
use lonewolf_storage::RedbStorage;

use super::Server;
use crate::deleter::{AccountDeleter, RecordDeleter};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct SocketFixture {
    directory: tempfile::TempDir,
    path: PathBuf,
    storage: RedbStorage,
    deleter: Arc<dyn AccountDeleter>,
}

impl SocketFixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("accounts.redb"))?;
        let deleter = Arc::new(RecordDeleter::new(storage.clone()));
        let path = directory.path().join("private/admin.sock");
        Ok(Self {
            directory,
            path,
            storage,
            deleter,
        })
    }

    fn create_private_parent(&self) -> TestResult {
        let parent = self.path.parent().ok_or("missing parent")?;
        fs::create_dir(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn bind(&self) -> io::Result<Server> {
        Server::bind(&self.path, self.storage.clone(), Arc::clone(&self.deleter))
    }

    fn bind_error(&self) -> TestResult<io::ErrorKind> {
        Ok(self
            .bind()
            .err()
            .ok_or("accepted an existing or public socket path")?
            .kind())
    }
}

#[test]
fn binding_creates_private_directory_and_socket_and_drop_removes_socket() -> TestResult {
    let fixture = SocketFixture::new()?;
    Runtime::new()?.block_on(async {
        let server = fixture.bind()?;
        assert_eq!(
            fs::metadata(fixture.path.parent().ok_or("missing parent")?)?.mode() & 0o777,
            0o700
        );
        assert_eq!(fs::metadata(&fixture.path)?.mode() & 0o777, 0o600);
        drop(server);
        assert!(!fixture.path.exists());
        Ok(())
    })
}

#[test]
fn binding_refuses_a_live_socket_and_preserves_its_inode() -> TestResult {
    let fixture = SocketFixture::new()?;
    Runtime::new()?.block_on(async {
        let server = fixture.bind()?;
        let before = fs::symlink_metadata(&fixture.path)?;
        assert_eq!(fixture.bind_error()?, io::ErrorKind::AddrInUse);
        let after = fs::symlink_metadata(&fixture.path)?;
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
        assert!(after.file_type().is_socket());
        drop(server);
        assert!(!fixture.path.exists());
        Ok(())
    })
}

#[test]
fn binding_refuses_a_stale_socket_and_preserves_its_inode() -> TestResult {
    let fixture = SocketFixture::new()?;
    fixture.create_private_parent()?;
    let stale = std::os::unix::net::UnixListener::bind(&fixture.path)?;
    drop(stale);
    let before = fs::symlink_metadata(&fixture.path)?;
    Runtime::new()?.block_on(async {
        assert_eq!(fixture.bind_error()?, io::ErrorKind::AddrInUse);
        let after = fs::symlink_metadata(&fixture.path)?;
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
        assert!(after.file_type().is_socket());
        Ok(())
    })
}

#[test]
fn binding_refuses_an_existing_file_and_preserves_its_contents() -> TestResult {
    let fixture = SocketFixture::new()?;
    fixture.create_private_parent()?;
    fs::write(&fixture.path, "keep")?;
    Runtime::new()?.block_on(async {
        assert_eq!(fixture.bind_error()?, io::ErrorKind::AddrInUse);
        assert_eq!(fs::read_to_string(&fixture.path)?, "keep");
        Ok(())
    })
}

#[test]
fn binding_refuses_a_dangling_symlink_and_preserves_its_target() -> TestResult {
    let fixture = SocketFixture::new()?;
    fixture.create_private_parent()?;
    let target = fixture.directory.path().join("target");
    symlink(&target, &fixture.path)?;
    Runtime::new()?.block_on(async {
        assert_eq!(fixture.bind_error()?, io::ErrorKind::AddrInUse);
        assert_eq!(fs::read_link(&fixture.path)?, target);
        assert!(!target.try_exists()?);
        Ok(())
    })
}

#[test]
fn dropping_the_server_preserves_a_replacement_file() -> TestResult {
    let fixture = SocketFixture::new()?;
    Runtime::new()?.block_on(async {
        let server = fixture.bind()?;
        fs::remove_file(&fixture.path)?;
        fs::write(&fixture.path, "replacement")?;
        drop(server);
        assert_eq!(fs::read_to_string(&fixture.path)?, "replacement");
        Ok(())
    })
}

#[test]
fn binding_refuses_a_public_parent_with_permission_denied() -> TestResult {
    let fixture = SocketFixture::new()?;
    let parent = fixture.path.parent().ok_or("missing parent")?;
    fs::create_dir(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o755))?;
    Runtime::new()?.block_on(async {
        assert_eq!(fixture.bind_error()?, io::ErrorKind::PermissionDenied);
        assert_eq!(fs::metadata(parent)?.mode() & 0o777, 0o755);
        assert!(!fixture.path.exists());
        Ok(())
    })
}
