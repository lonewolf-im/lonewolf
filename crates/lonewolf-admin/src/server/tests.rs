// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::sync::Arc;

use compio::runtime::Runtime;
use lonewolf_storage::RedbStorage;

use super::Server;
use crate::observer::{AccountDeleter, RecordDeleter};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn socket_permissions_and_existing_paths_are_preserved() -> TestResult {
    let directory = tempfile::tempdir()?;
    let storage = RedbStorage::open(directory.path().join("accounts.redb"))?;
    Runtime::new()?.block_on(async {
        let deleter: Arc<dyn AccountDeleter> = Arc::new(RecordDeleter::new(storage.clone()));
        let path = directory.path().join("private/admin.sock");
        let server = Server::bind(&path, storage.clone(), Arc::clone(&deleter))?;
        assert_eq!(
            fs::metadata(path.parent().ok_or("missing parent")?)?.mode() & 0o777,
            0o700
        );
        assert_eq!(fs::metadata(&path)?.mode() & 0o777, 0o600);
        assert!(Server::bind(&path, storage.clone(), Arc::clone(&deleter)).is_err());
        drop(server);
        assert!(!path.exists());

        let stale = std::os::unix::net::UnixListener::bind(&path)?;
        drop(stale);
        assert!(Server::bind(&path, storage.clone(), Arc::clone(&deleter)).is_err());
        assert!(path.exists());
        fs::remove_file(&path)?;

        fs::write(&path, "keep")?;
        assert!(Server::bind(&path, storage.clone(), Arc::clone(&deleter)).is_err());
        assert_eq!(fs::read_to_string(&path)?, "keep");
        fs::remove_file(&path)?;
        let target = directory.path().join("target");
        symlink(&target, &path)?;
        let error = Server::bind(&path, storage.clone(), Arc::clone(&deleter))
            .err()
            .ok_or("accepted an existing symlink")?;
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        assert_eq!(fs::read_link(&path)?, target);
        assert!(!target.try_exists()?);
        fs::remove_file(&path)?;

        let server = Server::bind(&path, storage.clone(), Arc::clone(&deleter))?;
        fs::remove_file(&path)?;
        fs::write(&path, "replacement")?;
        drop(server);
        assert_eq!(fs::read_to_string(&path)?, "replacement");

        let public = directory.path().join("public");
        fs::create_dir(&public)?;
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755))?;
        assert!(
            Server::bind(
                &public.join("admin.sock"),
                storage.clone(),
                Arc::clone(&deleter)
            )
            .is_err()
        );
        Ok(())
    })
}
