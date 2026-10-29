// SPDX-License-Identifier: Apache-2.0

use super::*;
use parking_lot::Condvar as PlCondvar;
use std::collections::HashSet;
use std::sync::Condvar;
use std::sync::atomic::{AtomicUsize, Ordering};
use ureq::unversioned::transport::time::Duration as UreqDuration;

fn timeout(duration: Duration) -> NextTimeout {
    NextTimeout {
        after: UreqDuration::Exact(duration),
        reason: ureq::Timeout::Resolve,
        ..NextTimeout::default()
    }
}

#[test]
fn stuck_workers_keep_two_threads_and_two_queued_jobs() {
    let gate = Arc::new((std::sync::Mutex::new(false), Condvar::new()));
    let (entered, started) = mpsc::channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let lookup_gate = gate.clone();
    let lookup_calls = calls.clone();
    let pool = Pool::new(Arc::new(move |_, port| {
        lookup_calls.fetch_add(1, Ordering::SeqCst);
        entered.send(thread::current().id()).unwrap();
        let (lock, changed) = &*lookup_gate;
        let mut released = lock.lock().unwrap();
        while !*released {
            released = changed.wait(released).unwrap();
        }
        Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
    }))
    .unwrap();
    let config = ureq::config::Config::default();
    let mut workers = HashSet::new();
    for _ in 0..2 {
        assert!(matches!(
            resolve_with(&pool, "example.com", 443, &config, timeout(Duration::ZERO)),
            Err(ureq::Error::Timeout(_))
        ));
        workers.insert(started.recv_timeout(Duration::from_secs(5)).unwrap());
    }
    for _ in 0..2 {
        assert!(matches!(
            resolve_with(&pool, "example.com", 443, &config, timeout(Duration::ZERO)),
            Err(ureq::Error::Timeout(_))
        ));
    }
    for _ in 0..100 {
        assert!(
            matches!(resolve_with(&pool, "example.com", 443, &config, timeout(Duration::ZERO)), Err(ureq::Error::Io(error)) if error.kind() == io::ErrorKind::WouldBlock)
        );
    }
    assert_eq!(workers.len(), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let (lock, changed) = &*gate;
    *lock.lock().unwrap() = true;
    changed.notify_all();
    for _ in 0..2 {
        assert!(workers.contains(&started.recv_timeout(Duration::from_secs(5)).unwrap()));
    }
}

#[test]
fn resolver_bounds_addresses_and_propagates_errors() {
    let pool = Pool::new(Arc::new(|_, port| {
        Ok((1..=40)
            .map(|n| SocketAddr::from(([127, 0, 0, n], port)))
            .collect())
    }))
    .unwrap();
    let config = ureq::config::Config::default();
    assert_eq!(
        resolve_with(
            &pool,
            "example.com",
            443,
            &config,
            timeout(Duration::from_secs(5))
        )
        .unwrap()
        .len(),
        16
    );
    let failed = Pool::new(Arc::new(|_, _| Err(io::Error::other("private DNS data")))).unwrap();
    assert!(matches!(
        resolve_with(
            &failed,
            "example.com",
            443,
            &config,
            timeout(Duration::from_secs(5))
        ),
        Err(ureq::Error::HostNotFound)
    ));
    let empty = Pool::new(Arc::new(|_, _| Ok(vec![]))).unwrap();
    assert!(matches!(
        resolve_with(
            &empty,
            "example.com",
            443,
            &config,
            timeout(Duration::from_secs(5))
        ),
        Err(ureq::Error::HostNotFound)
    ));
}

#[test]
fn numeric_addresses_bypass_dns_and_authorities_are_validated() {
    let config = ureq::config::Config::default();
    for (uri, expected) in [
        ("https://127.0.0.1:8443/", "127.0.0.1:8443"),
        ("https://[::1]/", "[::1]:443"),
    ] {
        let addresses = BoundedResolver
            .resolve(&uri.parse().unwrap(), &config, timeout(Duration::ZERO))
            .unwrap();
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0], expected.parse::<SocketAddr>().unwrap());
    }
    for uri in [
        "http://example.com/",
        "https://user@example.com/",
        "https://example.com:0/",
        "https://bad_host/",
    ] {
        assert!(
            BoundedResolver
                .resolve(&uri.parse().unwrap(), &config, timeout(Duration::ZERO))
                .is_err()
        );
    }
}

#[test]
fn process_pool_survives_transport_recreation() {
    let config = ureq::config::Config::default();
    let uri = "https://localhost/".parse().unwrap();
    BoundedResolver
        .resolve(&uri, &config, timeout(Duration::from_secs(5)))
        .expect("system resolver must resolve localhost for the pool ownership test");
    let first = std::ptr::from_ref(POOL.get().unwrap().as_ref().unwrap());
    for _ in 0..8 {
        let client = futures_executor::block_on(crate::AcmeHttpClient::new(
            crate::TransportOptions::default(),
        ))
        .unwrap();
        drop(client.for_attempt());
        drop(client);
        BoundedResolver
            .resolve(&uri, &config, timeout(Duration::from_secs(5)))
            .expect("system resolver must resolve localhost after transport recreation");
        assert_eq!(
            first,
            std::ptr::from_ref(POOL.get().unwrap().as_ref().unwrap())
        );
    }
}

#[test]
fn entered_dns_lookup_times_out_while_workers_remain_owned_then_cleans_up() {
    struct Release(Arc<(PlMutex<bool>, PlCondvar)>);
    impl Drop for Release {
        fn drop(&mut self) {
            *self.0.0.lock() = true;
            self.0.1.notify_all();
        }
    }
    struct WorkersGone(mpsc::Sender<()>);
    impl Drop for WorkersGone {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }
    let gate = Arc::new((PlMutex::new(false), PlCondvar::new()));
    let release = Release(gate.clone());
    let (entered, entries) = mpsc::channel();
    let (finished, completions) = mpsc::channel();
    let (gone, cleaned) = mpsc::channel();
    let ownership = WorkersGone(gone);
    let pool = Arc::new(
        Pool::new(Arc::new(move |_, port| {
            let _retained = &ownership;
            entered.send(thread::current().id()).unwrap();
            let mut open = gate.0.lock();
            gate.1.wait_while(&mut open, |open| !*open);
            finished.send(()).unwrap();
            Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
        }))
        .unwrap(),
    );
    let (returned, results) = mpsc::channel();
    let mut callers = Vec::new();
    for _ in 0..2 {
        let pool = pool.clone();
        let returned = returned.clone();
        callers.push(thread::spawn(move || {
            let result = resolve_with(
                &pool,
                "example.test",
                443,
                &ureq::config::Config::default(),
                timeout(Duration::from_secs(1)),
            );
            returned
                .send(matches!(result, Err(ureq::Error::Timeout(_))))
                .unwrap();
        }));
    }
    let first = entries.recv_timeout(Duration::from_secs(5)).unwrap();
    let second = entries.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_ne!(first, second);
    assert!(results.try_recv().is_err());
    for _ in 0..2 {
        assert!(results.recv_timeout(Duration::from_secs(5)).unwrap());
    }
    for caller in callers {
        caller.join().unwrap();
    }
    assert!(completions.try_recv().is_err());
    drop(pool);
    assert!(cleaned.try_recv().is_err());
    drop(release);
    for _ in 0..2 {
        completions.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    cleaned.recv_timeout(Duration::from_secs(5)).unwrap();
}
