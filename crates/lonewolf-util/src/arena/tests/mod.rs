// SPDX-License-Identifier: Apache-2.0

use super::{ARENA_IDS, ArenaError, IDENTITY_BATCH_SIZE, NEXT_ARENA_ID, take_identity};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn exhausted_identities_never_wrap() {
    let counter = AtomicUsize::new(usize::MAX - 3);
    let range = Cell::new((0, 0));
    for expected in usize::MAX - 3..usize::MAX {
        assert_eq!(take_identity(&counter, &range), Ok(expected));
    }
    assert_eq!(
        take_identity(&counter, &range),
        Err(ArenaError::IdentityExhausted)
    );
    assert_eq!(
        take_identity(&counter, &range),
        Err(ArenaError::IdentityExhausted)
    );
}

#[test]
fn identity_ranges_refill_without_reusing_abandoned_ids() -> Result<(), ArenaError> {
    let counter = AtomicUsize::new(1);
    let first = Cell::new((0, 0));
    let second = Cell::new((0, 0));
    assert_eq!(take_identity(&counter, &first)?, 1);
    for expected in IDENTITY_BATCH_SIZE + 1..=3 * IDENTITY_BATCH_SIZE {
        assert_eq!(take_identity(&counter, &second)?, expected);
    }
    assert_eq!(counter.load(Ordering::Relaxed), 3 * IDENTITY_BATCH_SIZE + 1);
    Ok(())
}

#[test]
fn thread_local_identities_stay_unique_across_refills_and_thread_exit() {
    let mut ids = Vec::new();
    for _ in 0..2 {
        std::thread::scope(|scope| {
            let workers: Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        (0..2 * IDENTITY_BATCH_SIZE + 1)
                            .map(|_| {
                                ARENA_IDS
                                    .with(|range| take_identity(&NEXT_ARENA_ID, range))
                                    .expect("identity")
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            for worker in workers {
                ids.extend(worker.join().expect("worker"));
            }
        });
    }
    ids.sort_unstable();
    assert!(ids[0] > 0);
    assert!(ids.windows(2).all(|pair| pair[0] != pair[1]));
}

mod behavior;
mod chunk_allocator;
