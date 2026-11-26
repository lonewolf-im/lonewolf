// SPDX-License-Identifier: Apache-2.0

use proptest::prelude::*;

use crate::arena::{Arena, ArenaConfig, ArenaError, ArenaRead, Handle, HandleError};

const BUDGET: usize = 1024;
type Allocations = Vec<(Handle<[u8]>, Vec<u8>)>;

#[derive(Debug)]
enum Operation {
    Allocate(usize, u8),
    Overwrite(u8, u8),
}

fn operation() -> impl Strategy<Value = (bool, Operation)> {
    let length = prop_oneof![4 => 1..=384usize, 1 => Just(BUDGET + 1)];
    let op = prop_oneof![
        (length, any::<u8>()).prop_map(|(len, byte)| Operation::Allocate(len, byte)),
        (any::<u8>(), any::<u8>()).prop_map(|(index, byte)| Operation::Overwrite(index, byte)),
    ];
    (any::<bool>(), op)
}

fn check_handles(arenas: &[impl ArenaRead; 2], model: &[Allocations; 2]) {
    for (owner, allocations) in model.iter().enumerate() {
        for (handle, expected) in allocations {
            assert_eq!(arenas[owner].get(*handle), Ok(expected.as_slice()));
            assert_eq!(arenas[1 - owner].get(*handle), Err(HandleError::WrongArena));
        }
    }
}

proptest! {
    #[test]
    #[ignore = "runs in the XMPP property workflow"]
    fn property_arena_handles(steps in prop::collection::vec(operation(), 1..=32)) {
        let config = ArenaConfig {
            chunk_size: 256.try_into()?,
            max_reserved_bytes: BUDGET.try_into()?,
        };
        let mut arenas = [Arena::try_new(config)?, Arena::try_new(config)?];
        let mut model: [Allocations; 2] = [Vec::new(), Vec::new()];
        for (arena, recorded) in arenas.iter_mut().zip(&mut model) {
            recorded.push((arena.try_alloc_slice_copy(&[0])?, vec![0]));
        }
        for (side, op) in steps {
            let owner = usize::from(side);
            let arena = &mut arenas[owner];
            let recorded = &mut model[owner];
            match op {
                Operation::Allocate(len, byte) => {
                    let before = arena.stats();
                    match arena.try_alloc_slice_fill(len, byte) {
                        Ok(handle) => {
                            prop_assert!(len <= BUDGET);
                            recorded.push((handle, vec![byte; len]));
                        }
                        Err(error) => {
                            prop_assert_eq!(error, ArenaError::ArenaLimitExceeded);
                            prop_assert_eq!(arena.stats(), before);
                        }
                    }
                    prop_assert!(arena.stats().reserved_bytes <= BUDGET);
                }
                Operation::Overwrite(index, byte) => {
                    let slot = usize::from(index) % recorded.len();
                    let (handle, expected) = &mut recorded[slot];
                    arena.get_mut(*handle)?.fill(byte);
                    expected.fill(byte);
                }
            }
            check_handles(&arenas, &model);
        }
        check_handles(&arenas.map(Arena::freeze), &model);
    }
}
