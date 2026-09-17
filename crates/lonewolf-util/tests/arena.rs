// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_util::arena::{
    Arena, ArenaConfig, ArenaError, Chunk, ChunkAllocator, Handle, HandleError, SharedArena,
};

fn assert_send<T: Send>() {}

fn assert_send_sync_static<T: Send + Sync + 'static>() {}

fn assert_copy<T: Copy>() {}

#[test]
fn owners_support_cross_thread_handoff() {
    assert_send::<Arena>();
    assert_send_sync_static::<Chunk>();
    assert_send_sync_static::<SharedArena>();
}

#[test]
fn arenas_accept_a_shared_allocator() {
    fn assert_allocator<A: ChunkAllocator>() {}

    type SharedAllocator = Arc<dyn ChunkAllocator>;

    assert_allocator::<SharedAllocator>();
    assert_send::<Arena<SharedAllocator>>();
    assert_send_sync_static::<SharedArena<SharedAllocator>>();

    let _: fn(ArenaConfig, SharedAllocator) -> Result<Arena<SharedAllocator>, ArenaError> =
        Arena::try_new_in;
}

#[test]
fn allocation_handles_are_copyable_across_threads() {
    assert_copy::<Handle<u64>>();
    assert_copy::<Handle<str>>();
    assert_copy::<Handle<[u8]>>();
    assert_send_sync_static::<Handle<u64>>();
    assert_send_sync_static::<Handle<str>>();
    assert_send_sync_static::<Handle<[u8]>>();
}

#[test]
fn shared_views_can_cross_await_in_a_send_future() {
    fn assert_future<F: Future<Output = Result<usize, HandleError>> + Send + 'static>(_future: F) {}

    let _check = |arena: SharedArena<Arc<dyn ChunkAllocator>>, handle: Handle<str>| {
        assert_future(async move {
            let text = arena.get(handle)?;
            std::future::ready(()).await;
            Ok(text.len())
        });
    };
}
