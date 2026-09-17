// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::{Arena, ArenaPool, Handle, HandleError, SharedArena};

fn assert_send<T: Send>() {}

fn assert_send_sync_static<T: Send + Sync + 'static>() {}

fn assert_copy<T: Copy>() {}

#[test]
fn owners_support_cross_thread_handoff() {
    assert_send::<Arena>();
    assert_send_sync_static::<ArenaPool>();
    assert_send_sync_static::<SharedArena>();
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

    let _check = |arena: SharedArena, handle: Handle<str>| {
        assert_future(async move {
            let text = arena.get(handle)?;
            std::future::ready(()).await;
            Ok(text.len())
        });
    };
}
