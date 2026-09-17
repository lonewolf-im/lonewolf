// SPDX-License-Identifier: Apache-2.0

use std::hint::black_box;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lonewolf_util::arena::{Arena, ArenaConfig, ChunkAllocator, GlobalChunkAllocator};
use lonewolf_util::pool::{MIN_POOL_SIZE, PoolConfig, PooledChunkAllocator};

fn sample<A: ChunkAllocator>(allocator: &Arc<A>, workers: usize, rounds: usize) -> Duration {
    let start = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                for _ in 0..rounds {
                    let mut arena = Arena::try_new_in(ArenaConfig::default(), allocator.clone())
                        .expect("arena");
                    let text = arena.try_alloc_str("alice@example.com").expect("text");
                    let data = arena.try_alloc_slice_fill(512, 7_u8).expect("data");
                    let shared = arena.freeze();
                    black_box(shared.get(text).expect("text view"));
                    black_box(shared.get(data).expect("data view"));
                    drop(shared);
                }
            });
        }
    });
    start.elapsed()
}

fn report<A: ChunkAllocator>(name: &str, allocator: &Arc<A>, workers: usize) {
    sample(allocator, workers, 1000);
    let mut times = std::array::from_fn::<_, 5, _>(|_| sample(allocator, workers, 100_000));
    times.sort();
    println!(
        "{name} workers={workers} median_ns_per_arena={:.1}",
        times[2].as_nanos() as f64 / (workers * 100_000) as f64
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let global = Arc::new(GlobalChunkAllocator);
    let pool = Arc::new(PooledChunkAllocator::try_new(PoolConfig {
        total_bytes: NonZeroUsize::new(MIN_POOL_SIZE).ok_or("pool size")?,
    })?);
    if !std::env::args().any(|argument| argument == "--bench") {
        sample(&global, 1, 1);
        sample(&pool, 1, 1);
        return Ok(());
    }
    println!("pool_bytes={MIN_POOL_SIZE} payload_bytes=512 samples=5 arenas_per_worker=100000");
    for workers in [1, 4] {
        report("global", &global, workers);
        report("pool", &pool, workers);
    }
    println!("heap_fallbacks={}", pool.stats().heap_allocation_count);
    Ok(())
}
