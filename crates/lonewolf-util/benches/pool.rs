// SPDX-License-Identifier: Apache-2.0

use std::alloc::Layout;
use std::hint::black_box;
use std::num::NonZeroUsize;
use std::sync::{Arc, Barrier, mpsc};
use std::time::{Duration, Instant};

use lonewolf_util::arena::{
    Arena, ArenaConfig, ChunkAllocator, ChunkAllocatorHandle, GlobalChunkAllocator, Handle,
    SharedArena,
};
use lonewolf_util::pool::{DEFAULT_POOL_SIZE, PoolConfig, PooledChunkAllocator};

const SAMPLE_COUNT: usize = 9;
const CALIBRATION_ROUNDS: usize = 25_000;
const TARGET_SAMPLE_NS: u128 = 100_000_000;
const MAX_ROUNDS: u128 = 1_000_000;

#[derive(Clone, Copy)]
enum Workload {
    Chunk,
    Arena,
    Fanout,
}

impl Workload {
    fn name(self) -> &'static str {
        match self {
            Self::Chunk => "chunk",
            Self::Arena => "arena",
            Self::Fanout => "fanout",
        }
    }

    fn producers(self, workers: usize) -> usize {
        match self {
            Self::Fanout => workers / 2,
            _ => workers,
        }
    }

    fn run<A: ChunkAllocator + Clone>(
        self,
        allocator: &(impl Fn() -> A + Sync),
        workers: usize,
        rounds: usize,
    ) -> Duration {
        match self {
            Self::Chunk => sample(workers, rounds, allocator, &chunk_cycle),
            Self::Arena => sample(workers, rounds, allocator, &arena_cycle),
            Self::Fanout => fanout_sample(allocator, workers, rounds),
        }
    }
}

fn sample<A>(
    workers: usize,
    rounds: usize,
    allocator: &(impl Fn() -> A + Sync),
    operation: &(impl Fn(&A) + Sync),
) -> Duration {
    let ready = Barrier::new(workers + 1);
    let start = Barrier::new(workers + 1);
    std::thread::scope(|scope| {
        let threads: Vec<_> = (0..workers)
            .map(|_| {
                let ready = &ready;
                let start = &start;
                scope.spawn(move || {
                    let allocator = allocator();
                    for _ in 0..1000 {
                        operation(&allocator);
                    }
                    ready.wait();
                    start.wait();
                    for _ in 0..rounds {
                        operation(&allocator);
                    }
                })
            })
            .collect();
        ready.wait();
        let began = Instant::now();
        start.wait();
        for thread in threads {
            thread.join().expect("worker");
        }
        began.elapsed()
    })
}

type Delivery<A> = (SharedArena<A>, Handle<str>, Handle<[u8]>);

fn build_arena<A: ChunkAllocator + Clone>(allocator: &A) -> Delivery<A> {
    let mut arena = Arena::try_new_in(ArenaConfig::default(), allocator.clone()).expect("arena");
    let text = arena.try_alloc_str("alice@example.com").expect("text");
    let bytes = arena.try_alloc_slice_fill(512, 7_u8).expect("bytes");
    (arena.freeze(), text, bytes)
}

fn read_arena<A: ChunkAllocator>((shared, text, bytes): Delivery<A>) {
    let text = black_box(shared.get(text).expect("text view"));
    let bytes = black_box(shared.get(bytes).expect("byte view"));
    black_box(
        text.bytes()
            .chain(bytes.iter().copied())
            .map(u64::from)
            .sum::<u64>(),
    );
}

fn arena_cycle<A: ChunkAllocator + Clone>(allocator: &A) {
    read_arena(build_arena(allocator));
}

fn fanout_sample<A: ChunkAllocator + Clone>(
    allocator: &(impl Fn() -> A + Sync),
    workers: usize,
    rounds: usize,
) -> Duration {
    let producers = workers / 2;
    let ready = Barrier::new(workers + 1);
    let start = Barrier::new(workers + 1);
    std::thread::scope(|scope| {
        let mut threads = Vec::with_capacity(workers);
        let senders: Vec<_> = (0..producers)
            .map(|_| {
                let ready = &ready;
                let start = &start;
                let (sender, receiver) = mpsc::sync_channel::<Delivery<A>>(16);
                threads.push(scope.spawn(move || {
                    ready.wait();
                    start.wait();
                    for delivery in receiver {
                        read_arena(delivery);
                    }
                }));
                sender
            })
            .collect();
        for producer in 0..producers {
            let ready = &ready;
            let start = &start;
            let first = senders[producer].clone();
            let second = senders[(producer + 1) % producers].clone();
            threads.push(scope.spawn(move || {
                let allocator = allocator();
                for _ in 0..1000 {
                    arena_cycle(&allocator);
                }
                ready.wait();
                start.wait();
                for _ in 0..rounds {
                    let delivery = build_arena(&allocator);
                    assert!(first.send(delivery.clone()).is_ok());
                    assert!(second.send(delivery).is_ok());
                }
            }));
        }
        drop(senders);
        ready.wait();
        let began = Instant::now();
        start.wait();
        for thread in threads {
            thread.join().expect("worker");
        }
        began.elapsed()
    })
}

fn chunk_cycle<A: ChunkAllocator>(allocator: &A) {
    let chunk = allocator
        .allocate(Layout::from_size_align(4096, 8).expect("layout"))
        .expect("chunk");
    // The allocation is exclusive until it is returned.
    unsafe {
        chunk.as_ptr().write_bytes(7, 512);
        black_box(std::slice::from_raw_parts(chunk.as_ptr(), 512));
        allocator.deallocate(chunk);
    }
}

fn quartiles(mut samples: [Duration; SAMPLE_COUNT], operations: usize) -> [f64; 3] {
    samples.sort_unstable();
    [samples[2], samples[4], samples[6]].map(|time| time.as_nanos() as f64 / operations as f64)
}

fn compare(workload: Workload, workers: usize, pools: &[Arc<PooledChunkAllocator>]) {
    let run = |backend: usize, rounds| match backend.checked_sub(1) {
        None => workload.run(&|| GlobalChunkAllocator, workers, rounds),
        Some(index) => workload.run(
            &|| ChunkAllocatorHandle::new(pools[index].clone()),
            workers,
            rounds,
        ),
    };
    let backend_count = pools.len() + 1;
    let fastest = (0..backend_count)
        .map(|backend| run(backend, CALIBRATION_ROUNDS).as_nanos())
        .min()
        .expect("global backend")
        .max(1);
    let rounds = (TARGET_SAMPLE_NS * CALIBRATION_ROUNDS as u128 / fastest)
        .clamp(CALIBRATION_ROUNDS as u128, MAX_ROUNDS) as usize;
    let operations = workload.producers(workers) * rounds;
    let mut samples: [_; SAMPLE_COUNT] =
        std::array::from_fn(|_| vec![Duration::ZERO; backend_count]);
    let name = workload.name();
    for (index, sample) in samples.iter_mut().enumerate() {
        for offset in 0..backend_count {
            let backend = (index + offset) % backend_count;
            let pool = backend.checked_sub(1).map(|index| &pools[index]);
            let allocator = if pool.is_some() { "pool" } else { "global" };
            let shards = pool.map_or(0, |pool| pool.config().shards_per_bucket.get());
            let before = pool.map_or(0, |pool| pool.stats().heap_allocation_count);
            let elapsed = run(backend, rounds);
            sample[backend] = elapsed;
            let fallbacks = pool.map_or(0, |pool| pool.stats().heap_allocation_count - before);
            println!(
                "sample workload={name} workers={workers} index={index} rounds={rounds} operations={operations} allocator={allocator} shards={shards} elapsed_ns={} pool_heap_fallbacks={fallbacks}",
                elapsed.as_nanos(),
            );
        }
    }
    let global_median = quartiles(std::array::from_fn(|index| samples[index][0]), operations)[1];
    for (backend, pool) in std::iter::once(None)
        .chain(pools.iter().map(Some))
        .enumerate()
    {
        let [p25, median, p75] = quartiles(
            std::array::from_fn(|index| samples[index][backend]),
            operations,
        );
        let allocator = if pool.is_some() { "pool" } else { "global" };
        let shards = pool.map_or(0, |pool| pool.config().shards_per_bucket.get());
        println!(
            "result workload={name} workers={workers} allocator={allocator} shards={shards} median_ns={median:.3} p25_ns={p25:.3} p75_ns={p75:.3} speedup={:.3}",
            global_median / median,
        );
    }
}

fn profile_count(
    name: &str,
    default: NonZeroUsize,
) -> Result<NonZeroUsize, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error.into()),
    }
}

fn profile(backend: &str) -> Result<(), Box<dyn std::error::Error>> {
    let defaults = PoolConfig::default();
    let workers = profile_count("LONEWOLF_BENCH_WORKERS", defaults.shards_per_bucket)?.get();
    let rounds = profile_count(
        "LONEWOLF_BENCH_ROUNDS",
        const { NonZeroUsize::new(2_000_000).unwrap() },
    )?
    .get();
    let workload = match std::env::var("LONEWOLF_BENCH_WORKLOAD").as_deref() {
        Ok("chunk") => Workload::Chunk,
        Ok("arena") | Err(std::env::VarError::NotPresent) => Workload::Arena,
        Ok("fanout") if workers.is_multiple_of(2) => Workload::Fanout,
        _ => return Err("expected chunk, arena, or fanout with an even worker count".into()),
    };
    let (elapsed, shards) = match backend {
        "global" => (workload.run(&|| GlobalChunkAllocator, workers, rounds), 0),
        "global-shared" | "global-handle" => {
            let allocator = Arc::new(GlobalChunkAllocator);
            let elapsed = if backend == "global-shared" {
                workload.run(&|| allocator.clone(), workers, rounds)
            } else {
                workload.run(
                    &|| ChunkAllocatorHandle::new(allocator.clone()),
                    workers,
                    rounds,
                )
            };
            (elapsed, 0)
        }
        "pool" | "pool-shared" => {
            let pool = Arc::new(PooledChunkAllocator::try_new(PoolConfig {
                total_bytes: profile_count("LONEWOLF_BENCH_POOL_BYTES", defaults.total_bytes)?,
                shards_per_bucket: profile_count(
                    "LONEWOLF_BENCH_POOL_SHARDS",
                    defaults.shards_per_bucket,
                )?,
            })?);
            let elapsed = if backend == "pool-shared" {
                workload.run(&|| pool.clone(), workers, rounds)
            } else {
                workload.run(&|| ChunkAllocatorHandle::new(pool.clone()), workers, rounds)
            };
            println!("heap_fallbacks={}", pool.stats().heap_allocation_count);
            (elapsed, pool.config().shards_per_bucket.get())
        }
        _ => {
            return Err(
                "expected global, global-shared, global-handle, pool, or pool-shared".into(),
            );
        }
    };
    println!(
        "profile backend={backend} workload={} workers={workers} shards={shards} rounds={rounds} ns_per_operation={:.3}",
        workload.name(),
        elapsed.as_nanos() as f64 / (workload.producers(workers) * rounds) as f64,
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match std::env::var("LONEWOLF_BENCH_PROFILE") {
        Ok(backend) => return profile(&backend),
        Err(std::env::VarError::NotPresent) => {}
        Err(error) => return Err(error.into()),
    }
    let benchmarking = std::env::args().any(|arg| arg == "--bench");
    let bytes = std::env::var("LONEWOLF_BENCH_POOL_BYTES")
        .ok()
        .map(|v| v.parse::<usize>())
        .transpose()?
        .unwrap_or(if benchmarking {
            DEFAULT_POOL_SIZE
        } else {
            lonewolf_util::pool::MIN_POOL_SIZE
        });
    let total_bytes = NonZeroUsize::new(bytes).ok_or("pool size")?;
    let requested_shards = match std::env::var("LONEWOLF_BENCH_POOL_SHARDS") {
        Ok(value) => value
            .split(',')
            .map(str::parse::<NonZeroUsize>)
            .collect::<Result<Vec<_>, _>>()?,
        Err(std::env::VarError::NotPresent) => vec![PoolConfig::default().shards_per_bucket],
        Err(error) => return Err(error.into()),
    };
    let mut pools = Vec::<Arc<PooledChunkAllocator>>::with_capacity(requested_shards.len());
    for shards_per_bucket in requested_shards {
        let pool = PooledChunkAllocator::try_new(PoolConfig {
            total_bytes,
            shards_per_bucket,
        })?;
        if pools
            .iter()
            .any(|existing| existing.config() == pool.config())
        {
            return Err("duplicate effective shard count after CPU cap".into());
        }
        pools.push(Arc::new(pool));
    }
    if !benchmarking {
        for workload in [Workload::Chunk, Workload::Arena, Workload::Fanout] {
            workload.run(&|| GlobalChunkAllocator, 2, 1);
            for pool in &pools {
                workload.run(&|| ChunkAllocatorHandle::new(pool.clone()), 2, 1);
            }
        }
        Workload::Fanout.run(&|| ChunkAllocatorHandle::new(pools[0].clone()), 4, 1);
        return Ok(());
    }
    println!(
        "pool_bytes={bytes} samples={SAMPLE_COUNT} calibration_rounds={CALIBRATION_ROUNDS} target_sample_ns={TARGET_SAMPLE_NS} max_rounds={MAX_ROUNDS} payload_bytes=512"
    );
    println!("fanout_producer_fraction=1/2 deliveries_per_arena=2 mailbox_capacity=16");
    println!("global_ownership=value pool_ownership=producer_handle");
    for pool in &pools {
        println!(
            "pool_shards={} bucket_shards={:?}",
            pool.config().shards_per_bucket,
            pool.stats().buckets.map(|bucket| bucket.shard_count),
        );
    }
    for workers in [2, 4, 8, 16, 24] {
        for workload in [Workload::Chunk, Workload::Arena, Workload::Fanout] {
            compare(workload, workers, &pools);
        }
    }
    for pool in &pools {
        println!(
            "pool_shards={} heap_fallbacks={}",
            pool.config().shards_per_bucket,
            pool.stats().heap_allocation_count,
        );
    }
    Ok(())
}
