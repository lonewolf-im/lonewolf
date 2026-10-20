// SPDX-License-Identifier: Apache-2.0

use crate::error::{BenchError, BenchResult, ErrorCode};
use std::{num::NonZeroUsize, sync::Arc};
use tokio::sync::Semaphore;

/// Runs CPU-bound jobs on the blocking pool with a fixed concurrency limit.
#[derive(Clone)]
pub struct CpuPool {
    permits: Arc<Semaphore>,
    size: u32,
}

impl CpuPool {
    pub fn new(size: NonZeroUsize) -> Self {
        let size = u32::try_from(size.get())
            .unwrap_or(u32::MAX)
            .min(Semaphore::MAX_PERMITS as u32);
        Self {
            permits: Arc::new(Semaphore::new(size as usize)),
            size,
        }
    }

    pub fn per_core() -> Self {
        Self::new(std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN))
    }

    pub fn size(&self) -> usize {
        self.size as usize
    }

    /// A submitted job keeps its permit until it finishes, even if the caller stops waiting.
    pub async fn run<T: Send + 'static>(
        &self,
        operation: impl FnOnce() -> BenchResult<T> + Send + 'static,
    ) -> BenchResult<T> {
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| failure())?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            operation()
        })
        .await
        .map_err(|_| failure())?
    }

    /// Waits until every job submitted before this call has finished.
    pub async fn barrier(&self) {
        let _ = self.permits.acquire_many(self.size).await;
    }
}

fn failure() -> BenchError {
    BenchError::new(ErrorCode::Runtime, "cpu_job_failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::Future,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn jobs_run_up_to_the_pool_size_and_barrier_waits_for_all() -> BenchResult<()> {
        let pool = CpuPool::new(const { NonZeroUsize::new(2).unwrap() });
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicUsize::new(0));
        let mut jobs = Vec::new();
        for _ in 0..4 {
            let pool = pool.clone();
            let (running, peak, finished) = (running.clone(), peak.clone(), finished.clone());
            let mut job = Box::pin(async move {
                pool.run(move || {
                    let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(50));
                    running.fetch_sub(1, Ordering::SeqCst);
                    finished.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
                .await
            });
            // One poll admits the job or queues it ahead of the barrier.
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(job.as_mut().poll(cx)))
                    .await
                    .is_pending()
            );
            jobs.push(tokio::spawn(job));
        }
        pool.barrier().await;
        assert_eq!(finished.load(Ordering::SeqCst), 4);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        for job in jobs {
            job.await.map_err(|_| failure())??;
        }
        Ok(())
    }

    #[tokio::test]
    async fn panicking_job_reports_an_error_and_releases_its_permit() {
        let pool = CpuPool::new(NonZeroUsize::MIN);
        assert!(
            pool.run(|| -> BenchResult<()> { panic!("job") })
                .await
                .is_err()
        );
        assert!(pool.run(|| Ok(1)).await.is_ok_and(|value| value == 1));
    }
}
