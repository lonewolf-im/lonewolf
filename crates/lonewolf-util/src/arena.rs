// SPDX-License-Identifier: Apache-2.0

use std::alloc::{Layout, alloc, dealloc};
use std::cell::Cell;
use std::fmt;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::num::NonZeroUsize;
use std::ptr::{self, NonNull};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering, fence};

pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024;
pub const DEFAULT_MAX_RESERVED_BYTES: usize = 8 * 1024 * 1024;

static NEXT_ARENA_ID: AtomicUsize = AtomicUsize::new(1);

/// Owns an uninitialized block. Return it through its allocator; dropping it does not free it.
///
/// ```compile_fail
/// use lonewolf_util::arena::Chunk;
///
/// fn duplicate(chunk: Chunk) -> (Chunk, Chunk) {
///     (chunk, chunk)
/// }
/// ```
pub struct Chunk {
    pointer: NonNull<u8>,
    layout: Layout,
}

impl Chunk {
    /// # Safety
    /// The layout must describe the whole writable block and have a nonzero size.
    /// The pointer must satisfy the layout's alignment and remain valid until deallocation.
    /// The caller transfers sole ownership and must keep the originating allocator alive.
    pub unsafe fn from_raw_parts(pointer: NonNull<u8>, layout: Layout) -> Self {
        Self { pointer, layout }
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.pointer.as_ptr()
    }

    pub fn capacity(&self) -> usize {
        self.layout.size()
    }

    /// Includes the full usable capacity and alignment to preserve for deallocation.
    pub fn layout(&self) -> Layout {
        self.layout
    }

    pub fn into_raw_parts(self) -> (NonNull<u8>, Layout) {
        (self.pointer, self.layout)
    }
}

// The descriptor gives no safe access to its memory.
unsafe impl Send for Chunk {}
unsafe impl Sync for Chunk {}

/// Supplies both payload storage and ownership metadata.
///
/// # Safety
/// Successful allocations must be disjoint and writable for their full returned layouts.
/// The returned layout must provide at least the requested size and alignment.
/// Blocks must stay valid until returned while the allocator is alive.
/// Moving the allocator must not invalidate its live blocks.
/// Releasing one block must not invalidate any other live block.
/// Allocation and deallocation must be valid on any thread.
pub unsafe trait ChunkAllocator: Send + Sync + 'static {
    /// Returns uninitialized storage. Zero-sized layouts must return an error.
    /// The allocator chooses any extra capacity. All returned bytes are usable by the caller.
    /// Exhaustion must return an error without waiting for memory to become available.
    fn allocate(&self, layout: Layout) -> Result<Chunk, AllocationError>;

    /// # Safety
    /// The chunk must be a live allocation from this allocator with its returned layout intact.
    /// No references or pending accesses to the block may remain.
    unsafe fn deallocate(&self, chunk: Chunk);
}

/// Returns exactly the requested usable layout from the global heap, with no size-class rounding.
#[derive(Clone, Copy, Debug, Default)]
pub struct GlobalChunkAllocator;

// Global allocations are disjoint and remain valid across threads until freed.
unsafe impl ChunkAllocator for GlobalChunkAllocator {
    fn allocate(&self, layout: Layout) -> Result<Chunk, AllocationError> {
        if layout.size() == 0 {
            return Err(AllocationError::UnsupportedLayout);
        }

        let pointer = NonNull::new(unsafe { alloc(layout) }).ok_or(AllocationError::Exhausted)?;
        Ok(Chunk { pointer, layout })
    }

    unsafe fn deallocate(&self, chunk: Chunk) {
        let (pointer, layout) = chunk.into_raw_parts();
        // The caller guarantees sole ownership and the original allocation layout.
        unsafe { dealloc(pointer.as_ptr(), layout) };
    }
}

// Shared ownership preserves the allocator and its allocation contracts.
unsafe impl<A: ChunkAllocator + ?Sized> ChunkAllocator for Arc<A> {
    fn allocate(&self, layout: Layout) -> Result<Chunk, AllocationError> {
        self.as_ref().allocate(layout)
    }

    unsafe fn deallocate(&self, chunk: Chunk) {
        unsafe { self.as_ref().deallocate(chunk) };
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationError {
    UnsupportedLayout,
    /// Global allocation failure can also indicate an unsupported size or alignment.
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArenaError {
    InvalidConfiguration,
    CapacityOverflow,
    ArenaLimitExceeded,
    IdentityExhausted,
    Allocation(AllocationError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleError {
    WrongArena,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArenaConfig {
    /// Minimum bytes requested for data chunks. Larger values request enough contiguous space.
    /// The arena does not round requests to size classes.
    /// Chunk metadata and alignment reduce the space available for values.
    pub chunk_size: NonZeroUsize,
    /// Maximum total returned capacity, including unused bytes and ownership metadata.
    /// A chunk that exceeds the remaining budget is returned and the allocation fails.
    pub max_reserved_bytes: NonZeroUsize,
}

impl Default for ArenaConfig {
    /// Uses 4 KiB chunk requests and an 8 MiB budget, including metadata and unused capacity.
    fn default() -> Self {
        Self {
            chunk_size: const { NonZeroUsize::new(DEFAULT_CHUNK_SIZE).unwrap() },
            max_reserved_bytes: const { NonZeroUsize::new(DEFAULT_MAX_RESERVED_BYTES).unwrap() },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArenaStats {
    /// Bytes in value layouts, excluding padding between allocations and metadata.
    pub used_bytes: usize,
    /// Total returned capacity, including unused bytes and ownership metadata.
    pub reserved_bytes: usize,
    /// Includes the block that stores ownership metadata.
    pub chunk_count: usize,
}

/// Does not retain storage. A handle stays valid through freezing.
/// Handles cannot be used with another arena, even if the same memory is reused.
pub struct Handle<T: ?Sized + 'static> {
    identity: usize,
    pointer: NonNull<T>,
    _value: PhantomData<fn(*mut T) -> *mut T>,
}

// Access requires a live owner with the same identity and the required borrow.
unsafe impl<T: ?Sized + Send + Sync + 'static> Send for Handle<T> {}
unsafe impl<T: ?Sized + Send + Sync + 'static> Sync for Handle<T> {}

impl<T: ?Sized + 'static> Copy for Handle<T> {}

impl<T: ?Sized + 'static> Clone for Handle<T> {
    fn clone(&self) -> Self {
        *self
    }
}

/// Can move between threads, but cannot be shared between them.
/// Keeps its allocator alive. All storage, including ownership metadata, uses that allocator.
/// Dropping the arena returns every chunk to the allocator, which may cache or free it.
///
/// ```compile_fail
/// use lonewolf_util::arena::Arena;
///
/// fn require_sync<T: Sync>() {}
/// require_sync::<Arena>();
/// ```
pub struct Arena<A: ChunkAllocator = GlobalChunkAllocator> {
    inner: NonNull<ArenaInner<A>>,
    _exclusive: PhantomData<Cell<()>>,
}

// The owner has exclusive access, and all stored values and the allocator can move across threads.
unsafe impl<A: ChunkAllocator> Send for Arena<A> {}

impl Arena<GlobalChunkAllocator> {
    pub fn try_new(config: ArenaConfig) -> Result<Self, ArenaError> {
        Self::try_new_in(config, GlobalChunkAllocator)
    }
}

impl<A: ChunkAllocator> Arena<A> {
    /// Reserves ownership metadata before returning so freezing needs no allocation.
    /// Each arena gets a fresh identity, even when its allocator reuses memory.
    /// The chunk size must fit a layout. It and ownership metadata must each fit the budget.
    pub fn try_new_in(config: ArenaConfig, allocator: A) -> Result<Self, ArenaError> {
        let (layout, header_offset) = Layout::new::<ArenaInner<A>>()
            .extend(Layout::new::<ChunkHeader>())
            .map_err(|_| ArenaError::InvalidConfiguration)?;
        if config.chunk_size > config.max_reserved_bytes
            || layout.size() > config.max_reserved_bytes.get()
            || Layout::from_size_align(config.chunk_size.get(), align_of::<ChunkHeader>()).is_err()
        {
            return Err(ArenaError::InvalidConfiguration);
        }

        let identity = take_identity(&NEXT_ARENA_ID)?;
        let chunk = allocator.allocate(layout).map_err(ArenaError::Allocation)?;
        let capacity = chunk.capacity();
        if capacity > config.max_reserved_bytes.get() {
            unsafe { allocator.deallocate(chunk) };
            return Err(ArenaError::ArenaLimitExceeded);
        }

        let inner = chunk.pointer.cast::<ArenaInner<A>>();
        // The header and payload are outside the control block's reference range.
        let head = unsafe {
            NonNull::new_unchecked(chunk.as_ptr().add(header_offset).cast::<ChunkHeader>())
        };
        unsafe {
            head.as_ptr().write(ChunkHeader {
                chunk,
                next: None,
                used: layout.size(),
            });
            inner.as_ptr().write(ArenaInner {
                allocator,
                owners: AtomicUsize::new(1),
                identity,
                config,
                stats: ArenaStats {
                    used_bytes: 0,
                    reserved_bytes: capacity,
                    chunk_count: 1,
                },
                head,
            });
        }
        Ok(Self {
            inner,
            _exclusive: PhantomData,
        })
    }

    pub fn try_alloc<T: Copy + Send + Sync + 'static>(
        &mut self,
        value: T,
    ) -> Result<Handle<T>, ArenaError> {
        let pointer = self.reserve_slice::<T>(1)?.cast::<T>();
        unsafe { pointer.as_ptr().write(value) };
        Ok(self.handle(pointer))
    }

    pub fn try_alloc_slice_copy<T: Copy + Send + Sync + 'static>(
        &mut self,
        values: &[T],
    ) -> Result<Handle<[T]>, ArenaError> {
        let pointer = self.reserve_slice::<T>(values.len())?;
        unsafe {
            ptr::copy_nonoverlapping(values.as_ptr(), pointer.cast::<T>().as_ptr(), values.len());
        }
        Ok(self.handle(pointer))
    }

    pub fn try_alloc_slice_fill<T: Copy + Send + Sync + 'static>(
        &mut self,
        length: usize,
        value: T,
    ) -> Result<Handle<[T]>, ArenaError> {
        let pointer = self.reserve_slice::<T>(length)?;
        if size_of::<T>() != 0 {
            for index in 0..length {
                unsafe { pointer.cast::<T>().as_ptr().add(index).write(value) };
            }
        }
        Ok(self.handle(pointer))
    }

    pub fn try_alloc_str(&mut self, value: &str) -> Result<Handle<str>, ArenaError> {
        let bytes = self.try_alloc_slice_copy(value.as_bytes())?;
        // The copied bytes preserve valid UTF-8 and the slice length.
        let pointer = unsafe { NonNull::new_unchecked(bytes.pointer.as_ptr() as *mut str) };
        Ok(self.handle(pointer))
    }

    pub fn get<T: ?Sized + Send + Sync + 'static>(
        &self,
        handle: Handle<T>,
    ) -> Result<&T, HandleError> {
        if handle.identity != unsafe { self.inner.as_ref() }.identity {
            return Err(HandleError::WrongArena);
        }
        // Handles are private, typed, and issued only after initialization.
        Ok(unsafe { handle.pointer.as_ref() })
    }

    pub fn get_mut<T: ?Sized + Send + Sync + 'static>(
        &mut self,
        mut handle: Handle<T>,
    ) -> Result<&mut T, HandleError> {
        if handle.identity != unsafe { self.inner.as_ref() }.identity {
            return Err(HandleError::WrongArena);
        }
        // The exclusive owner borrow prevents simultaneous access through copied handles.
        Ok(unsafe { handle.pointer.as_mut() })
    }

    /// Transfers ownership without copying or allocating. Existing handles remain valid.
    pub fn freeze(self) -> SharedArena<A> {
        let arena = ManuallyDrop::new(self);
        SharedArena { inner: arena.inner }
    }

    pub fn stats(&self) -> ArenaStats {
        unsafe { self.inner.as_ref() }.stats
    }

    fn reserve_slice<T>(&mut self, length: usize) -> Result<NonNull<[T]>, ArenaError> {
        let layout = Layout::array::<T>(length).map_err(|_| ArenaError::CapacityOverflow)?;
        let pointer = if layout.size() == 0 {
            NonNull::<T>::dangling()
        } else {
            unsafe { self.inner.as_mut() }.allocate(layout)?.cast::<T>()
        };
        Ok(NonNull::slice_from_raw_parts(pointer, length))
    }

    fn handle<T: ?Sized + 'static>(&self, pointer: NonNull<T>) -> Handle<T> {
        Handle {
            identity: unsafe { self.inner.as_ref() }.identity,
            pointer,
            _value: PhantomData,
        }
    }
}

impl<A: ChunkAllocator> Drop for Arena<A> {
    fn drop(&mut self) {
        unsafe { release_storage(self.inner) };
    }
}

/// Allows concurrent reads. Borrowed views cannot outlive their owning shared handle.
/// The final owner returns every chunk before dropping the allocator.
///
/// ```compile_fail
/// use lonewolf_util::arena::{Handle, HandleError, SharedArena};
///
/// fn escape(arena: SharedArena, handle: Handle<str>) -> Result<&'static str, HandleError> {
///     arena.get(handle)
/// }
/// ```
pub struct SharedArena<A: ChunkAllocator = GlobalChunkAllocator> {
    inner: NonNull<ArenaInner<A>>,
}

// Frozen storage is immutable. All stored values and the allocator support concurrent access.
unsafe impl<A: ChunkAllocator> Send for SharedArena<A> {}
unsafe impl<A: ChunkAllocator> Sync for SharedArena<A> {}

impl<A: ChunkAllocator> SharedArena<A> {
    pub fn get<T: ?Sized + Send + Sync + 'static>(
        &self,
        handle: Handle<T>,
    ) -> Result<&T, HandleError> {
        if handle.identity != unsafe { self.inner.as_ref() }.identity {
            return Err(HandleError::WrongArena);
        }
        Ok(unsafe { handle.pointer.as_ref() })
    }

    pub fn stats(&self) -> ArenaStats {
        unsafe { self.inner.as_ref() }.stats
    }
}

impl<A: ChunkAllocator> Clone for SharedArena<A> {
    /// Shares storage without allocating or copying its contents.
    fn clone(&self) -> Self {
        let owners = &unsafe { self.inner.as_ref() }.owners;
        // Abort before the count can wrap and allow premature deallocation.
        if owners.fetch_add(1, Ordering::Relaxed) >= isize::MAX as usize {
            std::process::abort();
        }
        Self { inner: self.inner }
    }
}

impl<A: ChunkAllocator> Drop for SharedArena<A> {
    fn drop(&mut self) {
        if unsafe { self.inner.as_ref() }
            .owners
            .fetch_sub(1, Ordering::Release)
            == 1
        {
            // All accesses through released owners must finish before freeing storage.
            fence(Ordering::Acquire);
            unsafe { release_storage(self.inner) };
        }
    }
}

struct ArenaInner<A> {
    allocator: A,
    owners: AtomicUsize,
    identity: usize,
    config: ArenaConfig,
    stats: ArenaStats,
    head: NonNull<ChunkHeader>,
}

impl<A: ChunkAllocator> ArenaInner<A> {
    fn allocate(&mut self, layout: Layout) -> Result<NonNull<u8>, ArenaError> {
        let used_bytes = self
            .stats
            .used_bytes
            .checked_add(layout.size())
            .ok_or(ArenaError::CapacityOverflow)?;
        let mut cursor = Some(self.head);
        while let Some(mut pointer) = cursor {
            let header = unsafe { pointer.as_mut() };
            if let Some(pointer) = header.allocate(layout) {
                self.stats.used_bytes = used_bytes;
                return Ok(pointer);
            }
            cursor = header.next;
        }

        let (combined, offset) = Layout::new::<ChunkHeader>()
            .extend(layout)
            .map_err(|_| ArenaError::CapacityOverflow)?;
        let requested = Layout::from_size_align(
            self.config.chunk_size.get().max(combined.size()),
            combined.align(),
        )
        .map_err(|_| ArenaError::CapacityOverflow)?;
        let remaining = self.config.max_reserved_bytes.get() - self.stats.reserved_bytes;
        if requested.size() > remaining {
            return Err(ArenaError::ArenaLimitExceeded);
        }
        let chunk_count = self
            .stats
            .chunk_count
            .checked_add(1)
            .ok_or(ArenaError::CapacityOverflow)?;
        let chunk = self
            .allocator
            .allocate(requested)
            .map_err(ArenaError::Allocation)?;
        let capacity = chunk.capacity();
        if capacity > remaining {
            unsafe { self.allocator.deallocate(chunk) };
            return Err(ArenaError::ArenaLimitExceeded);
        }

        let head = chunk.pointer.cast::<ChunkHeader>();
        let pointer = unsafe { NonNull::new_unchecked(chunk.as_ptr().add(offset)) };
        unsafe {
            head.as_ptr().write(ChunkHeader {
                chunk,
                next: Some(self.head),
                used: combined.size(),
            });
        }
        self.head = head;
        self.stats = ArenaStats {
            used_bytes,
            reserved_bytes: self.stats.reserved_bytes + capacity,
            chunk_count,
        };
        Ok(pointer)
    }
}

struct ChunkHeader {
    chunk: Chunk,
    next: Option<NonNull<ChunkHeader>>,
    used: usize,
}

impl ChunkHeader {
    fn allocate(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        let cursor = unsafe { self.chunk.as_ptr().add(self.used) };
        let offset = self.used.checked_add(cursor.align_offset(layout.align()))?;
        let end = offset.checked_add(layout.size())?;
        if end > self.chunk.capacity() {
            return None;
        }
        self.used = end;
        Some(unsafe { NonNull::new_unchecked(self.chunk.as_ptr().add(offset)) })
    }
}

fn take_identity(counter: &AtomicUsize) -> Result<usize, ArenaError> {
    let mut identity = counter.load(Ordering::Relaxed);
    loop {
        let next = identity
            .checked_add(1)
            .ok_or(ArenaError::IdentityExhausted)?;
        match counter.compare_exchange_weak(identity, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Ok(identity),
            Err(current) => identity = current,
        }
    }
}

unsafe fn release_storage<A: ChunkAllocator>(inner: NonNull<ArenaInner<A>>) {
    // Move the allocator out before returning the block that stores it.
    let allocator = unsafe { ptr::read(&raw const (*inner.as_ptr()).allocator) };
    let mut cursor = Some(unsafe { (*inner.as_ptr()).head });
    while let Some(pointer) = cursor {
        let header = unsafe { pointer.as_ptr().read() };
        cursor = header.next;
        unsafe { allocator.deallocate(header.chunk) };
    }
}

impl fmt::Display for AllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedLayout => "unsupported allocation layout",
            Self::Exhausted => "chunk allocation failed",
        })
    }
}

impl std::error::Error for AllocationError {}

impl fmt::Display for ArenaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => formatter.write_str("invalid arena configuration"),
            Self::CapacityOverflow => formatter.write_str("arena capacity overflow"),
            Self::ArenaLimitExceeded => formatter.write_str("arena memory limit exceeded"),
            Self::IdentityExhausted => formatter.write_str("arena identities exhausted"),
            Self::Allocation(error) => write!(formatter, "arena allocation failed: {error}"),
        }
    }
}

impl std::error::Error for ArenaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Allocation(error) => Some(error),
            _ => None,
        }
    }
}

impl fmt::Display for HandleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongArena => formatter.write_str("handle belongs to another arena"),
        }
    }
}

impl std::error::Error for HandleError {}

#[cfg(test)]
mod tests {
    use super::{ArenaError, take_identity};
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn exhausted_identities_never_wrap() {
        let counter = AtomicUsize::new(usize::MAX - 1);
        assert_eq!(take_identity(&counter), Ok(usize::MAX - 1));
        assert_eq!(take_identity(&counter), Err(ArenaError::IdentityExhausted));
        assert_eq!(take_identity(&counter), Err(ArenaError::IdentityExhausted));
    }
}
