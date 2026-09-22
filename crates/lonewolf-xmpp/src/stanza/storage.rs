// SPDX-License-Identifier: Apache-2.0

//! Copies shared slices before mutation to preserve published XML trees.

use lonewolf_util::arena::{Arena, ArenaError, ArenaRead, ChunkAllocator, Handle, HandleError};

use super::BuildError;

#[derive(Clone, Copy)]
pub(super) struct StoredSlice<T: Copy + Send + Sync + 'static> {
    values: Option<Handle<[T]>>,
    len: usize,
}

impl<T: Copy + Send + Sync + 'static> StoredSlice<T> {
    pub(super) fn get<'a>(&self, arena: &'a impl ArenaRead) -> Result<&'a [T], HandleError> {
        match self.values {
            Some(values) => Ok(&arena.get(values)?[..self.len]),
            None => Ok(&[]),
        }
    }
}

pub(super) struct SliceBuilder<T: Copy + Send + Sync + 'static> {
    slice: StoredSlice<T>,
    writable: bool,
}

impl<T: Copy + Send + Sync + 'static> SliceBuilder<T> {
    pub(super) fn new() -> Self {
        Self {
            slice: StoredSlice {
                values: None,
                len: 0,
            },
            writable: true,
        }
    }

    pub(super) fn from_slice(slice: StoredSlice<T>) -> Self {
        Self {
            slice,
            writable: false,
        }
    }

    pub(super) fn as_slice<'a>(&self, arena: &'a impl ArenaRead) -> Result<&'a [T], HandleError> {
        self.slice.get(arena)
    }

    pub(super) fn push<A: ChunkAllocator>(
        &mut self,
        value: T,
        arena: &mut Arena<A>,
    ) -> Result<(), BuildError> {
        let len = self
            .slice
            .len
            .checked_add(1)
            .ok_or(ArenaError::CapacityOverflow)?;
        let values = self.prepare(len, value, arena)?;
        arena.get_mut(values)?[self.slice.len] = value;
        self.slice.len = len;
        Ok(())
    }

    pub(super) fn set<A: ChunkAllocator>(
        &mut self,
        index: usize,
        value: T,
        arena: &mut Arena<A>,
    ) -> Result<(), BuildError> {
        let values = self.prepare(self.slice.len, value, arena)?;
        arena.get_mut(values)?[index] = value;
        Ok(())
    }

    pub(super) fn remove<A: ChunkAllocator>(
        &mut self,
        index: usize,
        arena: &mut Arena<A>,
    ) -> Result<(), BuildError> {
        let value = self.as_slice(arena)?[index];
        let values = self.prepare(self.slice.len, value, arena)?;
        arena
            .get_mut(values)?
            .copy_within(index + 1..self.slice.len, index);
        self.slice.len -= 1;
        Ok(())
    }

    pub(super) fn finish(self) -> StoredSlice<T> {
        self.slice
    }

    pub(super) fn retain<A: ChunkAllocator>(
        &mut self,
        arena: &mut Arena<A>,
        mut keep: impl FnMut(T, &Arena<A>) -> Result<bool, HandleError>,
    ) -> Result<(), BuildError> {
        let mut retained = 0;
        for index in 0..self.slice.len {
            let value = self.as_slice(arena)?[index];
            if keep(value, arena)? {
                if retained != index {
                    let values = self.prepare(self.slice.len, value, arena)?;
                    arena.get_mut(values)?[retained] = value;
                }
                retained += 1;
            }
        }
        self.slice.len = retained;
        Ok(())
    }

    fn prepare<A: ChunkAllocator>(
        &mut self,
        len: usize,
        fill: T,
        arena: &mut Arena<A>,
    ) -> Result<Handle<[T]>, BuildError> {
        if let Some(values) = self.slice.values
            && self.writable
            && arena.get(values)?.len() >= len
        {
            return Ok(values);
        }
        let capacity = if len > self.slice.len {
            self.slice
                .len
                .checked_mul(2)
                .ok_or(ArenaError::CapacityOverflow)?
                .max(len)
                .max(4)
        } else {
            len
        };
        // Handles expose the full capacity, so unused slots must also hold valid values.
        let values = arena.try_alloc_slice_fill(capacity, fill)?;
        for index in 0..self.slice.len {
            let value = self.as_slice(arena)?[index];
            arena.get_mut(values)?[index] = value;
        }
        self.slice.values = Some(values);
        self.writable = true;
        Ok(values)
    }
}
