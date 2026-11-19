// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;
use std::ops::Range;

/// Stored records from one bounded read, in read order.
pub struct StoredPage<M> {
    entries: Vec<(M, Range<usize>)>,
    bytes: Vec<u8>,
    read: usize,
    resume: Option<M>,
    complete: bool,
}

impl<M> StoredPage<M> {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            bytes: Vec::new(),
            read: 0,
            resume: None,
            complete: true,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Counts records copied before any filtering.
    pub fn read_len(&self) -> usize {
        self.read
    }

    /// Counts stanza bytes copied before any filtering.
    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&M, &[u8])> + '_ {
        self.entries
            .iter()
            .map(|(meta, range)| (meta, &self.bytes[range.clone()]))
    }

    /// Returns the last record read, even if filtering removed it.
    pub fn resume_after(&self) -> Option<&M> {
        self.resume.as_ref()
    }

    /// The read reached the end of its range.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Removes entries without changing read counts, the cursor, or completion.
    pub fn retain(&mut self, mut keep: impl FnMut(&M, &[u8]) -> bool) {
        self.entries
            .retain(|(meta, range)| keep(meta, &self.bytes[range.clone()]));
    }

    /// Storage implementations fill a page with these methods.
    pub fn start_read(&mut self) {
        self.entries.clear();
        self.bytes.clear();
        self.read = 0;
        self.resume = None;
        self.complete = false;
    }

    /// Storage implementations fill a page with these methods.
    pub fn admits(&self, record_len: usize, max_bytes: NonZeroUsize) -> bool {
        self.entries.is_empty() || self.bytes.len().saturating_add(record_len) <= max_bytes.get()
    }

    /// Storage implementations fill a page with these methods.
    pub fn push(&mut self, meta: M, record: &[u8]) {
        let start = self.bytes.len();
        self.bytes.extend_from_slice(record);
        self.entries.push((meta, start..self.bytes.len()));
    }

    /// Storage implementations fill a page with these methods.
    pub fn finish_read(&mut self, complete: bool)
    where
        M: Clone,
    {
        self.read = self.entries.len();
        self.resume = self.entries.last().map(|(meta, _)| meta.clone());
        self.complete = complete;
    }
}

impl<M> Default for StoredPage<M> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_pages_are_empty_and_complete() {
        let page = StoredPage::<u64>::new();
        assert!(page.is_empty());
        assert!(page.is_complete());
        assert_eq!(page.read_len(), 0);
        assert_eq!(page.byte_len(), 0);
        assert_eq!(page.resume_after(), None);
    }

    #[test]
    fn the_first_record_is_admitted_even_above_the_limit() {
        let mut page = StoredPage::new();
        assert!(page.admits(2, NonZeroUsize::MIN));
        page.push(1, b"ab");
        assert!(!page.admits(0, NonZeroUsize::MIN));
    }

    #[test]
    fn records_are_admitted_while_the_total_stays_within_the_limit() {
        let limit = NonZeroUsize::new(20).unwrap();
        let mut page = StoredPage::new();
        for index in 1..=2 {
            assert!(page.admits(10, limit));
            page.push(index, &[0; 10]);
        }
        assert!(!page.admits(1, limit));
    }

    #[test]
    fn retain_keeps_the_cursor_counts_and_completion() {
        let mut page = StoredPage::new();
        page.push(1, b"ab");
        page.push(2, b"cde");
        page.finish_read(false);
        page.retain(|meta, bytes| *meta == 1 && bytes == b"ab");

        assert_eq!(page.len(), 1);
        assert_eq!(page.iter().next(), Some((&1, &b"ab"[..])));
        assert_eq!(page.read_len(), 2);
        assert_eq!(page.byte_len(), 5);
        assert_eq!(page.resume_after(), Some(&2));
        assert!(!page.is_complete());
    }

    #[test]
    fn start_read_keeps_buffer_capacity() {
        let mut page = StoredPage::new();
        page.push(1, b"ab");
        page.finish_read(true);
        let capacities = (page.entries.capacity(), page.bytes.capacity());

        page.start_read();

        assert_eq!((page.entries.capacity(), page.bytes.capacity()), capacities);
        assert!(page.is_empty());
        assert_eq!(page.read_len(), 0);
        assert_eq!(page.byte_len(), 0);
        assert_eq!(page.resume_after(), None);
        assert!(!page.is_complete());
    }
}
