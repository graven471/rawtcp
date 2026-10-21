#![allow(unused)]

use core::{alloc::Layout, ptr::NonNull};
use thiserror::Error;

extern crate alloc;

#[derive(Debug, PartialEq, thiserror::Error)]
pub(crate) enum RingBufferError {
    #[error("invalid capacity {capacity}: capacity must be a non-zero power of two")]
    InvalidCapacity { capacity: usize },

    #[error("memory allocation failed for {size} bytes with alignment {align}")]
    AllocError { size: usize, align: usize },

    #[error("invalid memory layout: {0}")]
    LayoutError(#[from] core::alloc::LayoutError),

    #[error("ring buffer is full (capacity: {capacity}, length: {len})")]
    Overflow { capacity: usize, len: usize },

    #[error("ring buffer is empty; no element is available to dequeue")]
    Empty,

    #[error(
        "insufficient free space: requested {requested} slots, \
         available {available} (capacity: {capacity}, length: {len})"
    )]
    InsufficientCapacity {
        requested: usize,
        available: usize,
        capacity: usize,
        len: usize,
    },

    #[error(
        "batch operation exceeds buffer capacity: requested {requested} elements, \
         maximum capacity is {capacity}"
    )]
    BatchTooLarge { requested: usize, capacity: usize },
}

#[derive(Debug)]
pub(crate) struct RingBuffer<T> {
    // consumer increments this
    // next read position
    head: u32,
    // producer increments this
    // next write position
    tail: u32,
    capacity: usize,
    storage: NonNull<T>,
}

impl<T> Drop for RingBuffer<T> {
    fn drop(&mut self) {
        unsafe {
            for i in 0..self.len() {
                let index = (self.head as usize + i) & self.mask();
                self.storage.as_ptr().add(index).drop_in_place();
            }

            let layout =
                Layout::array::<T>(self.capacity).expect("RingBuffer layout must remain valid");
            alloc::alloc::dealloc(self.storage.as_ptr().cast(), layout);
        }
    }
}

impl<T> RingBuffer<T> {
    pub(crate) fn new(capacity: usize) -> Result<Self, RingBufferError> {
        if capacity == 0 || !capacity.is_power_of_two() {
            return Err(RingBufferError::InvalidCapacity { capacity });
        }

        let layout = Layout::array::<T>(capacity)?;
        let ptr = unsafe { alloc::alloc::alloc(layout) };

        if ptr.is_null() {
            return Err(RingBufferError::AllocError {
                size: layout.size(),
                align: layout.align(),
            });
        }

        Ok(Self {
            head: 0,
            tail: 0,
            capacity,
            // SAFETY: we already checked ptr.is_null()
            storage: unsafe { NonNull::new_unchecked(ptr.cast()) },
        })
    }

    #[inline]
    pub(crate) const fn head(&self) -> u32 {
        self.head
    }

    #[inline]
    pub(crate) const fn tail(&self) -> u32 {
        self.tail
    }

    #[inline]
    pub(crate) const fn capacity(&self) -> usize {
        self.capacity
    }

    const fn mask(&self) -> usize {
        self.capacity() - 1
    }

    const fn write_index(&self) -> usize {
        (self.tail() as usize & self.mask()) as usize
    }

    const fn read_index(&self) -> usize {
        (self.head() as usize & self.mask()) as usize
    }

    const fn empty(&self) -> bool {
        self.head() == self.tail()
    }

    const fn full(&self) -> bool {
        self.tail().wrapping_sub(self.head()) as usize == self.capacity()
    }

    pub const fn len(&self) -> usize {
        (self.tail().wrapping_sub(self.head())) as usize
    }

    pub(crate) fn enqueue(&mut self, val: T) -> Result<(), RingBufferError> {
        if self.full() {
            return Err(RingBufferError::Overflow {
                capacity: self.capacity(),
                len: self.len(),
            });
        }

        unsafe {
            self.storage.as_ptr().add(self.write_index()).write(val);
        }

        self.tail = self.tail().wrapping_add(1);

        Ok(())
    }

    pub(crate) fn try_enqueue_slice(&mut self, data: &[T]) -> Result<(), RingBufferError>
    where
        T: Copy,
    {
        if data.is_empty() {
            return Ok(());
        }

        let len = self.len();
        let available = self.capacity() - len;

        if data.len() > available {
            return Err(RingBufferError::InsufficientCapacity {
                requested: data.len(),
                available,
                capacity: self.capacity(),
                len,
            });
        }

        for v in data {
            self.enqueue(*v)?;
        }

        Ok(())
    }

    pub(crate) fn try_enqueue(&mut self, val: T) -> Result<(), (RingBufferError, T)> {
        if self.full() {
            return Err((
                RingBufferError::Overflow {
                    capacity: self.capacity(),
                    len: self.len(),
                },
                val,
            ));
        }

        unsafe {
            self.storage.as_ptr().add(self.write_index()).write(val);
        }

        self.tail = self.tail().wrapping_add(1);

        Ok(())
    }

    pub(crate) fn try_dequeue(&mut self) -> Result<T, RingBufferError> {
        if self.empty() {
            return Err(RingBufferError::Empty);
        }

        let val = unsafe { self.storage.as_ptr().add(self.read_index()).read() };
        self.head = self.head().wrapping_add(1);

        Ok(val)
    }

    pub(crate) fn dequeue(&mut self) -> Result<T, RingBufferError> {
        self.try_dequeue()
    }
}

#[cfg(test)]
mod ring_buffer_test {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    // ---------------------------------------------------------
    // Construction and capacity invariants
    // ---------------------------------------------------------

    #[test]
    fn rejects_zero_capacity() {
        assert!(matches!(
            RingBuffer::<u8>::new(0),
            Err(RingBufferError::InvalidCapacity { capacity: 0 })
        ));
    }

    #[test]
    fn rejects_non_power_of_two_capacities() {
        for capacity in [3, 5, 6, 7, 9, 15, 17, 100] {
            assert!(
                matches!(
                    RingBuffer::<u8>::new(capacity),
                    Err(RingBufferError::InvalidCapacity { capacity: c })
                        if c == capacity
                ),
                "capacity {capacity} should be rejected"
            );
        }
    }

    #[test]
    fn accepts_power_of_two_capacities() {
        for capacity in [1, 2, 4, 8, 16, 64, 1024] {
            let buffer = RingBuffer::<u8>::new(capacity).unwrap();

            assert_eq!(buffer.capacity(), capacity);
            assert_eq!(buffer.len(), 0);
            assert!(buffer.empty());
            assert!(!buffer.full());
        }
    }

    // ---------------------------------------------------------
    // Empty/full state transitions
    // ---------------------------------------------------------

    #[test]
    fn dequeue_from_empty_returns_empty_error() {
        let mut buffer = RingBuffer::<u32>::new(4).unwrap();

        assert!(matches!(buffer.dequeue(), Err(RingBufferError::Empty)));

        assert!(buffer.empty());
        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.head(), 0);
        assert_eq!(buffer.tail(), 0);
    }

    #[test]
    fn capacity_one_transitions_between_empty_and_full() {
        let mut buffer = RingBuffer::<u32>::new(1).unwrap();

        buffer.enqueue(42).unwrap();

        assert!(buffer.full());
        assert_eq!(buffer.len(), 1);

        assert!(matches!(
            buffer.enqueue(99),
            Err(RingBufferError::Overflow {
                capacity: 1,
                len: 1
            })
        ));

        assert_eq!(buffer.dequeue().unwrap(), 42);
        assert!(buffer.empty());

        buffer.enqueue(99).unwrap();
        assert_eq!(buffer.dequeue().unwrap(), 99);
        assert!(buffer.empty());
    }

    #[test]
    fn fills_to_capacity_and_rejects_overflow() {
        let mut buffer = RingBuffer::<u32>::new(4).unwrap();

        for value in 10..14 {
            buffer.enqueue(value).unwrap();
        }

        assert!(buffer.full());
        assert_eq!(buffer.len(), 4);
        assert_eq!(buffer.head(), 0);
        assert_eq!(buffer.tail(), 4);

        assert!(matches!(
            buffer.enqueue(999),
            Err(RingBufferError::Overflow {
                capacity: 4,
                len: 4
            })
        ));

        assert_eq!(buffer.len(), 4);
        assert_eq!(buffer.head(), 0);
        assert_eq!(buffer.tail(), 4);

        for expected in 10..14 {
            assert_eq!(buffer.dequeue().unwrap(), expected);
        }

        assert!(buffer.empty());
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn overflow_does_not_overwrite_oldest_element() {
        let mut buffer = RingBuffer::<u32>::new(2).unwrap();

        buffer.enqueue(1).unwrap();
        buffer.enqueue(2).unwrap();

        assert!(buffer.enqueue(3).is_err());

        assert_eq!(buffer.dequeue().unwrap(), 1);
        assert_eq!(buffer.dequeue().unwrap(), 2);
        assert!(buffer.empty());
    }

    // ---------------------------------------------------------
    // try_enqueue
    // ---------------------------------------------------------

    #[test]
    fn try_enqueue_succeeds_when_space_is_available() {
        let mut buffer = RingBuffer::<u32>::new(2).unwrap();

        assert_eq!(buffer.try_enqueue(10), Ok(()));
        assert_eq!(buffer.try_enqueue(20), Ok(()));

        assert!(buffer.full());
        assert_eq!(buffer.dequeue().unwrap(), 10);
        assert_eq!(buffer.dequeue().unwrap(), 20);
    }

    #[test]
    fn try_enqueue_returns_original_value_when_full() {
        let mut buffer = RingBuffer::<String>::new(2).unwrap();

        buffer.try_enqueue("packet-A".into()).unwrap();
        buffer.try_enqueue("packet-B".into()).unwrap();

        let (error, value) = buffer.try_enqueue("packet-C".into()).unwrap_err();

        assert!(matches!(
            error,
            RingBufferError::Overflow {
                capacity: 2,
                len: 2
            }
        ));
        assert_eq!(value, "packet-C");

        assert_eq!(buffer.dequeue().unwrap(), "packet-A");
        assert_eq!(buffer.dequeue().unwrap(), "packet-B");
        assert!(buffer.empty());
    }

    #[test]
    fn try_enqueue_preserves_value_after_wraparound() {
        let mut buffer = RingBuffer::<u32>::new(2).unwrap();

        buffer.try_enqueue(1).unwrap();
        buffer.try_enqueue(2).unwrap();
        assert_eq!(buffer.dequeue().unwrap(), 1);

        buffer.try_enqueue(3).unwrap();

        let (error, value) = buffer.try_enqueue(4).unwrap_err();

        assert!(matches!(
            error,
            RingBufferError::Overflow {
                capacity: 2,
                len: 2
            }
        ));
        assert_eq!(value, 4);

        assert_eq!(buffer.dequeue().unwrap(), 2);
        assert_eq!(buffer.dequeue().unwrap(), 3);
        assert!(buffer.empty());
    }

    #[derive(Debug)]
    struct DropSpy(Arc<AtomicUsize>);

    impl Drop for DropSpy {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn try_enqueue_does_not_drop_rejected_value() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut buffer = RingBuffer::<DropSpy>::new(1).unwrap();

        buffer.try_enqueue(DropSpy(Arc::clone(&drops))).unwrap();

        let rejected = buffer.try_enqueue(DropSpy(Arc::clone(&drops)));

        assert!(rejected.is_err());
        assert_eq!(drops.load(Ordering::SeqCst), 0);

        let (error, value) = rejected.unwrap_err();

        assert!(matches!(
            error,
            RingBufferError::Overflow {
                capacity: 1,
                len: 1
            }
        ));

        drop(value);
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        drop(buffer);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn try_enqueue_allows_retry_after_dequeue() {
        let mut buffer = RingBuffer::<u32>::new(2).unwrap();

        buffer.try_enqueue(10).unwrap();
        buffer.try_enqueue(20).unwrap();

        let (error, value) = buffer.try_enqueue(30).unwrap_err();

        assert!(matches!(error, RingBufferError::Overflow { .. }));

        assert_eq!(buffer.dequeue().unwrap(), 10);
        buffer.try_enqueue(value).unwrap();

        assert_eq!(buffer.dequeue().unwrap(), 20);
        assert_eq!(buffer.dequeue().unwrap(), 30);
        assert!(buffer.empty());
    }

    // ---------------------------------------------------------
    // try_enqueue_slice
    // ---------------------------------------------------------

    #[test]
    fn try_enqueue_slice_accepts_entire_slice() {
        let mut buffer = RingBuffer::<u32>::new(8).unwrap();

        buffer.try_enqueue_slice(&[10, 20, 30]).unwrap();

        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.dequeue().unwrap(), 10);
        assert_eq!(buffer.dequeue().unwrap(), 20);
        assert_eq!(buffer.dequeue().unwrap(), 30);
        assert!(buffer.empty());
    }

    #[test]
    fn try_enqueue_slice_accepts_exact_remaining_capacity() {
        let mut buffer = RingBuffer::<u32>::new(4).unwrap();

        buffer.enqueue(10).unwrap();
        buffer.enqueue(20).unwrap();

        buffer.try_enqueue_slice(&[30, 40]).unwrap();

        assert!(buffer.full());

        for expected in [10, 20, 30, 40] {
            assert_eq!(buffer.dequeue().unwrap(), expected);
        }
    }

    #[test]
    fn try_enqueue_slice_reports_insufficient_capacity() {
        let mut buffer = RingBuffer::<u32>::new(4).unwrap();

        buffer.enqueue(10).unwrap();
        buffer.enqueue(20).unwrap();
        buffer.enqueue(30).unwrap();

        let error = buffer.try_enqueue_slice(&[40, 50]).unwrap_err();

        assert!(matches!(
            error,
            RingBufferError::InsufficientCapacity {
                requested: 2,
                available: 1,
                capacity: 4,
                len: 3
            }
        ));

        // Batch insertion must be atomic.
        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.dequeue().unwrap(), 10);
        assert_eq!(buffer.dequeue().unwrap(), 20);
        assert_eq!(buffer.dequeue().unwrap(), 30);
        assert!(buffer.empty());
    }

    #[test]
    fn try_enqueue_slice_on_full_buffer_reports_zero_available() {
        let mut buffer = RingBuffer::<u32>::new(2).unwrap();

        buffer.enqueue(10).unwrap();
        buffer.enqueue(20).unwrap();

        let error = buffer.try_enqueue_slice(&[30]).unwrap_err();

        assert!(matches!(
            error,
            RingBufferError::InsufficientCapacity {
                requested: 1,
                available: 0,
                capacity: 2,
                len: 2
            }
        ));

        assert_eq!(buffer.dequeue().unwrap(), 10);
        assert_eq!(buffer.dequeue().unwrap(), 20);
    }

    #[test]
    fn try_enqueue_slice_accepts_empty_input() {
        let mut buffer = RingBuffer::<u32>::new(2).unwrap();

        buffer.try_enqueue_slice(&[]).unwrap();
        assert!(buffer.empty());

        buffer.enqueue(10).unwrap();
        buffer.enqueue(20).unwrap();

        // An empty batch is a no-op even when full.
        buffer.try_enqueue_slice(&[]).unwrap();

        assert!(buffer.full());
        assert_eq!(buffer.len(), 2);
        assert_eq!(buffer.dequeue().unwrap(), 10);
        assert_eq!(buffer.dequeue().unwrap(), 20);
    }

    #[test]
    fn try_enqueue_slice_rejects_batch_larger_than_capacity() {
        let mut buffer = RingBuffer::<u32>::new(4).unwrap();
        let error = buffer.try_enqueue_slice(&[1, 2, 3, 4, 5]).unwrap_err();

        assert!(matches!(
            error,
            RingBufferError::InsufficientCapacity {
                requested: 5,
                available: 4,
                capacity: 4,
                len: 0
            }
        ));

        assert!(buffer.empty());
    }

    #[test]
    fn try_enqueue_slice_preserves_fifo_across_wraparound() {
        let mut buffer = RingBuffer::<u32>::new(4).unwrap();

        buffer.try_enqueue_slice(&[1, 2, 3]).unwrap();

        assert_eq!(buffer.dequeue().unwrap(), 1);
        assert_eq!(buffer.dequeue().unwrap(), 2);

        // The physical write range wraps around the allocation.
        buffer.try_enqueue_slice(&[4, 5, 6]).unwrap();

        for expected in [3, 4, 5, 6] {
            assert_eq!(buffer.dequeue().unwrap(), expected);
        }

        assert!(buffer.empty());
    }

    #[test]
    fn try_enqueue_slice_handles_nonzero_head_and_tail() {
        let mut buffer = RingBuffer::<u32>::new(8).unwrap();

        buffer.try_enqueue_slice(&[1, 2, 3, 4, 5]).unwrap();

        for expected in [1, 2, 3] {
            assert_eq!(buffer.dequeue().unwrap(), expected);
        }

        buffer.try_enqueue_slice(&[6, 7, 8, 9]).unwrap();

        for expected in [4, 5, 6, 7, 8, 9] {
            assert_eq!(buffer.dequeue().unwrap(), expected);
        }

        assert!(buffer.empty());
    }

    // ---------------------------------------------------------
    // FIFO ordering and physical wraparound
    // ---------------------------------------------------------

    #[test]
    fn preserves_fifo_order() {
        let mut buffer = RingBuffer::<u32>::new(8).unwrap();

        for value in 0..8 {
            buffer.enqueue(value).unwrap();
        }

        for expected in 0..8 {
            assert_eq!(buffer.dequeue().unwrap(), expected);
        }
    }

    #[test]
    fn wraps_write_index_after_reaching_capacity() {
        let mut buffer = RingBuffer::<u32>::new(4).unwrap();

        for value in 0..4 {
            buffer.enqueue(value).unwrap();
        }

        assert_eq!(buffer.dequeue().unwrap(), 0);
        assert_eq!(buffer.dequeue().unwrap(), 1);

        buffer.enqueue(4).unwrap();
        buffer.enqueue(5).unwrap();

        assert!(buffer.full());
        assert_eq!(buffer.len(), 4);

        for expected in 2..6 {
            assert_eq!(buffer.dequeue().unwrap(), expected);
        }

        assert!(buffer.empty());
    }

    #[test]
    fn wraps_read_and_write_indices_repeatedly() {
        let mut buffer = RingBuffer::<u64>::new(4).unwrap();

        for round in 0..100 {
            let base = round * 4;

            for offset in 0..4 {
                buffer.enqueue(base + offset).unwrap();
            }

            for offset in 0..4 {
                assert_eq!(buffer.dequeue().unwrap(), base + offset);
            }

            assert!(buffer.empty());
        }
    }

    #[test]
    fn interleaved_enqueue_and_dequeue_preserve_order() {
        let mut buffer = RingBuffer::<u32>::new(4).unwrap();

        for value in 0..1000 {
            buffer.enqueue(value).unwrap();
            assert_eq!(buffer.dequeue().unwrap(), value);
            assert!(buffer.empty());
        }
    }

    // ---------------------------------------------------------
    // Payload types and networking workloads
    // ---------------------------------------------------------

    #[test]
    fn supports_non_copy_payloads() {
        let mut buffer = RingBuffer::<String>::new(4).unwrap();

        buffer.enqueue("SYN".into()).unwrap();
        buffer.enqueue("ACK".into()).unwrap();
        buffer.enqueue("FIN".into()).unwrap();

        assert_eq!(buffer.dequeue().unwrap(), "SYN");
        assert_eq!(buffer.dequeue().unwrap(), "ACK");
        assert_eq!(buffer.dequeue().unwrap(), "FIN");
        assert!(buffer.empty());
    }

    #[test]
    fn preserves_payloads_across_wraparound() {
        let mut buffer = RingBuffer::<String>::new(2).unwrap();

        buffer.enqueue("packet-A".into()).unwrap();
        buffer.enqueue("packet-B".into()).unwrap();

        assert_eq!(buffer.dequeue().unwrap(), "packet-A");

        buffer.enqueue("packet-C".into()).unwrap();

        assert_eq!(buffer.dequeue().unwrap(), "packet-B");
        assert_eq!(buffer.dequeue().unwrap(), "packet-C");
        assert!(buffer.empty());
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Packet {
        sequence: u64,
        payload: Vec<u8>,
    }

    #[test]
    fn handles_packet_sized_payloads() {
        let mut buffer = RingBuffer::<Packet>::new(8).unwrap();
        let payload_sizes = [0, 1, 64, 512, 1500, 4096, 65535];

        for (sequence, size) in payload_sizes.iter().copied().enumerate() {
            buffer
                .enqueue(Packet {
                    sequence: sequence as u64,
                    payload: vec![sequence as u8; size],
                })
                .unwrap();
        }

        for (sequence, size) in payload_sizes.iter().copied().enumerate() {
            let packet = buffer.dequeue().unwrap();

            assert_eq!(packet.sequence, sequence as u64);
            assert_eq!(packet.payload.len(), size);
            assert!(packet.payload.iter().all(|&byte| byte == sequence as u8));
        }

        assert!(buffer.empty());
    }

    #[test]
    fn handles_bursty_traffic() {
        let mut buffer = RingBuffer::<u64>::new(64).unwrap();
        let mut next_sequence = 0u64;
        let mut expected = VecDeque::new();

        for burst_size in [1, 8, 64, 17, 32, 64, 3, 48] {
            for _ in 0..burst_size {
                if buffer.full() {
                    assert_eq!(buffer.dequeue().unwrap(), expected.pop_front().unwrap());
                }

                buffer.enqueue(next_sequence).unwrap();
                expected.push_back(next_sequence);
                next_sequence += 1;
            }

            while !expected.is_empty() {
                assert_eq!(buffer.dequeue().unwrap(), expected.pop_front().unwrap());
            }

            assert!(buffer.empty());
        }
    }

    #[test]
    fn sustained_production_and_consumption() {
        const CAPACITY: usize = 256;
        const TOTAL: u64 = 100_000;

        let mut buffer = RingBuffer::<u64>::new(CAPACITY).unwrap();
        let mut produced = 0u64;
        let mut consumed = 0u64;

        while consumed < TOTAL {
            while produced < TOTAL && !buffer.full() {
                buffer.enqueue(produced).unwrap();
                produced += 1;
            }

            for _ in 0..32 {
                if consumed == TOTAL || buffer.empty() {
                    break;
                }

                assert_eq!(buffer.dequeue().unwrap(), consumed);
                consumed += 1;
            }
        }

        assert_eq!(produced, TOTAL);
        assert_eq!(consumed, TOTAL);
        assert!(buffer.empty());
    }

    // ---------------------------------------------------------
    // Resource ownership and destruction
    // ---------------------------------------------------------

    #[test]
    fn dequeued_values_are_dropped_exactly_once() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut buffer = RingBuffer::<DropSpy>::new(4).unwrap();

        buffer.enqueue(DropSpy(Arc::clone(&drops))).unwrap();
        buffer.enqueue(DropSpy(Arc::clone(&drops))).unwrap();

        drop(buffer.dequeue().unwrap());
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        drop(buffer.dequeue().unwrap());
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn dropping_buffer_drops_all_remaining_elements() {
        let drops = Arc::new(AtomicUsize::new(0));

        {
            let mut buffer = RingBuffer::<DropSpy>::new(4).unwrap();

            for _ in 0..3 {
                buffer.enqueue(DropSpy(Arc::clone(&drops))).unwrap();
            }

            drop(buffer.dequeue().unwrap());
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }

        assert_eq!(drops.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn dropping_buffer_after_wraparound_drops_remaining_elements() {
        let drops = Arc::new(AtomicUsize::new(0));

        {
            let mut buffer = RingBuffer::<DropSpy>::new(4).unwrap();

            for _ in 0..4 {
                buffer.enqueue(DropSpy(Arc::clone(&drops))).unwrap();
            }

            drop(buffer.dequeue().unwrap());
            drop(buffer.dequeue().unwrap());

            buffer.enqueue(DropSpy(Arc::clone(&drops))).unwrap();
            buffer.enqueue(DropSpy(Arc::clone(&drops))).unwrap();

            assert_eq!(buffer.len(), 4);
        }

        assert_eq!(drops.load(Ordering::SeqCst), 6);
    }

    // ---------------------------------------------------------
    // Counter wraparound
    // ---------------------------------------------------------

    #[test]
    fn counters_wrap_without_losing_fifo_invariants() {
        let mut buffer = RingBuffer::<u32>::new(4).unwrap();

        buffer.head = u32::MAX - 1;
        buffer.tail = u32::MAX - 1;

        for value in [10, 20, 30, 40] {
            buffer.enqueue(value).unwrap();
        }

        assert!(buffer.full());
        assert_eq!(buffer.len(), 4);

        for expected in [10, 20, 30, 40] {
            assert_eq!(buffer.dequeue().unwrap(), expected);
        }

        assert!(buffer.empty());
    }

    // ---------------------------------------------------------
    // Differential testing against VecDeque
    // ---------------------------------------------------------

    #[test]
    fn matches_vecdeque_for_deterministic_operation_sequence() {
        let mut buffer = RingBuffer::<u32>::new(8).unwrap();
        let mut reference = VecDeque::<u32>::with_capacity(8);

        // Deterministic pseudo-random sequence; no extra dependency.
        let mut state = 0x1234_5678u32;

        for _ in 0..10_000 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);

            if state & 1 == 0 {
                let value = state;

                if reference.len() < 8 {
                    buffer.enqueue(value).unwrap();
                    reference.push_back(value);
                } else {
                    assert!(matches!(
                        buffer.enqueue(value),
                        Err(RingBufferError::Overflow {
                            capacity: 8,
                            len: 8
                        })
                    ));
                }
            } else if let Some(expected) = reference.pop_front() {
                assert_eq!(buffer.dequeue().unwrap(), expected);
            } else {
                assert!(matches!(buffer.dequeue(), Err(RingBufferError::Empty)));
            }

            assert_eq!(buffer.len(), reference.len());
            assert_eq!(buffer.empty(), reference.is_empty());
            assert_eq!(buffer.full(), reference.len() == 8);
        }

        while let Some(expected) = reference.pop_front() {
            assert_eq!(buffer.dequeue().unwrap(), expected);
        }

        assert!(buffer.empty());
    }
}
