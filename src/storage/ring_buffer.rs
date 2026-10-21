#![allow(unused)]

use core::{alloc::Layout, ptr::NonNull};
use thiserror::Error;

extern crate alloc;

#[derive(Debug, PartialEq, thiserror::Error)]
pub(crate) enum RingBufferError {
    #[error("capacity must be a power of two")]
    InvalidCapacity,
    #[error("allocation failed")]
    AllocError,
    #[error("invalid layout: {0}")]
    LayoutError(#[from] core::alloc::LayoutError),
    #[error("buffer is full")]
    Overflow,
    #[error("buffer is empty")]
    Empty,
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
            return Err(RingBufferError::InvalidCapacity);
        }

        let layout = Layout::array::<T>(capacity)?;
        let ptr = unsafe { alloc::alloc::alloc(layout) };

        if ptr.is_null() {
            return Err(RingBufferError::AllocError);
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

    const fn len(&self) -> usize {
        (self.tail().wrapping_sub(self.head())) as usize
    }

    pub(crate) fn enqueue(&mut self, val: T) -> Result<(), RingBufferError> {
        if self.full() {
            return Err(RingBufferError::Overflow);
        }

        unsafe {
            self.storage.as_ptr().add(self.write_index()).write(val);
        }

        self.tail = self.tail().wrapping_add(1);

        Ok(())
    }

    pub(crate) fn try_enqueue(&mut self, val: T) -> Result<(), (RingBufferError, T)> {
        if self.full() {
            return Err((RingBufferError::Overflow, val));
        };

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
            Err(RingBufferError::InvalidCapacity)
        ));
    }

    #[test]
    fn rejects_non_power_of_two_capacities() {
        for capacity in [3, 5, 6, 7, 9, 15, 17, 100] {
            assert!(
                matches!(
                    RingBuffer::<u8>::new(capacity),
                    Err(RingBufferError::InvalidCapacity)
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
    // Empty and full state transitions
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

        assert!(buffer.enqueue(42).is_ok());
        assert!(buffer.full());
        assert_eq!(buffer.len(), 1);

        assert!(matches!(buffer.enqueue(99), Err(RingBufferError::Overflow)));

        assert_eq!(buffer.dequeue().unwrap(), 42);
        assert!(buffer.empty());
        assert_eq!(buffer.len(), 0);

        assert!(buffer.enqueue(99).is_ok());
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
            Err(RingBufferError::Overflow)
        ));

        // A failed enqueue must not mutate the queue.
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
    // Try enqueue
    // ---------------------------------------------------------

    #[test]
    fn try_enqueue_succeeds_when_buffer_has_space() {
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

        let result = buffer.try_enqueue("packet-C".into());

        match result {
            Err((RingBufferError::Overflow, value)) => {
                assert_eq!(value, "packet-C");
            }
            _ => panic!("expected Overflow with the original value"),
        }

        // Existing elements remain unchanged and in FIFO order.
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
        assert!(buffer.full());

        match buffer.try_enqueue(4) {
            Err((RingBufferError::Overflow, value)) => {
                assert_eq!(value, 4);
            }
            _ => panic!("expected Overflow with value 4"),
        }

        assert_eq!(buffer.dequeue().unwrap(), 2);
        assert_eq!(buffer.dequeue().unwrap(), 3);
        assert!(buffer.empty());
    }

    #[test]
    fn try_enqueue_does_not_drop_rejected_value() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        #[derive(Debug)]
        struct DropSpy(Arc<AtomicUsize>);

        impl Drop for DropSpy {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let drops = Arc::new(AtomicUsize::new(0));
        let mut buffer = RingBuffer::<DropSpy>::new(1).unwrap();

        buffer.try_enqueue(DropSpy(Arc::clone(&drops))).unwrap();

        let rejected = buffer.try_enqueue(DropSpy(Arc::clone(&drops)));

        assert!(rejected.is_err());
        assert_eq!(drops.load(Ordering::SeqCst), 0);

        // The rejected value is still owned by the caller.
        let (error, value) = rejected.unwrap_err();
        assert!(matches!(error, RingBufferError::Overflow));
        drop(value);

        assert_eq!(drops.load(Ordering::SeqCst), 1);

        // The queued value is independent and remains alive.
        drop(buffer);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn try_enqueue_allows_retry_after_capacity_becomes_available() {
        let mut buffer = RingBuffer::<u32>::new(2).unwrap();

        buffer.try_enqueue(10).unwrap();
        buffer.try_enqueue(20).unwrap();

        let rejected = buffer.try_enqueue(30);
        assert!(rejected.is_err());

        let (error, value) = rejected.unwrap_err();
        assert!(matches!(error, RingBufferError::Overflow));

        assert_eq!(buffer.dequeue().unwrap(), 10);

        // Retry the exact value returned by the failed attempt.
        buffer.try_enqueue(value).unwrap();

        assert_eq!(buffer.dequeue().unwrap(), 20);
        assert_eq!(buffer.dequeue().unwrap(), 30);
        assert!(buffer.empty());
    }

    // ---------------------------------------------------------
    // FIFO ordering and wraparound
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

        for expected in 0..2 {
            assert_eq!(buffer.dequeue().unwrap(), expected);
        }

        // The next two writes wrap to physical slots 0 and 1.
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
    // Payload types and ownership
    // ---------------------------------------------------------

    #[test]
    fn supports_non_copy_payloads() {
        let mut buffer = RingBuffer::<String>::new(4).unwrap();

        buffer.enqueue(String::from("SYN")).unwrap();
        buffer.enqueue(String::from("ACK")).unwrap();
        buffer.enqueue(String::from("FIN")).unwrap();

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

    // ---------------------------------------------------------
    // Networking-style workloads
    // ---------------------------------------------------------

    #[derive(Debug, PartialEq, Eq)]
    struct Packet {
        sequence: u64,
        payload: Vec<u8>,
    }

    #[test]
    fn handles_packet_sized_payloads() {
        let mut buffer = RingBuffer::<Packet>::new(8).unwrap();

        let payload_sizes = [0, 1, 64, 512, 1500, 4096, 65535];

        for (sequence, size) in payload_sizes.into_iter().enumerate() {
            let packet = Packet {
                sequence: sequence as u64,
                payload: vec![sequence as u8; size],
            };

            buffer.enqueue(packet).unwrap();
        }

        for (sequence, size) in payload_sizes.into_iter().enumerate() {
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

        // Simulate bursts of incoming packets followed by draining.
        for burst_size in [1, 8, 64, 17, 32, 64, 3, 48] {
            let accepted = burst_size.min(buffer.capacity());

            for _ in 0..accepted {
                // Drain if this burst exceeds available capacity.
                if buffer.full() {
                    assert_eq!(
                        buffer.dequeue().unwrap(),
                        next_sequence - buffer.len() as u64
                    );
                }

                buffer.enqueue(next_sequence).unwrap();
                next_sequence += 1;
            }

            while !buffer.empty() {
                let value = buffer.dequeue().unwrap();
                assert!(value < next_sequence);
            }
        }

        assert!(buffer.empty());
    }

    #[test]
    fn sustained_production_and_consumption() {
        const CAPACITY: usize = 256;
        const TOTAL: u64 = 100_000;

        let mut buffer = RingBuffer::<u64>::new(CAPACITY).unwrap();
        let mut produced = 0u64;
        let mut consumed = 0u64;

        while consumed < TOTAL {
            // Producer phase: fill the currently available space.
            while produced < TOTAL && !buffer.full() {
                buffer.enqueue(produced).unwrap();
                produced += 1;
            }

            // Consumer phase: drain a bounded batch.
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
    // Resource ownership
    // ---------------------------------------------------------

    struct DropSpy(Arc<AtomicUsize>);

    impl Drop for DropSpy {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

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

        // The two remaining initialized slots must be dropped.
        assert_eq!(drops.load(Ordering::SeqCst), 3);
    }

    // ---------------------------------------------------------
    // Counter wraparound
    // ---------------------------------------------------------

    #[test]
    fn counters_wrap_without_losing_fifo_invariants() {
        let mut buffer = RingBuffer::<u32>::new(4).unwrap();

        // Simulate a valid empty queue near the u32 counter limit.
        // The physical read/write indices remain valid.
        buffer.head = u32::MAX - 1;
        buffer.tail = u32::MAX - 1;

        buffer.enqueue(10).unwrap();
        buffer.enqueue(20).unwrap();
        buffer.enqueue(30).unwrap();
        buffer.enqueue(40).unwrap();

        assert!(buffer.full());
        assert_eq!(buffer.len(), 4);

        for expected in [10, 20, 30, 40] {
            assert_eq!(buffer.dequeue().unwrap(), expected);
        }

        assert!(buffer.empty());
    }
}
