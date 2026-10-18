use std::cmp::Ordering;

/// This value wraps and should be compared using sequence space arithmetic.
#[derive(Clone, Copy, Debug)]
pub struct SequenceNumber(pub u32);

const SERIAL_BITS: u32 = 32;
const MAX_INCREMENT: u32 = (1u32 << (SERIAL_BITS - 1)) - 1;

impl SequenceNumber {
    // [0 .. (2^(SERIAL_BITS - 1) - 1)]
    #[inline(always)]
    pub const fn wrapping_add(&self, n: u32) -> Self {
        // s' = (s + n) modulo (2 ^ SERIAL_BITS)
        // n < 2_147_483_648 (2^31 - 1) if its greater then its UB
        assert!(n <= MAX_INCREMENT, "increment exceeds serial half-range");
        Self(self.0.wrapping_add(n))
    }
}

impl PartialEq for SequenceNumber {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    fn ne(&self, other: &Self) -> bool {
        self.0 != other.0
    }
}

impl PartialOrd for SequenceNumber {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.0 == other.0 {
            Some(Ordering::Equal)
        } else if self.lt(other) {
            Some(Ordering::Less)
        } else if self.gt(other) {
            Some(Ordering::Greater)
        } else {
            None
        }
    }

    fn gt(&self, other: &Self) -> bool {
        (self.0 < other.0 && other.0 - self.0 > (1u32 << (SERIAL_BITS - 1)))
            || (self.0 > other.0 && self.0 - other.0 < (1u32 << (SERIAL_BITS - 1)))
    }

    fn lt(&self, other: &Self) -> bool {
        (self.0 < other.0 && other.0 - self.0 < (1u32 << (SERIAL_BITS - 1)))
            || (self.0 > other.0 && self.0 - other.0 > (1u32 << (SERIAL_BITS - 1)))
    }

    fn le(&self, other: &Self) -> bool {
        self.lt(other) || self.0 == other.0
    }

    fn ge(&self, other: &Self) -> bool {
        self.gt(other) || self.0 == other.0
    }
}

impl std::ops::Add<u32> for SequenceNumber {
    type Output = Self;

    #[inline]
    fn add(self, rhs: u32) -> Self::Output {
        self.wrapping_add(rhs)
    }
}
