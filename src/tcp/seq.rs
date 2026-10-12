pub struct SeqNumber(pub u32);

impl SeqNumber {
    #[inline(always)]
    pub const fn wrapping_add(self, n: u32) -> Self {
        Self(self.0.wrapping_add(n))
    }

    #[inline(always)]
    pub const fn wrapping_sub(self, other: Self) -> u32 {
        self.0.wrapping_sub(other.0)
    }
}
