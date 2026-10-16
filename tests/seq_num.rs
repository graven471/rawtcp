#[cfg(test)]
mod tests {
    use rawtcp::tcp::seq::SequenceNumber;

    use std::cmp::Ordering;

    const HALF: u32 = 1 << 31;
    const MAX: u32 = u32::MAX;

    const SERIAL_BITS: u32 = 32;
    const MAX_INCREMENT: u32 = (1u32 << (SERIAL_BITS - 1)) - 1;

    fn seq(n: u32) -> SequenceNumber {
        SequenceNumber(n)
    }

    // ------------------------------------------------------------
    // Equality
    // ------------------------------------------------------------

    #[test]
    fn equality_same_value() {
        assert_eq!(seq(0), seq(0));
        assert_eq!(seq(1), seq(1));
        assert_eq!(seq(MAX), seq(MAX));
    }

    #[test]
    fn equality_different_values() {
        assert_ne!(seq(0), seq(1));
        assert_ne!(seq(0), seq(MAX));
        assert_ne!(seq(HALF), seq(HALF - 1));
    }

    #[test]
    fn equality_across_wrap_boundary_is_numeric_equality() {
        assert_eq!(seq(0), seq(0));
        assert_ne!(seq(0), seq(MAX));
        assert_ne!(seq(1), seq(MAX));
    }

    // ------------------------------------------------------------
    // Partial ordering: ordinary, non-wrapping values
    // ------------------------------------------------------------

    #[test]
    fn ordering_equal() {
        let a = seq(42);
        let b = seq(42);

        assert_eq!(a.partial_cmp(&b), Some(Ordering::Equal));
        assert!(!a.lt(&b));
        assert!(!a.gt(&b));
        assert!(a.le(&b));
        assert!(a.ge(&b));
    }

    #[test]
    fn ordering_adjacent_values() {
        let a = seq(100);
        let b = seq(101);

        assert_eq!(a.partial_cmp(&b), Some(Ordering::Less));
        assert_eq!(b.partial_cmp(&a), Some(Ordering::Greater));

        assert!(a.lt(&b));
        assert!(a.le(&b));
        assert!(!a.gt(&b));
        assert!(!a.ge(&b));

        assert!(b.gt(&a));
        assert!(b.ge(&a));
        assert!(!b.lt(&a));
        assert!(!b.le(&a));
    }

    #[test]
    fn ordering_zero_and_maximum() {
        // 0 follows u32::MAX in serial number space.
        assert_eq!(seq(MAX).partial_cmp(&seq(0)), Some(Ordering::Less));
        assert_eq!(seq(0).partial_cmp(&seq(MAX)), Some(Ordering::Greater));

        assert!(seq(MAX).lt(&seq(0)));
        assert!(seq(0).gt(&seq(MAX)));
    }

    // ------------------------------------------------------------
    // Half-range boundary
    // ------------------------------------------------------------

    #[test]
    fn ordering_just_below_half_range() {
        let a = seq(0);
        let b = seq(HALF - 1);

        assert_eq!(a.partial_cmp(&b), Some(Ordering::Less));
        assert_eq!(b.partial_cmp(&a), Some(Ordering::Greater));

        assert!(a.lt(&b));
        assert!(b.gt(&a));
    }

    #[test]
    fn ordering_exactly_half_range_is_ambiguous() {
        let a = seq(0);
        let b = seq(HALF);

        assert_eq!(a.partial_cmp(&b), None);
        assert_eq!(b.partial_cmp(&a), None);

        assert!(!a.lt(&b));
        assert!(!a.gt(&b));
        assert!(!a.le(&b));
        assert!(!a.ge(&b));

        assert!(!b.lt(&a));
        assert!(!b.gt(&a));
        assert!(!b.le(&a));
        assert!(!b.ge(&a));
    }

    #[test]
    fn ordering_half_range_boundary_at_nonzero_origin() {
        let a = seq(123);
        let b = seq(123u32.wrapping_add(HALF));

        assert_eq!(a.partial_cmp(&b), None);
        assert_eq!(b.partial_cmp(&a), None);
    }

    #[test]
    fn ordering_just_above_half_range() {
        let a = seq(0);
        let b = seq(HALF + 1);

        assert_eq!(a.partial_cmp(&b), Some(Ordering::Greater));
        assert_eq!(b.partial_cmp(&a), Some(Ordering::Less));

        assert!(a.gt(&b));
        assert!(b.lt(&a));
    }

    // ------------------------------------------------------------
    // Ordering across wraparound
    // ------------------------------------------------------------

    #[test]
    fn ordering_across_wraparound_near_zero() {
        let before_wrap = seq(MAX - 1);
        let last = seq(MAX);
        let zero = seq(0);
        let after_wrap = seq(1);

        assert_eq!(before_wrap.partial_cmp(&last), Some(Ordering::Less));
        assert_eq!(last.partial_cmp(&zero), Some(Ordering::Less));
        assert_eq!(zero.partial_cmp(&after_wrap), Some(Ordering::Less));

        assert_eq!(before_wrap.partial_cmp(&zero), Some(Ordering::Less));
        assert_eq!(last.partial_cmp(&after_wrap), Some(Ordering::Less));

        assert_eq!(
            after_wrap.partial_cmp(&before_wrap),
            Some(Ordering::Greater)
        );
    }

    #[test]
    fn ordering_across_wraparound_in_reverse() {
        let a = seq(1);
        let b = seq(MAX);

        assert_eq!(a.partial_cmp(&b), Some(Ordering::Greater));
        assert_eq!(b.partial_cmp(&a), Some(Ordering::Less));
    }

    #[test]
    fn ordering_near_half_range_across_wraparound() {
        // From MAX - 5 to 3 is a forward distance of 9.
        let a = seq(MAX - 5);
        let b = seq(3);

        assert_eq!(a.partial_cmp(&b), Some(Ordering::Less));
        assert_eq!(b.partial_cmp(&a), Some(Ordering::Greater));

        // Reverse direction must be greater than half-range.
        let c = seq(HALF - 1);
        let d = seq(0);

        assert_eq!(c.partial_cmp(&d), Some(Ordering::Greater));
        assert_eq!(d.partial_cmp(&c), Some(Ordering::Less));
    }

    // ------------------------------------------------------------
    // wrapping_add
    // ------------------------------------------------------------

    #[test]
    fn wrapping_add_zero() {
        for value in [0, 1, HALF, MAX - 1, MAX] {
            assert_eq!(seq(value).wrapping_add(0), seq(value));
        }
    }

    #[test]
    fn wrapping_add_one() {
        assert_eq!(seq(0).wrapping_add(1), seq(1));
        assert_eq!(seq(41).wrapping_add(1), seq(42));
        assert_eq!(seq(MAX - 1).wrapping_add(1), seq(MAX));
        assert_eq!(seq(MAX).wrapping_add(1), seq(0));
    }

    #[test]
    fn wrapping_add_wraps_at_u32_max() {
        assert_eq!(seq(MAX).wrapping_add(2), seq(1));
        assert_eq!(seq(MAX - 2).wrapping_add(5), seq(2));
        assert_eq!(seq(MAX - 9).wrapping_add(10), seq(0));
    }

    #[test]
    fn wrapping_add_half_range_minus_one() {
        assert_eq!(seq(0).wrapping_add(MAX_INCREMENT), seq(HALF - 1));
    }

    #[test]
    fn wrapping_add_maximum_increment_across_wrap() {
        assert_eq!(seq(MAX - 5).wrapping_add(MAX_INCREMENT), seq(HALF - 7),);
    }

    #[test]
    #[should_panic(expected = "increment exceeds serial half-range")]
    fn wrapping_add_rejects_half_range() {
        let _ = seq(0).wrapping_add(HALF);
    }

    #[test]
    #[should_panic(expected = "increment exceeds serial half-range")]
    fn wrapping_add_rejects_u32_max() {
        let _ = seq(0).wrapping_add(MAX);
    }

    // ------------------------------------------------------------
    // Ordering invariants
    // ------------------------------------------------------------

    #[test]
    fn ordering_is_antisymmetric_for_comparable_pairs() {
        let values = [
            0,
            1,
            2,
            10,
            HALF - 2,
            HALF - 1,
            HALF,
            HALF + 1,
            MAX - 2,
            MAX - 1,
            MAX,
        ];

        for &x in &values {
            for &y in &values {
                let a = seq(x);
                let b = seq(y);

                match (a.partial_cmp(&b), b.partial_cmp(&a)) {
                    (Some(Ordering::Less), Some(Ordering::Greater)) => {}
                    (Some(Ordering::Greater), Some(Ordering::Less)) => {}
                    (Some(Ordering::Equal), Some(Ordering::Equal)) => {
                        assert_eq!(x, y);
                    }
                    (None, None) => {
                        assert_eq!(x.abs_diff(y), HALF);
                    }
                    pair => panic!("inconsistent ordering: {x} vs {y}: {pair:?}"),
                }
            }
        }
    }

    #[test]
    fn ordering_comparison_methods_match_partial_cmp() {
        let values = [0, 1, 2, 100, HALF - 1, HALF, HALF + 1, MAX - 1, MAX];

        for &x in &values {
            for &y in &values {
                let a = seq(x);
                let b = seq(y);

                match a.partial_cmp(&b) {
                    Some(Ordering::Less) => {
                        assert!(a.lt(&b));
                        assert!(a.le(&b));
                        assert!(!a.gt(&b));
                        assert!(!a.ge(&b));
                    }
                    Some(Ordering::Equal) => {
                        assert!(!a.lt(&b));
                        assert!(a.le(&b));
                        assert!(!a.gt(&b));
                        assert!(a.ge(&b));
                    }
                    Some(Ordering::Greater) => {
                        assert!(!a.lt(&b));
                        assert!(!a.le(&b));
                        assert!(a.gt(&b));
                        assert!(a.ge(&b));
                    }
                    None => {
                        assert!(!a.lt(&b));
                        assert!(!a.le(&b));
                        assert!(!a.gt(&b));
                        assert!(!a.ge(&b));
                    }
                }
            }
        }
    }

    #[test]
    fn ordering_is_transitive_within_a_half_range_window() {
        // All values are within a small forward window, so serial
        // ordering must be transitive.
        let base = MAX - 5;
        let values: Vec<_> = (0..=10)
            .map(|offset| seq(base.wrapping_add(offset)))
            .collect();

        for a in &values {
            for b in &values {
                for c in &values {
                    if a.lt(b) && b.lt(c) {
                        assert!(a.lt(c));
                    }
                }
            }
        }
    }
}
