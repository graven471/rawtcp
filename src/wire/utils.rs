pub(crate) fn checksum_sum(bytes: &[u8]) -> u32 {
    bytes
        .chunks(2)
        .map(|c| {
            let word = match c {
                &[hi, lo] => u16::from_be_bytes([hi, lo]),
                &[hi] => u16::from_be_bytes([hi, 0]),
                _ => unreachable!(),
            };
            word as u32
        })
        .sum()
}
