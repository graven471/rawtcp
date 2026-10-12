// fixme: will panic on odd-length slice
pub(crate) fn checksum_sum(bytes: &[u8]) -> u32 {
    bytes
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]) as u32)
        .sum::<u32>()
}
