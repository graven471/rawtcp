use hmac_sha256::HMAC;
use std::time::Instant;

use crate::tcp::seq::SequenceNumber;

static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

fn timer_4us() -> u32 {
    let start = START.get_or_init(Instant::now);
    let us = start.elapsed().as_micros();
    return us as u32 / 4;
}

pub(crate) fn generate_isn(tuple: &[u8], secret: &[u8; 32]) -> SequenceNumber {
    let timer = timer_4us();

    let hash = HMAC::mac(secret, tuple);
    let truncated = u32::from_be_bytes(hash[0..4].try_into().unwrap());
    return SequenceNumber(timer.wrapping_add(truncated));
}
