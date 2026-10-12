#[cfg(test)]
mod tests {
    use rawtcp::{
        error::{Error, TcpHeaderError},
        net::ipv4::{IPV4_HEADER_LEN, IpProtocol, Ipv4Header},
        wire::{tcp_header::TcpFlags, tcp_segment::TcpSegment},
    };

    fn make_packet(
        ipv4_header_len: usize,
        tcp_header_len: usize,
        payload: &[u8],
    ) -> (Ipv4Header, Vec<u8>) {
        assert_eq!(ipv4_header_len, IPV4_HEADER_LEN);
        assert!(tcp_header_len >= 20 && tcp_header_len <= 60);
        assert_eq!(tcp_header_len % 4, 0);

        let total_len = ipv4_header_len + tcp_header_len + payload.len();
        let mut bytes = vec![0u8; total_len];

        // IPv4 header.
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        bytes[8] = 64;
        bytes[9] = IpProtocol::Tcp as u8;
        bytes[12..16].copy_from_slice(&[192, 168, 1, 10]);
        bytes[16..20].copy_from_slice(&[192, 168, 1, 20]);

        // TCP header.
        let tcp_start = ipv4_header_len;

        bytes[tcp_start..tcp_start + 2].copy_from_slice(&12345u16.to_be_bytes());
        bytes[tcp_start + 2..tcp_start + 4].copy_from_slice(&80u16.to_be_bytes());
        bytes[tcp_start + 4..tcp_start + 8].copy_from_slice(&1000u32.to_be_bytes());
        bytes[tcp_start + 8..tcp_start + 12].copy_from_slice(&2000u32.to_be_bytes());

        bytes[tcp_start + 12] = ((tcp_header_len / 4) as u8) << 4;
        bytes[tcp_start + 13] = 0x02; // SYN
        bytes[tcp_start + 14..tcp_start + 16].copy_from_slice(&4096u16.to_be_bytes());

        let payload_start = tcp_start + tcp_header_len;
        bytes[payload_start..].copy_from_slice(payload);

        let ipv4 = Ipv4Header::parse(&bytes[..IPV4_HEADER_LEN])
            .expect("test packet must contain a valid IPv4 header");

        (ipv4, bytes)
    }

    // ---------------------------------------------------------
    // Successful parsing
    // ---------------------------------------------------------

    #[test]
    fn parses_tcp_header_and_payload() {
        let payload = b"hello, TCP!";
        let (ipv4, bytes) = make_packet(20, 20, payload);

        let segment = TcpSegment::parse(&ipv4, &bytes).unwrap();

        assert_eq!(segment.header.src_port, 12345);
        assert_eq!(segment.header.dst_port, 80);
        assert_eq!(segment.header.seq_number, 1000);
        assert_eq!(segment.header.ack_number, 2000);
        assert_eq!(segment.header.flags, TcpFlags::Syn);
        assert_eq!(segment.header.window_size, 4096);
        assert_eq!(segment.payload, payload);
    }

    #[test]
    fn parses_empty_payload() {
        let (ipv4, bytes) = make_packet(20, 20, &[]);

        let segment = TcpSegment::parse(&ipv4, &bytes).unwrap();

        assert!(segment.payload.is_empty());
        assert_eq!(segment.header.src_port, 12345);
        assert_eq!(segment.header.dst_port, 80);
    }

    #[test]
    fn parses_tcp_header_with_options() {
        let payload = b"data";
        let (ipv4, bytes) = make_packet(20, 24, payload);

        let segment = TcpSegment::parse(&ipv4, &bytes).unwrap();

        assert_eq!(segment.payload, payload);
        assert_eq!(segment.header.src_port, 12345);
    }

    #[test]
    fn parses_maximum_tcp_header_length() {
        let payload = b"x";
        let (ipv4, bytes) = make_packet(20, 60, payload);

        let segment = TcpSegment::parse(&ipv4, &bytes).unwrap();

        assert_eq!(segment.payload, payload);
    }

    // ---------------------------------------------------------
    // Truncated input
    // ---------------------------------------------------------

    #[test]
    fn rejects_truncated_tcp_header() {
        let (ipv4, mut bytes) = make_packet(20, 20, b"payload");

        bytes.truncate(20 + 19);

        assert_eq!(ipv4.total_length(), 47);

        assert!(matches!(
            TcpSegment::parse(&ipv4, &bytes),
            Err(Error::TcpHeader(TcpHeaderError::TruncatedHeader))
        ));
    }

    #[test]
    fn rejects_truncated_tcp_options() {
        let (ipv4, mut bytes) = make_packet(20, 24, b"payload");

        // Keep the complete 20-byte TCP base header but truncate its options.
        bytes.truncate(20 + 22);

        assert!(matches!(
            TcpSegment::parse(&ipv4, &bytes),
            Err(Error::TcpHeader(TcpHeaderError::TruncatedHeader))
        ));
    }

    // ---------------------------------------------------------
    // Payload boundaries
    // ---------------------------------------------------------

    #[test]
    fn payload_excludes_ipv4_and_tcp_headers() {
        let payload = [0xAA, 0xBB, 0xCC, 0xDD];
        let (ipv4, bytes) = make_packet(20, 24, &payload);

        let segment = TcpSegment::parse(&ipv4, &bytes).unwrap();

        assert_eq!(segment.payload, &payload);
    }

    #[test]
    fn ignores_bytes_beyond_ipv4_total_length() {
        let payload = b"actual payload";
        let (ipv4, mut bytes) = make_packet(20, 20, payload);

        bytes.extend_from_slice(b"EXTRA");

        let segment = TcpSegment::parse(&ipv4, &bytes).unwrap();

        assert_eq!(segment.payload, payload);
    }

    #[test]
    fn rejects_tcp_header_length_beyond_available_segment() {
        let (ipv4, mut bytes) = make_packet(20, 20, b"");

        // TCP header starts at byte 20; data offset is the high nibble.
        bytes[20 + 12] = 0xF0;

        assert!(matches!(
            TcpSegment::parse(&ipv4, &bytes),
            Err(Error::TcpHeader(_))
        ));
    }
}
