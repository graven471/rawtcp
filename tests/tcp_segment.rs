#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use bytemuck::bytes_of;
    use rawtcp::{
        error::Error,
        net::ipv4::{IPV4_HEADER_LEN, IpProtocol, Ipv4Header},
        wire::{tcp_header::TcpFlags, tcp_segment::TcpSegment},
    };

    const TCP_HEADER_LEN: usize = 20;
    const SRC_IP: [u8; 4] = [192, 168, 1, 10];
    const DST_IP: [u8; 4] = [192, 168, 1, 20];

    fn make_packet(
        ipv4_header_len: usize,
        tcp_header_len: usize,
        payload: &[u8],
    ) -> (Ipv4Header, Vec<u8>) {
        assert_eq!(ipv4_header_len, IPV4_HEADER_LEN);
        assert!(tcp_header_len >= TCP_HEADER_LEN && tcp_header_len <= 60);
        assert_eq!(tcp_header_len % 4, 0);

        let total_len = ipv4_header_len + tcp_header_len + payload.len();
        let mut bytes = vec![0u8; total_len];

        // IPv4 header.
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        bytes[8] = 64;
        bytes[9] = IpProtocol::Tcp as u8;
        bytes[12..16].copy_from_slice(&SRC_IP);
        bytes[16..20].copy_from_slice(&DST_IP);

        // TCP fixed header.
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

    // Independent checksum implementation for test fixtures.
    // TCP checksum words are interpreted in network (big-endian) order.
    fn reference_tcp_checksum(src: [u8; 4], dst: [u8; 4], tcp: &[u8]) -> u16 {
        let mut pseudo_and_segment = Vec::with_capacity(12 + tcp.len());
        pseudo_and_segment.extend_from_slice(&src);
        pseudo_and_segment.extend_from_slice(&dst);
        pseudo_and_segment.extend_from_slice(&[0, IpProtocol::Tcp as u8]);
        pseudo_and_segment.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        pseudo_and_segment.extend_from_slice(tcp);

        let mut sum = 0u64;
        for pair in pseudo_and_segment.chunks(2) {
            let word = match pair {
                [hi, lo] => u16::from_be_bytes([*hi, *lo]),
                [hi] => u16::from_be_bytes([*hi, 0]),
                _ => unreachable!(),
            };
            sum += u64::from(word);
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    fn make_packet_with_valid_tcp_checksum(
        ipv4_header_len: usize,
        tcp_header_len: usize,
        payload: &[u8],
    ) -> (Ipv4Header, Vec<u8>) {
        let (ipv4, mut bytes) = make_packet(ipv4_header_len, tcp_header_len, payload);
        let tcp_start = ipv4_header_len;
        let tcp_end = bytes.len();

        // Checksum field is already zero in the fixture.
        let checksum = reference_tcp_checksum(SRC_IP, DST_IP, &bytes[tcp_start..tcp_end]);
        bytes[tcp_start + 16..tcp_start + 18].copy_from_slice(&checksum.to_be_bytes());

        (ipv4, bytes)
    }

    fn parse_segment<'a>(ipv4: &Ipv4Header, bytes: &'a [u8]) -> TcpSegment<'a> {
        TcpSegment::parse(ipv4, bytes).expect("segment should parse")
    }

    // ---------------------------------------------------------
    // Successful parsing
    // ---------------------------------------------------------

    #[test]
    fn parses_tcp_header_and_payload() {
        let payload = b"hello, TCP!";
        let (ipv4, bytes) = make_packet_with_valid_tcp_checksum(20, 20, payload);

        let segment = parse_segment(&ipv4, &bytes);

        assert_eq!(segment.header.src_port(), 12345);
        assert_eq!(segment.header.dst_port(), 80);
        assert_eq!(segment.header.seq_number(), 1000);
        assert_eq!(segment.header.ack_number(), 2000);
        assert_eq!(segment.header.flags(), TcpFlags::Syn);
        assert_eq!(segment.header.window_size(), 4096);
        assert_eq!(segment.payload, payload);
    }

    #[test]
    fn parses_empty_payload() {
        let (ipv4, bytes) = make_packet_with_valid_tcp_checksum(20, 20, &[]);

        let segment = parse_segment(&ipv4, &bytes);

        assert!(segment.payload.is_empty());
        assert_eq!(segment.header.src_port(), 12345);
        assert_eq!(segment.header.dst_port(), 80);
    }

    #[test]
    fn parses_tcp_header_with_options() {
        let payload = b"data";
        let (ipv4, bytes) = make_packet_with_valid_tcp_checksum(20, 24, payload);

        let segment = parse_segment(&ipv4, &bytes);

        assert_eq!(segment.payload, payload);
        assert_eq!(segment.header.src_port(), 12345);
        assert_eq!(segment.header.offset(), 6);
        assert!(segment.header.has_options());
    }

    #[test]
    fn parses_maximum_tcp_header_length() {
        let payload = b"x";
        let (ipv4, bytes) = make_packet_with_valid_tcp_checksum(20, 60, payload);

        let segment = parse_segment(&ipv4, &bytes);

        assert_eq!(segment.payload, payload);
        assert_eq!(segment.header.offset(), 15);
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
            Err(Error::TruncatedPacket(_))
        ));
    }

    #[test]
    fn rejects_truncated_tcp_options() {
        let (ipv4, mut bytes) = make_packet(20, 24, b"payload");
        // Keep the full fixed header but truncate the declared TCP options.
        bytes.truncate(20 + 22);

        assert!(matches!(
            TcpSegment::parse(&ipv4, &bytes),
            Err(Error::TruncatedPacket(_))
        ));
    }

    // ---------------------------------------------------------
    // Payload boundaries
    // ---------------------------------------------------------

    #[test]
    fn payload_excludes_ipv4_and_tcp_headers() {
        let payload = [0xAA, 0xBB, 0xCC, 0xDD];
        let (ipv4, bytes) = make_packet_with_valid_tcp_checksum(20, 24, &payload);

        let segment = parse_segment(&ipv4, &bytes);

        assert_eq!(segment.payload, &payload);
    }

    #[test]
    fn ignores_bytes_beyond_ipv4_total_length() {
        let payload = b"actual payload";
        let (ipv4, mut bytes) = make_packet_with_valid_tcp_checksum(20, 20, payload);
        bytes.extend_from_slice(b"EXTRA");

        let segment = parse_segment(&ipv4, &bytes);

        assert_eq!(segment.payload, payload);
    }

    #[test]
    fn rejects_tcp_header_length_beyond_available_segment() {
        let (ipv4, mut bytes) = make_packet(20, 20, b"");
        bytes[20 + 12] = 0xF0;

        assert!(matches!(
            TcpSegment::parse(&ipv4, &bytes),
            Err(Error::TcpHeader(_))
        ));
    }

    // ---------------------------------------------------------
    // TCP checksum calculation
    // ---------------------------------------------------------

    #[test]
    fn calculates_checksum_for_header_without_payload() {
        let (ipv4, bytes) = make_packet(20, 20, b"");
        let mut segment = TcpSegment::parse(&ipv4, &bytes).unwrap();

        let checksum = segment.calculate_checksum(Ipv4Addr::from(SRC_IP), Ipv4Addr::from(DST_IP));

        assert_eq!(segment.header.checksum(), checksum);
        assert_ne!(checksum, 0);

        // The generated checksum should make the one's-complement sum
        // of pseudo-header + complete TCP segment equal 0xFFFF.
        let mut tcp = bytes_of(&segment.header).to_vec();
        tcp.extend_from_slice(segment.payload);

        let expected = reference_tcp_checksum(SRC_IP, DST_IP, &{
            let mut tcp_with_zero_checksum = tcp.clone();
            tcp_with_zero_checksum[16..18].fill(0);
            tcp_with_zero_checksum
        });

        assert_eq!(checksum, expected);
    }

    #[test]
    fn calculates_checksum_for_even_length_payload() {
        let payload = b"even";
        let (ipv4, bytes) = make_packet(20, 20, payload);
        let mut segment = TcpSegment::parse(&ipv4, &bytes).unwrap();

        let checksum = segment.calculate_checksum(Ipv4Addr::from(SRC_IP), Ipv4Addr::from(DST_IP));

        let mut tcp = bytes_of(&segment.header).to_vec();
        tcp[16..18].fill(0);
        tcp.extend_from_slice(payload);

        assert_eq!(checksum, reference_tcp_checksum(SRC_IP, DST_IP, &tcp));
    }

    #[test]
    fn calculates_checksum_for_odd_length_payload() {
        let payload = b"odd!";
        let odd_payload = &payload[..3];
        let (ipv4, bytes) = make_packet(20, 20, odd_payload);
        let mut segment = TcpSegment::parse(&ipv4, &bytes).unwrap();

        let checksum = segment.calculate_checksum(Ipv4Addr::from(SRC_IP), Ipv4Addr::from(DST_IP));

        let mut tcp = bytes_of(&segment.header).to_vec();
        tcp[16..18].fill(0);
        tcp.extend_from_slice(odd_payload);

        assert_eq!(checksum, reference_tcp_checksum(SRC_IP, DST_IP, &tcp));
    }

    #[test]
    fn checksum_changes_when_payload_changes() {
        let (ipv4_a, bytes_a) = make_packet(20, 20, b"alpha");
        let (ipv4_b, bytes_b) = make_packet(20, 20, b"bravo");
        let mut segment_a = TcpSegment::parse(&ipv4_a, &bytes_a).unwrap();
        let mut segment_b = TcpSegment::parse(&ipv4_b, &bytes_b).unwrap();

        let checksum_a =
            segment_a.calculate_checksum(Ipv4Addr::from(SRC_IP), Ipv4Addr::from(DST_IP));
        let checksum_b =
            segment_b.calculate_checksum(Ipv4Addr::from(SRC_IP), Ipv4Addr::from(DST_IP));

        assert_ne!(checksum_a, checksum_b);
    }

    #[test]
    fn checksum_depends_on_pseudo_header_addresses() {
        let (ipv4, bytes) = make_packet(20, 20, b"same payload");
        let mut segment_a = TcpSegment::parse(&ipv4, &bytes).unwrap();
        let mut segment_b = TcpSegment::parse(&ipv4, &bytes).unwrap();

        let checksum_a = segment_a.calculate_checksum(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 20),
        );
        let checksum_b = segment_b.calculate_checksum(
            Ipv4Addr::new(192, 168, 1, 11),
            Ipv4Addr::new(192, 168, 1, 20),
        );

        assert_ne!(checksum_a, checksum_b);
    }

    #[test]
    fn generated_checksum_is_encoded_in_network_byte_order() {
        let (ipv4, bytes) = make_packet(20, 20, b"wire bytes");
        let mut segment = TcpSegment::parse(&ipv4, &bytes).unwrap();

        let checksum = segment.calculate_checksum(Ipv4Addr::from(SRC_IP), Ipv4Addr::from(DST_IP));

        assert_eq!(&bytes_of(&segment.header)[16..18], &checksum.to_be_bytes());
    }
}
