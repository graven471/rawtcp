#[cfg(test)]
mod tests {
    use rawtcp::{
        error::Ipv4Error,
        net::ipv4::{IPV4_HEADER_LEN, IpProtocol, Ipv4Packet},
    };

    use std::net::Ipv4Addr;

    fn valid_header() -> [u8; IPV4_HEADER_LEN] {
        [
            0x45, // Version = 4, IHL = 5
            0xB9, // DSCP = 46, ECN = 1
            0x00, 0x54, // Total length = 84
            0x12, 0x34, // Identification = 0x1234
            0x40, 0x00, // Flags = DF, fragment offset = 0
            64,   // TTL
            17,   // Protocol = UDP
            0xAB, 0xCD, // Header checksum
            192, 168, 1, 10, // Source = 192.168.1.10
            8, 8, 8, 8, // Destination = 8.8.8.8
        ]
    }

    #[test]
    fn parses_valid_ipv4_header() {
        let bytes = valid_header();
        let packet = Ipv4Packet::parse(&bytes).unwrap();

        assert_eq!(packet.version, 4);
        assert_eq!(packet.ihl, 5);
        assert_eq!(packet.dscp, 46);
        assert_eq!(packet.ecn, 1);
        assert_eq!(packet.total_length, 84);
        assert_eq!(packet.identification, 0x1234);
        assert_eq!(packet.flags, 0b010);
        assert!(!packet.reserved);
        assert!(packet.df);
        assert!(!packet.mf);
        assert_eq!(packet.fragment_offset, 0);
        assert_eq!(packet.byte_offset, 0);
        assert_eq!(packet.ttl, 64);
        assert_eq!(packet.protocol, IpProtocol::Udp);
        assert_eq!(packet.checksum, 0xABCD);
        assert_eq!(packet.source, Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(packet.dest, Ipv4Addr::new(8, 8, 8, 8));
    }

    #[test]
    fn rejects_invalid_version() {
        let mut bytes = valid_header();
        bytes[0] = 0x65; // Version = 6, IHL = 5

        assert!(matches!(
            Ipv4Packet::parse(&bytes),
            Err(Ipv4Error::InvalidVersion(6))
        ));
    }

    #[test]
    fn rejects_ihl_less_than_five() {
        for ihl in 0..5 {
            let mut bytes = valid_header();
            bytes[0] = (4 << 4) | ihl;

            assert!(
                matches!(Ipv4Packet::parse(&bytes), Err(Ipv4Error::ParseError(_))),
                "expected IHL {ihl} to be rejected"
            );
        }
    }

    #[test]
    fn accepts_minimum_ihl() {
        let mut bytes = valid_header();
        bytes[0] = 0x45;

        let packet = Ipv4Packet::parse(&bytes).unwrap();

        assert_eq!(packet.ihl, 5);
    }

    #[test]
    fn accepts_maximum_ihl_value() {
        let mut bytes = valid_header();
        bytes[0] = 0x4F;

        let packet = Ipv4Packet::parse(&bytes).unwrap();

        assert_eq!(packet.ihl, 15);
    }

    #[test]
    fn parses_dscp_and_ecn_boundaries() {
        let cases = [
            (0b0000_0000, 0, 0),
            (0b0000_0011, 0, 3),
            (0b1111_1100, 63, 0),
            (0b1111_1111, 63, 3),
            (0b1010_1010, 42, 2),
        ];

        for (field, expected_dscp, expected_ecn) in cases {
            let mut bytes = valid_header();
            bytes[1] = field;

            let packet = Ipv4Packet::parse(&bytes).unwrap();

            assert_eq!(packet.dscp, expected_dscp);
            assert_eq!(packet.ecn, expected_ecn);
        }
    }

    #[test]
    fn parses_multibyte_fields_as_big_endian() {
        let mut bytes = valid_header();
        bytes[2..4].copy_from_slice(&0xABCDu16.to_be_bytes());
        bytes[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        bytes[10..12].copy_from_slice(&0xFEDCu16.to_be_bytes());

        let packet = Ipv4Packet::parse(&bytes).unwrap();

        assert_eq!(packet.total_length, 0xABCD);
        assert_eq!(packet.identification, 0x1234);
        assert_eq!(packet.checksum, 0xFEDC);
    }

    #[test]
    fn parses_all_flag_combinations() {
        for flags in 0u8..8 {
            let mut bytes = valid_header();
            bytes[6] = flags << 5;
            bytes[7] = 0;

            let packet = Ipv4Packet::parse(&bytes).unwrap();

            assert_eq!(packet.flags, flags);
            assert_eq!(packet.reserved, flags & 0b100 != 0);
            assert_eq!(packet.df, flags & 0b010 != 0);
            assert_eq!(packet.mf, flags & 0b001 != 0);
        }
    }

    #[test]
    fn parses_fragment_offset_zero() {
        let mut bytes = valid_header();
        bytes[6] = 0;
        bytes[7] = 0;

        let packet = Ipv4Packet::parse(&bytes).unwrap();

        assert_eq!(packet.fragment_offset, 0);
        assert_eq!(packet.byte_offset, 0);
    }

    #[test]
    fn parses_fragment_offset_one() {
        let mut bytes = valid_header();
        bytes[6] = 0;
        bytes[7] = 1;

        let packet = Ipv4Packet::parse(&bytes).unwrap();

        assert_eq!(packet.fragment_offset, 1);
        assert_eq!(packet.byte_offset, 8);
    }

    #[test]
    fn parses_fragment_offset_across_byte_boundary() {
        let mut bytes = valid_header();

        // Offset = 0b00001_00000001 = 257.
        bytes[6] = 0b0000_0001;
        bytes[7] = 0b0000_0001;

        let packet = Ipv4Packet::parse(&bytes).unwrap();

        assert_eq!(packet.fragment_offset, 257);
        assert_eq!(packet.byte_offset, 2056);
    }

    #[test]
    fn parses_maximum_fragment_offset() {
        let mut bytes = valid_header();

        // 13-bit fragment offset maximum: 8191.
        bytes[6] = 0b0001_1111;
        bytes[7] = 0b1111_1111;

        let packet = Ipv4Packet::parse(&bytes).unwrap();

        assert_eq!(packet.fragment_offset, 8191);
        assert_eq!(packet.byte_offset, 65_528);
    }

    #[test]
    fn fragment_offset_does_not_include_flag_bits() {
        let mut bytes = valid_header();

        // Reserved + DF + MF, with fragment offset 0x1234.
        bytes[6] = 0b1111_0010;
        bytes[7] = 0b0011_0100;

        let packet = Ipv4Packet::parse(&bytes).unwrap();

        assert_eq!(packet.flags, 0b111);
        assert!(packet.reserved);
        assert!(packet.df);
        assert!(packet.mf);
        assert_eq!(packet.fragment_offset, 0x1234);
        assert_eq!(packet.byte_offset, 0x1234 * 8);
    }

    #[test]
    fn parses_ttl_boundaries() {
        for ttl in [0, 1, 64, 128, 255] {
            let mut bytes = valid_header();
            bytes[8] = ttl;

            let packet = Ipv4Packet::parse(&bytes).unwrap();

            assert_eq!(packet.ttl, ttl);
        }
    }

    #[test]
    fn parses_ipv4_addresses_correctly() {
        let cases = [
            ([0, 0, 0, 0], [255, 255, 255, 255]),
            ([192, 168, 1, 10], [8, 8, 8, 8]),
            ([127, 0, 0, 1], [10, 20, 30, 40]),
            ([255, 0, 128, 1], [1, 128, 0, 255]),
        ];

        for (src, dst) in cases {
            let mut bytes = valid_header();
            bytes[12..16].copy_from_slice(&src);
            bytes[16..20].copy_from_slice(&dst);

            let packet = Ipv4Packet::parse(&bytes).unwrap();

            assert_eq!(packet.source, Ipv4Addr::from(src));
            assert_eq!(packet.dest, Ipv4Addr::from(dst));
        }
    }

    #[test]
    fn parses_source_and_destination_independently() {
        let mut bytes = valid_header();
        bytes[12..16].copy_from_slice(&[1, 2, 3, 4]);
        bytes[16..20].copy_from_slice(&[5, 6, 7, 8]);

        let packet = Ipv4Packet::parse(&bytes).unwrap();

        assert_eq!(packet.source, Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(packet.dest, Ipv4Addr::new(5, 6, 7, 8));
        assert_ne!(packet.source, packet.dest);
    }

    #[test]
    fn rejects_unsupported_protocol() {
        let mut bytes = valid_header();
        bytes[9] = 255;

        assert!(matches!(
            Ipv4Packet::parse(&bytes),
            Err(Ipv4Error::UnsupportedProtocol(_))
        ));
    }

    #[test]
    fn accepts_supported_protocol_values() {
        // Adjust this list to the variants supported by your IpProtocol enum.
        let supported = [IpProtocol::Icmp, IpProtocol::Tcp, IpProtocol::Udp];

        for protocol in supported {
            let mut bytes = valid_header();
            bytes[9] = protocol as u8;

            let packet = Ipv4Packet::parse(&bytes).unwrap();

            assert_eq!(packet.protocol, protocol);
        }
    }

    #[test]
    fn parses_total_length_boundaries() {
        for total_length in [0u16, 20, 60, 1500, u16::MAX] {
            let mut bytes = valid_header();
            bytes[2..4].copy_from_slice(&total_length.to_be_bytes());

            let packet = Ipv4Packet::parse(&bytes).unwrap();

            assert_eq!(packet.total_length, total_length);
        }
    }

    #[test]
    fn parses_identification_boundaries() {
        for identification in [0u16, 1, 0x00FF, 0xFF00, u16::MAX] {
            let mut bytes = valid_header();
            bytes[4..6].copy_from_slice(&identification.to_be_bytes());

            let packet = Ipv4Packet::parse(&bytes).unwrap();

            assert_eq!(packet.identification, identification);
        }
    }

    #[test]
    fn parses_zero_filled_header() {
        let mut bytes = [0u8; IPV4_HEADER_LEN];
        bytes[0] = 0x45;
        bytes[9] = IpProtocol::Udp as u8;

        let packet = Ipv4Packet::parse(&bytes).unwrap();

        assert_eq!(packet.version, 4);
        assert_eq!(packet.ihl, 5);
        assert_eq!(packet.total_length, 0);
        assert_eq!(packet.identification, 0);
        assert_eq!(packet.flags, 0);
        assert_eq!(packet.fragment_offset, 0);
        assert_eq!(packet.byte_offset, 0);
        assert_eq!(packet.source, Ipv4Addr::UNSPECIFIED);
        assert_eq!(packet.dest, Ipv4Addr::UNSPECIFIED);
    }
}
