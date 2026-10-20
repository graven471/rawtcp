#[cfg(test)]
mod tests {
    use rawtcp::{
        error::Ipv4Error,
        net::ipv4::{IPV4_HEADER_LEN, IpProtocol, Ipv4Header},
    };

    use std::net::Ipv4Addr;

    // ------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------

    fn valid_header_bytes() -> [u8; IPV4_HEADER_LEN] {
        let mut bytes = [0u8; IPV4_HEADER_LEN];

        bytes[0] = 0x45; // IPv4, IHL = 5 (20-byte header)
        bytes[1] = 0xB9; // DSCP = 46, ECN = 1
        bytes[2..4].copy_from_slice(&84u16.to_be_bytes());
        bytes[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        bytes[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
        bytes[8] = 64; // TTL
        bytes[9] = IpProtocol::Udp as u8;
        bytes[12..16].copy_from_slice(&[192, 168, 1, 10]);
        bytes[16..20].copy_from_slice(&[8, 8, 8, 8]);

        // Calculate the checksum from wire bytes, with checksum bytes zero.
        let checksum = ipv4_checksum(&bytes);
        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());

        bytes
    }

    // Independent checksum helper for test input bytes.
    // Returns zero when called on a valid header including its checksum.
    fn ipv4_checksum(bytes: &[u8]) -> u16 {
        assert_eq!(bytes.len() % 2, 0);

        let mut sum = 0u32;
        for word in bytes.chunks_exact(2) {
            sum += u16::from_be_bytes([word[0], word[1]]) as u32;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    fn bytes_with_checksum(mut bytes: [u8; IPV4_HEADER_LEN]) -> [u8; IPV4_HEADER_LEN] {
        bytes[10] = 0;
        bytes[11] = 0;
        let checksum = ipv4_checksum(&bytes);
        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        bytes
    }

    // ------------------------------------------------------------
    // Basic parsing and header layout
    // ------------------------------------------------------------

    #[test]
    fn header_size_is_twenty_bytes() {
        assert_eq!(core::mem::size_of::<Ipv4Header>(), IPV4_HEADER_LEN);
        assert_eq!(IPV4_HEADER_LEN, 20);
    }

    #[test]
    fn parses_valid_header() {
        let bytes = valid_header_bytes();
        let header = Ipv4Header::parse(&bytes).unwrap();

        assert_eq!(header.version(), 4);
        assert_eq!(header.total_length(), 84);
        assert_eq!(header.identification(), 0x1234);
        assert_eq!(header.ttl(), 64);
        assert_eq!(header.protocol(), IpProtocol::Udp);
        assert_eq!(header.source(), Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(header.destination(), Ipv4Addr::new(8, 8, 8, 8));
    }

    #[test]
    fn rejects_short_header() {
        let bytes = [0u8; IPV4_HEADER_LEN - 1];
        assert!(Ipv4Header::parse(&bytes).is_err());
    }

    #[test]
    fn accepts_trailing_bytes() {
        let mut bytes = valid_header_bytes().to_vec();
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        assert!(Ipv4Header::parse(&bytes).is_ok());
    }

    #[test]
    fn rejects_non_ipv4_version() {
        let mut bytes = valid_header_bytes();
        bytes[0] = 0x65;

        assert!(Ipv4Header::parse(&bytes).is_err());
    }

    #[test]
    fn rejects_ihl_below_five() {
        let mut bytes = valid_header_bytes();
        bytes[0] = 0x44;

        assert!(Ipv4Header::parse(&bytes).is_err());
    }

    #[test]
    fn rejects_ihl_above_five_when_options_are_unsupported() {
        let mut bytes = valid_header_bytes();
        bytes[0] = 0x46;

        assert!(Ipv4Header::parse(&bytes).is_err());
    }

    // ------------------------------------------------------------
    // Multibyte fields and boundaries
    // ------------------------------------------------------------

    #[test]
    fn parses_multibyte_fields_as_big_endian() {
        let mut bytes = valid_header_bytes();
        bytes[2..4].copy_from_slice(&0xABCDu16.to_be_bytes());
        bytes[4..6].copy_from_slice(&0x5678u16.to_be_bytes());
        let bytes = bytes_with_checksum(bytes);

        let header = Ipv4Header::parse(&bytes).unwrap();

        assert_eq!(header.total_length(), 0xABCD);
        assert_eq!(header.identification(), 0x5678);
    }

    #[test]
    fn parses_total_length_boundaries() {
        for length in [0u16, 20, 60, 1500, u16::MAX] {
            let mut bytes = valid_header_bytes();
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            let bytes = bytes_with_checksum(bytes);

            let header = Ipv4Header::parse(&bytes).unwrap();
            assert_eq!(header.total_length(), length);
        }
    }

    #[test]
    fn parses_identification_boundaries() {
        for identification in [0u16, 1, 0x00FF, 0xFF00, u16::MAX] {
            let mut bytes = valid_header_bytes();
            bytes[4..6].copy_from_slice(&identification.to_be_bytes());
            let bytes = bytes_with_checksum(bytes);

            let header = Ipv4Header::parse(&bytes).unwrap();
            assert_eq!(header.identification(), identification);
        }
    }

    // ------------------------------------------------------------
    // TTL, protocol, and addresses
    // ------------------------------------------------------------

    #[test]
    fn parses_ttl_boundaries() {
        for ttl in [0, 1, 64, 128, 255] {
            let mut bytes = valid_header_bytes();
            bytes[8] = ttl;
            let bytes = bytes_with_checksum(bytes);

            let header = Ipv4Header::parse(&bytes).unwrap();
            assert_eq!(header.ttl(), ttl);
        }
    }

    #[test]
    fn accepts_supported_protocols() {
        for protocol in [IpProtocol::Icmp, IpProtocol::Tcp, IpProtocol::Udp] {
            let mut bytes = valid_header_bytes();
            bytes[9] = protocol as u8;
            let bytes = bytes_with_checksum(bytes);

            let header = Ipv4Header::parse(&bytes).unwrap();
            assert_eq!(header.protocol(), protocol);
        }
    }

    #[test]
    fn rejects_unsupported_protocol() {
        let mut bytes = valid_header_bytes();
        bytes[9] = 255;
        let bytes = bytes_with_checksum(bytes);

        assert!(matches!(
            Ipv4Header::parse(&bytes),
            Err(Ipv4Error::UnsupportedProtocol(_))
        ));
    }

    #[test]
    fn parses_source_and_destination_addresses() {
        let cases = [
            ([0, 0, 0, 0], [255, 255, 255, 255]),
            ([192, 168, 1, 10], [8, 8, 8, 8]),
            ([127, 0, 0, 1], [10, 20, 30, 40]),
            ([255, 0, 128, 1], [1, 128, 0, 255]),
        ];

        for (source, destination) in cases {
            let mut bytes = valid_header_bytes();
            bytes[12..16].copy_from_slice(&source);
            bytes[16..20].copy_from_slice(&destination);
            let bytes = bytes_with_checksum(bytes);

            let header = Ipv4Header::parse(&bytes).unwrap();
            assert_eq!(header.source(), Ipv4Addr::from(source));
            assert_eq!(header.destination(), Ipv4Addr::from(destination));
        }
    }

    // ------------------------------------------------------------
    // Checksum validation
    // ------------------------------------------------------------

    #[test]
    fn known_minimal_header_checksum_is_baee() {
        let mut bytes = [0u8; IPV4_HEADER_LEN];
        bytes[0] = 0x45;
        bytes[9] = IpProtocol::Udp as u8;

        let checksum = ipv4_checksum(&bytes);
        assert_eq!(checksum, 0xBAEE);

        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(ipv4_checksum(&bytes), 0);
    }

    #[test]
    fn validate_checksum_accepts_valid_header() {
        let bytes = valid_header_bytes();
        let header = Ipv4Header::parse(&bytes).unwrap();

        assert!(matches!(header.validate_checksum(), Ok(())));
    }

    #[test]
    fn validate_checksum_rejects_corrupted_ttl() {
        let mut bytes = valid_header_bytes();
        bytes[8] ^= 0x01; // Change TTL without updating checksum.
        let header = Ipv4Header::parse(&bytes).unwrap();

        assert!(matches!(
            header.validate_checksum(),
            Err(Ipv4Error::InvalidChecksum)
        ));
    }

    #[test]
    fn validate_checksum_rejects_corrupted_checksum_field() {
        let mut bytes = valid_header_bytes();
        bytes[10] ^= 0x01;
        let header = Ipv4Header::parse(&bytes).unwrap();

        assert!(matches!(
            header.validate_checksum(),
            Err(Ipv4Error::InvalidChecksum)
        ));
    }

    #[test]
    fn validate_checksum_rejects_corrupted_source_address() {
        let mut bytes = valid_header_bytes();
        bytes[12] ^= 0x80;
        let header = Ipv4Header::parse(&bytes).unwrap();

        assert!(matches!(
            header.validate_checksum(),
            Err(Ipv4Error::InvalidChecksum)
        ));
    }

    #[test]
    fn validate_checksum_rejects_corrupted_total_length() {
        let mut bytes = valid_header_bytes();
        bytes[2] ^= 0x01;
        let header = Ipv4Header::parse(&bytes).unwrap();

        assert!(matches!(
            header.validate_checksum(),
            Err(Ipv4Error::InvalidChecksum)
        ));
    }

    #[test]
    fn validate_checksum_rejects_corrupted_flags_and_fragment_offset() {
        let mut bytes = valid_header_bytes();
        bytes[6] ^= 0x20;
        let header = Ipv4Header::parse(&bytes).unwrap();

        assert!(matches!(
            header.validate_checksum(),
            Err(Ipv4Error::InvalidChecksum)
        ));
    }
}
