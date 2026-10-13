#[cfg(test)]
mod tests {
    use bytemuck::bytes_of;
    use rawtcp::{
        error::TcpHeaderError,
        wire::tcp_header::{TcpFlags, TcpHeader},
    };

    const HEADER_LEN: usize = 20;

    fn valid_header_bytes() -> [u8; HEADER_LEN] {
        [
            0x1F, 0x90, // src_port: 8080
            0x00, 0x50, // dst_port: 80
            0x12, 0x34, 0x56, 0x78, // seq_number
            0x9A, 0xBC, 0xDE, 0xF0, // ack_number
            0x50, // data offset = 5, reserved = 0, NS = 0
            0x12, // SYN | ACK
            0x20, 0x00, // window_size
            0xAB, 0xCD, // checksum
            0xEF, 0x01, // urgent_pointer
        ]
    }

    fn parse_bytes(bytes: &[u8]) -> Result<TcpHeader, TcpHeaderError> {
        TcpHeader::parse(bytes)
    }

    // ---------------------------------------------------------
    // 1. Structure layout and wire representation
    // ---------------------------------------------------------

    #[test]
    fn header_size_is_exactly_20_bytes() {
        assert_eq!(core::mem::size_of::<TcpHeader>(), HEADER_LEN);
    }

    #[test]
    fn parsed_header_preserves_wire_byte_representation() {
        let bytes = valid_header_bytes();
        let header = parse_bytes(&bytes).unwrap();

        assert_eq!(bytes_of(&header), &bytes);
    }

    // ---------------------------------------------------------
    // 2. Input length boundaries
    // ---------------------------------------------------------

    #[test]
    fn rejects_every_input_length_below_20() {
        let bytes = valid_header_bytes();

        for len in 0..HEADER_LEN {
            assert!(
                matches!(
                    parse_bytes(&bytes[..len]),
                    Err(TcpHeaderError::TruncatedHeader)
                ),
                "unexpected result for input length {len}"
            );
        }
    }

    #[test]
    fn accepts_exactly_20_bytes() {
        assert!(parse_bytes(&valid_header_bytes()).is_ok());
    }

    #[test]
    fn accepts_input_longer_than_20_bytes() {
        let mut bytes = valid_header_bytes().to_vec();
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        assert!(parse_bytes(&bytes).is_ok());
    }

    #[test]
    fn trailing_bytes_do_not_change_parsed_fields() {
        let bytes = valid_header_bytes();
        let expected = parse_bytes(&bytes).unwrap();

        let mut extended = bytes.to_vec();
        extended.extend_from_slice(&[0xFF; 64]);
        let actual = parse_bytes(&extended).unwrap();

        assert_eq!(actual.src_port(), expected.src_port());
        assert_eq!(actual.dst_port(), expected.dst_port());
        assert_eq!(actual.seq_number(), expected.seq_number());
        assert_eq!(actual.ack_number(), expected.ack_number());
        assert_eq!(actual.offset(), expected.offset());
        assert_eq!(actual.flags(), expected.flags());
        assert_eq!(actual.window_size(), expected.window_size());
        assert_eq!(actual.checksum(), expected.checksum());
        assert_eq!(bytes_of(&actual), bytes_of(&expected));
    }

    // ---------------------------------------------------------
    // 3. Successful parsing of every exposed field
    // ---------------------------------------------------------

    #[test]
    fn parses_all_fields_correctly() {
        let header = parse_bytes(&valid_header_bytes()).unwrap();

        assert_eq!(header.src_port(), 8080);
        assert_eq!(header.dst_port(), 80);
        assert_eq!(header.seq_number(), 0x1234_5678);
        assert_eq!(header.ack_number(), 0x9ABC_DEF0);
        assert_eq!(header.offset(), 5);
        assert!(!header.has_options());
        assert_eq!(header.flags(), TcpFlags::Syn | TcpFlags::Ack);
        assert_eq!(header.window_size(), 0x2000);
        assert_eq!(header.checksum(), 0xABCD);

        // urgent_pointer currently has no getter; verify its wire bytes.
        assert_eq!(&bytes_of(&header)[18..20], &[0xEF, 0x01]);
    }

    #[test]
    fn parses_zero_valued_fields() {
        let mut bytes = valid_header_bytes();
        bytes[0..12].fill(0);
        bytes[13] = 0;
        bytes[14..20].fill(0);

        let header = parse_bytes(&bytes).unwrap();

        assert_eq!(header.src_port(), 0);
        assert_eq!(header.dst_port(), 0);
        assert_eq!(header.seq_number(), 0);
        assert_eq!(header.ack_number(), 0);
        assert_eq!(header.flags(), TcpFlags::empty());
        assert_eq!(header.window_size(), 0);
        assert_eq!(header.checksum(), 0);
        assert_eq!(&bytes_of(&header)[18..20], &[0, 0]);
    }

    #[test]
    fn parses_maximum_valued_fields() {
        let mut bytes = valid_header_bytes();
        bytes[0..12].fill(0xFF);
        bytes[14..20].fill(0xFF);

        let header = parse_bytes(&bytes).unwrap();

        assert_eq!(header.src_port(), u16::MAX);
        assert_eq!(header.dst_port(), u16::MAX);
        assert_eq!(header.seq_number(), u32::MAX);
        assert_eq!(header.ack_number(), u32::MAX);
        assert_eq!(header.window_size(), u16::MAX);
        assert_eq!(header.checksum(), u16::MAX);
        assert_eq!(&bytes_of(&header)[18..20], &[0xFF, 0xFF]);
    }

    // ---------------------------------------------------------
    // 4. Big-endian decoding through host-order getters
    // ---------------------------------------------------------

    #[test]
    fn decodes_ports_as_big_endian() {
        let mut bytes = valid_header_bytes();
        bytes[0..4].copy_from_slice(&[0x01, 0x23, 0xAB, 0xCD]);

        let header = parse_bytes(&bytes).unwrap();

        assert_eq!(header.src_port(), 0x0123);
        assert_eq!(header.dst_port(), 0xABCD);
    }

    #[test]
    fn decodes_sequence_number_as_big_endian() {
        let mut bytes = valid_header_bytes();
        bytes[4..8].copy_from_slice(&[0x01, 0x23, 0x45, 0x67]);

        assert_eq!(parse_bytes(&bytes).unwrap().seq_number(), 0x0123_4567);
    }

    #[test]
    fn decodes_acknowledgment_number_as_big_endian() {
        let mut bytes = valid_header_bytes();
        bytes[8..12].copy_from_slice(&[0x89, 0xAB, 0xCD, 0xEF]);

        assert_eq!(parse_bytes(&bytes).unwrap().ack_number(), 0x89AB_CDEF);
    }

    #[test]
    fn decodes_window_and_checksum_as_big_endian() {
        let mut bytes = valid_header_bytes();
        bytes[14..16].copy_from_slice(&[0x01, 0xFE]);
        bytes[16..18].copy_from_slice(&[0x23, 0xDC]);

        let header = parse_bytes(&bytes).unwrap();

        assert_eq!(header.window_size(), 0x01FE);
        assert_eq!(header.checksum(), 0x23DC);
    }

    // ---------------------------------------------------------
    // 5. Setters store values in wire byte order
    // ---------------------------------------------------------

    #[test]
    fn setters_expose_host_order_and_store_big_endian_bytes() {
        // Construct a valid zero-valued header through the parser.
        let mut header = parse_bytes(&{
            let mut bytes = valid_header_bytes();
            bytes[0..12].fill(0);
            bytes[13] = 0;
            bytes[14..20].fill(0);
            bytes
        })
        .unwrap();

        header.set_src_port(0x1234);
        header.set_dst_port(0xABCD);
        header.set_seq_number(0x1234_5678);
        header.set_ack_number(0x9ABC_DEF0);
        header.set_window(0x1357);
        header.set_checksum(0x2468);

        assert_eq!(header.src_port(), 0x1234);
        assert_eq!(header.dst_port(), 0xABCD);
        assert_eq!(header.seq_number(), 0x1234_5678);
        assert_eq!(header.ack_number(), 0x9ABC_DEF0);
        assert_eq!(header.window_size(), 0x1357);
        assert_eq!(header.checksum(), 0x2468);

        let wire = bytes_of(&header);
        assert_eq!(&wire[0..2], &[0x12, 0x34]);
        assert_eq!(&wire[2..4], &[0xAB, 0xCD]);
        assert_eq!(&wire[4..8], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(&wire[8..12], &[0x9A, 0xBC, 0xDE, 0xF0]);
        assert_eq!(&wire[14..16], &[0x13, 0x57]);
        assert_eq!(&wire[16..18], &[0x24, 0x68]);
    }

    // ---------------------------------------------------------
    // 6. TCP data offset validation
    // ---------------------------------------------------------

    #[test]
    fn accepts_minimum_data_offset() {
        let mut bytes = valid_header_bytes();
        bytes[12] = 0x50;

        let header = parse_bytes(&bytes).unwrap();

        assert_eq!(header.offset(), 5);
        assert!(!header.has_options());
    }

    #[test]
    fn accepts_every_valid_data_offset_value() {
        let mut bytes = valid_header_bytes();

        for offset in 5u8..=15 {
            bytes[12] = offset << 4;

            let header = parse_bytes(&bytes)
                .unwrap_or_else(|_| panic!("data offset {offset} should be accepted"));

            assert_eq!(header.offset(), offset);
            assert_eq!(header.has_options(), offset != 5);
        }
    }

    #[test]
    fn rejects_every_data_offset_below_five() {
        let mut bytes = valid_header_bytes();

        for offset in 0u8..5 {
            bytes[12] = offset << 4;

            assert!(
                matches!(
                    parse_bytes(&bytes),
                    Err(TcpHeaderError::InvalidDataOffset(actual))
                        if actual == offset as usize
                ),
                "data offset {offset} should be rejected"
            );
        }
    }

    #[test]
    fn accepts_maximum_data_offset_with_only_20_input_bytes() {
        let mut bytes = valid_header_bytes();
        bytes[12] = 0xF0;

        // parse() validates the fixed header only; it does not validate
        // that the input contains all TCP option bytes.
        assert_eq!(parse_bytes(&bytes).unwrap().offset(), 15);
    }

    // ---------------------------------------------------------
    // 7. Reserved bits validation
    // ---------------------------------------------------------

    #[test]
    fn accepts_zero_reserved_bits() {
        let mut bytes = valid_header_bytes();
        bytes[12] = 0x50;

        assert!(parse_bytes(&bytes).is_ok());
    }

    #[test]
    fn rejects_each_reserved_bit_individually() {
        let mut bytes = valid_header_bytes();

        for reserved_bit in [0x02, 0x04, 0x08] {
            bytes[12] = 0x50 | reserved_bit;

            assert!(
                matches!(
                    parse_bytes(&bytes),
                    Err(TcpHeaderError::InvalidReservedBits)
                ),
                "reserved bit {reserved_bit:#04x} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_every_nonzero_reserved_bit_combination() {
        let mut bytes = valid_header_bytes();

        for reserved in 1u8..=7 {
            bytes[12] = 0x50 | (reserved << 1);

            assert!(
                matches!(
                    parse_bytes(&bytes),
                    Err(TcpHeaderError::InvalidReservedBits)
                ),
                "reserved-bit combination {reserved:#05b} should be rejected"
            );
        }
    }

    #[test]
    fn accepts_ns_bit_when_reserved_bits_are_zero() {
        let mut bytes = valid_header_bytes();
        bytes[12] = 0x51;

        assert!(parse_bytes(&bytes).is_ok());
    }

    #[test]
    fn ns_bit_does_not_change_data_offset() {
        let mut bytes = valid_header_bytes();
        bytes[12] = 0x51;

        let header = parse_bytes(&bytes).unwrap();

        assert_eq!(header.offset(), 5);
        assert_eq!(bytes_of(&header)[12], 0x51);
    }

    // ---------------------------------------------------------
    // 8. TCP flags
    // ---------------------------------------------------------

    #[test]
    fn accepts_empty_flags() {
        let mut bytes = valid_header_bytes();
        bytes[13] = 0;

        assert_eq!(parse_bytes(&bytes).unwrap().flags(), TcpFlags::empty());
    }

    #[test]
    fn accepts_each_defined_flag_individually() {
        let cases = [
            (0x01, TcpFlags::Fin),
            (0x02, TcpFlags::Syn),
            (0x04, TcpFlags::Rst),
            (0x08, TcpFlags::Psh),
            (0x10, TcpFlags::Ack),
            (0x20, TcpFlags::Urg),
        ];

        for (wire_value, expected) in cases {
            let mut bytes = valid_header_bytes();
            bytes[13] = wire_value;

            assert_eq!(
                parse_bytes(&bytes).unwrap().flags(),
                expected,
                "flag byte {wire_value:#04x}"
            );
        }
    }

    #[test]
    fn accepts_all_combinations_of_defined_flags() {
        let mut bytes = valid_header_bytes();

        for flags in 0u8..=0x3F {
            bytes[13] = flags;

            let header = parse_bytes(&bytes)
                .unwrap_or_else(|_| panic!("flag combination {flags:#04x} should be accepted"));

            assert_eq!(header.flags().bits(), flags);
            assert_eq!(bytes_of(&header)[13], flags);
        }
    }

    #[test]
    fn undefined_flag_bits_are_preserved_in_wire_bytes_but_truncated_by_flags_getter() {
        let mut bytes = valid_header_bytes();

        for unknown_bit in [0x40, 0x80, 0xC0] {
            bytes[13] = unknown_bit | 0x12;

            let header = parse_bytes(&bytes).unwrap();

            assert_eq!(bytes_of(&header)[13], unknown_bit | 0x12);
            assert_eq!(header.flags(), TcpFlags::Syn | TcpFlags::Ack);
        }
    }

    // ---------------------------------------------------------
    // 9. Validation precedence
    // ---------------------------------------------------------

    #[test]
    fn truncated_input_takes_precedence_over_invalid_fields() {
        let mut bytes = valid_header_bytes();
        bytes[12] = 0x00;
        bytes[13] = 0xC0;

        for len in 0..HEADER_LEN {
            assert!(
                matches!(
                    parse_bytes(&bytes[..len]),
                    Err(TcpHeaderError::TruncatedHeader)
                ),
                "input length {len}"
            );
        }
    }

    #[test]
    fn invalid_data_offset_takes_precedence_over_reserved_bits() {
        let mut bytes = valid_header_bytes();

        // Offset 4 is invalid; bit 1 is also reserved.
        bytes[12] = 0x42;

        assert!(matches!(
            parse_bytes(&bytes),
            Err(TcpHeaderError::InvalidDataOffset(offset)) if offset == 4
        ));
    }

    // ---------------------------------------------------------
    // 10. Independence of fields
    // ---------------------------------------------------------

    #[test]
    fn changing_flags_does_not_change_other_fields() {
        let mut bytes = valid_header_bytes();
        let original = parse_bytes(&bytes).unwrap();

        bytes[13] = 0x2F;
        let modified = parse_bytes(&bytes).unwrap();

        assert_eq!(modified.src_port(), original.src_port());
        assert_eq!(modified.dst_port(), original.dst_port());
        assert_eq!(modified.seq_number(), original.seq_number());
        assert_eq!(modified.ack_number(), original.ack_number());
        assert_eq!(modified.offset(), original.offset());
        assert_eq!(modified.window_size(), original.window_size());
        assert_eq!(modified.checksum(), original.checksum());
        assert_eq!(&bytes_of(&modified)[0..13], &bytes_of(&original)[0..13]);
        assert_eq!(&bytes_of(&modified)[14..20], &bytes_of(&original)[14..20]);
    }

    #[test]
    fn changing_one_port_byte_does_not_change_other_fields() {
        let bytes = valid_header_bytes();
        let original = parse_bytes(&bytes).unwrap();

        let mut modified_bytes = bytes;
        modified_bytes[0] ^= 0xFF;
        let modified = parse_bytes(&modified_bytes).unwrap();

        assert_ne!(modified.src_port(), original.src_port());
        assert_eq!(modified.dst_port(), original.dst_port());
        assert_eq!(modified.seq_number(), original.seq_number());
        assert_eq!(modified.ack_number(), original.ack_number());
        assert_eq!(modified.flags(), original.flags());
        assert_eq!(modified.window_size(), original.window_size());
        assert_eq!(modified.checksum(), original.checksum());
    }
}
