#[cfg(test)]
mod tests {
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
    // 1. Structure layout
    // ---------------------------------------------------------

    #[test]
    fn header_size_is_exactly_20_bytes() {
        assert_eq!(core::mem::size_of::<TcpHeader>(), HEADER_LEN);
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
        let bytes = valid_header_bytes();
        assert!(parse_bytes(&bytes).is_ok());
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

        assert_eq!(actual.src_port, expected.src_port);
        assert_eq!(actual.dst_port, expected.dst_port);
        assert_eq!(actual.seq_number, expected.seq_number);
        assert_eq!(actual.ack_number, expected.ack_number);
        assert_eq!(actual.data_offset, expected.data_offset);
        assert_eq!(actual.flags, expected.flags);
        assert_eq!(actual.window_size, expected.window_size);
        assert_eq!(actual.checksum, expected.checksum);
        assert_eq!(actual.urgent_pointer, expected.urgent_pointer);
    }

    // ---------------------------------------------------------
    // 3. Successful parsing of every field
    // ---------------------------------------------------------

    #[test]
    fn parses_all_fields_correctly() {
        let bytes = valid_header_bytes();
        let header = parse_bytes(&bytes).unwrap();

        assert_eq!(header.src_port, 8080);
        assert_eq!(header.dst_port, 80);
        assert_eq!(header.seq_number, 0x1234_5678);
        assert_eq!(header.ack_number, 0x9ABC_DEF0);
        assert_eq!(header.data_offset, 0x50);
        assert_eq!(header.flags, TcpFlags::Syn | TcpFlags::Ack);
        assert_eq!(header.window_size, 0x2000);
        assert_eq!(header.checksum, 0xABCD);
        assert_eq!(header.urgent_pointer, 0xEF01);
    }

    #[test]
    fn parses_zero_valued_fields() {
        let mut bytes = valid_header_bytes();

        bytes[0..12].fill(0);
        bytes[13] = 0;
        bytes[14..20].fill(0);

        let header = parse_bytes(&bytes).unwrap();

        assert_eq!(header.src_port, 0);
        assert_eq!(header.dst_port, 0);
        assert_eq!(header.seq_number, 0);
        assert_eq!(header.ack_number, 0);
        assert_eq!(header.flags, TcpFlags::empty());
        assert_eq!(header.window_size, 0);
        assert_eq!(header.checksum, 0);
        assert_eq!(header.urgent_pointer, 0);
    }

    #[test]
    fn parses_maximum_valued_fields() {
        let mut bytes = valid_header_bytes();

        bytes[0..12].fill(0xFF);
        bytes[14..20].fill(0xFF);

        let header = parse_bytes(&bytes).unwrap();

        assert_eq!(header.src_port, u16::MAX);
        assert_eq!(header.dst_port, u16::MAX);
        assert_eq!(header.seq_number, u32::MAX);
        assert_eq!(header.ack_number, u32::MAX);
        assert_eq!(header.window_size, u16::MAX);
        assert_eq!(header.checksum, u16::MAX);
        assert_eq!(header.urgent_pointer, u16::MAX);
    }

    // ---------------------------------------------------------
    // 4. Big-endian integer decoding
    // ---------------------------------------------------------

    #[test]
    fn decodes_ports_as_big_endian() {
        let mut bytes = valid_header_bytes();
        bytes[0..4].copy_from_slice(&[0x01, 0x23, 0xAB, 0xCD]);

        let header = parse_bytes(&bytes).unwrap();

        assert_eq!(header.src_port, 0x0123);
        assert_eq!(header.dst_port, 0xABCD);
    }

    #[test]
    fn decodes_sequence_number_as_big_endian() {
        let mut bytes = valid_header_bytes();
        bytes[4..8].copy_from_slice(&[0x01, 0x23, 0x45, 0x67]);

        let header = parse_bytes(&bytes).unwrap();

        assert_eq!(header.seq_number, 0x0123_4567);
    }

    #[test]
    fn decodes_acknowledgment_number_as_big_endian() {
        let mut bytes = valid_header_bytes();
        bytes[8..12].copy_from_slice(&[0x89, 0xAB, 0xCD, 0xEF]);

        let header = parse_bytes(&bytes).unwrap();

        assert_eq!(header.ack_number, 0x89AB_CDEF);
    }

    #[test]
    fn decodes_window_checksum_and_urgent_pointer_as_big_endian() {
        let mut bytes = valid_header_bytes();

        bytes[14..16].copy_from_slice(&[0x01, 0xFE]);
        bytes[16..18].copy_from_slice(&[0x23, 0xDC]);
        bytes[18..20].copy_from_slice(&[0x45, 0xBA]);

        let header = parse_bytes(&bytes).unwrap();

        assert_eq!(header.window_size, 0x01FE);
        assert_eq!(header.checksum, 0x23DC);
        assert_eq!(header.urgent_pointer, 0x45BA);
    }

    // ---------------------------------------------------------
    // 5. TCP data offset validation
    // ---------------------------------------------------------

    #[test]
    fn accepts_minimum_data_offset() {
        let mut bytes = valid_header_bytes();
        bytes[12] = 0x50;

        let header = parse_bytes(&bytes).unwrap();

        assert_eq!(header.data_offset, 0x50);
    }

    #[test]
    fn accepts_every_valid_data_offset_value() {
        let mut bytes = valid_header_bytes();

        for offset in 5u8..=15 {
            bytes[12] = offset << 4;

            let result = parse_bytes(&bytes);

            assert!(result.is_ok(), "data offset {offset} should be accepted");

            assert_eq!(result.unwrap().data_offset, offset << 4);
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

        assert!(parse_bytes(&bytes).is_ok());
    }

    // ---------------------------------------------------------
    // 6. Reserved bits validation
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
    fn ns_bit_does_not_change_stored_data_offset() {
        let mut bytes = valid_header_bytes();
        bytes[12] = 0x51;

        let header = parse_bytes(&bytes).unwrap();

        assert_eq!(header.data_offset, 0x51);
    }

    // ---------------------------------------------------------
    // 7. TCP flags validation
    // ---------------------------------------------------------

    #[test]
    fn accepts_empty_flags() {
        let mut bytes = valid_header_bytes();
        bytes[13] = 0;

        let header = parse_bytes(&bytes).unwrap();

        assert_eq!(header.flags, TcpFlags::empty());
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

            let header = parse_bytes(&bytes).unwrap();

            assert_eq!(header.flags, expected, "flag byte {wire_value:#04x}");
        }
    }

    #[test]
    fn accepts_all_combinations_of_defined_flags() {
        let mut bytes = valid_header_bytes();

        for flags in 0u8..=0x3F {
            bytes[13] = flags;

            let result = parse_bytes(&bytes);

            assert!(
                result.is_ok(),
                "defined flag combination {flags:#04x} should be accepted"
            );

            assert_eq!(result.unwrap().flags.bits(), flags);
        }
    }

    #[test]
    fn rejects_each_undefined_flag_bit_individually() {
        let mut bytes = valid_header_bytes();

        for unknown_bit in [0x40, 0x80] {
            bytes[13] = unknown_bit;

            assert!(
                matches!(parse_bytes(&bytes), Err(TcpHeaderError::InvalidFlags)),
                "undefined flag bit {unknown_bit:#04x} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_undefined_flags_combined_with_defined_flags() {
        let mut bytes = valid_header_bytes();

        for unknown_bit in [0x40, 0x80] {
            for defined_flags in [0x00, 0x01, 0x02, 0x10, 0x3F] {
                bytes[13] = unknown_bit | defined_flags;

                assert!(
                    matches!(parse_bytes(&bytes), Err(TcpHeaderError::InvalidFlags)),
                    "flags {:#04x} should be rejected",
                    bytes[13]
                );
            }
        }
    }

    #[test]
    fn rejects_both_undefined_flag_bits_together() {
        let mut bytes = valid_header_bytes();
        bytes[13] = 0xC0;

        assert!(matches!(
            parse_bytes(&bytes),
            Err(TcpHeaderError::InvalidFlags)
        ));
    }

    // ---------------------------------------------------------
    // 8. Validation precedence
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
            Err(TcpHeaderError::InvalidDataOffset(offset))
                if offset == 4
        ));
    }

    #[test]
    fn invalid_reserved_bits_take_precedence_over_invalid_flags() {
        let mut bytes = valid_header_bytes();
        bytes[12] = 0x52;
        bytes[13] = 0x40;

        assert!(matches!(
            parse_bytes(&bytes),
            Err(TcpHeaderError::InvalidReservedBits)
        ));
    }

    // ---------------------------------------------------------
    // 9. Independence of fields
    // ---------------------------------------------------------

    #[test]
    fn changing_flags_does_not_change_other_fields() {
        let mut bytes = valid_header_bytes();
        let original = parse_bytes(&bytes).unwrap();

        bytes[13] = 0x2F;

        let modified = parse_bytes(&bytes).unwrap();

        assert_eq!(modified.src_port, original.src_port);
        assert_eq!(modified.dst_port, original.dst_port);
        assert_eq!(modified.seq_number, original.seq_number);
        assert_eq!(modified.ack_number, original.ack_number);
        assert_eq!(modified.data_offset, original.data_offset);
        assert_eq!(modified.window_size, original.window_size);
        assert_eq!(modified.checksum, original.checksum);
        assert_eq!(modified.urgent_pointer, original.urgent_pointer);
    }

    #[test]
    fn changing_one_integer_field_does_not_change_other_fields() {
        let bytes = valid_header_bytes();
        let original = parse_bytes(&bytes).unwrap();

        let mut modified_bytes = bytes;
        modified_bytes[0] ^= 0xFF;

        let modified = parse_bytes(&modified_bytes).unwrap();

        assert_ne!(modified.src_port, original.src_port);
        assert_eq!(modified.dst_port, original.dst_port);
        assert_eq!(modified.seq_number, original.seq_number);
        assert_eq!(modified.ack_number, original.ack_number);
        assert_eq!(modified.flags, original.flags);
        assert_eq!(modified.window_size, original.window_size);
        assert_eq!(modified.checksum, original.checksum);
        assert_eq!(modified.urgent_pointer, original.urgent_pointer);
    }
}
