#[cfg(test)]
mod tests {
    use super::*;
    use rawtcp::{error::Ipv4Error, net::ipv4::IpHeaderv4};

    fn valid_packet() -> [u8; 20] {
        let mut buf = [0u8; 20];
        buf[0] = 0x45; // version=4, ihl=5
        buf[9] = 6; // protocol=TCP
        buf
    }

    #[test]
    fn parses_valid_tcp_packet() {
        let buf = valid_packet();
        let header = IpHeaderv4::parse(buf).unwrap();
        assert_eq!(header.version_ihl >> 4, 4);
        assert_eq!(header.protocol, 6);
    }

    #[test]
    fn rejects_wrong_version() {
        let mut buf = valid_packet();
        buf[0] = 0x35;
        let err = IpHeaderv4::parse(buf).unwrap_err();
        assert!(matches!(err, Ipv4Error::InvalidVersion(3)));
    }

    #[test]
    fn rejects_unsupported_protocol() {
        let mut buf = valid_packet();
        buf[9] = 99;
        let err = IpHeaderv4::parse(buf).unwrap_err();
        assert!(matches!(err, Ipv4Error::UnsupportedProtocol(99)));
    }

    #[test]
    fn parses_source_and_dest() {
        let mut buf = valid_packet();
        buf[12..16].copy_from_slice(&[192, 168, 1, 1]);
        buf[16..20].copy_from_slice(&[10, 0, 0, 1]);
        let header = IpHeaderv4::parse(buf).unwrap();
        assert_eq!(header.ip_source, [192, 168, 1, 1]);
        assert_eq!(header.ip_destination, [10, 0, 0, 1]);
    }
}
