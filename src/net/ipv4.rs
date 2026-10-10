use zerocopy::{FromBytes, Immutable, KnownLayout};

use crate::error::Ipv4Error;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
}

impl TryFrom<u8> for IpProtocol {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Icmp),
            6 => Ok(Self::Tcp),
            17 => Ok(Self::Udp),
            other => Err(other),
        }
    }
}

const IPV4_HEADER_LEN: usize = 20;

#[derive(Debug, Clone, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct IpHeaderv4 {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub ip_source: [u8; 4],
    pub ip_destination: [u8; 4],
}

impl IpHeaderv4 {
    pub fn parse(bytes: impl AsRef<[u8]>) -> Result<IpHeaderv4, Ipv4Error> {
        // 0-3 is version must be 4 for ipv4
        // 4-7 is ihl
        //         let version_ihl = u8::from_le_bytes(bytes[0].to_le_bytes());
        //
        //         let version = version_ihl >> 4u8;
        //         let ihl = version_ihl & 0x0Fu8;
        //
        //         if version != 0x04 {
        //             return Err(Ipv4Error::InvalidVersion(version));
        //         }

        let (v4header, _) = IpHeaderv4::ref_from_prefix(bytes.as_ref())
            .map_err(|err| Ipv4Error::ParseError(err.to_string()))?;

        IpProtocol::try_from(v4header.protocol).map_err(|e| Ipv4Error::UnsupportedProtocol(e))?;

        let version = v4header.version_ihl >> 4u8;

        if version != 0x04 {
            return Err(Ipv4Error::InvalidVersion(version));
        }

        Ok(v4header.to_owned())
    }
}
