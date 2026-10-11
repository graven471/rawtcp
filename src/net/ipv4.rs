use std::net::Ipv4Addr;

use crate::error::Ipv4Error;

pub const IPV4_HEADER_LEN: usize = 20;

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

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Ipv4Header {
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

const _: () = assert!(
    core::mem::size_of::<Ipv4Header>() == 20,
    "Ipv4Header must be 20-bytes"
);

impl Ipv4Header {
    pub fn serialize(_bytes: &[u8]) -> Result<Self, Ipv4Error> {
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
pub struct Ipv4Packet {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub reserved: bool,
    pub df: bool,
    pub mf: bool,
    pub fragment_offset: u16,
    pub byte_offset: u32,
    pub ttl: u8,
    pub protocol: IpProtocol,
    pub checksum: u16,
    pub source: Ipv4Addr,
    pub dest: Ipv4Addr,
}

impl Ipv4Packet {
    pub fn parse(bytes: &[u8]) -> Result<Self, Ipv4Error> {
        if bytes.len() < IPV4_HEADER_LEN {
            return Err(Ipv4Error::InvalidHeaderLength(bytes.len()));
        }

        // 0-3 is version must be 4 for ipv4
        // 4-7 is ihl
        let version_ihl = bytes[0];
        let version = version_ihl >> 4;
        let ihl = version_ihl & 0x0F;

        if version != 4 {
            return Err(Ipv4Error::InvalidVersion(version));
        }

        if ihl < 5 {
            return Err(Ipv4Error::ParseError("IHL must be atleast 5".into()));
        }

        // 0-5 DSCP, 6-7 ECN
        let dscp_ecn = bytes[1];
        let dscp = dscp_ecn >> 2;
        let ecn = dscp_ecn & 0x03;

        let total_length = u16::from_be_bytes([bytes[2], bytes[3]]);
        let identification = u16::from_be_bytes([bytes[4], bytes[5]]);

        // byte 6-7 first 3-bits of byte-6 is flag then remaining is fragment offset
        let flags = bytes[6] >> 5;
        let frag_offset = u16::from_be_bytes([(bytes[6] & 0x1F), bytes[7]]);

        let reserved = (flags & 0b100) != 0;
        let df = (flags & 0b010) != 0;
        let mf = (flags & 0b001) != 0;

        let byte_offset = (frag_offset as u32) * 8;

        let ttl = bytes[8];

        let protocol =
            IpProtocol::try_from(bytes[9]).map_err(|err| Ipv4Error::UnsupportedProtocol(err))?;

        let checksum = u16::from_be_bytes([bytes[10], bytes[11]]);

        let source_address = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let destination_address = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);

        Ok(Self {
            version,
            ihl,
            dscp,
            ecn,
            total_length,
            identification,
            flags,
            reserved,
            df,
            mf,
            fragment_offset: frag_offset,
            byte_offset,
            ttl,
            protocol,
            checksum,
            source: Ipv4Addr::from_bits(source_address),
            dest: Ipv4Addr::from_bits(destination_address),
        })
    }

    #[inline]
    pub const fn header_len(&self) -> u8 {
        self.ihl.to_le() * 4
    }

    #[inline]
    pub fn checksum(&self) -> Result<(), Ipv4Error> {
        unimplemented!()
    }
}
