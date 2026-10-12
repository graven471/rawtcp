use crate::error::Ipv4Error;

use bytemuck::{Pod, Zeroable};

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

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct Ipv4Header {
    version_ihl: u8,
    dscp_ecn: u8,
    total_length: u16,
    identification: u16,
    flags_fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    ip_source: [u8; 4],
    ip_destination: [u8; 4],
}

const _: () = assert!(
    core::mem::size_of::<Ipv4Header>() == 20,
    "Ipv4Header must be 20-bytes"
);

impl Ipv4Header {
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

        // we don't support options for now
        if ihl != 5 {
            return Err(Ipv4Error::ParseError(
                "IHL needs to be 5 we don't support options".into(),
            ));
        }

        let ttl = bytes[8];

        let protocol =
            IpProtocol::try_from(bytes[9]).map_err(|err| Ipv4Error::UnsupportedProtocol(err))?;

        Ok(Self {
            version_ihl: version_ihl,
            dscp_ecn: bytes[1],
            total_length: u16::from_be_bytes([bytes[2], bytes[3]]),
            identification: u16::from_be_bytes([bytes[4], bytes[5]]),
            flags_fragment_offset: u16::from_be_bytes([bytes[6], bytes[7]]),
            ttl,
            protocol: protocol as u8,
            checksum: u16::from_be_bytes([bytes[10], bytes[11]]),
            ip_source: [bytes[12], bytes[13], bytes[14], bytes[15]],
            ip_destination: [bytes[16], bytes[17], bytes[18], bytes[19]],
        })
    }

    #[inline]
    pub const fn checksum(&self) -> u16 {
        self.checksum
    }

    #[inline]
    pub const fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    #[inline]
    pub const fn total_length(&self) -> u16 {
        self.total_length
    }

    #[inline]
    pub const fn header_len(&self) -> u8 {
        (self.version_ihl & 0x0F) * 4
    }

    #[inline]
    pub const fn identification(&self) -> u16 {
        self.identification
    }

    pub const fn ttl(&self) -> u8 {
        self.ttl
    }

    #[inline]
    pub fn protocol(&self) -> IpProtocol {
        // we can use unwrap here fields are private and in Self::parse
        // i am validating protocol
        IpProtocol::try_from(self.protocol).unwrap()
    }

    #[inline]
    pub const fn source(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from_octets(self.ip_source)
    }

    #[inline]
    pub const fn destination(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from_octets(self.ip_destination)
    }

    pub fn serialize(_bytes: &[u8]) -> Result<Self, Ipv4Error> {
        unimplemented!()
    }

    // todo: benchmark this can we copy here freely ?
    #[inline]
    fn calculate_checksum(&self) -> u16 {
        let mut bytes = [0u8; IPV4_HEADER_LEN];

        bytes[0] = self.version_ihl;
        bytes[1] = self.dscp_ecn;
        bytes[2..4].copy_from_slice(&self.total_length.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.identification.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.flags_fragment_offset.to_be_bytes());
        bytes[8] = self.ttl;
        bytes[9] = self.protocol;
        // Checksum bytes 10..12 remain zero
        bytes[12..16].copy_from_slice(&self.ip_source);
        bytes[16..20].copy_from_slice(&self.ip_destination);

        let sum: u32 = bytes
            .chunks_exact(2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]) as u32)
            .sum();

        let mut sum = sum;

        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    #[inline]
    pub fn validate_checksum(&mut self) -> Result<(), Ipv4Error> {
        if self.checksum() != self.calculate_checksum() {
            return Err(Ipv4Error::InvalidChecksum);
        }

        Ok(())
    }
}
