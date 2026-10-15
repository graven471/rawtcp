use std::net::Ipv4Addr;

use crate::{
    error::{Error, TcpHeaderError},
    net::ipv4::{IpProtocol, Ipv4Header},
    wire::{tcp_header::TcpHeader, utils::checksum_sum},
};

// neovim tips:
// rX -> replace character under cursor with X
// cw -> delete the character and puts in insert mode
// ciwHello -> replace the entire word with Hello

#[derive(Debug, Clone)]
pub struct TcpSegment<'p> {
    pub header: TcpHeader,
    pub payload: &'p [u8],
}

impl<'p> TcpSegment<'p> {
    pub fn new(header: TcpHeader, payload: &'p [u8]) -> Self {
        Self { header, payload }
    }

    pub fn parse(ipv4: &Ipv4Header, bytes: &'p [u8]) -> Result<Self, Error> {
        let header_len = ipv4.header_len() as usize;
        let total_len = ipv4.total_length() as usize;

        // bound check
        if bytes.len() < header_len || total_len < header_len || total_len > bytes.len() {
            return Err(Error::TruncatedPacket(bytes.len()));
        }

        let tcp_bytes = &bytes[header_len..total_len];

        let header = TcpHeader::parse(tcp_bytes)?;

        if header.has_options() {
            // parse options
        }

        // parse payload
        let tcp_header_len = header.offset() as usize * 4;

        if tcp_header_len > tcp_bytes.len() {
            return Err(Error::TcpHeader(TcpHeaderError::TruncatedHeader));
        }

        let payload = &tcp_bytes[tcp_header_len..];

        if payload.is_empty() {
            return Ok(Self {
                header,
                payload: &[],
            });
        }

        Ok(Self { header, payload })
    }

    #[inline]
    pub fn calculate_checksum(&mut self, ip_source: Ipv4Addr, ip_dst: Ipv4Addr) -> u16 {
        self.header.set_checksum(0);
        let tcp_len =
            ((self.header.offset() as usize * 4 + self.payload.len()) as u16).to_be_bytes();

        let mut sum = 0;

        // todo: benchmark this
        sum += checksum_sum(&ip_source.octets());
        sum += checksum_sum(&ip_dst.octets());
        sum += checksum_sum(&[0, IpProtocol::Tcp as u8]);
        sum += checksum_sum(&tcp_len);
        sum += checksum_sum(bytemuck::bytes_of(&self.header));

        if !self.payload.is_empty() {
            sum += checksum_sum(self.payload);
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        let checksum = !(sum as u16);

        self.header.set_checksum(checksum);

        checksum
    }

    pub(crate) fn deserialize(&self) {
        todo!()
    }
}
