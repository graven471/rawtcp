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
pub struct TcpSegment<'a> {
    pub header: TcpHeader,
    pub options: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> TcpSegment<'a> {
    pub fn new(header: TcpHeader, payload: &'a [u8]) -> Self {
        Self {
            header,
            options: &[],
            payload,
        }
    }

    pub fn parse(ipv4: &Ipv4Header, bytes: &'a [u8]) -> Result<Self, Error> {
        let header_len = ipv4.header_len() as usize;
        let total_len = ipv4.total_length() as usize;

        // bound check
        if bytes.len() < header_len || total_len < header_len || total_len > bytes.len() {
            return Err(Error::TruncatedPacket(bytes.len()));
        }

        let tcp_bytes = &bytes[header_len..total_len];
        let header = TcpHeader::parse(tcp_bytes)?;

        if header.has_options() {
            // todo: parse options
        }

        // parse payload
        let tcp_header_len = header.offset() as usize * 4;
        let options_len = tcp_header_len - 20;

        if tcp_header_len > tcp_bytes.len() {
            return Err(Error::TcpHeader(TcpHeaderError::TruncatedHeader));
        }

        let payload = &tcp_bytes[tcp_header_len..];

        if payload.is_empty() {
            return Ok(Self {
                header,
                options: &tcp_bytes[20..20 + options_len],
                payload: &[],
            });
        }

        Ok(Self {
            header,
            options: &tcp_bytes[20..20 + options_len],
            payload,
        })
    }

    pub fn emit(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(bytemuck::bytes_of(&self.header));
        buf.extend_from_slice(self.payload);
    }

    #[inline]
    pub fn set_checksum(&mut self, checksum: u16) {
        self.header.set_checksum(checksum);
    }

    #[inline]
    pub fn calculate_checksum(&self, ip_source: Ipv4Addr, ip_dst: Ipv4Addr) -> u16 {
        let mut header = self.header;
        header.set_checksum(0);

        let tcp_len = ((header.offset() as usize * 4 + self.payload.len()) as u16).to_be_bytes();
        let mut sum = 0;

        sum += checksum_sum(&ip_source.octets());
        sum += checksum_sum(&ip_dst.octets());
        sum += checksum_sum(&[0, IpProtocol::Tcp as u8]);
        sum += checksum_sum(&tcp_len);
        sum += checksum_sum(bytemuck::bytes_of(&header));

        if !self.payload.is_empty() {
            sum += checksum_sum(self.payload);
        }

        sum += checksum_sum(self.options);

        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        return !(sum as u16);
    }

    #[inline]
    #[must_use]
    pub fn validate_checksum(
        &self,
        ip_source: Ipv4Addr,
        ip_dst: Ipv4Addr,
    ) -> Result<(), TcpHeaderError> {
        if self.header.checksum() != self.calculate_checksum(ip_source, ip_dst) {
            return Err(TcpHeaderError::InvalidChecksum);
        }

        Ok(())
    }
}
