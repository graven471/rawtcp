#![allow(unused)]
use std::net::Ipv4Addr;

use crate::{
    error::Error,
    net::ipv4::{IpProtocol, Ipv4Header},
    wire::{tcp_header::TcpHeader, utils::checksum_sum},
};

// neovim tips:
// rX -> replace character under cursor with X
// cw -> delete the character and puts in insert mode
// ciwHello -> replace the entire word with Hello

pub struct TcpSegment<'p> {
    pub header: TcpHeader,
    pub payload: &'p [u8],
}

impl<'p> TcpSegment<'p> {
    pub fn parse(ipv4: &Ipv4Header, bytes: &'p [u8]) -> Result<Self, Error> {
        let header_len = ipv4.header_len() as usize;
        let total_len = ipv4.total_length() as usize;

        let tcp_bytes = &bytes[header_len..total_len];

        let header = TcpHeader::parse(tcp_bytes)?;

        if header.has_options() {
            // parse options
        }

        // parse payload
        let tcp_header_len = header.offset() as usize * 4;
        let payload = &tcp_bytes[tcp_header_len..];

        if payload.is_empty() {
            return Ok(Self {
                header,
                payload: &[],
            });
        }

        Ok(Self { header, payload })
    }

    pub fn calculate_checksum(
        &mut self,
        ip_source: Ipv4Addr,
        ip_dst: Ipv4Addr,
    ) -> Result<(), Error> {
        let tcp_len =
            (((self.header.offset() * 4) as u32) + self.payload.len() as u32).to_be_bytes();

        let mut sum = 0;

        sum += checksum_sum(&ip_source.octets());
        sum += checksum_sum(&ip_dst.octets());
        // zero + ip protocol
        sum += checksum_sum(&[0, IpProtocol::Tcp as u8]);
        sum += checksum_sum(&tcp_len);
        // header and payload

        unimplemented!()
    }
}
