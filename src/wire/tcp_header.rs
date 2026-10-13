use bytemuck::{Pod, Zeroable};

use crate::error::TcpHeaderError;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub struct TcpFlags: u8 {
        const Syn = 0x02;
        const Ack = 0x10;
        const Fin = 0x01;
        const Psh = 0x08;
        const Rst = 0x04;
        const Urg = 0x20;
    }
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq_number: u32,
    ack_number: u32,
    data_offset: u8,
    flags: u8,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
}

const _: () = assert!(
    core::mem::size_of::<TcpHeader>() == 20,
    "Tcp header must be 20-bytes"
);

impl TcpHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self, TcpHeaderError> {
        if bytes.len() < 20 {
            return Err(TcpHeaderError::TruncatedHeader);
        }

        let src_port = u16::from_be_bytes([bytes[0], bytes[1]]);
        let dst_port = u16::from_be_bytes([bytes[2], bytes[3]]);

        let seq_num = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let ack_num = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

        let data_offset = (bytes[12] & 0xF0) >> 4;
        let _ms = bytes[12] & 0x01;

        if data_offset < 5 {
            return Err(TcpHeaderError::InvalidDataOffset(data_offset as usize));
        }

        // reserved bits
        if (bytes[12] & 0x0E) >> 1 != 0 {
            return Err(TcpHeaderError::InvalidReservedBits);
        }

        let window_size = u16::from_be_bytes([bytes[14], bytes[15]]);
        let checksum = u16::from_be_bytes([bytes[16], bytes[17]]);
        let urgent_ptr = u16::from_be_bytes([bytes[18], bytes[19]]);

        Ok(Self {
            src_port: src_port.to_be(),
            dst_port: dst_port.to_be(),
            seq_number: seq_num.to_be(),
            ack_number: ack_num.to_be(),
            data_offset: bytes[12],
            flags: bytes[13],
            window_size: window_size.to_be(),
            checksum: checksum.to_be(),
            urgent_pointer: urgent_ptr.to_be(),
        })
    }

    pub fn set_src_port(&mut self, port: u16) {
        self.src_port = port.to_be();
    }

    pub fn set_dst_port(&mut self, port: u16) {
        self.dst_port = port.to_be();
    }

    pub fn set_seq_number(&mut self, seq_num: u32) {
        self.seq_number = seq_num.to_be();
    }

    pub fn set_ack_number(&mut self, ack_num: u32) {
        self.ack_number = ack_num.to_be();
    }

    pub fn set_window(&mut self, win: u16) {
        self.window_size = win.to_be();
    }

    pub fn set_checksum(&mut self, checksum: u16) {
        self.checksum = checksum.to_be();
    }

    #[inline]
    pub const fn has_options(&self) -> bool {
        (self.data_offset & 0xF0) >> 4 != 5
    }

    #[inline]
    pub const fn offset(&self) -> u8 {
        (self.data_offset & 0xF0) >> 4
    }

    #[inline]
    pub const fn flags(&self) -> TcpFlags {
        TcpFlags::from_bits_truncate(self.flags)
    }

    pub const fn src_port(&self) -> u16 {
        u16::from_be(self.src_port)
    }

    pub const fn dst_port(&self) -> u16 {
        u16::from_be(self.dst_port)
    }

    pub const fn seq_number(&self) -> u32 {
        u32::from_be(self.seq_number)
    }

    pub const fn ack_number(&self) -> u32 {
        u32::from_be(self.ack_number)
    }

    pub const fn window_size(&self) -> u16 {
        u16::from_be(self.window_size)
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be(self.checksum)
    }
}
