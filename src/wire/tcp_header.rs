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

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_number: u32,
    pub ack_number: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

const _: () = assert!(
    core::mem::size_of::<TcpHeader>() == 20,
    "Tcp header must be 20-bytes"
);

// todo: avoid luck numbers
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

        let flags = TcpFlags::from_bits(bytes[13]).ok_or(TcpHeaderError::InvalidFlags)?;

        let window_size = u16::from_be_bytes([bytes[14], bytes[15]]);
        let checksum = u16::from_be_bytes([bytes[16], bytes[17]]);
        let urgent_ptr = u16::from_be_bytes([bytes[18], bytes[19]]);

        Ok(Self {
            src_port,
            dst_port,
            seq_number: seq_num,
            ack_number: ack_num,
            data_offset: bytes[12],
            flags,
            window_size,
            checksum,
            urgent_pointer: urgent_ptr,
        })
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
        self.flags
    }

    pub fn checksum(&mut self) -> Result<(), TcpHeaderError> {
        unimplemented!()
    }
}
