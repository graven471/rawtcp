use std::net::Ipv4Addr;

use crate::tcp::packet::ParsedTcpPacket;

// Packet:  Client ──SYN──> Server
// Source      = Client (remote)
// Destination = Server (local)

#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConnectionKey {
    pub(crate) local_addr: Ipv4Addr,
    pub(crate) local_port: u16,
    pub(crate) remote_addr: Ipv4Addr,
    pub(crate) remote_port: u16,
}

impl ConnectionKey {
    pub fn from_packet(packet: &ParsedTcpPacket<'_>) -> Self {
        return Self {
            local_addr: packet.ipv4.destination(),
            local_port: packet.segment.header.dst_port(),
            remote_addr: packet.ipv4.source(),
            remote_port: packet.segment.header.src_port(),
        };
    }
}
