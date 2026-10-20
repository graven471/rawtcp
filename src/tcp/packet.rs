use crate::{error::Error, net::ipv4::Ipv4Header, wire::tcp_segment::TcpSegment};

#[derive(Debug, Clone)]
pub(crate) struct ParsedTcpPacket<'a> {
    pub ipv4: Ipv4Header,
    pub segment: TcpSegment<'a>,
}

pub(crate) fn parse_incoming_packet(packet: &[u8]) -> Result<ParsedTcpPacket<'_>, Error> {
    let ipv4_hdr = Ipv4Header::parse(packet)?;
    ipv4_hdr.validate_checksum()?;

    let seg = TcpSegment::parse(&ipv4_hdr, packet)?;
    seg.validate_checksum(ipv4_hdr.source(), ipv4_hdr.destination())?;

    return Ok(ParsedTcpPacket {
        ipv4: ipv4_hdr,
        segment: seg,
    });
}
