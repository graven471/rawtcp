#![allow(unused)]

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use rand::RngExt;
use tokio::sync::oneshot;

use crate::{
    error::{ConnectionError, Error},
    net::ipv4::{IpProtocol, Ipv4Header},
    platform::linux::tun::Device,
    tcp::{
        seq::SequenceNumber,
        state::TcpState::{self, *},
        tcb::{OpenKind, SegmentAction::Continue, Tcb, TcbKey},
    },
    wire::{
        tcp_header::{TcpFlags, TcpHeader},
        tcp_segment::TcpSegment,
    },
};

const EPHEMERAL_MIN: u16 = 49152;
const EPHEMERAL_MAX: u16 = 65535;

pub struct Interface {
    table: HashMap<TcbKey, Tcb>,
    device: Device,
}

unsafe impl Send for Interface {}

impl Interface {
    // todo: support config
    pub fn new(device: Device) -> Self {
        Self {
            table: HashMap::new(),
            device: device,
        }
    }

    // we are the client
    pub fn connect(&mut self, remote: SocketAddr) -> Result<(), Error> {
        // generate isn seq. number for now use rand
        // find a dst port
        // create a table with TcbKey
        // send a Syn Packet and transition state to Syn-Sent
        // wait for peer SYN | ACK then validate then send ACK
        // after than unblock the thread and return Ok()

        if (!remote.is_ipv4()) {
            return Err(Error::from(ConnectionError::ConnectFailed { remote }));
        }

        let src_port = remote.port();

        let src_ip = match remote.ip() {
            IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        };

        let key = loop {
            let local_port: u16 = rand::rng().random_range(EPHEMERAL_MIN..=EPHEMERAL_MAX);

            let key = TcbKey {
                remote_addr: src_ip,
                remote_port: src_port,
                local_addr: self.device.address(),
                local_port,
            };

            if !self.table.contains_key(&key) {
                break key;
            }
        };

        let isn: u32 = rand::rng().random();

        // create tcb
        let mut tcb = Tcb::new(
            key.local_addr,
            key.local_port,
            key.remote_addr,
            key.remote_port,
            SequenceNumber(isn),
        );

        // [ IPv4 header ] [ TCP header ] [ payload ]

        let mut ipv4_hdr = Ipv4Header::new(
            key.local_addr.octets(),
            key.remote_addr.octets(),
            // todo: do not hardcode derive it
            20 + 20,
            IpProtocol::Tcp,
        );

        let _ = ipv4_hdr.calculate_checksum();

        // craft a segment with SYN
        let mut seg = {
            let header = TcpHeader::new(key.local_port, key.remote_port, isn, 0, TcpFlags::Syn);
            TcpSegment {
                header,
                payload: &[],
            }
        };

        seg.calculate_checksum(key.local_addr, key.remote_addr);

        {
            // fixme: for now do allocation and copy fix it later
            let mut buf = Vec::new();
            buf.extend_from_slice(bytemuck::bytes_of(&ipv4_hdr));
            buf.extend_from_slice(bytemuck::bytes_of(&seg.header));
            buf.extend_from_slice(seg.payload);

            eprintln!("buf: {:02x?}", &buf);

            eprintln!("sending SYN to {:?}", key);
            let _ = self.device.send(buf)?;
            eprintln!("SYN sent, waiting for SYN-ACK");

            // transition state to SynSent
            tcb.state = SynSent;
            tcb.open_kind = OpenKind::Active;
        }

        loop {
            let mut buf = [0u8; 200];
            let n = self.device.recv(&mut buf)?;
            let mut ipv4_hdr = match Ipv4Header::parse(&buf[..n]) {
                Ok(hdr) => hdr,
                Err(_) => continue,
            };

            // let _ = ipv4_hdr.calculate_checksum();

            let mut seg = match TcpSegment::parse(&ipv4_hdr, &buf[..n]) {
                Ok(seg) => seg,
                Err(_) => continue,
            };

            // let _ = seg.calculate_checksum(ipv4_hdr.source(), ipv4_hdr.destination());

            // valid SYN | ACK packet
            if let Some(mut seg) = tcb.process(seg) {
                let mut buf = Vec::new();
                let mut out_ip = Ipv4Header::new(
                    key.local_addr.octets(),
                    key.remote_addr.octets(),
                    20 + 20,
                    IpProtocol::Tcp,
                );

                out_ip.calculate_checksum();
                seg.calculate_checksum(out_ip.source(), out_ip.destination());

                buf.extend_from_slice(bytemuck::bytes_of(&out_ip));
                buf.extend_from_slice(bytemuck::bytes_of(&seg.header));
                buf.extend_from_slice(seg.payload);

                let _ = self.device.send(buf)?;
                break;
            } else {
                continue;
            }
        }

        if tcb.state() == TcpState::Established {
            self.table.insert(key, tcb);
        }

        Ok(())
    }

    // we are the server
    pub fn listen(&mut self, local: SocketAddr) -> Result<(), Error> {
        loop {
            let mut buf = [0u8; 124];
            let n = self.device.recv(&mut buf)?;

            let ipv4_hdr = match Ipv4Header::parse(&buf[..n]) {
                Ok(hdr) => hdr,
                Err(_) => continue,
            };

            let seg = match TcpSegment::parse(&ipv4_hdr, &buf[..n]) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let key = TcbKey {
                local_addr: ipv4_hdr.destination(),
                local_port: seg.header.dst_port(),
                remote_addr: ipv4_hdr.source(),
                remote_port: seg.header.src_port(),
            };

            // check if key already contains

            let mut tcb = Tcb::new(
                key.local_addr,
                key.local_port,
                key.remote_addr,
                key.remote_port,
                SequenceNumber(1391),
            );

            tcb.open_kind = OpenKind::Active;
            tcb.state = Listen;

            if let Some(mut seg) = tcb.process(seg) {
                let mut buf = Vec::new();
                let mut out_ip = Ipv4Header::new(
                    key.local_addr.octets(),
                    key.remote_addr.octets(),
                    20 + 20,
                    IpProtocol::Tcp,
                );

                out_ip.calculate_checksum();
                seg.calculate_checksum(out_ip.source(), out_ip.destination());

                buf.extend_from_slice(bytemuck::bytes_of(&out_ip));
                buf.extend_from_slice(bytemuck::bytes_of(&seg.header));
                buf.extend_from_slice(seg.payload);

                let _ = self.device.send(buf)?;
                break;
            }

            if tcb.state() == TcpState::Established {
                self.table.insert(key, tcb);
            }
        }

        Ok(())
    }
}
