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

            if buf[0] >> 4 != 4 {
                continue;
            }

            let ipv4_hdr = match Ipv4Header::parse(&buf[..n]) {
                Ok(hdr) => hdr,
                Err(_) => {
                    continue;
                }
            };

            let seg = match TcpSegment::parse(&ipv4_hdr, &buf[..n]) {
                Ok(s) => s,
                Err(_) => {
                    continue;
                }
            };

            eprintln!("seg_header: {:?}", seg.header);

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

#[cfg(test)]
mod handshake {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn three_way_handshake_completes() {
        let client_ip = Ipv4Addr::new(10, 0, 0, 1);
        let server_ip = Ipv4Addr::new(10, 0, 0, 2);
        let client_port = 40000;
        let server_port = 8080;
        let client_isn = 100;

        let mut client = Tcb::new(
            client_ip,
            client_port,
            server_ip,
            server_port,
            SequenceNumber(client_isn),
        );
        client.state = TcpState::SynSent;
        client.open_kind = OpenKind::Active;
        client.snd_nxt = SequenceNumber(client_isn + 1);

        let mut server = Tcb::new(
            server_ip,
            server_port,
            client_ip,
            client_port,
            SequenceNumber(500),
        );
        server.state = TcpState::Listen;
        server.open_kind = OpenKind::Passive;
        server.rcv_wnd = 65535;

        // 1. Client -> Server: SYN
        let syn = TcpSegment::new(
            TcpHeader::new(client_port, server_port, client_isn, 0, TcpFlags::Syn),
            &[],
        );

        // Copy the SYN-ACK header values so the response no longer
        // borrows the server when we inspect its state.
        let (syn_ack_seq, syn_ack_ack) = {
            let response = server.process(syn).expect("server should respond to SYN");

            assert!(response.header.syn());
            assert!(response.header.ack());

            (response.header.seq_number(), response.header.ack_number())
        };

        assert_eq!(server.state, TcpState::SynReceived);
        assert_eq!(syn_ack_ack, client_isn + 1);

        // 2. Server -> Client: SYN-ACK
        let syn_ack = TcpSegment::new(
            TcpHeader::new(
                server_port,
                client_port,
                syn_ack_seq,
                syn_ack_ack,
                TcpFlags::Syn | TcpFlags::Ack,
            ),
            &[],
        );

        // Copy the final ACK fields before checking client.state.
        let (final_ack_seq, final_ack_num) = {
            let response = client
                .process(syn_ack)
                .expect("client should respond to SYN-ACK");

            assert!(response.header.ack());
            assert!(!response.header.syn());

            (response.header.seq_number(), response.header.ack_number())
        };

        assert_eq!(client.state, TcpState::Established);
        assert_eq!(final_ack_seq, client_isn + 1);
        assert_eq!(final_ack_num, syn_ack_seq.wrapping_add(1));

        // 3. Client -> Server: final ACK
        let final_ack = TcpSegment::new(
            TcpHeader::new(
                client_port,
                server_port,
                final_ack_seq,
                final_ack_num,
                TcpFlags::Ack,
            ),
            &[],
        );

        let response = server.process(final_ack);
        assert!(response.is_none(), "final ACK should not require a reply");
        drop(response);

        assert_eq!(server.state, TcpState::Established);
    }

    #[test]
    fn syn_sent_rejects_syn_ack_with_ack_beyond_snd_nxt() {
        let client_ip = Ipv4Addr::new(10, 0, 0, 1);
        let server_ip = Ipv4Addr::new(10, 0, 0, 2);

        let mut client = Tcb::new(client_ip, 40000, server_ip, 8080, SequenceNumber(100));
        client.state = TcpState::SynSent;
        client.snd_nxt = SequenceNumber(101);

        // ACK=102 is beyond SND.NXT=101.
        let syn_ack = TcpSegment::new(
            TcpHeader::new(8080, 40000, 500, 102, TcpFlags::Syn | TcpFlags::Ack),
            &[],
        );

        let (rst, seq_num, ack_num) = {
            let response = client
                .process(syn_ack)
                .expect("invalid SYN-ACK should trigger RST");

            (
                response.header.rst(),
                response.header.seq_number(),
                response.header.ack_number(),
            )
        };

        assert!(rst, "response should have the RST flag set");
        assert_eq!(seq_num, 102);
        assert_eq!(ack_num, 0);
        assert_eq!(client.state, TcpState::SynSent);
        assert_eq!(client.snd_una, SequenceNumber(100));
    }

    #[test]
    fn syn_received_rejects_final_ack_beyond_snd_nxt() {
        let client_ip = Ipv4Addr::new(10, 0, 0, 1);
        let server_ip = Ipv4Addr::new(10, 0, 0, 2);

        let mut server = Tcb::new(server_ip, 8080, client_ip, 40000, SequenceNumber(100));
        server.state = TcpState::SynReceived;
        server.snd_una = SequenceNumber(100);
        server.snd_nxt = SequenceNumber(101);
        server.rcv_nxt = SequenceNumber(200);
        server.rcv_wnd = 100;

        // ACK=102 is beyond SND.NXT=101.
        let final_ack = TcpSegment::new(TcpHeader::new(40000, 8080, 200, 102, TcpFlags::Ack), &[]);

        let (ack, rst) = {
            let response = server
                .process(final_ack)
                .expect("unacceptable ACK should trigger an ACK response");

            (response.header.ack(), response.header.rst())
        };

        assert!(ack);
        assert!(!rst);
        assert_eq!(server.state, TcpState::SynReceived);
        assert_eq!(server.snd_una, SequenceNumber(100));
    }
}
