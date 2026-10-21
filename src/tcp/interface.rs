// #![allow(unused)]

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use rand::RngExt;

use crate::{
    error::{ConnectionError, Error},
    net::ipv4::{IPV4_HEADER_LEN, IpProtocol, Ipv4Header},
    platform::linux::tun::Device,
    tcp::{
        connection_key::ConnectionKey,
        isn::generate_isn,
        packet::parse_incoming_packet,
        seq::SequenceNumber,
        state::TcpState::{self, *},
        tcb::{
            OpenKind::{self, Passive},
            Tcb,
        },
    },
    wire::{
        tcp_header::{TcpFlags, TcpHeader},
        tcp_segment::{OwnedSegment, TcpSegment},
    },
};

const EPHEMERAL_MIN: u16 = 49152;
const EPHEMERAL_MAX: u16 = 65535;

pub struct Interface {
    table: HashMap<ConnectionKey, Tcb>,
    device: Device,
}

impl Interface {
    // todo: support config
    pub fn new(device: Device) -> Self {
        Self {
            table: HashMap::new(),
            device: device,
        }
    }

    #[must_use]
    fn send_packet(
        &mut self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        segment: &OwnedSegment,
    ) -> Result<(), Error> {
        let total_length =
            IPV4_HEADER_LEN + usize::from(segment.header.offset()) * 4 + segment.payload.len();

        let mut ipv4_hdr = Ipv4Header::new(
            src.octets(),
            dst.octets(),
            total_length as u16,
            IpProtocol::Tcp,
        );
        ipv4_hdr.set_checksum(ipv4_hdr.calculate_checksum());

        let tcp_header = TcpHeader::new(
            segment.header.src_port(),
            segment.header.dst_port(),
            segment.header.seq_number(),
            segment.header.ack_number(),
            65535,
            segment.header.flags(),
        );

        let mut seg = TcpSegment::new(tcp_header, &segment.payload);
        seg.set_checksum(seg.calculate_checksum(ipv4_hdr.source(), ipv4_hdr.destination()));

        // [ipv4_header] [tcp_header] [tcp_options if any] [payload]

        let mut packet = Vec::with_capacity(total_length);
        packet.extend_from_slice(bytemuck::bytes_of(&ipv4_hdr));
        packet.extend_from_slice(bytemuck::bytes_of(&seg.header));
        packet.extend_from_slice(seg.options);
        packet.extend_from_slice(seg.payload);

        self.device.send(&packet)?;

        return Ok(());
    }

    // we are the client
    pub fn connect(&mut self, remote: SocketAddr) -> Result<(), Error> {
        // generate isn seq. number for now use rand
        // find a dst port
        // create a table withConnectionKey
        // send a Syn Packet and transition state to Syn-Sent
        // wait for peer SYN | ACK then validate then send ACK
        // after than unblock the thread and return Ok()

        if remote.is_ipv4() {
            return Err(Error::from(ConnectionError::ConnectFailed { remote }));
        }

        let src_port = remote.port();

        let src_ip = match remote.ip() {
            IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        };

        let key = loop {
            let local_port: u16 = rand::rng().random_range(EPHEMERAL_MIN..=EPHEMERAL_MAX);

            let key = ConnectionKey {
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

        let ipv4_hdr = Ipv4Header::new(
            key.local_addr.octets(),
            key.remote_addr.octets(),
            // todo: do not hardcode derive it
            20 + 20,
            IpProtocol::Tcp,
        );

        let _ = ipv4_hdr.calculate_checksum();

        // craft a segment with SYN
        let seg = {
            let header = TcpHeader::new(
                key.local_port,
                key.remote_port,
                isn,
                0,
                65535,
                TcpFlags::Syn,
            );
            TcpSegment {
                header,
                options: &[],
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

            let _ = self.device.send(buf)?;

            // transition state to SynSent
            tcb.state = SynSent;
            tcb.open_kind = OpenKind::Active;
        }

        loop {
            let mut buf = [0u8; 200];
            let n = self.device.recv(&mut buf)?;
            let ipv4_hdr = match Ipv4Header::parse(&buf[..n]) {
                Ok(hdr) => hdr,
                Err(_) => continue,
            };

            let seg = match TcpSegment::parse(&ipv4_hdr, &buf[..n]) {
                Ok(seg) => seg,
                Err(_) => continue,
            };

            // valid SYN | ACK packet
            if let Some(seg) = tcb.process(&seg) {
                let mut buf = Vec::new();
                let out_ip = Ipv4Header::new(
                    key.local_addr.octets(),
                    key.remote_addr.octets(),
                    20 + 20,
                    IpProtocol::Tcp,
                );

                let seg = TcpSegment::from(&seg);

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

    //     fn handle_incoming_packet(&mut self, packet: ParsedTcpPacket<'_>) -> Result<(), Error> {
    //         let conn_key = ConnectionKey::from_packet(&packet);
    //         // if connection exists then call tcb.process and send packet
    //         // else check if syn is valid then create new tcp, insert it and do process
    //
    //         let response = {
    //             let tcb = self.table.get_mut(&conn_key);
    //             tcb.and_then(|t| t.process(&packet.segment))
    //         };
    //
    //         Ok(())
    //     }

    // we are the server
    pub fn listen(&mut self, _local: SocketAddr) -> Result<(), Error> {
        loop {
            let mut buf = [0u8; 124];
            let n = self.device.recv(&mut buf)?;

            // skip non ipv4 packets
            if buf[0] >> 4 != 4 {
                continue;
            }

            // skip non-TCP packet
            if buf[9] != 6 {
                continue;
            }

            let Ok(packet) = parse_incoming_packet(&buf[..n]) else {
                continue;
            };

            let conn_key = ConnectionKey::from_packet(&packet);

            let response = {
                let tcb = self.table.get_mut(&conn_key);
                tcb.and_then(|t| t.process(&packet.segment))
            };

            if let Some(seg) = response {
                self.send_packet(conn_key.local_addr, conn_key.remote_addr, &seg)?;
            } else if packet.segment.header.syn()
                && !packet.segment.header.ack()
                && !packet.segment.header.rst()
            {
                // fixme: generate actual random strong secret
                let isn = generate_isn(&conn_key.bytes(), &[42u8; 32]);

                let mut tcb = Tcb::new(
                    conn_key.local_addr,
                    conn_key.local_port,
                    conn_key.remote_addr,
                    conn_key.remote_port,
                    isn,
                );
                tcb.state = Listen;
                tcb.open_kind = Passive;
                let seg = tcb.process(&packet.segment);
                self.table.insert(conn_key, tcb);
                if let Some(seg) = seg {
                    self.send_packet(conn_key.local_addr, conn_key.remote_addr, &seg)?;
                }
            }
        }
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
            TcpHeader::new(
                client_port,
                server_port,
                client_isn,
                0,
                65535,
                TcpFlags::Syn,
            ),
            &[],
        );

        // Copy the SYN-ACK header values so the response no longer
        // borrows the server when we inspect its state.
        let (syn_ack_seq, syn_ack_ack) = {
            let response = server.process(&syn).expect("server should respond to SYN");

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
                65535,
                TcpFlags::Syn | TcpFlags::Ack,
            ),
            &[],
        );

        // Copy the final ACK fields before checking client.state.
        let (final_ack_seq, final_ack_num) = {
            let response = client
                .process(&syn_ack)
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
                65535,
                TcpFlags::Ack,
            ),
            &[],
        );

        let response = server.process(&final_ack);
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
            TcpHeader::new(8080, 40000, 500, 102, 65535, TcpFlags::Syn | TcpFlags::Ack),
            &[],
        );

        let (rst, seq_num, ack_num) = {
            let response = client
                .process(&syn_ack)
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
        let final_ack = TcpSegment::new(
            TcpHeader::new(40000, 8080, 200, 102, 65535, TcpFlags::Ack),
            &[],
        );

        let (ack, rst) = {
            let response = server
                .process(&final_ack)
                .expect("unacceptable ACK should trigger an ACK response");

            (response.header.ack(), response.header.rst())
        };

        assert!(ack);
        assert!(!rst);
        assert_eq!(server.state, TcpState::SynReceived);
        assert_eq!(server.snd_una, SequenceNumber(100));
    }
}
