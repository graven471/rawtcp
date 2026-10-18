#![allow(unused)]

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use rand::RngExt;

use crate::{
    error::{ConnectionError, Error},
    platform::linux::tun::Device,
    tcp::{
        seq::SequenceNumber,
        state::TcpState::*,
        tcb::{OpenKind, Tcb, TcbKey},
    },
    wire::{
        tcp_header::{TcpFlags, TcpHeader},
        tcp_segment::TcpSegment,
    },
};

const EPHEMERAL_MIN: u16 = 49152;
const EPHEMERAL_MAX: u16 = 65535;

pub(crate) struct Interface {
    table: HashMap<TcbKey, Tcb>,
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

        // craft a segment with SYN
        let seg = {
            let header = TcpHeader::new(key.local_port, key.remote_port, isn, 0, TcpFlags::Syn);
            TcpSegment {
                header,
                payload: &[],
            }
        };

        // fixme: for now do allocation and copy fix it later
        let mut buf = Vec::new();
        buf.extend_from_slice(bytemuck::bytes_of(&seg.header));
        buf.extend_from_slice(seg.payload);

        let _ = self.device.send(buf)?;
        // transition state to SynSent
        tcb.state = SynSent;
        tcb.open_kind = OpenKind::Active;

        self.table.insert(key, tcb);

        Ok(())
    }

    // we are the server
    pub(crate) fn listen(local: SocketAddr) {
        unimplemented!()
    }
}
