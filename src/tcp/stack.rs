#![allow(unused)]

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
};

use crate::{
    net::ipv4::Ipv4Header,
    tcp::{
        seq::SequenceNumber,
        tcb::{Tcb, TcbKey},
    },
    wire::tcp_segment::TcpSegment,
};

#[derive(Debug)]
pub(crate) struct TcpStack {
    pub(crate) connections: HashMap<TcbKey, Tcb>,
}

impl TcpStack {
    // we are the client
    pub(crate) fn connect(remote: SocketAddr) {
        // create a new connection send SYN and call connection.process
        unimplemented!()
    }

    // we are the server
    pub(crate) fn listen(local: SocketAddr) {
        unimplemented!()
    }

    pub(crate) fn foo(&mut self, ipv4: Ipv4Header, seg: TcpSegment) {
        // assuming passive open, we are the server
        let key = TcbKey {
            local_addr: ipv4.source(),
            local_port: seg.header.src_port(),
            remote_addr: ipv4.destination(),
            remote_port: seg.header.dst_port(),
        };

        if let Some(tcb) = self.connections.get_mut(&key) {
            tcb.process(seg);
        } else {
            let conn = Tcb::new(&key, SequenceNumber(0));
            self.connections.insert(key, conn);
            let mut conn = self.connections.get_mut(&key).unwrap();
            conn.process(seg);
        }
    }
}
