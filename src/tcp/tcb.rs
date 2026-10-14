#![allow(unused)]
use std::{collections::HashMap, net::Ipv4Addr};

use crate::{
    error::Error,
    tcp::state::TcpState,
    wire::{tcp_header::TcpFlags, tcp_segment::TcpSegment},
};

#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TcbKey {
    pub(crate) local_addr: Ipv4Addr,
    pub(crate) local_port: u16,
    pub(crate) remote_addr: Ipv4Addr,
    pub(crate) remote_port: u16,
}

#[derive(Debug, Clone)]
pub(crate) struct Tcb {
    pub(crate) state: TcpState,

    pub(crate) src_addr: Ipv4Addr,
    pub(crate) dst_addr: Ipv4Addr,

    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,

    // send
    pub(crate) snd_una: u32,
    pub(crate) snd_nxt: u32,
    pub(crate) snd_wnd: u16,
    pub(crate) snd_up: u16,
    pub(crate) snd_wl1: u32,
    pub(crate) snd_wl2: u32,
    pub(crate) iss: u32,

    // recv
    pub(crate) rcv_nxt: u32,
    pub(crate) rcv_wnd: u16,
    pub(crate) rcv_up: u16,
    pub(crate) irs: u32,
}

impl Tcb {
    pub(crate) fn new(key: &TcbKey, iss: u32) -> Self {
        Self {
            state: TcpState::Closed,
            src_addr: key.remote_addr,
            src_port: key.remote_port,
            dst_addr: key.local_addr,
            dst_port: key.local_port,
            iss,
            irs: 0,
            rcv_nxt: 0,
            rcv_up: 0,
            rcv_wnd: 0,
            snd_nxt: 0,
            snd_una: 0,
            snd_up: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            snd_wnd: 0,
        }
    }

    #[must_use]
    pub(crate) fn process(&mut self, seg: TcpSegment) -> Result<TcpSegment<'_>, Error> {
        // get flag from segment, check current state do validation and transition state
        let flags = seg.header.flags();

        debug_assert!(self.snd_nxt > self.snd_una);

        // for passive open (we initiated) -> we send SYN -> SynSent -> peer sends SYN|ACK -> we sent ACK -> established
        // for active open (peer initiated) -> we send SYN|ACK -> SynReceived -> peer sends ACK -> Established

        if self.state == TcpState::Listen
            && flags.contains(TcpFlags::Syn)
            && !flags.contains(TcpFlags::Ack)
        {
            // generate inital ISN and set ack to be SEQ + 1 send the packet SYN|ACK
            // transition state to SynReceived
        }

        if self.state == TcpState::SynSent
            && flags.contains(TcpFlags::Syn)
            && flags.contains(TcpFlags::Ack)
        {
            // transition state to Established
        }

        if self.state == TcpState::SynReceived && flags.contains(TcpFlags::Ack) {
            // validate ack
            // transition state to Established
        }

        if (flags.contains(TcpFlags::Rst)) {
            // send ack
            // transition state to CLOSE_WAIT
        }

        unimplemented!()
    }
}
