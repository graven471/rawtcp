#![allow(unused)]
use std::{collections::HashMap, net::Ipv4Addr};

use rand::RngExt;

use crate::{
    error::Error,
    tcp::state::TcpState::{self, Established, SynReceived, SynSent},
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

    // snd_una.......snd_nxt, where ... is in-flight data
    //    1         2          3          4
    // ----------|----------|----------|----------
    //        SND.UNA    SND.NXT    SND.UNA
    //                              +SND.WND
    // the seq. number of oldest byte sent but not my acknowledged
    // confirmed up to here
    pub(crate) snd_una: u32,
    // the next seq. number that will be assigned to the next byte
    // of new data sent
    // sent up to here (but maybe not confirmed yet)
    // advances when sequence-space data is sent
    pub(crate) snd_nxt: u32,
    pub(crate) snd_wnd: u16,
    pub(crate) snd_up: u16,
    pub(crate) snd_wl1: u32,
    pub(crate) snd_wl2: u32,
    pub(crate) iss: u32,

    // seq. number of the next byte i am expecting to receive
    // this is what we will put in ack. number we reply
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
        let flags = seg.header.flags();

        match self.state {
            SynSent => {
                // this happens when we initiated the connection, `connect()` it will
                // send the initial SYN seg. and transition state to SynSent
                // here we are waiting for peer SYN | ACK we have to validate
                // peer ack = snd_nxt
                // and then we will send ACK, ack = peer seq. + 1
                // and update snd_nxt = + 1 ?
                self.state = Established;
            }
            SynReceived => {
                // this happens when we send SYN | ACK and waiting for peer ACK seg.
                // validate peer ack = snd_nxt and then we transition state to Established
                self.state = Established;
            }
            Established => {
                // 3WHS is completed now we can send and receive payload
                todo!()
            }
            TcpState::Listen => {
                if flags.contains(TcpFlags::Syn) && !flags.contains(TcpFlags::Ack) {
                    // here we are the client the peer sent the SYN we have to
                    // create our own initial seq. number ack the peer syn and
                    // build a  TcpSegment with SYN|ACK flag
                    // transition state to SynReceived
                }
            }
            TcpState::FinWait1 => todo!(),
            TcpState::FinWait2 => todo!(),
            TcpState::CloseWait => todo!(),
            TcpState::Closing => todo!(),
            TcpState::LastAck => todo!(),
            TcpState::TimeWait => todo!(),
            TcpState::Closed => todo!(),
        }

        unimplemented!()
    }
}
