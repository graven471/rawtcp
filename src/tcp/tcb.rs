#![allow(unused)]
use std::{collections::HashMap, net::Ipv4Addr};

use rand::{RngExt, rngs::ThreadRng};

use crate::{
    error::Error,
    tcp::state::TcpState::{self, CloseWait, Closed, Established, SynReceived, SynSent},
    wire::{
        tcp_header::{TcpFlags, TcpHeader},
        tcp_segment::TcpSegment,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum OpenKind {
    Passive,
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SegmentAction {
    Drop,
    SendAck,
    Reset,
    Continue,
}

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

    pub(crate) open_kind: OpenKind,

    // temp: remove when we have isn formula
    rand: ThreadRng,

    // RFC 5961  data injection attack, and mitigation
    pub(crate) max_snd_wnd: u16,

    // snd_una.......snd_nxt, where ... is in-flight data
    //    1         2          3          4
    // ----------|----------|----------|----------
    //        SND.UNA    SND.NXT    SND.UNA
    //                              +SND.WND
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
        // todo: remote{addr,port} will change based on active or passive connection
        Self {
            state: TcpState::Closed,
            src_addr: key.remote_addr,
            src_port: key.remote_port,
            dst_addr: key.local_addr,
            dst_port: key.local_port,
            open_kind: OpenKind::Active,
            rand: rand::rng(),
            // todo: see if we can use different value
            max_snd_wnd: u16::MAX,
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

    #[inline]
    const fn is_valid_ack(&self, ack: u32) -> bool {
        // ack must be between (snd_una, snd_nxt] closed interval
        self.snd_una < ack && ack <= self.snd_nxt
    }

    #[inline]
    const fn is_valid_syn_sent_ack(&self, ack: u32) -> bool {
        // (self.iss, snd_nxt] interval
        self.iss < ack && ack <= self.snd_nxt
    }

    #[inline]
    fn seg_len(seg: &TcpSegment) -> u32 {
        // both syn and fin consumes 1-byte
        seg.payload.len() as u32 + u32::from(seg.header.syn()) + u32::from(seg.header.fin())
    }

    #[inline]
    fn is_ack_acceptable(&self, ack_num: u32) -> bool {
        //  RFC 5961 mitigation check:
        //  ACK value is acceptable only if it is in the range of
        //  ((SND.UNA - MAX.SND.WND) =< SEG.ACK =< SND.NXT)
        //  All incoming segments whose ACK value doesn't satisfy the above condition
        //  MUST be discarded and an ACK sent back.
        return (self.snd_una.wrapping_sub(u32::from(self.max_snd_wnd)) <= ack_num)
            && ack_num <= self.snd_nxt;
    }

    #[inline]
    fn is_segment_acceptable(&self, seg: &TcpSegment) -> bool {
        let seg_len = Self::seg_len(seg);

        match (seg_len, self.rcv_nxt) {
            (0, 0) => {
                return seg.header.seq_number() == self.rcv_nxt;
            }

            (0, 1..) => {
                // test -> RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                // seg.seq is >= rcv_nxt and seg.seq < rcv_nxt + rcv_wnd
                return seg.header.seq_number() >= self.rcv_nxt
                    && seg.header.seq_number() < self.rcv_nxt + u32::from(self.rcv_wnd);
            }

            (1.., 0) => {
                // not acceptable
                // but RFC says:
                // If the RCV.WND is zero, no segments will be acceptable,
                // but special allowance should be made to accept valid ACKs, URGs, and RSTs.
                return false;
            }

            (1.., 1..) => {
                // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                // or
                // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
                // seg.seq + seg.len - 1 >= rcv_nxt and seg.seq + seg.len - 1 < rcv_nxt + rcv_wnd

                let rcv_wnd = u32::from(self.rcv_wnd);

                let first_seq_in_window = seg.header.seq_number() >= self.rcv_nxt
                    && seg.header.seq_number() < self.rcv_nxt + rcv_wnd;

                // todo: make sure to replace seq_number with SeqNumber when i have it
                let last_seq_in_segment = seg.header.seq_number() + seg_len - 1;

                let last_seq_in_window = last_seq_in_segment >= self.rcv_nxt
                    && last_seq_in_segment < self.rcv_nxt + rcv_wnd;

                return first_seq_in_window | last_seq_in_window;
            }
        }
    }

    /// RFC 9293 state machine
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

                match (seg.header.syn(), seg.header.ack(), seg.header.rst()) {
                    // we have syn, ack and rst
                    (true, true, true) => {
                        // if seg.ack < iss or seg.ack > snd_nxt then drop the
                        // segment without sending a reset because RST flag is already set
                        if (self.is_valid_syn_sent_ack(seg.header.ack_number())) {
                            // this is a connection reset: report connection reset
                            // transition to Closed, delete TCB and return
                            self.state = Closed;
                        } else {
                            // drop the connection do not sent RST
                        }

                        todo!()
                    }

                    (true, true, false) => {
                        if self.is_valid_syn_sent_ack(seg.header.ack_number()) {
                            // send the ACK of seg.header.seq + 1
                        } else {
                            // send RST
                        }
                        todo!()
                    }
                    (true, false, true) => {
                        // we have syn and rst
                        // discard the segment stay in synSent
                        todo!()
                    }

                    (true, false, false) => {
                        self.irs = seg.header.seq_number();
                        self.rcv_nxt = seg.header.seq_number() + 1;

                        self.state = SynReceived;
                        // send syn | ack
                    }
                    (false, false, true) => {
                        // rst without ack in synSent what should i do
                    }
                    (false, false, false) => {
                        // lol
                    }

                    // for now
                    _ => unreachable!(),
                }
            }
            SynReceived => {
                let segment_acceptable = self.is_segment_acceptable(&seg);
                let ack_valid = self.is_valid_ack(seg.header.ack_number());

                match (
                    segment_acceptable,
                    seg.header.rst(),
                    seg.header.syn(),
                    ack_valid,
                ) {
                    // seg is invalid and rst is set
                    (false, true, _, _) => {
                        // drop the segment silently and return
                    }

                    // seg is invalid and rst is not set
                    (false, false, _, _) => {
                        // send  <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK> then drop the unacceptable segment and return
                    }

                    // seg is valid and rst is set
                    (true, true, _, _) => {
                        // If this connection was initiated with a passive OPEN (i.e., came from the LISTEN state),
                        //  then return this connection to LISTEN state and return. The user need not be informed.
                        //  If this connection was initiated with an active OPEN (i.e., came from SYN-SENT state),
                        //  then the connection was refused; signal the user "connection refused".
                        //  In either case, the retransmission queue should be flushed. And in the active OPEN case,
                        //  enter the CLOSED state and delete the TCB, and return.
                        if seg.header.seq_number() == self.rcv_nxt {
                            // if open kind is passive came from Listen then
                            // return this connection to listen state and return or if
                            // its active open came from SYN-SENT then the connection was refused
                            // signal the user "connection refused" delete the TCB and return
                        } else {
                            // send <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                        }
                    }

                    // seg is valid and RST is not set
                    (true, false, _, _) => {
                        // check syn bit
                        if seg.header.syn() {
                            // If the connection was initiated with a passive OPEN,
                            //  then return this connection to the LISTEN state and return.
                            // else  send  <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK> and drop the seg return
                        }

                        // check 5: ACK
                        if !seg.header.ack() {
                            // drop the segment and return
                        }

                        // RFC 5961 mitigation check
                        if !self.is_ack_acceptable(seg.header.ack_number()) {
                            // send ACK then discard the seg stop processing
                        }

                        if !self.is_valid_ack(seg.header.ack_number()) {
                            // send  <SEQ=SEG.ACK><CTL=RST>
                            // todo: find out does RFC allows to drop the seg and return
                            // or we just need to send rst
                        }

                        // note: is_valid_ack already checked SND.UNA < SEG.ACK =< SND.NXT
                        // so we can update these freely
                        self.snd_wnd = seg.header.window_size();
                        self.snd_wl1 = seg.header.seq_number();
                        self.snd_wl2 = seg.header.ack_number();
                        self.state = Established;

                        // check 8: FIN
                        if seg.header.fin() {
                            // signal the user "connection closing" and return any pending RECEIVEs with same message,
                            //  advance RCV.NXT over the FIN, and send an acknowledgment for the FIN.
                            // enter the close wait state
                            self.state = CloseWait;
                        }
                    }
                }
            }
            Established => {
                // todo: i need these in most of the states so extract it into helper function
                if !self.is_segment_acceptable(&seg) {
                    if seg.header.rst() {
                        // sliently drop and return
                    } else {
                        //  <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                        // drop the segment and return
                    }
                }

                if seg.header.rst() {
                    if seg.header.seq_number() == self.rcv_nxt {
                        // if open kind is passive came from Listen then
                        // return this connection to listen state and return or if
                        // its active open came from SYN-SENT then the connection was refused
                        // signal the user "connection refused" delete the TCB and return
                    } else {
                        // send  <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                        // and drop the unacceptable segment and stop processing incoming packet further
                    }

                    // If the RST bit is set, then any outstanding RECEIVEs and SEND should receive "reset" responses. All segment queues should be flushed. Users should also receive an unsolicited general "connection reset" signal. Enter the CLOSED state, delete the TCB, and return.
                }

                if !seg.header.rst() && seg.header.syn() {
                    //  <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                    // drop the segment and stop processing further
                }

                // RFC check 5
                if (!self.is_ack_acceptable(seg.header.ack_number())) {
                    // send <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK> then discard the seg stop processing
                }

                if !seg.header.ack() {
                    // drop the segment and return
                }

                //==============ESTABLISHED specific checks================

                // duplicate ack
                if (seg.header.ack_number() <= self.snd_una) {
                    // ignore it
                }

                // we did not send this so send ACK drop the seg and return
                if (seg.header.ack_number() > self.snd_nxt) {}

                // advance snd_una
                self.snd_una = seg.header.ack_number();
                // todo: Any segments on the retransmission queue that are thereby entirely acknowledged are removed.

                let wl_updated_needed = self.snd_wl1 == seg.header.seq_number()
                    && self.snd_wl2 <= seg.header.ack_number();

                if self.snd_wl1 < seg.header.seq_number() || wl_updated_needed {
                    self.snd_wnd = seg.header.window_size();
                    self.snd_wl1 = seg.header.seq_number();
                    self.snd_wl2 = seg.header.ack_number();
                }

                todo!()
            }
            TcpState::Listen => {
                // note: first check sequence number
                if flags.contains(TcpFlags::Syn) && !flags.contains(TcpFlags::Ack) {
                    // here we are the client the peer sent the SYN we have to
                    // create our own initial seq. number ack the peer syn and
                    // build a  TcpSegment with SYN|ACK flag
                    // transition state to SynReceived
                }
            }
            TcpState::FinWait1 => {
                // note: first check sequence number
            }
            TcpState::FinWait2 => {
                // note: first check sequence number
            }
            TcpState::CloseWait => {
                // note: first check sequence number
                //  If the RST bit is set, then any outstanding RECEIVEs and SEND should receive "reset" responses.
                //  All segment queues should be flushed. Users should also receive
                //  an unsolicited general "connection reset" signal.
                //  Enter the CLOSED state, delete the TCB, and return.
            }
            TcpState::Closing => {
                // note: first check sequence number
            }
            TcpState::LastAck => {
                // note: first check sequence number
            }
            TcpState::TimeWait => {
                // note: first check sequence number
                //  If the RST bit is set, then enter the CLOSED state, delete the TCB, and return.
                // if the ACK bit is off, drop the segment and return
            }
            TcpState::Closed => {
                // we can enjoy some cookie here
            }
        }

        unimplemented!()
    }
}
