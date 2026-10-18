#![allow(unused)]
use std::{collections::HashMap, net::Ipv4Addr, ptr::addr_of};

use rand::{RngExt, rngs::ThreadRng};

use crate::tcp::seq::SequenceNumber;

use crate::{
    error::Error,
    tcp::state::TcpState::{
        self, CloseWait, Closed, Established, FinWait2, Listen, SynReceived, SynSent,
    },
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
    pub(crate) snd_una: SequenceNumber,
    // the next seq. number that will be assigned to the next byte
    // of new data sent
    // sent up to here (but maybe not confirmed yet)
    // advances when sequence-space data is sent
    pub(crate) snd_nxt: SequenceNumber,
    pub(crate) snd_wnd: u16,
    pub(crate) snd_up: u16,
    pub(crate) snd_wl1: SequenceNumber,
    pub(crate) snd_wl2: SequenceNumber,
    pub(crate) iss: SequenceNumber,

    // seq. number of the next byte i am expecting to receive
    // this is what we will put in ack. number we reply
    pub(crate) rcv_nxt: SequenceNumber,
    pub(crate) rcv_wnd: u16,
    pub(crate) rcv_up: u16,
    pub(crate) irs: SequenceNumber,
}

impl Tcb {
    pub(crate) fn new(key: &TcbKey, iss: SequenceNumber) -> Self {
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
            irs: SequenceNumber(0),
            rcv_nxt: SequenceNumber(0),
            rcv_up: 0,
            rcv_wnd: 0,
            snd_nxt: SequenceNumber(0),
            snd_una: SequenceNumber(0),
            snd_up: 0,
            snd_wl1: SequenceNumber(0),
            snd_wl2: SequenceNumber(0),
            snd_wnd: 0,
        }
    }

    #[inline]
    fn is_valid_ack(&self, ack: SequenceNumber) -> bool {
        // ack must be between (snd_una, snd_nxt] closed interval
        self.snd_una < ack && ack <= self.snd_nxt
    }

    #[inline]
    fn is_valid_syn_sent_ack(&self, ack: SequenceNumber) -> bool {
        // (self.iss, snd_nxt] interval
        self.iss < ack && ack <= self.snd_nxt
    }

    #[inline]
    fn seg_len(seg: &TcpSegment) -> u32 {
        // both syn and fin consumes 1-byte
        seg.payload.len() as u32 + u32::from(seg.header.syn()) + u32::from(seg.header.fin())
    }

    #[inline]
    fn is_ack_acceptable(&self, ack_num: SequenceNumber) -> bool {
        //  RFC 5961 mitigation check:
        //  ACK value is acceptable only if it is in the range of
        //  ((SND.UNA - MAX.SND.WND) =< SEG.ACK =< SND.NXT)
        //  All incoming segments whose ACK value doesn't satisfy the above condition
        //  MUST be discarded and an ACK sent back.
        return SequenceNumber(self.snd_una.0.wrapping_sub(u32::from(self.max_snd_wnd))) <= ack_num
            && ack_num <= self.snd_nxt;
    }

    #[inline]
    fn is_segment_acceptable(&self, seg: &TcpSegment) -> bool {
        let seg_len = Self::seg_len(seg);

        match (seg_len, self.rcv_nxt.0) {
            (0, 0) => {
                return SequenceNumber(seg.header.seq_number()) == self.rcv_nxt;
            }

            (0, 1..) => {
                // test -> RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                // seg.seq is >= rcv_nxt and seg.seq < rcv_nxt + rcv_wnd
                return SequenceNumber(seg.header.seq_number()) >= self.rcv_nxt
                    && SequenceNumber(seg.header.seq_number())
                        < self.rcv_nxt + u32::from(self.rcv_wnd);
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

                let first_seq_in_window = SequenceNumber(seg.header.seq_number()) >= self.rcv_nxt
                    && SequenceNumber(seg.header.seq_number()) < self.rcv_nxt + rcv_wnd;

                // todo: make sure to replace seq_number with SeqNumber when i have it
                let last_seq_in_segment = SequenceNumber(seg.header.seq_number()) + (seg_len - 1);

                let last_seq_in_window = last_seq_in_segment >= self.rcv_nxt
                    && last_seq_in_segment < self.rcv_nxt + rcv_wnd;

                return first_seq_in_window | last_seq_in_window;
            }
        }
    }

    #[must_use]
    fn build_segment(
        &self,
        seq_num: SequenceNumber,
        ack_num: SequenceNumber,
        flags: TcpFlags,
    ) -> TcpSegment<'_> {
        let header = TcpHeader::new(self.src_port, self.dst_port, seq_num.0, ack_num.0, flags);
        TcpSegment::new(header, &[])
    }

    #[must_use]
    #[inline]
    fn send_syn(&self, seq_num: SequenceNumber) -> TcpSegment<'_> {
        self.build_segment(seq_num, SequenceNumber(0), TcpFlags::Syn)
    }

    #[must_use]
    #[inline]
    fn send_ack(&self, seq_num: SequenceNumber, ack_num: SequenceNumber) -> TcpSegment<'_> {
        self.build_segment(seq_num, ack_num, TcpFlags::Ack)
    }

    #[must_use]
    #[inline]
    fn send_syn_ack(&self, seq_num: SequenceNumber, ack_num: SequenceNumber) -> TcpSegment<'_> {
        self.build_segment(seq_num, ack_num, TcpFlags::Syn | TcpFlags::Ack)
    }

    #[must_use]
    #[inline]
    fn send_rst(&self, seq_num: SequenceNumber) -> TcpSegment<'_> {
        self.build_segment(seq_num, SequenceNumber(0), TcpFlags::Rst)
    }

    #[must_use]
    #[inline]
    fn send_fin(&self, seq_num: SequenceNumber, ack_num: SequenceNumber) -> TcpSegment<'_> {
        self.build_segment(seq_num, ack_num, TcpFlags::Fin)
    }

    #[inline]
    fn handle_unacceptable_segment(&self, seg: &TcpSegment<'_>) -> Option<TcpSegment<'_>> {
        if seg.header.rst() {
            return None;
        }

        //  <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
        return Some(self.send_ack(self.snd_nxt, self.rcv_nxt));
    }

    #[inline]
    fn process_ack(&mut self, seg: &TcpSegment<'_>) -> SegmentAction {
        // mitigation check
        if (!self.is_ack_acceptable(SequenceNumber(seg.header.ack_number()))) {
            return SegmentAction::SendAck;
        }

        if (SequenceNumber(seg.header.ack_number()) <= self.snd_una) {
            return SegmentAction::Drop;
        }

        if (SequenceNumber(seg.header.ack_number()) > self.snd_nxt) {
            return SegmentAction::SendAck;
        }

        // advance snd_una
        self.snd_una = SequenceNumber(seg.header.ack_number());
        // todo: Any segments on the retransmission queue that are thereby entirely acknowledged are removed.

        let wl_updated_needed = self.snd_wl1 == SequenceNumber(seg.header.seq_number())
            && self.snd_wl2 <= SequenceNumber(seg.header.ack_number());

        if self.snd_wl1 < SequenceNumber(seg.header.seq_number()) || wl_updated_needed {
            self.snd_wnd = seg.header.window_size();
            self.snd_wl1 = SequenceNumber(seg.header.seq_number());
            self.snd_wl2 = SequenceNumber(seg.header.ack_number());
        };

        return SegmentAction::Continue;
    }

    #[must_use]
    fn handle_listen(&mut self, seg: &TcpSegment<'_>) -> Option<TcpSegment<'_>> {
        // note: first check sequence number
        if seg.header.syn() && !seg.header.ack() {
            // here we are the client the peer sent the SYN we have to
            // create our own initial seq. number ack the peer syn and
            // build a  TcpSegment with SYN|ACK flag
            // transition state to SynReceived
        }

        todo!()
    }

    #[must_use]
    fn handle_syn_sent(&mut self, seg: &TcpSegment<'_>) -> Option<TcpSegment<'_>> {
        let seg_ack = SequenceNumber(seg.header.ack_number());
        let seg_seq = SequenceNumber(seg.header.seq_number());
        // todo: i don't quite like the current implementation maybe i should refactor

        if !seg.header.ack() {
            if seg.header.rst() {
                return None;
            }

            if !seg.header.rst() && !seg.header.syn() {
                return None;
            }

            self.rcv_nxt = seg_seq + 1;
            self.irs = seg_seq;

            if self.snd_una > self.iss {
                self.state = Established;
                return Some(self.send_ack(self.snd_nxt, self.rcv_nxt));
            }

            self.state = SynReceived;
            self.snd_wnd = seg.header.window_size();
            self.snd_wl1 = seg_seq;
            self.snd_wl2 = seg_ack;

            return Some(self.send_syn_ack(self.iss, self.rcv_nxt));
        }

        // ack is set
        if !self.is_valid_syn_sent_ack(seg_ack) {
            if seg.header.rst() {
                return None;
            } else {
                return Some(self.send_rst(seg_ack));
            }
        }

        let ack_valid = self.is_valid_ack(seg_ack);

        if seg.header.rst() {
            if seg_seq == self.rcv_nxt && ack_valid {
                // todo: signal "error: connection reset"
                // delete the TLB
                self.state = Closed;
                return None;
            } else {
                return None;
            }
        }

        // only reach when ACK is ok or there is no ACK
        if seg.header.syn() && ack_valid {
            self.rcv_nxt = seg_seq + 1;
            self.irs = seg_seq;
            self.snd_una = seg_ack;

            // todo: any segments on the retransmission queue that are thereby acknowledged should be removed.

            if self.snd_una > self.iss {
                self.state = Established;
                return Some(self.send_ack(self.snd_nxt, self.rcv_nxt));
            }

            self.state = SynReceived;
            self.snd_wnd = seg.header.window_size();
            self.snd_wl1 = seg_seq;
            self.snd_wl2 = seg_ack;

            return Some(self.send_syn_ack(self.iss, self.rcv_nxt));
        }

        return None;
    }

    #[must_use]
    fn handle_syn_received(&mut self, seg: &TcpSegment<'_>) -> Option<TcpSegment<'_>> {
        let segment_acceptable = self.is_segment_acceptable(&seg);
        let ack_valid = self.is_valid_ack(SequenceNumber(seg.header.ack_number()));

        match (
            segment_acceptable,
            seg.header.rst(),
            seg.header.syn(),
            ack_valid,
        ) {
            // seg is invalid and rst is set
            (false, true, _, _) => {
                // drop the segment silently and return
                return None;
            }

            // seg is invalid and rst is not set
            (false, false, _, _) => {
                return Some(self.send_ack(self.snd_nxt, self.rcv_nxt));
            }

            // seg is valid and rst is set
            (true, true, _, _) => {
                // 5961 mitigation check
                if SequenceNumber(seg.header.seq_number()) == self.rcv_nxt {
                    // if open kind is passive came from Listen then
                    // return this connection to listen state and return or if
                    // its active open came from SYN-SENT then the connection was refused
                    // signal the user "connection refused" delete the TCB and return

                    if self.open_kind == OpenKind::Passive {
                        self.state = Listen;
                        return None;
                    } else {
                        // todo i have to handle how to send "connection refused"
                        return None;
                    }
                } else {
                    return Some(self.send_ack(self.snd_nxt, self.rcv_nxt));
                }
            }

            // seg is valid and RST is not set
            (true, false, _, _) => {
                // check 4: Syn
                if seg.header.syn() {
                    if self.open_kind == OpenKind::Passive {
                        self.state = Listen;
                        return None;
                    } else {
                        return Some(self.send_ack(self.snd_nxt, self.rcv_nxt));
                    }
                }

                // check 5: ACK
                if !seg.header.ack() {
                    return None;
                }

                // RFC 5961 mitigation check
                if !self.is_ack_acceptable(SequenceNumber(seg.header.ack_number())) {
                    return Some(self.send_ack(self.snd_nxt, self.rcv_nxt));
                }

                if !self.is_valid_ack(SequenceNumber(seg.header.ack_number())) {
                    return Some(self.send_rst(SequenceNumber(seg.header.ack_number())));
                }

                self.snd_wnd = seg.header.window_size();
                self.snd_wl1 = SequenceNumber(seg.header.seq_number());
                self.snd_wl2 = SequenceNumber(seg.header.ack_number());
                self.state = Established;

                // check 8: FIN
                if seg.header.fin() {
                    // signal the user "connection closing" and return any pending RECEIVEs with same message,
                    //  advance RCV.NXT over the FIN, and send an acknowledgment for the FIN.
                    // enter the close wait state
                    self.state = CloseWait;
                }

                todo!()
            }
        }
    }

    #[must_use]
    fn handle_established(&mut self, seg: &TcpSegment<'_>) -> Option<TcpSegment<'_>> {
        if !self.is_segment_acceptable(seg) {
            return self.handle_unacceptable_segment(seg);
        }

        if seg.header.rst() {
            if SequenceNumber(seg.header.seq_number()) == self.rcv_nxt {
                //  If the RST bit is set, then any outstanding RECEIVEs and SEND
                //  should receive "reset" responses. All segment queues should be flushed.
                //  Users should also receive an unsolicited general "connection reset" signal.
                //  Enter the CLOSED state, delete the TCB, and return.
                self.state = Closed;
                return None;
            } else {
                return Some(self.send_ack(self.snd_nxt, self.rcv_nxt));
            }
        }

        if seg.header.syn() {
            return Some(self.send_ack(self.snd_nxt, self.rcv_nxt));
        }

        // check 5
        if !seg.header.ack() {
            return None;
        }

        // todo: check 7 process the segment text

        // it can only return drop, sendAck, or continue
        let ack_action = self.process_ack(seg);

        if ack_action == SegmentAction::Drop {
            return None;
        }

        if ack_action == SegmentAction::SendAck {
            return Some(self.send_ack(self.snd_nxt, self.rcv_nxt));
        }

        // do establish related operation now

        None
    }

    #[must_use]
    fn handle_fin_wait1(&mut self, seg: &TcpSegment<'_>) -> Option<TcpSegment<'_>> {
        if !self.is_segment_acceptable(seg) {
            return self.handle_unacceptable_segment(seg);
        }

        if seg.header.rst() {
            if SequenceNumber(seg.header.seq_number()) == self.rcv_nxt {
                // todo: any outstanding RECEIVEs and SEND should receive "reset" responses.
                //  All segment queues should be flushed. Users should also receive
                //  an unsolicited general "connection reset" signal.
                self.state = Closed;
                return None;
            } else {
                return Some(self.send_ack(self.snd_nxt, self.rcv_nxt));
            }
        }

        if seg.header.syn() {
            // todo: maybe do ack throttling
            return Some(self.send_ack(self.snd_nxt, self.rcv_nxt));
        }

        if !seg.header.ack() {
            return None;
        }

        if !self.is_ack_acceptable(SequenceNumber(seg.header.ack_number())) {
            return Some(self.send_ack(self.snd_nxt, self.rcv_nxt));
        }

        let ack_action = self.process_ack(seg);

        if ack_action == SegmentAction::Drop {
            return None;
        }

        if ack_action == SegmentAction::SendAck {
            return Some(self.send_ack(self.snd_nxt, self.rcv_nxt));
        }

        // if the FIN segment is now acknowledged, then enter FIN-WAIT-2 and continue processing in that state.
        // fin consumes a sequence number
        if self.snd_una == self.snd_nxt {
            self.state = FinWait2;
        }

        if seg.header.fin() {
            // our FIN has been ACKed (perhaps in this segment), then enter TIME-WAIT,
            //  start the time-wait timer, turn off the other timers; otherwise, enter the CLOSING state.
        }

        None
    }

    #[must_use]
    fn handle_fin_wait2(&mut self, seg: &TcpSegment<'_>) -> Option<TcpSegment<'_>> {
        todo!()
    }

    #[must_use]
    fn handle_close_wait(&mut self, seg: &TcpSegment<'_>) -> Option<TcpSegment<'_>> {
        todo!()
    }

    #[must_use]
    fn handle_closing(&mut self, seg: &TcpSegment<'_>) -> Option<TcpSegment<'_>> {
        todo!()
    }

    #[must_use]
    fn handle_last_ack(&mut self, seg: &TcpSegment<'_>) -> Option<TcpSegment<'_>> {
        todo!()
    }

    #[must_use]
    fn handle_time_wait(&mut self, seg: &TcpSegment<'_>) -> Option<TcpSegment<'_>> {
        todo!()
    }

    /// RFC 9293 state machine
    #[must_use]
    pub(crate) fn process(&mut self, seg: TcpSegment) -> Option<TcpSegment<'_>> {
        match self.state {
            SynSent => self.handle_syn_sent(&seg),
            SynReceived => self.handle_syn_received(&seg),
            Established => self.handle_established(&seg),
            TcpState::Listen => self.handle_listen(&seg),
            TcpState::FinWait1 => self.handle_fin_wait1(&seg),
            TcpState::FinWait2 => self.handle_fin_wait2(&seg),
            TcpState::CloseWait => self.handle_close_wait(&seg),
            TcpState::Closing => self.handle_closing(&seg),
            TcpState::LastAck => self.handle_last_ack(&seg),
            TcpState::TimeWait => self.handle_time_wait(&seg),
            TcpState::Closed => {
                todo!()
                // we can enjoy some cookie here
            }
        }
    }
}

#[cfg(test)]
mod state_machine_tests {
    use super::*;

    use std::{
        net::Ipv4Addr,
        panic::{AssertUnwindSafe, catch_unwind},
    };

    fn make_tcb(state: TcpState) -> Tcb {
        let key = TcbKey {
            local_addr: Ipv4Addr::new(10, 0, 0, 1),
            local_port: 8080,
            remote_addr: Ipv4Addr::new(10, 0, 0, 2),
            remote_port: 50000,
        };

        let mut tcb = Tcb::new(&key, SequenceNumber(100));
        tcb.state = state;
        tcb.snd_una = SequenceNumber(100);
        tcb.snd_nxt = SequenceNumber(101);
        tcb.rcv_nxt = SequenceNumber(200);
        tcb.rcv_wnd = 100;
        tcb.snd_wnd = 4096;
        tcb.max_snd_wnd = u16::MAX;

        tcb
    }

    fn segment(seq: u32, ack: u32, flags: TcpFlags) -> TcpSegment<'static> {
        let header = TcpHeader::new(50000, 8080, seq, ack, flags);
        TcpSegment::new(header, &[])
    }

    #[test]
    fn established_to_closed_on_in_window_rst() {
        let mut tcb = make_tcb(TcpState::Established);
        let seg = segment(200, 0, TcpFlags::Rst);

        let response = tcb.process(seg);
        assert!(response.is_none());
        drop(response);

        assert_eq!(tcb.state, TcpState::Closed);
    }

    #[test]
    fn syn_sent_drops_acceptable_ack_without_syn_or_rst() {
        let mut tcb = make_tcb(TcpState::SynSent);
        let seg = segment(200, 101, TcpFlags::Ack);

        let response = tcb.process(seg);

        assert!(response.is_none());
        assert_eq!(tcb.state, TcpState::SynSent);
    }

    #[test]
    fn established_sends_ack_for_rst_with_wrong_sequence() {
        let mut tcb = make_tcb(TcpState::Established);
        let seg = segment(201, 0, TcpFlags::Rst);

        let response = tcb.process(seg).expect("expected ACK response");

        let is_ack = response.header.ack();
        let seq = response.header.seq_number();
        let ack = response.header.ack_number();

        drop(response);

        assert_eq!(tcb.state, TcpState::Established);
        assert!(is_ack);
        assert_eq!(seq, 101);
        assert_eq!(ack, 200);
    }

    #[test]
    fn fin_wait1_to_fin_wait2_when_fin_is_acknowledged() {
        let mut tcb = make_tcb(TcpState::FinWait1);
        let seg = segment(200, 101, TcpFlags::Ack);

        let response = tcb.process(seg);
        assert!(response.is_none());
        drop(response);

        assert_eq!(tcb.state, TcpState::FinWait2);
        assert_eq!(tcb.snd_una, SequenceNumber(101));
    }

    #[test]
    fn syn_sent_to_syn_received_on_syn_without_ack() {
        let mut tcb = make_tcb(TcpState::SynSent);
        let seg = segment(900, 0, TcpFlags::Syn);

        let response = tcb.process(seg).expect("expected SYN-ACK response");

        assert!(response.header.syn());
        assert!(response.header.ack());
        assert_eq!(response.header.seq_number(), 100);
        assert_eq!(response.header.ack_number(), 901);

        drop(response);

        assert_eq!(tcb.state, TcpState::SynReceived);
        assert_eq!(tcb.irs, SequenceNumber(900));
        assert_eq!(tcb.rcv_nxt, SequenceNumber(901));
    }

    #[test]
    fn syn_received_to_established_on_valid_ack() {
        let mut tcb = make_tcb(TcpState::SynReceived);

        // Valid ACK: snd_una < ACK <= snd_nxt.
        let mut header = TcpHeader::new(50000, 8080, 200, 101, TcpFlags::Ack);
        header.set_window(4096);
        let seg = TcpSegment::new(header, &[]);

        // The current handler changes state, then reaches todo!().
        let result = catch_unwind(AssertUnwindSafe(|| tcb.process(seg)));

        assert!(result.is_err(), "current handler is unfinished");
        assert_eq!(tcb.state, TcpState::Established);
        assert_eq!(tcb.snd_wnd, 4096);
    }

    #[test]
    fn syn_received_to_close_wait_when_valid_ack_also_has_fin() {
        let mut tcb = make_tcb(TcpState::SynReceived);
        let seg = segment(200, 101, TcpFlags::Ack | TcpFlags::Fin);

        // The current handler changes state to Established and then CloseWait,
        // before reaching todo!().
        let result = catch_unwind(AssertUnwindSafe(|| tcb.process(seg)));

        assert!(result.is_err(), "current handler is unfinished");
        assert_eq!(tcb.state, TcpState::CloseWait);
    }
}
