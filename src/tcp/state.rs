#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TcpState {
    /// represents no connection state at all
    Closed,
    /// represents waiting for connection request from any remote TCP peer and port
    Listen,
    /// represents waiting for a matching connection request after having sent a connection
    /// request
    SynSent,
    /// represents waiting for confirmation connection request acknowledgment after having
    /// both received and sent a connection request
    SynReceived,
    /// represents an open connection, data received can be delivered to the user
    Established,
    FinWait1,
    FinWait2,
    /// represents waiting for a connection termination request from the local user
    CloseWait,
    /// represents waiting for a connection termination request acknowledgment from the remote TCP peer
    Closing,
    LastAck,
    TimeWait,
}
