use std::net::AddrParseError;

use thiserror::Error;

/// Top-level error type exposed by the rawtcp library.
#[derive(Debug, Error)]
pub enum Error {
    // --------------------------------------------------
    // Configuration
    // --------------------------------------------------
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("invalid IP address")]
    InvalidAddress(#[from] AddrParseError),

    #[error("unsupported IP version: {0}")]
    UnsupportedIpVersion(u8),

    // --------------------------------------------------
    // Platform / transport
    // --------------------------------------------------
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TUN device error: {0}")]
    Tun(String),

    #[error("transport is closed")]
    TransportClosed,

    #[error("failed to send packet: {0}")]
    PacketSend(String),

    #[error("received packet exceeds configured size limit")]
    PacketTooLarge,

    #[error("packet buffer is too small: required {required} bytes, got {actual}")]
    BufferTooSmall { required: usize, actual: usize },

    // --------------------------------------------------
    // IP layer
    // --------------------------------------------------
    #[error("malformed IPv4 packet: {0}")]
    Ipv4(#[from] Ipv4Error),

    #[error("unsupported IP protocol number: {0}")]
    UnsupportedIpProtocol(u8),

    #[error("IPv4 fragmentation is unsupported")]
    FragmentationUnsupported,

    #[error("invalid IPv4 header checksum")]
    InvalidIpv4Checksum,

    // --------------------------------------------------
    // TCP wire format
    // --------------------------------------------------
    #[error("malformed TCP segment: {0}")]
    TcpHeader(#[from] TcpHeaderError),

    #[error("invalid TCP checksum")]
    InvalidTcpChecksum,

    #[error("unsupported TCP option: {0}")]
    UnsupportedTcpOption(u8),

    // #[error("failed to parse: {0}")]
    // Zerocopy(#[from] zerocopy::ConvertError<zerocopy::SizeError>),

    // --------------------------------------------------
    // Connection management
    // --------------------------------------------------
    #[error("connection not found")]
    ConnectionNotFound,

    #[error("connection already exists")]
    ConnectionAlreadyExists,

    #[error("connection is closed")]
    ConnectionClosed,

    #[error("connection reset by peer")]
    ConnectionReset,

    #[error("connection timed out")]
    ConnectionTimedOut,

    #[error("connection is in an invalid state for this operation")]
    InvalidConnectionState,

    #[error("connection establishment failed: {0}")]
    ConnectionFailed(String),

    #[error("connection backlog is full")]
    BacklogFull,

    #[error("no listening socket matches the destination")]
    ListenerNotFound,

    #[error("local address is already in use")]
    AddressInUse,

    #[error("no local port is available")]
    NoAvailablePort,

    // --------------------------------------------------
    // Application-facing API
    // --------------------------------------------------
    #[error("operation would block")]
    WouldBlock,

    #[error("operation is not supported")]
    OperationNotSupported,

    #[error("invalid operation for the current endpoint state")]
    InvalidOperation,

    #[error("send buffer is full")]
    SendBufferFull,

    #[error("receive side has been closed")]
    ReceiveClosed,

    #[error("send side has been closed")]
    SendClosed,

    // --------------------------------------------------
    // Resources
    // --------------------------------------------------
    #[error("resource limit exceeded: {0}")]
    ResourceLimitExceeded(&'static str),

    #[error("allocation size overflow")]
    AllocationSizeOverflow,

    // --------------------------------------------------
    // Internal failures
    // --------------------------------------------------
    #[error("internal invariant violated: {0}")]
    InternalInvariant(&'static str),
}

/// Errors encountered while parsing or validating IPv4 packets.
#[derive(Debug, Error)]
pub enum Ipv4Error {
    // Header bounds
    #[error("packet is shorter than the minimum IPv4 header")]
    TruncatedHeader,

    #[error("IPv4 header length is invalid: {0} bytes")]
    InvalidHeaderLength(usize),

    #[error("IPv4 header length exceeds available packet data")]
    TruncatedHeaderOptions,

    #[error("IPv4 total length is smaller than its header length")]
    TotalLengthSmallerThanHeader,

    #[error("IPv4 total length exceeds available packet data")]
    TruncatedPacket,

    #[error("IPv4 packet contains trailing data: {0} bytes")]
    TrailingData(usize),

    // Header fields
    #[error("invalid IPv4 version: {0}")]
    InvalidVersion(u8),

    #[error("invalid IPv4 header checksum")]
    InvalidChecksum,

    #[error("IPv4 reserved flag is set")]
    ReservedFlagSet,

    #[error("IPv4 TTL is zero")]
    ZeroTtl,

    #[error("IPv4 header contains an invalid DSCP value: {0}")]
    InvalidDscp(u8),

    #[error("IPv4 header contains an invalid ECN value: {0}")]
    InvalidEcn(u8),

    // Options
    #[error("IPv4 options are malformed")]
    MalformedOptions,

    #[error("IPv4 options exceed the maximum allowed length")]
    OptionsTooLong,

    #[error("IPv4 option has an invalid length: {0}")]
    InvalidOptionLength(u8),

    #[error("IPv4 option is truncated")]
    TruncatedOption,

    #[error("IPv4 option is unsupported: {0}")]
    UnsupportedOption(u8),

    #[error("IPv4 options contain an invalid alignment")]
    InvalidOptionAlignment,

    // Fragmentation
    #[error("IPv4 packet contains an unsupported fragment")]
    UnsupportedFragment,

    #[error("IPv4 fragment offset and flags are inconsistent")]
    InvalidFragment,

    #[error("IPv4 fragment offset exceeds the supported range")]
    FragmentOffsetOutOfRange,

    #[error("IPv4 fragment payload length is invalid")]
    InvalidFragmentPayloadLength,

    #[error("IPv4 fragment is too small to contain the required header")]
    TruncatedFragment,

    #[error("IPv4 packet has the DF flag set but requires fragmentation")]
    DontFragmentSet,

    // Protocol and payload
    #[error("IPv4 payload length is invalid")]
    InvalidPayloadLength,

    #[error("IPv4 packet uses a disallowed protocol number: {0}")]
    UnsupportedProtocol(u8),

    // Configuration and policy
    #[error("IPv4 packet exceeds the configured maximum size")]
    PacketTooLarge,

    #[error("IPv4 packet has a forbidden source address")]
    ForbiddenSourceAddress,

    #[error("IPv4 packet has a forbidden destination address")]
    ForbiddenDestinationAddress,

    #[error("IPv4 packet failed validation policy: {0}")]
    PolicyViolation(&'static str),

    #[error("failed to parse IPv4 packet: {0}")]
    ParseError(String),
}

/// Errors encountered while parsing or validating TCP headers and options.
#[derive(Debug, Error)]
pub enum TcpHeaderError {
    // Fixed header
    #[error("TCP segment is shorter than the minimum TCP header")]
    TruncatedHeader,

    #[error("TCP data offset is invalid: {0} bytes")]
    InvalidDataOffset(usize),

    #[error("TCP header length exceeds available segment data")]
    TruncatedSegment,

    #[error("TCP segment length is invalid")]
    InvalidSegmentLength,

    // Reserved bits and flags
    #[error("TCP reserved bits are nonzero")]
    InvalidReservedBits,

    #[error("TCP control flags contain an invalid combination")]
    InvalidFlags,

    #[error("TCP NS flag is invalid")]
    InvalidNsFlag,

    // Options
    #[error("TCP options are malformed")]
    MalformedOptions,

    #[error("TCP option has an invalid length")]
    InvalidOptionLength,

    #[error("TCP option exceeds the available header")]
    TruncatedOption,

    #[error("TCP option kind is unsupported: {0}")]
    UnsupportedOption(u8),

    #[error("TCP option kind {kind} occurs more than once")]
    DuplicateOption { kind: u8 },

    #[error("TCP option {kind} has an invalid length: {length}")]
    InvalidOptionLengthForKind { kind: u8, length: usize },

    #[error("TCP option padding is invalid")]
    InvalidOptionPadding,

    #[error("TCP option is missing required data")]
    MissingOptionData,

    // Specific option validation
    #[error("TCP Maximum Segment Size option has an invalid value: {0}")]
    InvalidMss(u16),

    #[error("TCP window scale option has an invalid shift count: {0}")]
    InvalidWindowScale(u8),

    #[error("TCP SACK option has an invalid block length")]
    InvalidSackLength,

    #[error("TCP timestamp option is malformed")]
    InvalidTimestampOption,

    // Segment semantics
    #[error("TCP urgent pointer is invalid for this segment")]
    InvalidUrgentPointer,

    #[error("TCP checksum is invalid")]
    InvalidChecksum,

    #[error("TCP segment contains trailing data inconsistent with its header")]
    InvalidPayloadOffset,

    // Resource and parsing limits
    #[error("TCP header exceeds the maximum permitted length: {0} bytes")]
    HeaderTooLarge(usize),

    #[error("TCP options exceed the maximum permitted length: {0} bytes")]
    OptionsTooLarge(usize),

    #[error("TCP header parsing encountered an unexpected end of input")]
    UnexpectedEnd,
}
