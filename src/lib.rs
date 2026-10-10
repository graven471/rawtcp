pub mod error;
pub mod net;
pub mod platform;
pub mod tcp;
pub mod wire;
/*
* ok so here is overall design initially
*
* there will be a seperate api for TUN device something like
* let tun = TunTap::new();
* let fd = tun.get_fd();
*
* let tcp = Connection::new(fd);
* or
* let tcp = Connection::new_with_option(fd, options)
* tcp.send(N);
* tcp.listen();
* tcp.accept();
* tcp.close();
*
*tcp-stack/
├── Cargo.toml
├── README.md
├── docs/
│   ├── architecture.md
│   ├── state-machine.md
│   └── rfc-compliance.md
│
├── src/
│   ├── lib.rs
│   ├── main.rs
│   │
│   ├── platform/
│   │   └── tun/
│   │       ├── mod.rs
│   │       ├── device.rs
│   │       └── config.rs
│   │
│   ├── net/
│   │   ├── mod.rs
│   │   ├── packet.rs
│   │   ├── ipv4.rs
│   │   ├── ipv6.rs
│   │   └── route.rs
│   │
│   ├── wire/
│   │   ├── mod.rs
│   │   ├── tcp_header.rs
│   │   ├── options.rs
│   │   └── checksum.rs
│   │
│   ├── tcp/
│   │   ├── mod.rs
│   │   ├── stack.rs
│   │   ├── demux.rs
│   │   ├── listener.rs
│   │   ├── connection.rs
│   │   ├── state.rs
│   │   ├── seq.rs
│   │   ├── handshake.rs
│   │   ├── send.rs
│   │   ├── receive.rs
│   │   ├── reassembly.rs
│   │   ├── ack.rs
│   │   ├── retransmit.rs
│   │   ├── flow_control.rs
│   │   ├── congestion.rs
│   │   └── close.rs
│   │
│   ├── runtime/
│   │   ├── mod.rs
│   │   ├── event_loop.rs
│   │   └── timer.rs
│   │
│   └── socket/
│       ├── mod.rs
│       └── stream.rs
│
├── tests/
│   ├── packet_io.rs
│   ├── handshake.rs
│   ├── data_transfer.rs
│   ├── retransmission.rs
│   └── teardown.rs
│
└── examples/
    └── echo.rs
*
*/
