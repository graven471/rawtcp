use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use rawtcp::platform::linux::tun::{Device, DeviceOptions};
use rawtcp::tcp::interface::Interface;

fn main() {
    let options = DeviceOptions {
        name: "test_tun0",
        addr: Ipv4Addr::new(192, 168, 10, 1),
        netmask: 24,
        broadcast: Ipv4Addr::new(192, 168, 10, 255),
    };

    let mut device = Device::new().expect("failed to create tun device run with sudo");
    device.up().expect("failed to bring up tun device");

    let mut tcp = Interface::new(device);

    // let sock_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 2)), 8080);
    let listen_sock_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 1)), 8080);

    tcp.listen(listen_sock_addr).unwrap();
    // tcp.connect(sock_addr).unwrap();
}
