use std::net::Ipv4Addr;

use rawtcp::platform::linux::tun::{Device, DeviceOptions};
use tappers::DeviceState;

#[test]
#[ignore = "Creates/configures a real TUN interface; requires suitable privileges"]
fn new_creates_default_device() {
    let device = Device::new().expect("Device::new failed");

    assert_eq!(device.state, DeviceState::Down);
}

#[test]
#[ignore = "Creates/configures a real TUN interface; requires suitable privileges"]
fn new_with_options_creates_device() {
    let options = DeviceOptions {
        name: "test_tun0",
        addr: Ipv4Addr::new(192, 168, 10, 1),
        netmask: 24,
        broadcast: Ipv4Addr::new(192, 168, 10, 255),
    };

    let device = Device::new_with_options(options).expect("Device::new_with_options failed");

    assert_eq!(device.state, DeviceState::Down);
}

#[test]
#[ignore = "Requires a real TUN interface"]
fn up_changes_state_to_up() {
    let mut device = Device::new().expect("Device::new failed");

    device.up().expect("up failed");

    assert_eq!(device.state, DeviceState::Up);
}

#[test]
#[ignore = "Requires a real TUN interface"]
fn down_changes_state_to_down() {
    let mut device = Device::new().expect("Device::new failed");

    device.up().expect("up failed");
    device.down().expect("down failed");

    assert_eq!(device.state, DeviceState::Down);
}

#[test]
#[ignore = "Requires a real TUN interface"]
fn up_is_idempotent() {
    let mut device = Device::new().expect("Device::new failed");

    device.up().expect("first up failed");
    device.up().expect("second up failed");

    assert_eq!(device.state, DeviceState::Up);
}

#[test]
#[ignore = "Requires a real TUN interface"]
fn down_is_idempotent() {
    let mut device = Device::new().expect("Device::new failed");

    // Device starts Down, so this should be a no-op.
    device.down().expect("down failed");

    assert_eq!(device.state, DeviceState::Down);
}

#[test]
#[ignore = "Requires a real TUN interface"]
fn can_transition_repeatedly_between_up_and_down() {
    let mut device = Device::new().expect("Device::new failed");

    device.up().expect("up failed");
    assert_eq!(device.state, DeviceState::Up);

    device.down().expect("down failed");
    assert_eq!(device.state, DeviceState::Down);

    device.up().expect("second up failed");
    assert_eq!(device.state, DeviceState::Up);

    device.down().expect("second down failed");
    assert_eq!(device.state, DeviceState::Down);
}

#[test]
#[ignore = "Requires a real TUN interface"]
fn send_empty_buffer_succeeds_or_returns_io_error() {
    let device = Device::new().expect("Device::new failed");

    // An empty write may be accepted or rejected by the OS/backend.
    // This test checks only that the API returns a Result without panicking.
    let _result = device.send([]);
}

#[test]
#[ignore = "Requires a real TUN interface"]
fn recv_empty_buffer_succeeds_or_returns_io_error() {
    let mut device = Device::new().expect("Device::new failed");

    // A zero-length receive should not write beyond the provided buffer.
    let mut buffer = [];

    let _result = device.recv(&mut buffer);
}
