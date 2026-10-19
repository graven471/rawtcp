use std::{net::Ipv4Addr, os::fd::AsRawFd};

// todo: replace tappers with my own abstraction
use tappers::{AddAddressV4, DeviceState, Interface, linux::Tun};

use crate::error::Error;

#[derive(Debug, Clone, Copy)]
pub struct DeviceOptions<'a> {
    pub name: &'a str,
    pub addr: Ipv4Addr,
    pub netmask: u8,
    pub broadcast: Ipv4Addr,
}

pub struct Device {
    handle: Tun,
    addr: Ipv4Addr,
    pub state: DeviceState,
}

impl Device {
    pub fn new() -> Result<Self, Error> {
        let interface_name = Interface::new("tun0")?;
        let handle = Tun::new_named(interface_name)?;

        let addr = Ipv4Addr::new(10, 0, 0, 1);
        //         let mut addr_req = AddAddressV4::new(addr);
        //         addr_req.set_netmask(24);
        //         addr_req.set_broadcast(Ipv4Addr::new(10, 100, 0, 255));
        //
        //         handle.add_addr(addr_req)?;

        Ok(Self {
            handle,
            addr,
            state: DeviceState::Down,
        })
    }

    pub fn new_with_options(options: DeviceOptions) -> Result<Self, Error> {
        let interface_name = Interface::new(options.name)?;
        let handle = Tun::new_named(interface_name)?;

        let mut addr_req = AddAddressV4::new(options.addr);
        // addr_req.set_netmask(options.netmask);
        addr_req.set_broadcast(options.broadcast);

        handle.add_addr(options.addr)?;

        Ok(Self {
            handle,
            addr: options.addr,
            state: DeviceState::Down,
        })
    }

    #[inline]
    pub fn fd(&self) -> i32 {
        self.handle.as_raw_fd()
    }

    #[inline]
    pub fn address(&self) -> Ipv4Addr {
        self.addr
    }

    #[inline]
    pub fn up(&mut self) -> Result<(), Error> {
        if self.state == DeviceState::Up {
            return Ok(());
        }

        self.handle.set_state(DeviceState::Up)?;
        self.state = DeviceState::Up;
        Ok(())
    }

    #[inline]
    pub fn down(&mut self) -> Result<(), Error> {
        if self.state == DeviceState::Down {
            return Ok(());
        }

        self.handle.set_state(DeviceState::Down)?;
        self.state = DeviceState::Down;
        Ok(())
    }

    #[inline]
    pub fn send(&self, buf: impl AsRef<[u8]>) -> Result<usize, Error> {
        Ok(self.handle.send(buf.as_ref())?)
    }

    #[inline]
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        Ok(self.handle.recv(buf)?)
    }
}
