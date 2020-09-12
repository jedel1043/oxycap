use std::fmt;

use ux::*;

pub use ipv4_frame::*;
pub use ipv6_frame::*;
pub use icmp_frame::*;
pub use igmp_frame::*;

use crate::clone_into_array;
use crate::error_check::*;
use crate::netframe::UnknownFrame;

use super::datalink::EthernetFrame;
use super::transport::*;

mod ipv4_frame;
mod ipv6_frame;
mod icmp_frame;
mod igmp_frame;

pub enum IpProtocol<'a> {
    Tcp(TcpFrame<'a>),
    Udp(UdpFrame<'a>),
    Icmp(IcmpFrame<'a>),
    Igmp(IgmpFrame<'a>),
    Other(UnknownFrame<'a>),
}

impl<'a> fmt::Display for IpProtocol<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpProtocol::Tcp(_) => write!(f, "TCP (0x06)"),
            IpProtocol::Udp(_) => write!(f, "UDP (0x11)"),
            IpProtocol::Icmp(_) => write!(f, "ICMP (0x01)"),
            IpProtocol::Igmp(_) => write!(f, "IGMP (0x02)"),
            IpProtocol::Other(typ) => write!(f, "Other (0x{:02X})", typ.type_id())
        }
    }
}