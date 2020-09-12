use pcap::Packet;

use crate::netframe::UnknownFrame;

use super::HwAddr;
use super::*;

pub enum EtherType<'a> {
    Ipv4(Ipv4Frame<'a>),
    Ipv6(Ipv6Frame<'a>),
    Arp(ArpFrame<'a>),
    IeeeLlc(IeeeLlcFrame<'a>),
    IeeeSnap,
    NovellIeee,
    Other(UnknownFrame<'a>),
}

impl<'a> fmt::Display for EtherType<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EtherType::Ipv4(_) => write!(f, "IPv4 (0x0800)"),
            EtherType::Ipv6(_) => write!(f, "IPv6 (0x86DD)"),
            EtherType::Arp(_) => write!(f, "ARP (0x0806)"),
            EtherType::IeeeLlc(_) => write!(f, "IEEE 802.2 LLC (< 1500)"),
            EtherType::IeeeSnap => write!(
                f, 
                "IEEE 802.2 SNAP (< 1500, payload begins with 0xAAAA)"
            ),
            EtherType::NovellIeee => write!(
                f,
                "Novell raw IEEE 802.3 (< 1500, payload begins with 0xFFFF)"
            ),
            EtherType::Other(typ) => write!(f, "Other (0x{:04X})", typ.type_id()),
        }
    }
}

pub struct EthernetFrame<'a> {
    header: &'a [u8],
    payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    pub fn dest_addr(&self) -> HwAddr {
        HwAddr::from(&self.header[0..6])
    }

    pub fn src_addr(&self) -> HwAddr {
        HwAddr::from(&self.header[6..12])
    }

    pub fn ether_type(&self) -> u16 {
        u16::from_be_bytes(clone_into_array(&self.header[12..14]))
    }

    pub fn try_next_header(self) -> EtherType<'a> {
        match self.ether_type() {
            0x0800 => EtherType::Ipv4(Ipv4Frame::from(self)),
            0x86DD => EtherType::Ipv6(Ipv6Frame::from(self)),
            0x0806 => EtherType::Arp(ArpFrame::from(self)),
            size if size <= 1500 => {
                let id = u16::from_be_bytes(clone_into_array(&self.payload[0..2]));
                if id == 0xFFFF {
                    EtherType::NovellIeee
                } else if id == 0xAAAA {
                    EtherType::IeeeSnap
                } else {
                    EtherType::IeeeLlc(IeeeLlcFrame::from(self))
                }
            }
            other => EtherType::Other(UnknownFrame::from_u8_slice(self.payload, other)),
        }
    }

    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

impl<'a> From<&'a [u8]> for EthernetFrame<'a> {
    fn from(slice: &'a [u8]) -> Self {
        let (header, payload) = slice.split_at(14);
        Self { header, payload }
    }
}

impl<'a> From<Packet<'a>> for EthernetFrame<'a> {
    fn from(pkg: Packet<'a>) -> Self {
        Self::from(pkg.data)
    }
}
