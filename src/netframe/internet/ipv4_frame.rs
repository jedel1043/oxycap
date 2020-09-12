use std::net::Ipv4Addr;

use super::*;

pub struct Ipv4Frame<'a> {
    header: &'a [u8],
    opts: Option<&'a [u8]>,
    payload: &'a [u8],
}

impl<'a> Ipv4Frame<'a> {
    pub fn raw_header(&self) -> &'a [u8] {
        self.header
    }

    pub fn ver(&self) -> u4 {
        u4::new(self.header[0] >> 4)
    }

    pub fn ihl(&self) -> u4 {
        u4::new(self.header[0] & 0x0F)
    }

    pub fn dscp(&self) -> u6 {
        u6::new(self.header[1] >> 2)
    }

    pub fn ecn(&self) -> u2 {
        u2::new(self.header[1] & 0b0000_0011)
    }

    pub fn total_len(&self) -> u16 {
        u16::from_be_bytes(clone_into_array(&self.header[2..=3]))
    }

    pub fn id(&self) -> u16 {
        u16::from_be_bytes(clone_into_array(&self.header[4..=5]))
    }

    pub fn flags(&self) -> u8 {
        self.header[6] >> 5
    }

    pub fn dont_fragment(&self) -> bool {
        self.flags() & 0b010 == 1
    }

    pub fn more_fragments(&self) -> bool {
        self.flags() & 0b001 == 1
    }

    pub fn offset(&self) -> u13 {
        u13::new(u16::from_be_bytes([
            self.header[6] & 0b0001_1111,
            self.header[7],
        ]))
    }

    pub fn ttl(&self) -> u8 {
        self.header[8]
    }

    pub fn protocol(&self) -> u8 {
        self.header[9]
    }

    pub fn try_next_header(self) -> IpProtocol<'a> {
        match self.protocol() {
            0x06 => IpProtocol::Tcp(TcpFrame::from(self)),
            0x11 => IpProtocol::Udp(UdpFrame::from(self)),
            0x01 => IpProtocol::Icmp(IcmpFrame::from(self)),
            0x02 => IpProtocol::Igmp(IgmpFrame::from(self)),
            other => IpProtocol::Other(UnknownFrame::from_u8_slice(self.payload, other as u16))
        }
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(clone_into_array(&self.header[10..=11]))
    }

    pub fn src_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(clone_into_array::<[u8; 4], u8>(&self.header[12..=15]))
    }

    pub fn dest_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(clone_into_array::<[u8; 4], u8>(&self.header[16..=19]))
    }

    pub fn header_len(&self) -> u16 {
        u16::from(u8::from(self.ihl()) * 4)
    }

    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    pub fn opts(&self) -> Option<&'a [u8]> {
        self.opts
    }

    pub fn has_integrity(&self) -> bool {
        match self.opts {
            None => u8_checksum16(&self.header) == 0,
            Some(opts) => {
                u16_checksum16(&[u8_slice_to_sum16(&self.header), u8_slice_to_sum16(opts)]) == 0
            }
        }
    }
}

impl<'a> From<&'a [u8]> for Ipv4Frame<'a> {
    fn from(slice: &'a [u8]) -> Self {
        let header_len = usize::from(slice[0] & 0x0F);

        let (header, payload) = slice.split_at(header_len * 4);
        let (header, opts) = header.split_at(20);
        Self {
            header,
            payload,
            opts: match opts {
                [] => None,
                _ => Some(opts),
            },
        }
    }
}

impl<'a> From<EthernetFrame<'a>> for Ipv4Frame<'a> {
    fn from(frame: EthernetFrame<'a>) -> Self {
        Self::from(frame.payload())
    }
}
