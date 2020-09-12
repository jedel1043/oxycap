use std::net::Ipv6Addr;

use super::*;

pub struct Ipv6Frame<'a> {
    header: &'a [u8],
    payload: &'a [u8],
}

impl<'a> Ipv6Frame<'a> {
    pub fn raw_header(&self) -> &'a [u8] {
        self.header
    }

    pub fn ver(&self) -> u4 {
        u4::new(self.header[0] >> 4)
    }

    pub fn traffic_class(&self) -> u8 {
        let upper_nibble = (self.header[0] & 0x0F) << 4;
        let lower_nibble = (self.header[1] & 0xf0) >> 4;
        u8::from(upper_nibble | lower_nibble)
    }

    pub fn flow_label(&self) -> u20 {
        let upper_nibble = u32::from(self.header[1] & 0x0F) << 16;
        let lower_double_byte = u32::from_be_bytes([0, 0, self.header[2], self.header[3]]);
        u20::new(upper_nibble | lower_double_byte)
    }

    pub fn payload_len(&self) -> u16 {
        u16::from_be_bytes(clone_into_array(&self.header[4..6]))
    }

    pub fn next_header(&self) -> u8 {
        self.header[6]
    }

    pub fn hop_limit(&self) -> u8 {
        self.header[7]
    }

    pub fn src_addr(&self) -> Ipv6Addr {
        Ipv6Addr::new(
            u16::from_be_bytes([self.header[8], self.header[9]]),
            u16::from_be_bytes([self.header[10], self.header[11]]),
            u16::from_be_bytes([self.header[12], self.header[13]]),
            u16::from_be_bytes([self.header[14], self.header[15]]),
            u16::from_be_bytes([self.header[16], self.header[17]]),
            u16::from_be_bytes([self.header[18], self.header[19]]),
            u16::from_be_bytes([self.header[20], self.header[21]]),
            u16::from_be_bytes([self.header[22], self.header[23]]),
        )
    }

    pub fn dest_addr(&self) -> Ipv6Addr {
        Ipv6Addr::new(
            u16::from_be_bytes([self.header[24], self.header[25]]),
            u16::from_be_bytes([self.header[26], self.header[27]]),
            u16::from_be_bytes([self.header[28], self.header[29]]),
            u16::from_be_bytes([self.header[30], self.header[31]]),
            u16::from_be_bytes([self.header[32], self.header[33]]),
            u16::from_be_bytes([self.header[34], self.header[35]]),
            u16::from_be_bytes([self.header[36], self.header[37]]),
            u16::from_be_bytes([self.header[38], self.header[39]]),
        )
    }

    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

impl<'a> From<&'a [u8]> for Ipv6Frame<'a> {
    fn from(slice: &'a [u8]) -> Self {
        assert_eq!(slice[0] & 0xF0, 0x60);

        let (header, payload) = slice.split_at(40);
        Self {
            header,
            payload,
        }
    }
}

impl<'a> From<EthernetFrame<'a>> for Ipv6Frame<'a> {
    fn from(frame: EthernetFrame<'a>) -> Self {
        Self::from(frame.payload())
    }
}
