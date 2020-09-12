use crate::clone_into_array;
use crate::error_check::*;

use super::{Ipv4Frame, Ipv6Frame};

pub struct UdpFrame<'a> {
    pseudo_header_sum: u16,
    header: &'a [u8],
    payload: &'a [u8],
}

impl<'a> UdpFrame<'a> {
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(clone_into_array(&self.header[0..2]))
    }

    pub fn dest_port(&self) -> u16 {
        u16::from_be_bytes(clone_into_array(&self.header[2..4]))
    }

    pub fn len(&self) -> u16 {
        u16::from_be_bytes(clone_into_array(&self.header[4..6]))
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(clone_into_array(&self.header[6..8]))
    }

    pub fn has_integrity(&self) -> bool {
        u16_checksum16(&[
            self.pseudo_header_sum,
            u8_slice_to_sum16(self.header),
            u8_slice_to_sum16(self.payload),
        ]) == 0
    }

    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

impl<'a> From<Ipv4Frame<'a>> for UdpFrame<'a> {
    fn from(frame: Ipv4Frame<'a>) -> Self {
        let addr_sum = u8_slice_to_sum16(&frame.raw_header()[12..20]);
        let protocol = 0x11 as u16;
        let payload_len = frame.payload().len() as u16;

        let (header, payload) = frame.payload().split_at(8);
        Self {
            pseudo_header_sum: u16_slice_to_sum16(&[addr_sum, protocol, payload_len]),
            header,
            payload,
        }
    }
}

impl<'a> From<Ipv6Frame<'a>> for UdpFrame<'a> {
    fn from(frame: Ipv6Frame<'a>) -> Self {
        let addr_sum = u8_slice_to_sum16(&frame.raw_header()[8..40]);
        let protocol = 0x11 as u16;
        let payload_len = match frame.payload().len() {
            x if x > 0x00_00_FF_FF => {
                u16_slice_to_sum16(&[(x >> 16) as u16, (x & 0x00_00_FF_FF) as u16])
            }
            x => x as u16,
        };
        let (header, payload) = frame.payload().split_at(8);
        Self {
            pseudo_header_sum: u16_slice_to_sum16(&[addr_sum, protocol, payload_len]),
            header,
            payload,
        }
    }
}
