use ux::*;

use crate::clone_into_array;
use crate::error_check::*;

use super::{Ipv4Frame, Ipv6Frame};

pub struct TcpFrame<'a> {
    pseudo_header_sum: u16,
    header: &'a [u8],
    opts: Option<&'a [u8]>,
    payload: &'a [u8],
}

impl<'a> TcpFrame<'a> {
    pub fn raw_header(&self) -> &'a [u8] {
        self.header
    }

    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(clone_into_array(&self.header[0..2]))
    }

    pub fn dest_port(&self) -> u16 {
        u16::from_be_bytes(clone_into_array(&self.header[2..4]))
    }

    pub fn seq_num(&self) -> u32 {
        u32::from_be_bytes(clone_into_array(&self.header[4..8]))
    }

    pub fn ack_num(&self) -> Option<u32> {
        if self.ack() {
            Some(u32::from_be_bytes(clone_into_array(&self.header[8..12])))
        } else {
            None
        }
    }

    pub fn data_offset(&self) -> u4 {
        u4::new(self.header[12] >> 4)
    }

    pub fn ns(&self) -> bool {
        self.header[12] & 0b0000_0001 != 0
    }

    pub fn cwr(&self) -> bool {
        self.header[13] & 0b1000_0000 != 0
    }

    pub fn ece(&self) -> bool {
        self.header[13] & 0b0100_0000 != 0
    }

    pub fn urg(&self) -> bool {
        self.header[13] & 0b0010_0000 != 0
    }

    pub fn ack(&self) -> bool {
        self.header[13] & 0b0001_0000 != 0
    }

    pub fn psh(&self) -> bool {
        self.header[13] & 0b0000_1000 != 0
    }

    pub fn rst(&self) -> bool {
        self.header[13] & 0b0000_0100 != 0
    }

    pub fn syn(&self) -> bool {
        self.header[13] & 0b0000_0010 != 0
    }

    pub fn fin(&self) -> bool {
        self.header[13] & 0b0000_0001 != 0
    }

    pub fn window_sz(&self) -> u16 {
        u16::from_be_bytes(clone_into_array(&self.header[14..16]))
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(clone_into_array(&self.header[16..18]))
    }

    pub fn urg_pnt(&self) -> Option<u16> {
        if self.urg() {
            Some(u16::from_be_bytes(clone_into_array(&self.header[18..20])))
        } else {
            None
        }
    }

    pub fn opts(&self) -> Option<&'a [u8]> {
        self.opts
    }

    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    pub fn has_integrity(&self) -> bool {
        u16_checksum16(&[
            self.pseudo_header_sum,
            u8_slice_to_sum16(self.header),
            u8_slice_to_sum16(self.payload),
            if let Some(opts) = self.opts {
                u8_slice_to_sum16(opts)
            } else {
                0
            },
        ]) == 0
    }
}

impl<'a> From<Ipv4Frame<'a>> for TcpFrame<'a> {
    fn from(frame: Ipv4Frame<'a>) -> Self {
        let payload = frame.payload();
        let addr_sum = u8_slice_to_sum16(&frame.raw_header()[12..20]);
        let protocol = 0x06 as u16;
        let payload_len = payload.len() as u16;

        let header_len = usize::from(payload[12] >> 4);

        let (header, payload) = payload.split_at(header_len * 4);
        let (header, opts) = header.split_at(20);
        Self {
            pseudo_header_sum: u16_slice_to_sum16(&[addr_sum, protocol, payload_len]),
            header,
            opts: match opts {
                [] => None,
                _ => Some(opts),
            },
            payload,
        }
    }
}

impl<'a> From<Ipv6Frame<'a>> for TcpFrame<'a> {
    fn from(frame: Ipv6Frame<'a>) -> Self {
        let payload = frame.payload();
        let addr_sum = u8_slice_to_sum16(&frame.raw_header()[8..40]);
        let protocol = 0x06 as u16;
        let payload_len = match frame.payload().len() {
            x if x > 0x0000FFFF => u16_slice_to_sum16(&[(x >> 16) as u16, (x & 0x0000FFFF) as u16]),
            x => x as u16,
        };

        let header_len = usize::from(payload[12] >> 4);
        let (header, payload) = payload.split_at(header_len * 4);
        let (header, opts) = header.split_at(20);
        Self {
            pseudo_header_sum: u16_slice_to_sum16(&[addr_sum, protocol, payload_len]),
            header,
            opts: match opts {
                [] => None,
                _ => Some(opts),
            },
            payload,
        }
    }
}
