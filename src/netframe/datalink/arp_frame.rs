use super::*;

pub enum Operation {
    Request,
    Reply,
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operation::Reply => write!(f, "Reply"),
            Operation::Request => write!(f, "Request")
        }
    }
}

pub struct ArpFrame<'a>(&'a [u8]);

impl<'a> ArpFrame<'a> {
    pub fn htype(&self) -> u16 {
        u16::from_be_bytes(clone_into_array(&self.0[0..2]))
    }

    pub fn ptype(&self) -> u16 {
        u16::from_be_bytes(clone_into_array(&self.0[2..4]))
    }

    pub fn hlen(&self) -> u8 {
        self.0[4]
    }

    pub fn plen(&self) -> u8 {
        self.0[5]
    }

    pub fn oper(&self) -> Operation {
        if self.0[7] == 1 {
            Operation::Request
        } else {
            Operation::Reply
        }
    }

    pub fn sha(&self) -> &'a [u8] {
        let size = self.hlen() as usize;
        &self.0[8..8 + size]
    }

    pub fn spa(&self) -> &'a [u8] {
        let begin = (8 + self.hlen()) as usize;
        let end = begin + self.plen() as usize;
        &self.0[begin..end]
    }

    pub fn tha(&self) -> &'a [u8] {
        let begin = (8 + self.hlen() + self.plen()) as usize;
        let end = begin + self.hlen() as usize;
        &self.0[begin..end]
    }

    pub fn tpa(&self) -> &'a [u8] {
        let begin = (8 + self.hlen() * 2 + self.plen()) as usize;
        let end = begin + self.plen() as usize;
        &self.0[begin..end]
    }
}

impl<'a> From<EthernetFrame<'a>> for ArpFrame<'a> {
    fn from(frame: EthernetFrame<'a>) -> Self {
        Self(frame.payload())
    }
}