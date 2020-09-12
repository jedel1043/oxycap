use std::net::Ipv4Addr;
use super::*;
pub enum IgmpMsg {
    GeneralQuery(u8),
    SpecialQuery(Ipv4Addr, u8),
    MembershipReport(Ipv4Addr),
    LeaveReport(Ipv4Addr),
    Other(u8)
}

impl fmt::Display for IgmpMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GeneralQuery(_) => write!(f, "General query"),
            Self::SpecialQuery(_, _) => write!(f, "Special query"),
            Self::MembershipReport(_) => write!(f, "Membership report"),
            Self::LeaveReport(_) => write!(f, "Leave report"),
            Self::Other(code) => write!(f, "Unknown message (0x{:02X})", code)
        }
    }
}

pub struct IgmpFrame<'a>(&'a [u8]);

impl <'a> IgmpFrame<'a> {
    pub fn raw_header(&self) -> &'a [u8] {
        &self.0
    }

    pub fn type_(&self) -> u8 {
        self.0[0]
    }

    pub fn mrt(&self) -> u8 {
        self.0[1]
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(clone_into_array(&self.0[2..=3]))
    }

    pub fn has_integrity(&self) -> bool {
        u8_checksum16(&self.0) == 0
    }

    pub fn get_msg(&self) -> IgmpMsg {
        match self.type_() {
            0x11 => {
                let addr = self.group_addr();
                if !addr.is_unspecified() {
                    IgmpMsg::SpecialQuery(addr, self.mrt())
                } else {IgmpMsg::GeneralQuery(self.mrt())}
            }
            0x12 | 0x16 => IgmpMsg::MembershipReport(self.group_addr()),
            0x17 => IgmpMsg::LeaveReport(self.group_addr()),
            val => IgmpMsg::Other(val)
        }
    }

    pub fn group_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(clone_into_array::<[u8;4], u8>(&self.0[4..=7]))
    }
}

impl<'a> From<Ipv4Frame<'a>> for IgmpFrame<'a> {
    fn from(frame: Ipv4Frame<'a>) -> Self {
        IgmpFrame(frame.payload())
    }
}