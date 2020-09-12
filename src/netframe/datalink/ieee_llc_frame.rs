use ux::*;

use super::*;

fn reverse(b: u8) -> u8 {
    let mut b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
    b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
    b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
    b
}

pub enum SapName {
    NullSap,
    // 0x00
    ILlc,
    // 0x02
    GLlc,
    // 0x03
    SnaI,
    // 0x04
    SnaG,
    // 0x05
    DodIp,
    // 0x06
    ProWayLan,
    // 0x0E
    TexasIns,
    // 0x18
    SpanningTree,
    // 0x42
    EiaRs511,
    // 0x4E
    IsiIp,
    // 0x5E
    Iso802_2,
    // 0x7E
    Xns,
    // 0x80
    Bacnet,
    // 0x82
    Nestar,
    // 0x86
    ProWayLan955,
    // 0x8E
    Arp,
    // 0x98
    Rde,
    // 0xA6
    Snap,
    // 0xAA
    Banyan,
    // 0xBC
    NetWare,
    // 0xE0
    NetBios,
    // 0xF0
    LanManI,
    // 0xF4
    LanManG,
    // 0xF5
    Rpl,
    // 0xF8
    Ungermann,
    // 0xFA
    Osi,
    // 0xFE
    GlobalSap,
    // 0xFF
    Other(u8),
}

impl fmt::Display for SapName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let outstr = match self {
            Self::NullSap => "Null SAP",
            Self::ILlc => "Individual LLC Sublayer Mgt",
            Self::GLlc => "Group LLC Sublayer Mgt",
            Self::SnaI => "SNA Path Control (individual)",
            Self::SnaG => "SNA Path Control (group)",
            Self::DodIp => "Reserved for DoD IP",
            Self::ProWayLan => "ProWay-LAN",
            Self::TexasIns => "Texas Instruments",
            Self::SpanningTree => "IEEE 802.1 Bridge Spanning Tree Protocol",
            Self::EiaRs511 => "EIA-RS 511",
            Self::IsiIp => "ISI IP",
            Self::Iso802_2 => "ISO 802.2",
            Self::Xns => "Xerox Network Systems (XNS)",
            Self::Bacnet => "BACnet/Ethernet",
            Self::Nestar => "Nestar",
            Self::ProWayLan955 => "ProWay-LAN (IEC 955)",
            Self::Arp => "ARPANET Address Resolution Protocol (ARP)",
            Self::Rde => "RDE (route determination entity)",
            Self::Snap => "SNAP Extension Used",
            Self::Banyan => "Banyan Vines",
            Self::NetWare => "Novell NetWare",
            Self::NetBios => "IBM NetBIOS",
            Self::LanManI => "IBM LAN Management (individual)",
            Self::LanManG => "IBM LAN Management (group)",
            Self::Rpl => "IBM Remote Program Load (RPL)",
            Self::Ungermann => "Ungermann-Bass",
            Self::Osi => "OSI protocols ISO CLNS IS 8473",
            Self::GlobalSap => "Global DSAP (broadcast to all)",
            Self::Other(sap) => {
                return write!(f, "Other (0x{:02X})", sap);
            }
        };
        write!(f, "{}", outstr)
    }
}

impl From<u8> for SapName {
    fn from(val: u8) -> Self {
        match val {
            0x00 => Self::NullSap,
            0x02 => Self::ILlc,
            0x03 => Self::GLlc,
            0x04 => Self::SnaI,
            0x05 => Self::SnaG,
            0x06 => Self::DodIp,
            0x0E => Self::ProWayLan,
            0x18 => Self::TexasIns,
            0x42 => Self::SpanningTree,
            0x4E => Self::EiaRs511,
            0x5E => Self::IsiIp,
            0x7F => Self::Iso802_2,
            0x80 => Self::Xns,
            0x82 => Self::Bacnet,
            0x86 => Self::Nestar,
            0x8E => Self::ProWayLan955,
            0x98 => Self::Arp,
            0xA6 => Self::Rde,
            0xAA => Self::Snap,
            0xBC => Self::Banyan,
            0xE0 => Self::NetWare,
            0xF0 => Self::NetBios,
            0xF4 => Self::LanManI,
            0xF5 => Self::LanManG,
            0xF8 | 0xFC => Self::Rpl,
            0xFA => Self::Ungermann,
            0xFE => Self::Osi,
            0xFF => Self::GlobalSap,
            _ => Self::Other(val),
        }
    }
}

pub enum LlcControl {
    UFrame(UFrame),
    IFrame(IFrame),
    IFrameExt(IFrameExt),
    SFrame(SFrame),
    SFrameExt(SFrameExt),
}

impl fmt::Display for LlcControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let outstr = match self {
            Self::UFrame(_) => "Unnumbered Frame",
            Self::IFrame(_) => "Information Frame",
            Self::IFrameExt(_) => "Information Extended Frame",
            Self::SFrame(_) => "Supervisory frame",
            Self::SFrameExt(_) => "Supervisory Extended Frame ",
        };
        write!(f, "{}", outstr)
    }
}

impl<'a> From<IeeeLlcFrame<'a>> for LlcControl {
    fn from(header: IeeeLlcFrame<'a>) -> Self {
        if header.raw_control().len() == 1 {
            let control = header.raw_control()[0];
            match control & 0x03 {
                0x03 => Self::UFrame(UFrame { header: control, is_command: header.is_command() }),
                0x01 => Self::SFrame(SFrame { header: control, is_command: header.is_command() }),
                _ => Self::IFrame(IFrame { header: control, is_command: header.is_command() })
            }
        } else {
            let control = u16::from_be_bytes(clone_into_array(&header.raw_control()[0..2]));
            match control & 0x0300 {
                0x0300 => Self::UFrame(UFrame { header: (control >> 8) as u8, is_command: header.is_command() }),
                0x0100 => Self::SFrameExt(SFrameExt { header: control, is_command: header.is_command() }),
                _ => Self::IFrameExt(IFrameExt { header: control, is_command: header.is_command() })
            }
        }
    }
}

pub enum UCode {
    /*  COMMAND         RESPONSE */
    SNRM,
    //NONE
    SNRME,
    //NONE
    SARM,
    DM,
    SARME,
    //NONE
    SABM,
    //NONE
    SABME,
    //NONE
    UI,
    //FOR BOTH C & R
    /*NONE*/ UA,
    DISC,
    RD,
    SIM,
    RIM,
    UP,
    //NONE
    RSET,
    //NONE
    XID,
    //FOR BOTH C & R
    FRMR, //FOR BOTH C & R
}

impl UCode {
    pub fn from_u8(val: u8, is_command: bool) -> Self {
        match val {
            0b00_001 if is_command => Self::SNRM,
            0b11_011 if is_command => Self::SNRME,
            0b11_100 => {
                if is_command {
                    Self::SABM
                } else {
                    Self::DM
                }
            }
            0b11_110 if is_command => Self::SABME,
            0b00_000 => Self::UI,
            0b00_110 if !is_command => Self::UA,
            0b00_010 => {
                if is_command {
                    Self::DISC
                } else {
                    Self::RD
                }
            }
            0b10_000 => {
                if is_command {
                    Self::SIM
                } else {
                    Self::RIM
                }
            }
            0b00_100 if is_command => Self::UP,
            0b11_001 if is_command => Self::RSET,
            0b11_101 => Self::XID,
            0b10_001 => Self::FRMR,
            _ => panic!("UCode not found")
        }
    }
}

impl fmt::Display for UCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let outstr = match self {
            Self::SNRM => "Set normal response mode SNRM",
            Self::SNRME => "SNRM extended SNRME",
            Self::SARM => "Set asynchronous response mode SARM",
            Self::SARME => "SARM extended SARME",
            Self::SABM => "Set asynchronous balanced mode SABM",
            Self::SABME => "SABM extended SABME",
            Self::DM => "Disconnect mode DM",
            Self::UI => "Unnumbered information UI",
            Self::UA => "Unnumbered acknowledgment UA",
            Self::DISC => "Disconnect DISC",
            Self::RD => "Request disconnect RD",
            Self::SIM => "Set initialization mode SIM",
            Self::RIM => "Request initialization mode RIM",
            Self::UP => "Unnumbered poll UP",
            Self::RSET => "Reset RSET",
            Self::XID => "Exchange identification XID",
            Self::FRMR => "Frame reject FRMR",
        };
        write!(f, "{}", outstr)
    }
}

pub struct UFrame {
    header: u8,
    is_command: bool,
}

impl UFrame {
    pub fn ucode(&self) -> UCode {
        let mut code = reverse(self.header);
        code = (code & 0x07) | ((code & 0x30) >> 1);
        UCode::from_u8(code, self.is_command)
    }

    pub fn poll_final(&self) -> bool {
        self.header & 0x10 != 0
    }

    pub fn is_command(&self) -> bool {
        self.is_command
    }
}

pub struct IFrame {
    header: u8,
    is_command: bool,
}

impl IFrame {
    pub fn rec_seq(&self) -> u3 {
        u3::new((self.header & 0xE0) >> 5)
    }

    pub fn send_seq(&self) -> u3 {
        u3::new((self.header & 0x0E) >> 1)
    }

    pub fn poll_final(&self) -> bool {
        self.header & 0x10 != 0
    }

    pub fn is_command(&self) -> bool {
        self.is_command
    }
}

pub struct IFrameExt {
    header: u16,
    is_command: bool,
}

impl IFrameExt {
    pub fn rec_seq(&self) -> u7 {
        u7::new(((self.header & 0x00FE) >> 1) as u8)
    }

    pub fn send_seq(&self) -> u7 {
        u7::new((self.header >> 9) as u8)
    }

    pub fn poll_final(&self) -> bool {
        self.header & 0x0001 != 0
    }

    pub fn is_command(&self) -> bool {
        self.is_command
    }
}

pub enum SCode {
    RR,
    REJ,
    RNR,
    SREJ,
}

impl fmt::Display for SCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let outstr = match self {
            Self::RR => "Receive Ready (RR)",
            Self::REJ => "Reject (REJ)",
            Self::RNR => "Receive Not Ready (RNR)",
            Self::SREJ => "Selective Reject (SREJ)",
        };
        write!(f, "{}", outstr)
    }
}

impl From<u8> for SCode {
    fn from(val: u8) -> Self {
        match val {
            0b00 => Self::RR,
            0b01 => Self::REJ,
            0b10 => Self::RNR,
            0b11 => Self::SREJ,
            _ => panic!("SCode not found")
        }
    }
}

pub struct SFrame {
    header: u8,
    is_command: bool,
}

impl SFrame {
    pub fn rec_seq(&self) -> u3 {
        u3::new(self.header >> 5)
    }

    pub fn poll_final(&self) -> bool {
        self.header & 0x10 != 0
    }

    pub fn scode(&self) -> SCode {
        SCode::from((self.header & 0x0C) >> 2)
    }

    pub fn is_command(&self) -> bool {
        self.is_command
    }
}

pub struct SFrameExt {
    header: u16,
    is_command: bool,
}

impl SFrameExt {
    pub fn rec_seq(&self) -> u7 {
        u7::new(((self.header & 0x00FE) >> 1) as u8)
    }

    pub fn poll_final(&self) -> bool {
        self.header & 0x0001 != 0
    }

    pub fn scode(&self) -> SCode {
        SCode::from(((self.header & 0x0C00) >> 10) as u8)
    }

    pub fn is_command(&self) -> bool {
        self.is_command
    }
}

pub struct IeeeLlcFrame<'a> {
    header: &'a [u8],
    payload: &'a [u8],
}

impl<'a> IeeeLlcFrame<'a> {
    pub fn raw_header(&self) -> &'a [u8] {
        self.header
    }

    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    pub fn dsap(&self) -> SapName {
        SapName::from(self.header[0])
    }

    pub fn ssap(&self) -> SapName {
        SapName::from(self.header[1])
    }

    pub fn is_individual(&self) -> bool {
        self.header[0] & 0b00000001 == 0
    }

    pub fn is_command(&self) -> bool {
        self.header[1] & 0b00000001 == 0
    }

    pub fn raw_control(&self) -> &'a [u8] {
        &self.header[2..]
    }

    pub fn control(self) -> LlcControl {
        LlcControl::from(self)
    }
}

impl<'a> From<EthernetFrame<'a>> for IeeeLlcFrame<'a> {
    fn from(frame: EthernetFrame<'a>) -> Self {
        let (header, payload) =
            frame
                .payload()
                .split_at(if frame.ether_type() > 3 { 4 } else { 3 });
        Self { header, payload }
    }
}
