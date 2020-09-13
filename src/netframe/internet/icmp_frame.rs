use super::*;
use chrono::prelude::*;
use std::net::Ipv4Addr;
use std::time::Duration;

pub enum DestUnreachable {
    DestNetUnreachable,      // 0
    DestHostUnreachable,     // 1
    DestProtocolUnreachable, // 2
    DestPortUnreachable,     // 3
    FragReq(u16),                 // 4
    SrcRouteFailed,          // 5
    DestNetUnk,              // 6
    DestHostUnk,             // 7
    SrcHostIsolated,         // 8
    NetAdminProhib,          // 9
    HostAdminProhib,         // 10
    NetUnreachableToS,       // 11
    HostUnreachableToS,      // 12
    CommAdminProhib,         // 13
    HostPrecViolation,       // 14
    PrecCutoff,              // 15
}

impl From<&[u8]> for DestUnreachable {
    fn from(header: &[u8]) -> Self {
        match header[1] {
            0 => Self::DestNetUnreachable,      // 0
            1 => Self::DestHostUnreachable,     // 1
            2 => Self::DestProtocolUnreachable, // 2
            3 => Self::DestPortUnreachable,     // 3
            4 => Self::FragReq(u16::from_be_bytes(clone_into_array(&header[6..=7]))),                 // 4
            5 => Self::SrcRouteFailed,          // 5
            6 => Self::DestNetUnk,              // 6
            7 => Self::DestHostUnk,             // 7
            8 => Self::SrcHostIsolated,         // 8
            9 => Self::NetAdminProhib,          // 9
            10 => Self::HostAdminProhib,        // 10
            11 => Self::NetUnreachableToS,      // 11
            12 => Self::HostUnreachableToS,     // 12
            13 => Self::CommAdminProhib,        // 13
            14 => Self::HostPrecViolation,      // 14
            15 => Self::PrecCutoff,             // 15
            _ => panic!("invalid option for DestUnreachable enum"),
        }  
    }
}

impl fmt::Display for DestUnreachable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DestNetUnreachable => write!(f, "Destination network unreachable"),
            Self::DestHostUnreachable => write!(f, "Destination host unreachable"),
            Self::DestProtocolUnreachable => write!(f, "Destination protocol unreachable"),
            Self::DestPortUnreachable => write!(f, "Destination port unreachable"),
            Self::FragReq(_) => write!(f, "Fragmentation required, and DF flag set"),
            Self::SrcRouteFailed => write!(f, "Source route failed"),
            Self::DestNetUnk => write!(f, "Destination network unknown"),
            Self::DestHostUnk => write!(f, "Destination host unknown"),
            Self::SrcHostIsolated => write!(f, "Source host isolated"),
            Self::NetAdminProhib => write!(f, "Network administratively prohibited"),
            Self::HostAdminProhib => write!(f, "Host administratively prohibited"),
            Self::NetUnreachableToS => write!(f, "Network unreachable for ToS"),
            Self::HostUnreachableToS => write!(f, "Host unreachable for ToS"),
            Self::CommAdminProhib => write!(f, "Communication administratively prohibited"),
            Self::HostPrecViolation => write!(f, "Host Precedence Violation"),
            Self::PrecCutoff => write!(f, "Precedence cutoff in effect"),
        }
    }
}

pub enum RedirectType {
    RedirectData4Net,
    RedirectData4Host,
    RedirectData4ToSNet,
    RedirectData4ToSHost,
}

impl From<u8> for RedirectType {
    fn from(input: u8) -> Self {
        match input {
            0 => Self::RedirectData4Net,
            1 => Self::RedirectData4Host,
            2 => Self::RedirectData4ToSNet,
            3 => Self::RedirectData4ToSHost,
            _ => panic!("invalid option for RedirectMsg enum"),
        }
    }
}

pub struct RedirectMsg {
    r#type: RedirectType,
    addr: Ipv4Addr,
}

impl RedirectMsg {
    pub fn from(r#type: u8, addr: Ipv4Addr) -> RedirectMsg {
        RedirectMsg {
            r#type: RedirectType::from(r#type),
            addr,
        }
    }
}

impl fmt::Display for RedirectMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.r#type {
            RedirectType::RedirectData4Net => write!(
                f,
                "Redirect Datagram for the Network to address {}",
                self.addr
            ),
            RedirectType::RedirectData4Host => {
                write!(f, "Redirect Datagram for the Host to address {}", self.addr)
            }
            RedirectType::RedirectData4ToSNet => write!(
                f,
                "Redirect Datagram for the ToS & network to address {}",
                self.addr
            ),
            RedirectType::RedirectData4ToSHost => write!(
                f,
                "Redirect Datagram for the ToS & host to address {}",
                self.addr
            ),
        }
    }
}

pub enum TimeExceeded {
    TTLExpired,
    FragReassemblyTimeout,
}

impl From<u8> for TimeExceeded {
    fn from(input: u8) -> Self {
        match input {
            0 => Self::TTLExpired,
            1 => Self::FragReassemblyTimeout,
            _ => panic!("invalid option for TimeExceeded enum"),
        }
    }
}

impl fmt::Display for TimeExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TTLExpired => write!(f, "TTL expired in transit"),
            Self::FragReassemblyTimeout => write!(f, "Fragment reassembly time exceeded"),
        }
    }
}

pub enum BadIpHeader {
    PntIndicatesError,
    MissingOpt,
    BadLen,
}

impl From<u8> for BadIpHeader {
    fn from(input: u8) -> Self {
        match input {
            0 => Self::PntIndicatesError,
            1 => Self::MissingOpt,
            2 => Self::BadLen,
            _ => panic!("invalid option for TimeExceeded enum"),
        }
    }
}

impl fmt::Display for BadIpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PntIndicatesError => write!(f, "Pointer indicates the error"),
            Self::MissingOpt => write!(f, "Missing a required option"),
            Self::BadLen => write!(f, "Bad length"),
        }
    }
}


pub struct Timestamp {
    id: u16,
    seq_num: u16,
    originate_timestamp: u32
}

impl Timestamp {
    pub fn id(&self) -> u16 {
        self.id
    }
    pub fn seq_num(&self) -> u16 {
        self.seq_num
    }

    pub fn originate_timestamp(&self) -> DateTime<Utc> {
        let from_mid = Duration::from_millis(
            self.originate_timestamp.into(),
        );
        Utc::today()
            .and_time(NaiveTime::from_num_seconds_from_midnight(
                from_mid.as_secs() as u32,
                from_mid.subsec_nanos(),
            ))
            .unwrap()
    }

    pub fn from(header: &[u8], data: &[u8]) -> Self {
        Self {
            id: u16::from_be_bytes(clone_into_array(&header[4..=5])),
            seq_num: u16::from_be_bytes(clone_into_array(&header[6..=7])),
            originate_timestamp:
            u32::from_be_bytes(clone_into_array(&data[0..=3])),
        }
    }
}

pub struct TimestampReply{
    id: u16,
    seq_num: u16,
    originate_timestamp: u32,
    receive_timestamp: u32,
    transmit_timestamp: u32,
}

impl TimestampReply {
    pub fn id(&self) -> u16 {
        self.id
    }
    pub fn seq_num(&self) -> u16 {
        self.seq_num
    }

    pub fn originate_timestamp(&self) -> DateTime<Utc> {
        let from_mid = Duration::from_millis(
            self.originate_timestamp.into(),
        );
        Utc::today()
            .and_time(NaiveTime::from_num_seconds_from_midnight(
                from_mid.as_secs() as u32,
                from_mid.subsec_nanos(),
            ))
            .unwrap()
    }

    pub fn receive_timestamp(&self) -> DateTime<Utc> {
        let from_mid = Duration::from_millis(
            self.receive_timestamp.into(),
        );
        Utc::today()
            .and_time(NaiveTime::from_num_seconds_from_midnight(
                from_mid.as_secs() as u32,
                from_mid.subsec_nanos(),
            ))
            .unwrap()
    }

    pub fn transmit_timestamp(&self) -> DateTime<Utc> {
        let from_mid = Duration::from_millis(
            self.transmit_timestamp.into(),
        );
        Utc::today()
            .and_time(NaiveTime::from_num_seconds_from_midnight(
                from_mid.as_secs() as u32,
                from_mid.subsec_nanos(),
            ))
            .unwrap()
    }

    pub fn from(header: &[u8], data: &[u8]) -> Self {
        Self {
            id: u16::from_be_bytes(clone_into_array(&header[4..=5])),
            seq_num: u16::from_be_bytes(clone_into_array(&header[6..=7])),
            originate_timestamp:
            u32::from_be_bytes(clone_into_array(&data[0..=3])),
            receive_timestamp:
            u32::from_be_bytes(clone_into_array(&data[4..=7])),
            transmit_timestamp:
            u32::from_be_bytes(clone_into_array(&data[8..=11])),
        }
    }
}


pub struct AddrMaskRequest {
    id: u16,
    seq_num: u16,
}

impl AddrMaskRequest {
    pub fn id(&self) -> u16 {
        self.id
    }
    pub fn seq_num(&self) -> u16 {
        self.seq_num
    }
}

impl From<&[u8]> for AddrMaskRequest {
    fn from(header: &[u8]) -> Self {
        Self {
            id: u16::from_be_bytes(clone_into_array(&header[4..=5])),
            seq_num: u16::from_be_bytes(clone_into_array(&header[6..=7]))
        }
    }
}

pub struct AddrMaskReply {
    id: u16,
    seq_num: u16,
    addr_mask: Ipv4Addr
}

impl AddrMaskReply {
    pub fn id(&self) -> u16 {
        self.id
    }

    pub fn seq_num(&self) -> u16 {
        self.seq_num
    }

    pub fn addr_mask(&self) -> Ipv4Addr {
        self.addr_mask
    }

    pub fn from(header: &[u8], data: &[u8]) -> Self {
        Self {
            id: u16::from_be_bytes(clone_into_array(&header[4..=5])),
            seq_num: u16::from_be_bytes(clone_into_array(&header[6..=7])),
            addr_mask: Ipv4Addr::from(clone_into_array::<[u8; 4], u8>(&data[0..=3]))
        }
    }
}
pub enum IcmpMsg {
    EchoReply,                        // 0
    Reserved(u8), // 1, 2, 7, 19 (for security), 20-29 (for robustness experiment)
    DestUnreachable(DestUnreachable), // 3
    SrcQuench,    // 4 (deprecated)
    RedirectMsg(RedirectMsg), // 5
    AltHostAddr,  // 6 (deprecated)
    EchoRequest,  // 8
    RouterAdv,    // 9
    RouterSolicitation, // 10
    TimeExceeded(TimeExceeded), // 11
    BadIpHeader(BadIpHeader), // 12
    Timestamp(Timestamp),    // 13
    TimestampReply(TimestampReply), // 14
    InfoRequest,  // 15 (deprecated)
    InfoReply,    // 16 (deprecated)
    AddrMaskRequest(AddrMaskRequest), // 17 (deprecated)
    AddrMaskReply(AddrMaskReply), // 18 (deprecated)
    Traceroute,   // 30 (deprecated)
}

impl fmt::Display for IcmpMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EchoReply => write!(f, "Echo reply"),
            Self::DestUnreachable(_) => write!(f, "Destination unreachable", ),
            Self::SrcQuench => write!(f, "Source quench (congestion control) [deprecated]"),
            Self::RedirectMsg(_) => write!(f, "Redirect message"),
            Self::AltHostAddr => write!(f, "Alternate Host Address [deprecated]"),
            Self::EchoRequest => write!(f, "Echo request"),
            Self::RouterAdv => write!(f, "Router Advertisement"),
            Self::RouterSolicitation => write!(f, "Router discovery/selection/solicitation"),
            Self::TimeExceeded(_) => write!(f, "Time exceeded"),
            Self::BadIpHeader(_) => write!(f, "Parameter Problem - Bad IP header"),
            Self::Timestamp(_) => write!(f, "Timestamp"),
            Self::TimestampReply(_) => write!(f, "Timestamp reply"),
            Self::InfoRequest => write!(f, "Information Request [deprecated]"),
            Self::InfoReply => write!(f, "Information Reply [deprecated]"),
            Self::AddrMaskRequest(_) => write!(f, "Address Mask Request [deprecated]"),
            Self::AddrMaskReply(_) => write!(f, " 	Address Mask Reply [deprecated]"),
            Self::Traceroute => write!(f, "Information Request [deprecated]"),
            Self::Reserved(other) => write!(f, "Reserved ({})", other),
        }
    }
}

pub struct IcmpFrame<'a> {
    header: &'a [u8],
    payload: &'a [u8],
}

impl<'a> IcmpFrame<'a> {
    pub fn raw_header(&self) -> &'a [u8] {
        &self.header
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.payload
    }

    pub fn type_(&self) -> u8 {
        self.header[0]
    }

    pub fn code(&self) -> u8 {
        self.header[1]
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(clone_into_array(&self.header[2..=3]))
    }

    pub fn has_integrity(&self) -> bool {
        u16_checksum16(&[
            u8_slice_to_sum16(&self.header),
            u8_slice_to_sum16(&self.payload),
        ]) == 0
    }

    pub fn roh(&self) -> &'a [u8] {
        self.header.split_at(4).1
    }

    pub fn get_control_msg(&self) -> IcmpMsg {
        match self.header[0] {
            0 => IcmpMsg::EchoReply,
            3 => IcmpMsg::DestUnreachable(DestUnreachable::from(self.header)),
            4 => IcmpMsg::SrcQuench,
            5 => IcmpMsg::RedirectMsg(RedirectMsg::from(
                self.header[1],
                Ipv4Addr::from(clone_into_array::<[u8; 4], u8>(&self.header[4..=7])),
            )),
            6 => IcmpMsg::AltHostAddr,
            8 => IcmpMsg::EchoRequest,
            9 => IcmpMsg::RouterAdv,
            10 => IcmpMsg::RouterSolicitation,
            11 => IcmpMsg::TimeExceeded(TimeExceeded::from(self.header[1])),
            12 => IcmpMsg::BadIpHeader(BadIpHeader::from(self.header[1])),
            13 => IcmpMsg::Timestamp(Timestamp::from(self.header, self.payload)),
            14 => IcmpMsg::TimestampReply(TimestampReply::from(self.header, self.payload)),
            15 => IcmpMsg::InfoRequest,
            16 => IcmpMsg::InfoReply,
            17 => IcmpMsg::AddrMaskRequest(AddrMaskRequest::from(self.header)),
            18 => IcmpMsg::AddrMaskReply(AddrMaskReply::from(self.header, self.payload)),
            30 => IcmpMsg::Traceroute,
            other => IcmpMsg::Reserved(other),
        }
    }
}

impl<'a> From<Ipv4Frame<'a>> for IcmpFrame<'a> {
    fn from(frame: Ipv4Frame<'a>) -> Self {
        let (header, payload) = frame.payload().split_at(8);
        IcmpFrame { header, payload }
    }
}
