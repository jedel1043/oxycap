#[macro_use]
extern crate prettytable;

use std::path::PathBuf;

use chrono::prelude::*;
use pcap::{Activated, Capture, Device};
use prettytable::{format, Table};
use structopt::StructOpt;

use oxycap::netframe::{datalink::*, internet::*, transport::*};

#[derive(Debug, StructOpt)]
#[structopt(name = "rpcs")]
/// Rust + Pcap Sniffer
///
/// Network analysis tool written entirely in Rust using the Pcap crate.
struct Rpcs {
    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    /// Lists the network devices found by Pcap
    ///
    /// Use the device index with the command `sniff from-dev` to select the input device.
    // todo: add flags for additional info for the devices
    ListDev,
    /// Starts the sniffer loop
    ///
    /// Use `from-dev` to sniff from a network device, and `from-file` to analyze a .pcap file.
    Sniff(Mode),
}

#[derive(Debug, StructOpt)]
enum Mode {
    /// Sniffs using a network device as input
    FromDev {
        /// Index of the input device as listed in the command `list-dev`
        index: usize,

        /// Buffer size for the incoming data
        #[structopt(short, long, default_value = "1000000")]
        buffer_size: i32,

        /// Portion of the packet to capture
        #[structopt(short, long, default_value = "65535")]
        snaplen: i32,

        /// Package read timeout
        #[structopt(short, long, default_value = "0")]
        timeout: i32,

        /// Promiscuous mode flag
        #[structopt(short, long = "promiscuous")]
        promisc: bool,
    },
    /// Sniffs using a .pcap file as input
    FromFile {
        /// Path of the file to analyze
        #[structopt(parse(from_os_str))]
        path: PathBuf,
    },
}

// TODO: Error management. As it is, the program will panic with any error.
fn main() {
    // Catch all the arguments in a Rpcs struct
    let opt: Rpcs = Rpcs::from_args();
    match opt.cmd {
        // Print devices found by pcap as a table
        Command::ListDev => {
            println!("Device list:\n");
            let mut table = Table::new();
            table.set_format(*format::consts::FORMAT_CLEAN);
            table.add_row(row![b => "Index", "Name", "Description"]);

            // TODO: Throw error in case pcap fails to find any device
            for (index, device) in Device::list().unwrap().iter().enumerate() {
                table.add_row(row![
                    format!("{}.", index).as_str(),
                    device.name.as_str(),
                    match &device.desc {
                        Some(name) => name,
                        None => "",
                    }
                ]);
            }
            table.printstd();
        }
        // Starts the sniffer.
        Command::Sniff(mode) => {
            let mut sn_len = -1;
            // Using a `dyn Activated` type to avoid repeating the `while` loop code
            let mut cap: Capture<dyn Activated> = match mode {
                Mode::FromDev {
                    index,
                    snaplen,
                    promisc,
                    timeout,
                    buffer_size,
                } => {
                    // TODO: Throw error in case pcap fails to find any device
                    let dev = Device::list().unwrap().remove(index);
                    sn_len = snaplen;

                    Capture::<dyn Activated>::from(
                        Capture::from_device(dev)
                            .unwrap() // TODO: Throw error in case finding device fails
                            .promisc(promisc) // Set promiscuous mode flag
                            .snaplen(snaplen) // Set packet max length
                            .timeout(timeout) // Set max wait time between packets
                            .buffer_size(buffer_size) // Set max buffer size
                            .open()
                            .unwrap(), // TODO: throw error in case opening device fails
                    )
                }
                Mode::FromFile { path } => {
                    //TODO: Exception with opening file errors
                    Capture::<dyn Activated>::from(Capture::from_file(path).unwrap())
                }
            };
            let mut packet_count = 1u32;
            let ltype = cap.get_datalink();
            while let Ok(packet) = cap.next() {
                let current_time = Local
                    .timestamp(
                        packet.header.ts.tv_sec as i64,
                        packet.header.ts.tv_sec as u32,
                    )
                    .format("%+")
                    .to_string();
                let mut table = Table::new();
                table.set_format(*format::consts::FORMAT_CLEAN);
                let packet_desc = format!(
                    "Packet {} ({} bytes{})",
                    packet_count,
                    packet.data.len(),
                    if sn_len != -1 {
                        format!(", snapped to {} bytes", sn_len)
                    } else {
                        String::new()
                    }
                );

                table.add_row(row![H2 -> packet_desc]);
                table.add_row(row!["\tTimestamp:", current_time]);
                table.add_row(row!["\tPacket number:", packet_count]);
                table.add_row(row!["\tPacket length:", packet.len()]);
                if sn_len != -1 {
                    table.add_row(row!["\tCapture length:", sn_len]);
                }
                match ltype {
                    pcap::Linktype(1) => handle_ethernet(EthernetFrame::from(packet), table),
                    _ => {
                        table.add_row(row!["\tUnknown linktype:"]);
                    }
                }
                packet_count += 1;
            }
        }
    }
}

fn handle_ethernet(frame: EthernetFrame, mut table: Table) {
    let src_addr = frame.src_addr();
    let dest_addr = frame.dest_addr();
    table.add_row(row![H2 -> format!("Ethernet II, Src: {}, Dest: {}", src_addr, dest_addr)]);
    let ethertype = frame.ether_type();
    table.add_row(row!["\tSource:", src_addr]);
    table.add_row(row!["\tDestination:", dest_addr]);
    let frame = frame.try_next_header();
    table.add_row(row!["\tType:", frame]);
    if ethertype <= 1500 {
        table.add_row(row!["\tPayload size: ", ethertype]);
    }

    match frame {
        EtherType::Ipv4(frame) => handle_ipv4(frame, table),
        EtherType::Ipv6(frame) => handle_ipv6(frame, table),
        EtherType::Arp(frame) => handle_arp(frame, table),
        EtherType::IeeeLlc(frame) => handle_ieee_llc(frame, table),
        _ => {
            table.add_empty_row();
            table.add_empty_row();
            table.add_empty_row();
            table.printstd();
        }
    }
}

fn handle_ieee_llc(frame: IeeeLlcFrame, mut table: Table) {
    table.add_row(row!["\tDSAP:", frame.dsap()]);
    table.add_row(row!["\tSSAP:", frame.ssap()]);
    table.add_row(row![
        "\tI/G:",
        if frame.is_individual() {
            "Individual"
        } else {
            "Group"
        }
    ]);
    table.add_row(row![
        "\tC/R:",
        if frame.is_command() {
            "Command"
        } else {
            "Response"
        }
    ]);
    let frame = frame.control();
    table.add_row(row!["\tControl type:", frame]);
    match frame {
        LlcControl::UFrame(frame) => {
            table.add_row(row!["\t\tCode:", frame.ucode()]);
            if frame.poll_final() {
                table.add_row(row![if frame.is_command() {
                    "\t\tPoll"
                } else {
                    "\t\tFinal"
                }]);
            }
        }
        LlcControl::IFrame(frame) => {
            table.add_row(row!["\t\tReceive #:", frame.rec_seq()]);
            table.add_row(row!["\t\tSend #:", frame.send_seq()]);
            if frame.poll_final() {
                table.add_row(row![if frame.is_command() {
                    "\t\tPoll"
                } else {
                    "\t\tFinal"
                }]);
            }
        }
        LlcControl::IFrameExt(frame) => {
            table.add_row(row!["\t\tReceive #:", frame.rec_seq()]);
            table.add_row(row!["\t\tSend #:", frame.send_seq()]);
            if frame.poll_final() {
                table.add_row(row![if frame.is_command() {
                    "\t\tPoll"
                } else {
                    "\t\tFinal"
                }]);
            }
        }
        LlcControl::SFrame(frame) => {
            table.add_row(row!["\tCode:", frame.scode()]);
            table.add_row(row!["\tReceive #:", frame.rec_seq()]);
            if frame.poll_final() {
                table.add_row(row![if frame.is_command() {
                    "\tPoll"
                } else {
                    "\tFinal"
                }]);
            }
        }
        LlcControl::SFrameExt(frame) => {
            table.add_row(row!["\t\tCode:", frame.scode()]);
            table.add_row(row!["\t\tReceive #:", frame.rec_seq()]);
            if frame.poll_final() {
                table.add_row(row![if frame.is_command() {
                    "\t\tPoll"
                } else {
                    "\t\tFinal"
                }]);
            }
        }
    };
    table.add_empty_row();
    table.add_empty_row();
    table.add_empty_row();
    table.printstd();
}

fn handle_arp(frame: ArpFrame, mut table: Table) {
    let to_hex = |mut acc: String, val: &u8| {
        acc.push_str(format!("{:02X}", val).as_str());
        acc
    };

    let sha = frame.sha().iter().fold(String::new(), to_hex);
    let spa = frame.spa().iter().fold(String::new(), to_hex);
    let tha = frame.tha().iter().fold(String::new(), to_hex);
    let tpa = frame.tpa().iter().fold(String::new(), to_hex);

    table.add_row(row!["\tHTYPE:", format!("0x{:04X}", frame.htype())]);
    table.add_row(row!["\tPTYPE:", format!("0x{:04X}", frame.ptype())]);
    table.add_row(row!["\tHLEN:", format!("0x{:04X}", frame.hlen())]);
    table.add_row(row!["\tPLEN:", format!("0x{:04X}", frame.plen())]);
    table.add_row(row!["\tOPER:", frame.oper()]);
    table.add_row(row!["\tSHA:", sha]);
    table.add_row(row!["\tSPA:", spa]);
    table.add_row(row!["\tTHA:", tha]);
    table.add_row(row!["\tTPA:", tpa]);
    table.add_empty_row();
    table.add_empty_row();
    table.add_empty_row();
    table.printstd();
}

fn handle_ipv4(frame: Ipv4Frame, mut table: Table) {
    let src_addr = frame.src_addr();
    let dest_addr = frame.dest_addr();
    table.add_row(row![H2 -> format!("Internet Protocol, Src: {}, Dest: {}", src_addr, dest_addr)]);
    table.add_row(row!["\tVersion:", frame.ver()]);
    table.add_row(row![
        "\tHeader length:",
        format!("{} bytes", frame.header_len())
    ]);
    //TODO: Differentiated services print
    table.add_row(row![
        "\tTotal length:",
        format!("{} bytes", frame.total_len())
    ]);
    table.add_row(row![
        "\tIdentification:",
        format!("0x{:04X} ({})", frame.id(), frame.id())
    ]);
    table.add_row(row!["\tFlags:", format!("{:03b}", frame.flags())]);
    if frame.dont_fragment() {
        table.add_row(row!["", format!("\t\t.1. = Don't fragment")]);
    }
    if frame.more_fragments() {
        table.add_row(row!["", format!("\t\t..1 = More fragments")]);
    }
    table.add_row(row!["\tFragment offset:", frame.offset()]);
    table.add_row(row!["\tTime to live:", frame.ttl()]);
    table.add_row(row![
        "\tHeader checksum:",
        format!(
            "0x{:04X} ({})",
            frame.checksum(),
            if frame.has_integrity() {
                "PASS"
            } else {
                "FAIL"
            }
        )
    ]);
    table.add_row(row!["\tSource address:", src_addr]);
    table.add_row(row!["\tDestination address:", dest_addr]);
    //TODO: implement options on ipv4
    if let Some(opts) = frame.opts() {
        table.add_row(row!["\tOptions:"]);
        table.add_row(row![format!("\t\t{:?}", opts)]);
    }
    let frame = frame.try_next_header();
    table.add_row(row!["\tProtocol:", frame]);

    match frame {
        IpProtocol::Tcp(frame) => handle_tcp(frame, table),
        IpProtocol::Udp(frame) => handle_udp(frame, table),
        IpProtocol::Icmp(frame) => {
            table.add_row(row![H2 -> "Internet Control Management Protocol"]);
            table.add_row(row![format!("\t{}",frame.get_control_msg())]);
            table.add_row(row![
                "\tHeader checksum:",
                format!(
                    "0x{:04X} ({})",
                    frame.checksum(),
                    if frame.has_integrity() {
                        "PASS"
                    } else {
                        "FAIL"
                    }
                )
            ]);
            table.add_empty_row();
            table.add_empty_row();
            table.add_empty_row();
            table.printstd();
        }
        IpProtocol::Igmp(frame) => {
            table.add_row(row![H2 -> "Internet Group Management Protocol"]);
            let msg = frame.get_msg();
            table.add_row(row![format!("\t{}", msg)]);
            match msg {
                IgmpMsg::GeneralQuery(time) => {
                    table.add_row(row!["\tMax response time: ", format!("{} sec", time / 10)]);
                }
                IgmpMsg::SpecialQuery(addr, time) => {
                    table.add_row(row!["\tGroup address: ", addr]);
                    table.add_row(row!["\tMax response time: ", format!("{} sec", time / 10)]);
                }
                IgmpMsg::MembershipReport(addr) => {
                    table.add_row(row!["\tGroup address: ", addr]);
                }
                IgmpMsg::LeaveReport(addr) => {
                    table.add_row(row!["\tGroup address: ", addr]);
                }
                _ => {}
            };
            table.add_row(row![
                "\tHeader checksum:",
                format!(
                    "0x{:04X} ({})",
                    frame.checksum(),
                    if frame.has_integrity() {
                        "PASS"
                    } else {
                        "FAIL"
                    }
                )
            ]);
            table.add_empty_row();
            table.add_empty_row();
            table.add_empty_row();
            table.printstd();
        }
        _ => {
            table.add_empty_row();
            table.add_empty_row();
            table.add_empty_row();
            table.printstd();
        }
    }
}

fn handle_ipv6(frame: Ipv6Frame, mut table: Table) {
    table.add_row(row!["\tSource address:", frame.src_addr()]);
    table.add_row(row!["\tDestination address:", frame.dest_addr()]);
    table.add_empty_row();
    table.add_empty_row();
    table.add_empty_row();
    table.printstd();
}

fn handle_tcp(frame: TcpFrame, mut table: Table) {
    table.add_row(row![H2 -> "Transmission Control Protocol"]);
    table.add_row(row!["\tSource port:", frame.src_port()]);
    table.add_row(row!["\tDestination port:", frame.dest_port()]);
    table.add_row(row![
        "\tSequence number:",
        format!("0x{:08X}", frame.seq_num())
    ]);
    if let Some(ack) = frame.ack_num() {
        table.add_row(row![
            "\tAcknowledge number:",
            format!("0x{:08X}", ack)
        ]);
    }
    table.add_row(row!["\tData offset:", frame.data_offset()]);
    table.add_row(row![
        "\tHeader checksum:",
        format!(
            "0x{:04X} ({})",
            frame.checksum(),
            if frame.has_integrity() {
                "PASS"
            } else {
                "FAIL"
            }
        )
    ]);
    table.add_empty_row();
    table.add_empty_row();
    table.add_empty_row();
    table.printstd();
}

fn handle_udp(frame: UdpFrame, mut table: Table) {
    table.add_row(row![H2 -> "User Datagram Protocol Protocol"]);
    table.add_row(row!["\tSource port:", frame.src_port()]);
    table.add_row(row!["\tDestination port:", frame.dest_port()]);
    table.add_row(row![
        "\tHeader checksum:",
        format!(
            "0x{:04X} ({})",
            frame.checksum(),
            if frame.has_integrity() {
                "PASS"
            } else {
                "FAIL"
            }
        )
    ]);
    table.add_empty_row();
    table.add_empty_row();
    table.add_empty_row();
    table.printstd();
}
