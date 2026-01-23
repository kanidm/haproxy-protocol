//! An example pcapng parser that extracts TCP payloads and attempts to parse
//! them as HAProxy Proxy Protocol v1 or v2 headers.
//! Usage: cargo run --example pcapng_parser -- <path to pcapng file>

use haproxy_protocol::{ProxyHdrV1, ProxyHdrV2};
use pcap_parser::data::{PacketData, get_packetdata};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use std::env::args;
use std::fs::File;

fn handle_epb(block: EnhancedPacketBlock<'_>, if_linktypes: &mut [Linktype]) {
    if let Some(data) = get_packetdata(
        block.data,
        if_linktypes[block.if_id as usize],
        block.caplen as usize,
    ) {
        let bytes = match data {
            PacketData::L3(_, bytes) => {
                print!("L3 ");
                bytes
            }
            PacketData::L2(bytes) => {
                print!("L2 ");
                bytes
            }
            PacketData::L4(_, bytes) => {
                print!("L4 ");
                bytes
            }
            PacketData::Unsupported(_) => {
                eprintln!("Unsupported packet data: {:?}", block);
                return;
            }
        };

        let mut byte_offset = 0;

        if bytes.len() >= 14 {
            if bytes[12] == 0x08 && bytes[13] == 0x00 {
                print!("IPv4");
                byte_offset += 14;
            } else if bytes[12] == 0x86 && bytes[13] == 0xdd {
                println!("IPv6 packet, haven't implemented parsing yet, skipping");
                return;
            } else if bytes[12..14] == [0x7f, 0x00] {
                print!("Loopback packet ");
            } else {
                println!(
                    "Unsupported packet, skipping! Ethertype: {:02x}{:02x}",
                    bytes[12], bytes[13]
                );
                return;
            }
        }
        let header_length = bytes[byte_offset] & 0x0f;
        print!(" Header length: {}", header_length * 4);
        if bytes.len() >= byte_offset + (header_length as usize * 4) {
            let protocol = bytes[byte_offset + 9];
            match protocol {
                6 => print!(" TCP"),
                17 => println!(" UDP, ignoring"),
                1 => println!(" ICMP, ignoring"),
                _ => println!("  Protocol: Other ({}), ignoring", protocol),
            }
            if protocol != 6 {
                println!("Not TCP, skipping");
                return;
            }
        }
        byte_offset += header_length as usize * 4;
        if bytes.len() >= byte_offset + 20 {
            let src_port = (bytes[byte_offset] as u16) << 8 | (bytes[byte_offset + 1] as u16);
            let dst_port = (bytes[byte_offset + 2] as u16) << 8 | (bytes[byte_offset + 3] as u16);
            print!(" src port: {} dst port: {}", src_port, dst_port);
        } else {
            println!(" Not enough data for TCP header, skipping");
            return;
        }
        // get the seq number
        if bytes.len() >= byte_offset + 8 {
            let seq_number = (bytes[byte_offset + 4] as u32) << 24
                | (bytes[byte_offset + 5] as u32) << 16
                | (bytes[byte_offset + 6] as u32) << 8
                | (bytes[byte_offset + 7] as u32);
            print!("  SEQ: {}", seq_number);
        } else {
            println!("  Not enough data for TCP seq number, skipping");
            return;
        }
        // get the ack
        if bytes.len() >= byte_offset + 12 {
            let ack_number = (bytes[byte_offset + 8] as u32) << 24
                | (bytes[byte_offset + 9] as u32) << 16
                | (bytes[byte_offset + 10] as u32) << 8
                | (bytes[byte_offset + 11] as u32);
            print!("  ACK: {}", ack_number);
        } else {
            println!("  Not enough data for TCP ack number, skipping");
            return;
        }
        // header length
        let tcp_header_length = (bytes[byte_offset + 12] >> 4) * 4;
        print!("  TCP header length: {}", tcp_header_length);

        // if it's a RST we can continue
        let flags = bytes[byte_offset + 13];
        byte_offset += tcp_header_length as usize;
        if flags & 0x04 != 0 {
            println!(" RST packet, skipping payload");
            return;
        } else if flags == 0x12 {
            println!(" SYN-ACK packet, skipping payload");
            return;
        } else if flags == 0x02 {
            println!(" SYN flag set, skipping payload");
            return;
        } else if byte_offset == block.caplen as usize {
            println!(" No payload");
        } else {
            // payload time!

            let payload = bytes[byte_offset..].to_vec();
            if payload.is_empty() {
                println!(" No payload");
                return;
            }
            let payload_as_ascii = String::from_utf8_lossy(&payload);
            println!(
                "Payload as ascii:\n##############\n{}\n#############",
                payload_as_ascii
                    .replace('\r', r#"\r"#)
                    .replace('\n', r#"\n"#)
            );
            println!("Payload as hex:");
            let mut hexstring = String::new();
            let mut ascii_string = String::new();
            for byte in payload.iter() {
                hexstring.push_str(&format!("{:02x} ", byte));
                if byte.is_ascii_graphic() || *byte == b' ' {
                    ascii_string.push(*byte as char);
                    ascii_string.push_str("  ");
                } else if byte == &0x0d {
                    ascii_string.push_str(r#"\r "#);
                } else if byte == &0x0a {
                    ascii_string.push_str(r#"\n "#);
                } else {
                    ascii_string.push_str("🧐 ");
                }
            }
            println!("{}", hexstring);
            println!("{}", ascii_string);
            println!("\nAttempting to parse as proxy headers:");
            println!("v1: {:?}", ProxyHdrV1::parse(&payload));
            println!("v2: {:?}", ProxyHdrV2::parse(&payload));
            println!("############ End of payload ###########");
        }

        println!();
    } else {
        eprintln!("Could not parse packet data: {:?}", block);
    };
}

pub fn main() {
    if args().any(|arg| arg == "--help") || args().len() < 2 {
        eprintln!("Usage: pcapng_parser <pcapng file>");
        return;
    }

    let filename = args().nth(1).expect("Please provide a pcapng file path");

    let file = File::open(&filename).unwrap();
    let mut num_blocks = 0;
    if !filename.to_lowercase().ends_with(".pcapng") {
        eprintln!("This parser only supports pcapng files.");
        return;
    }
    let mut reader = PcapNGReader::new(65536, file).expect("PcapNGReader failed to open file");
    let mut if_linktypes = Vec::new();
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                num_blocks += 1;
                match block {
                    PcapBlockOwned::Legacy(legacy_pcap_block) => {
                        println!("legacy block: {:?}", legacy_pcap_block)
                    }
                    PcapBlockOwned::LegacyHeader(pcap_header) => {
                        println!("pcap header: {:?}", pcap_header)
                    }
                    PcapBlockOwned::NG(Block::SectionHeader(ref _shb)) => {
                        // starting a new section, clear known interfaces
                        if_linktypes = Vec::new();
                    }
                    PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
                        if_linktypes.push(idb.linktype);
                    }
                    PcapBlockOwned::NG(block) => {
                        // println!("ng block: {:?}", block);
                        match block {
                            Block::EnhancedPacket(epb) => {
                                handle_epb(epb, &mut if_linktypes);
                            }
                            _ => {
                                eprintln!("Unhandled block type: {:?}", block);
                            }
                        }
                        // println!();
                    }
                }

                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader.refill().unwrap();
            }
            Err(e) => {
                eprintln!("error while reading: {:?}", e);
                break;
            }
        }
    }
    println!("parsed {} pcap blocks", num_blocks);
}
