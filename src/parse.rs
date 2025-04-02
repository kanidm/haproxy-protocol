use crate::{Address, Command, Protocol, ProxyHdrV2};
use nom::Parser;
use nom::combinator::map_opt;
use nom::number::streaming::be_u8;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

impl Protocol {
    fn new(input: u8) -> Option<Self> {
        match input {
            0x00 | 0x31 | 0x32 => Some(Self::Unspec),
            0x11 => Some(Self::TcpV4),
            0x12 => Some(Self::UdpV4),
            0x21 => Some(Self::TcpV6),
            0x22 => Some(Self::UdpV6),
            // 0x31 => Some(Self::UnixStream),
            // 0x32 => Some(Self::UnixDgram),
            _ => None,
        }
    }
}

impl Command {
    fn new(input: u8) -> Option<Self> {
        match input {
            0x00 => Some(Self::Local),
            0x01 => Some(Self::Proxy),
            _ => None,
        }
    }
}

fn parse_bits(input: &[u8]) -> nom::IResult<&[u8], (u8, Command)> {
    // Turns the thing to bits, then back to bytes, you stuff all your bit parsers in here
    nom::bits::bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>((
        nom::bits::streaming::tag(0x02, 4usize),
        map_opt(nom::bits::streaming::take(4usize), Command::new),
    ))(input)
}

fn parse_addr_v4(input: &[u8]) -> nom::IResult<&[u8], Address> {
    let (input, src_addr) = nom::number::complete::be_u32(input)?;
    let (input, dst_addr) = nom::number::complete::be_u32(input)?;
    let (input, src_port) = nom::number::complete::be_u16(input)?;
    let (input, dst_port) = nom::number::complete::be_u16(input)?;

    let src = SocketAddrV4::new(Ipv4Addr::from_bits(src_addr), src_port);
    let dst = SocketAddrV4::new(Ipv4Addr::from_bits(dst_addr), dst_port);

    Ok((input, Address::V4 { src, dst }))
}

fn parse_addr_v6(input: &[u8]) -> nom::IResult<&[u8], Address> {
    let (input, src_addr) = nom::number::complete::be_u128(input)?;
    let (input, dst_addr) = nom::number::complete::be_u128(input)?;
    let (input, src_port) = nom::number::complete::be_u16(input)?;
    let (input, dst_port) = nom::number::complete::be_u16(input)?;

    let src = SocketAddrV6::new(Ipv6Addr::from_bits(src_addr), src_port, 0, 0);
    let dst = SocketAddrV6::new(Ipv6Addr::from_bits(dst_addr), dst_port, 0, 0);

    Ok((input, Address::V6 { src, dst }))
}

pub(crate) fn parse_proxy_hdr_v2(input_data: &[u8]) -> nom::IResult<&[u8], ProxyHdrV2> {
    let (input, _magic) = nom::bytes::streaming::tag(
        &b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"[..],
    )(input_data)?;

    let (input, (_version, command)) = parse_bits(input)?;

    let (input, protocol) = map_opt(be_u8, Protocol::new).parse(input)?;

    let (input, length) = nom::number::streaming::be_u16(input)?;
    let (remainder, input) = nom::bytes::streaming::take(length)(input)?;

    // Parse the address now based on what protocol was chosen.
    // FROM HERE we use bytes complete, because we have everything we need!
    let (_input, address) = match protocol {
        Protocol::Unspec => (input, Address::None),
        Protocol::TcpV4 | Protocol::UdpV4 => parse_addr_v4(input)?,
        Protocol::TcpV6 | Protocol::UdpV6 => parse_addr_v6(input)?,
    };

    Ok((
        remainder,
        ProxyHdrV2 {
            command,
            protocol,
            // length,
            address,
        },
    ))
}

#[cfg(test)]
mod tests {
    use crate::*;
    use std::net::{SocketAddrV4, SocketAddrV6};
    use std::str::FromStr;

    #[test]
    fn request_local() {
        let _ = tracing_subscriber::fmt::try_init();

        let sample = hex::decode("0d0a0d0a000d0a515549540a20000007030004a9b87e8f").unwrap();

        let (took, hdr) = ProxyHdrV2::parse(sample.as_slice()).unwrap();

        tracing::debug!(?hdr);

        assert_eq!(took, 23);
        assert_eq!(hdr.command, Command::Local);
        assert_eq!(hdr.protocol, Protocol::Unspec);
        assert_eq!(hdr.address, Address::None);
    }

    #[test]
    fn request_proxy_v4() {
        let _ = tracing_subscriber::fmt::try_init();

        let sample =
            hex::decode("0d0a0d0a000d0a515549540a2111000cac180c76ac180b8fcdcb027d").unwrap();

        let (took, hdr) = ProxyHdrV2::parse(sample.as_slice()).unwrap();

        tracing::debug!(?hdr);

        assert_eq!(took, 28);
        assert_eq!(hdr.command, Command::Proxy);
        assert_eq!(hdr.protocol, Protocol::TcpV4);
        assert_eq!(
            hdr.address,
            Address::V4 {
                src: SocketAddrV4::from_str("172.24.12.118:52683").unwrap(),
                dst: SocketAddrV4::from_str("172.24.11.143:637").unwrap(),
            }
        );
    }

    #[test]
    fn request_proxy_v6() {
        let _ = tracing_subscriber::fmt::try_init();

        let sample = hex::decode("0d0a0d0a000d0a515549540a212100242403580b7d88001200000000000001fe2403580b7d8800110000000000001043d34c027d").unwrap();

        let (took, hdr) = ProxyHdrV2::parse(sample.as_slice()).unwrap();

        tracing::debug!(?hdr);

        assert_eq!(took, 52);
        assert_eq!(hdr.command, Command::Proxy);
        assert_eq!(hdr.protocol, Protocol::TcpV6);
        assert_eq!(
            hdr.address,
            Address::V6 {
                src: SocketAddrV6::from_str("[2403:580b:7d88:12::1fe]:54092").unwrap(),
                dst: SocketAddrV6::from_str("[2403:580b:7d88:11::1043]:637").unwrap(),
            }
        );
    }
}
