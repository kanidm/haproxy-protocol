use crate::{Address, Command, Protocol, ProxyHdrV1, ProxyHdrV2};
use nom::{Parser, combinator::map_opt, number::streaming::be_u8};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

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

#[cfg(feature = "tokio")]
pub const V1_MIN_LEN: usize = 15;
#[cfg(feature = "tokio")]
pub const V1_MAX_LEN: usize = 107;
const V1_MAX_WORK_LEN: usize = 107 - 6;

fn bytes_to_str(input: &[u8]) -> nom::IResult<&[u8], &str> {
    str::from_utf8(input).map(|s| (input, s)).map_err(|_| {
        nom::Err::Failure(nom::error::Error {
            input,
            code: nom::error::ErrorKind::AlphaNumeric,
        })
    })
}

pub(crate) fn parse_proxy_hdr_v1(input_data: &[u8]) -> nom::IResult<&[u8], ProxyHdrV1> {
    // Do we have the correct header? If not, no point trying to continue.
    let (input_data, _magic) = nom::bytes::streaming::tag("PROXY ")(input_data)?;

    // First, limit the input data to the maximum length of the header. We have to setup our
    // "return" array here that defines how much data we are actually taking from the input
    let (ignore_crlf, working_data) = if input_data.len() > V1_MAX_WORK_LEN {
        // Limit the input length.
        let working_data = &input_data[..V1_MAX_WORK_LEN];

        // Note that we use COMPLETE here so that we don't return that we need more data.
        nom::character::complete::not_line_ending(working_data)?
    } else {
        // Note that we use STREAMING here so that we MAY return that we need more data.
        nom::character::streaming::not_line_ending(input_data)?
    };

    // Check that we HAVE the crlf - this is because not line ending also matches on \n.
    let (_excess, ignore_crlf) = nom::character::complete::crlf(ignore_crlf)?;

    // This MUST hold true as both ignore_crlf and working_data are subslices of the
    // original input_data.
    debug_assert!((ignore_crlf.len() + working_data.len()) <= input_data.len());
    // Setup the "remainder" for us to return that indicates where we STOPPED processing
    // bytes. This way higher level callers can advance their buffers properly.
    let remainder = &input_data[(2 + working_data.len())..];

    // THE INPUT IS COMPLETE - don't use the streaming types from this point onward!

    // Now we are looking for one of the protocol indicators.
    let (input, protocol) = nom::bytes::complete::take_till(|c| c == 0x20)(working_data)?;

    let protocol = if protocol == b"UNKNOWN" {
        Protocol::Unspec
    } else if protocol == b"TCP4" {
        Protocol::TcpV4
    } else if protocol == b"TCP6" {
        Protocol::TcpV6
    } else {
        return Err(nom::Err::Failure(nom::error::Error {
            input: protocol,
            code: nom::error::ErrorKind::Tag,
        }));
    };

    // If there are no more bytes, then we are done.
    if input.is_empty() {
        return Ok((
            remainder,
            ProxyHdrV1 {
                protocol,
                address: Address::None,
            },
        ));
    }

    let (input, _discard) = nom::character::complete::space1(input)?;

    let (input, src_addr_bytes) = nom::bytes::complete::take_till(|c| c == 0x20)(input)?;
    let (_ignore, src_addr_str) = bytes_to_str(src_addr_bytes)?;

    let (input, _discard) = nom::character::complete::space1(input)?;

    let (input, dest_addr_bytes) = nom::bytes::complete::take_till(|c| c == 0x20)(input)?;
    let (_ignore, dest_addr_str) = bytes_to_str(dest_addr_bytes)?;

    let (input, _discard) = nom::character::complete::space1(input)?;

    let (input, src_port_bytes) = nom::bytes::complete::take_till(|c| c == 0x20)(input)?;
    let (_ignore, src_port_str) = bytes_to_str(src_port_bytes)?;

    let (dest_port_bytes, _discard) = nom::character::complete::space1(input)?;
    let (_ignore, dest_port_str) = bytes_to_str(dest_port_bytes)?;

    // If we got all the needed bytes and they are valid strs, we now attempt to parse them.

    let src_addr = IpAddr::from_str(src_addr_str).map_err(|_| {
        nom::Err::Failure(nom::error::Error {
            input: src_addr_bytes,
            code: nom::error::ErrorKind::Satisfy,
        })
    })?;

    let src_port = u16::from_str(src_port_str).map_err(|_| {
        nom::Err::Failure(nom::error::Error {
            input: src_port_bytes,
            code: nom::error::ErrorKind::Satisfy,
        })
    })?;

    let dest_addr = IpAddr::from_str(dest_addr_str).map_err(|_| {
        nom::Err::Failure(nom::error::Error {
            input: dest_addr_bytes,
            code: nom::error::ErrorKind::Satisfy,
        })
    })?;

    let dest_port = u16::from_str(dest_port_str).map_err(|_| {
        nom::Err::Failure(nom::error::Error {
            input: dest_port_bytes,
            code: nom::error::ErrorKind::Satisfy,
        })
    })?;

    let src_sock_addr = SocketAddr::new(src_addr, src_port);
    let dest_sock_addr = SocketAddr::new(dest_addr, dest_port);

    let address = match (src_sock_addr, dest_sock_addr) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => Address::V4 { src, dst },
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => Address::V6 { src, dst },
        _ => Address::None,
    };

    Ok((remainder, ProxyHdrV1 { protocol, address }))
}

#[cfg(test)]
mod tests {
    use crate::*;
    use std::net::{SocketAddrV4, SocketAddrV6};
    use std::str::FromStr;

    #[test]
    fn request_local() {
        let _ = tracing_subscriber::fmt::try_init();

        let sample =
            hex::decode("0d0a0d0a000d0a515549540a20000007030004a9b87e8f").expect("valid hex");

        let (took, hdr) = ProxyHdrV2::parse(sample.as_slice()).expect("should parse local addr");

        tracing::debug!(?hdr);

        assert_eq!(took, 23);
        assert_eq!(hdr.command, Command::Local);
        assert_eq!(hdr.protocol, Protocol::Unspec);
        assert_eq!(hdr.address, Address::None);
    }

    #[test]
    fn request_proxy_v4() {
        let _ = tracing_subscriber::fmt::try_init();

        let sample = hex::decode("0d0a0d0a000d0a515549540a2111000cac180c76ac180b8fcdcb027d")
            .expect("valid hex");

        let (took, hdr) = ProxyHdrV2::parse(sample.as_slice()).expect("should parse v4 addr");

        tracing::debug!(?hdr);

        assert_eq!(took, 28);
        assert_eq!(hdr.command, Command::Proxy);
        assert_eq!(hdr.protocol, Protocol::TcpV4);
        assert_eq!(
            hdr.address,
            Address::V4 {
                src: SocketAddrV4::from_str("172.24.12.118:52683").expect("valid addr"),
                dst: SocketAddrV4::from_str("172.24.11.143:637").expect("valid addr"),
            }
        );
    }

    #[test]
    fn request_proxy_v6() {
        let _ = tracing_subscriber::fmt::try_init();

        let sample = hex::decode("0d0a0d0a000d0a515549540a212100242403580b7d88001200000000000001fe2403580b7d8800110000000000001043d34c027d").expect("valid hex");

        let (took, hdr) = ProxyHdrV2::parse(sample.as_slice()).expect("should parse v6 addr");

        tracing::debug!(?hdr);

        assert_eq!(took, 52);
        assert_eq!(hdr.command, Command::Proxy);
        assert_eq!(hdr.protocol, Protocol::TcpV6);
        assert_eq!(
            hdr.address,
            Address::V6 {
                src: SocketAddrV6::from_str("[2403:580b:7d88:12::1fe]:54092").expect("valid addr"),
                dst: SocketAddrV6::from_str("[2403:580b:7d88:11::1043]:637").expect("valid addr"),
            }
        );
    }

    #[test]
    fn request_proxyv1_v4_basic() {
        let _ = tracing_subscriber::fmt::try_init();

        let data = "PROXY TCP4 192.24.10.10 10.0.0.0 5789 80\r\nextra_data";

        let (took, hdr) = ProxyHdrV1::parse(data.as_bytes()).unwrap();
        assert_eq!(took, 42);

        tracing::debug!(?hdr);

        assert_eq!(hdr.protocol, Protocol::TcpV4);
        assert_eq!(
            hdr.address,
            Address::V4 {
                src: SocketAddrV4::from_str("192.24.10.10:5789").unwrap(),
                dst: SocketAddrV4::from_str("10.0.0.0:80").unwrap(),
            }
        );
    }

    #[test]
    fn request_proxyv1_v4_max() {
        let _ = tracing_subscriber::fmt::try_init();

        let data = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n excess";

        let (took, hdr) = ProxyHdrV1::parse(data.as_bytes()).unwrap();
        assert_eq!(took, 56);

        tracing::debug!(?hdr);

        assert_eq!(hdr.protocol, Protocol::TcpV4);
        assert_eq!(
            hdr.address,
            Address::V4 {
                src: SocketAddrV4::from_str("255.255.255.255:65535").unwrap(),
                dst: SocketAddrV4::from_str("255.255.255.255:65535").unwrap(),
            }
        );
    }

    #[test]
    fn request_proxyv1_v6_max() {
        let _ = tracing_subscriber::fmt::try_init();

        let data = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n more extra data";

        let (took, hdr) = ProxyHdrV1::parse(data.as_bytes()).unwrap();
        assert_eq!(took, 104);

        tracing::debug!(?hdr);

        assert_eq!(hdr.protocol, Protocol::TcpV6);
        assert_eq!(
            hdr.address,
            Address::V6 {
                src: SocketAddrV6::from_str("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535")
                    .unwrap(),
                dst: SocketAddrV6::from_str("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535")
                    .unwrap(),
            }
        );
    }

    #[test]
    fn request_proxyv1_unknown() {
        let _ = tracing_subscriber::fmt::try_init();

        let data = "PROXY UNKNOWN\r\n";

        let (took, hdr) = ProxyHdrV1::parse(data.as_bytes()).unwrap();
        assert_eq!(took, 15);

        tracing::debug!(?hdr);

        assert_eq!(hdr.protocol, Protocol::Unspec);
        assert_eq!(hdr.address, Address::None);
    }

    #[test]
    fn request_proxyv1_v6_unknown() {
        let _ = tracing_subscriber::fmt::try_init();

        let data = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n add extra data for luls";

        let (took, hdr) = ProxyHdrV1::parse(data.as_bytes()).unwrap();
        assert_eq!(took, 107);

        tracing::debug!(?hdr);

        assert_eq!(hdr.protocol, Protocol::Unspec);
        assert_eq!(
            hdr.address,
            Address::V6 {
                src: SocketAddrV6::from_str("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535")
                    .unwrap(),
                dst: SocketAddrV6::from_str("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535")
                    .unwrap(),
            }
        );
    }

    #[test]
    fn request_proxyv1_incomplete() {
        let _ = tracing_subscriber::fmt::try_init();

        let data = "PROXY UNKNO";

        let err = ProxyHdrV1::parse(data.as_bytes()).expect_err("Should fail!!!");

        tracing::debug!(?err);
        assert!(matches!(err, Error::Incomplete { .. }));
    }

    #[test]
    fn request_proxyv1_v6_too_long() {
        let _ = tracing_subscriber::fmt::try_init();

        let data = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535 too long\r\n";

        let err = ProxyHdrV1::parse(data.as_bytes()).expect_err("Should fail!!!");

        assert!(matches!(err, Error::Invalid));
    }
}
