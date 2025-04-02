use nom::Parser;
use nom::combinator::map_opt;
use nom::number::streaming::be_u8;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::num::NonZeroUsize;

#[derive(Debug)]
#[repr(u8)]
pub enum Protocol {
    Unspec = 0x00,
    TcpV4 = 0x11,
    UdpV4 = 0x12,
    TcpV6 = 0x21,
    UdpV6 = 0x22,
    // UnixStream = 0x31,
    // UnixDgram = 0x32,
}

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

#[derive(Debug)]
#[repr(u8)]
pub enum Command {
    Local = 0x00,
    Proxy = 0x01,
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

#[derive(Debug)]
pub enum Address {
    None,
    V4 {
        src: std::net::SocketAddrV4,
        dst: std::net::SocketAddrV4,
    },
    V6 {
        src: std::net::SocketAddrV6,
        dst: std::net::SocketAddrV6,
    },
    // Unix {
    //     src: PathBuf,
    //     dst: PathBuf,
    // }
}

#[derive(Debug)]
pub struct ProxyHdrV2 {
    pub command: Command,
    pub protocol: Protocol,
    // address_family: AddressFamily,
    pub length: u16,
    pub address: Address,
}

/*
#[derive(Debug)]
#[repr(u8)]
enum PP2TLV {
    Crc32c,
    UniqueId,
    Unknown,
}

impl PP2TLV {
    pub fn new(input: u8) -> Self {
        match input {
            0x03 => Self::Crc32c,
            0x04 => Self::UniqueId,
            _ => Self::Unknown,

        }
    }
}
*/

impl ProxyHdrV2 {
    pub fn size(&self) -> usize {
        (self.length + 16) as usize
    }

    pub fn parse(input_data: &[u8]) -> Result<(usize, Self), Error> {
        match parse_proxy_hdr_v2(input_data) {
            Ok((remainder, hdr)) => {
                let took = input_data.len() - remainder.len();
                Ok((took, hdr))
            }
            Err(nom::Err::Incomplete(nom::Needed::Size(need))) => Err(Error::Incomplete { need }),
            Err(nom::Err::Incomplete(nom::Needed::Unknown)) => Err(Error::UnableToComplete),

            Err(nom::Err::Error(err)) => {
                tracing::error!(?err);
                Err(Error::Invalid)
            }
            Err(nom::Err::Failure(err)) => {
                tracing::error!(?err);
                Err(Error::Invalid)
            }
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Invalid,
    Incomplete { need: NonZeroUsize },
    UnableToComplete,
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

fn parse_proxy_hdr_v2(input_data: &[u8]) -> nom::IResult<&[u8], ProxyHdrV2> {
    let (input, _magic) = nom::bytes::streaming::tag(
        &b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"[..],
    )(input_data)?;
    tracing::debug!(?_magic);

    let (input, (version, command)) = parse_bits(input)?;
    tracing::debug!(?version);
    tracing::debug!(?command);

    let (input, protocol) = map_opt(be_u8, Protocol::new).parse(input)?;

    let (input, length) = nom::number::streaming::be_u16(input)?;
    let (remainder, input) = nom::bytes::streaming::take(length)(input)?;

    tracing::debug!(?input);
    tracing::debug!(?remainder);

    // Parse the address now based on what protocol was chosen.
    // FROM HERE we use bytes complete, because we have everything we need!
    let (input, address) = match protocol {
        Protocol::Unspec => (input, Address::None),
        Protocol::TcpV4 | Protocol::UdpV4 => parse_addr_v4(input)?,
        Protocol::TcpV6 | Protocol::UdpV6 => parse_addr_v6(input)?,
    };

    // If there are bytes remaining, we could continue to parse out any PP2 options.
    tracing::debug!(?input);

    Ok((
        remainder,
        ProxyHdrV2 {
            command,
            protocol,
            length,
            address,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let _ = tracing_subscriber::fmt::try_init();

        let sample = hex::decode("0d0a0d0a000d0a515549540a20000007030004a9b87e8f").unwrap();

        let proxy = ProxyHdrV2::parse(sample.as_slice()).unwrap();

        tracing::debug!(?proxy);
    }
}
