use crate::parse::parse_proxy_hdr_v2;
use std::num::NonZeroUsize;

mod parse;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum Command {
    Local = 0x00,
    Proxy = 0x01,
}

#[derive(Debug, PartialEq, Eq, Clone)]
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

#[derive(Debug, Clone)]
pub struct ProxyHdrV2 {
    pub command: Command,
    pub protocol: Protocol,
    // address_family: AddressFamily,
    length: u16,
    pub address: Address,
}

impl ProxyHdrV2 {
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
