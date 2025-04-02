use crate::parse::parse_proxy_hdr_v2;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use tracing::{debug, error};

mod parse;

const HDR_SIZE_LIMIT: usize = 512;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
enum Protocol {
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
enum Command {
    Local = 0x00,
    Proxy = 0x01,
}

#[derive(Debug, PartialEq, Eq, Clone)]
enum Address {
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
    command: Command,
    protocol: Protocol,
    // address_family: AddressFamily,
    // length: u16,
    address: Address,
}

pub enum RemoteAddress {
    Local,
    Invalid,
    TcpV4 {
        src: std::net::SocketAddrV4,
        dst: std::net::SocketAddrV4,
    },
    UdpV4 {
        src: std::net::SocketAddrV4,
        dst: std::net::SocketAddrV4,
    },
    TcpV6 {
        src: std::net::SocketAddrV6,
        dst: std::net::SocketAddrV6,
    },
    UdpV6 {
        src: std::net::SocketAddrV6,
        dst: std::net::SocketAddrV6,
    },
}

#[derive(Debug)]
pub enum Error {
    Incomplete { need: NonZeroUsize },
    Invalid,
    UnableToComplete,
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

    pub fn to_remote_addr(self) -> RemoteAddress {
        match (self.command, self.protocol, self.address) {
            (Command::Local, _, _) => RemoteAddress::Local,
            (Command::Proxy, Protocol::TcpV4, Address::V4 { src, dst }) => {
                RemoteAddress::TcpV4 { src, dst }
            }
            (Command::Proxy, Protocol::UdpV4, Address::V4 { src, dst }) => {
                RemoteAddress::UdpV4 { src, dst }
            }
            (Command::Proxy, Protocol::TcpV6, Address::V6 { src, dst }) => {
                RemoteAddress::TcpV6 { src, dst }
            }
            (Command::Proxy, Protocol::UdpV6, Address::V6 { src, dst }) => {
                RemoteAddress::UdpV6 { src, dst }
            }
            _ => RemoteAddress::Invalid,
        }
    }
}

#[cfg(feature = "tokio")]
#[derive(Debug)]
pub enum AsyncReadError {
    Io(std::io::Error),
    Invalid,
    UnableToComplete,
    RequestTooLarge,
    InconsistentRead,
}

#[cfg(feature = "tokio")]
impl ProxyHdrV2 {
    pub async fn parse_from_read<S>(mut stream: S) -> Result<(S, ProxyHdrV2), AsyncReadError>
    where
        S: tokio::io::AsyncReadExt + std::marker::Unpin,
    {
        let mut buf = vec![0; 16];

        // First we need to read the exact amount to get up to the *length* field. This will
        // let us then proceed to parse the early header and return how much we need to continue
        // to read.
        let mut took = stream
            .read_exact(&mut buf)
            .await
            .map_err(AsyncReadError::Io)?;

        match ProxyHdrV2::parse(&buf) {
            // Okay, we got a valid header - this can occur with proxy for local conditions.
            Ok((_, hdr)) => return Ok((stream, hdr)),
            // We need more bytes, this is the precise amount we need.
            Err(Error::Incomplete { need }) => {
                let resize_to = buf.len() + usize::from(need);
                // Limit the amount so that we don't overflow anything or allocate a buffer that
                // is too large. Nice try hackers.
                if resize_to > HDR_SIZE_LIMIT {
                    error!(
                        "proxy header request was larger than {} bytes, refusing to proceed.",
                        HDR_SIZE_LIMIT
                    );
                    return Err(AsyncReadError::RequestTooLarge);
                }
                buf.resize(resize_to, 0);
            }
            Err(Error::Invalid) => {
                debug!(proxy_binary_dump = %hex::encode(&buf));
                error!("proxy header was invalid");
                return Err(AsyncReadError::Invalid);
            }
            Err(Error::UnableToComplete) => {
                debug!(proxy_binary_dump = %hex::encode(&buf));
                error!("proxy header was incomplete");
                return Err(AsyncReadError::UnableToComplete);
            }
        };

        // Now read any remaining bytes into the buffer.
        took += stream
            .read_exact(&mut buf[16..])
            .await
            .map_err(AsyncReadError::Io)?;

        match ProxyHdrV2::parse(&buf) {
            Ok((hdr_took, _)) if hdr_took != took => {
                // We took inconsistent byte amounts, error.
                error!("proxy header read an inconsistent amount from stream.");
                return Err(AsyncReadError::InconsistentRead);
            }
            Ok((_, hdr)) =>
            // HAPPY!!!!!
            {
                Ok((stream, hdr))
            }
            Err(Error::Incomplete { need: _ }) => {
                error!("proxy header could not be read to the end.");
                return Err(AsyncReadError::UnableToComplete);
            }
            Err(Error::Invalid) => {
                debug!(proxy_binary_dump = %hex::encode(&buf));
                error!("proxy header was invalid");
                return Err(AsyncReadError::Invalid);
            }
            Err(Error::UnableToComplete) => {
                debug!(proxy_binary_dump = %hex::encode(&buf));
                error!("proxy header was incomplete");
                return Err(AsyncReadError::UnableToComplete);
            }
        }
    }
}
