use std::convert::TryInto;
use std::net::Ipv4Addr;
use std::result;

use itertools::Itertools;

use crate::utils::{self, Error, Result};

struct RawMessage {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: [u8; 4],
    yiaddr: [u8; 4],
    siaddr: [u8; 4],
    giaddr: [u8; 4],
    chaddr: [u8; 16],
    sname: [u8; Self::SNAME_SIZE],
    file: [u8; Self::FILE_SIZE],
    options: [u8; Self::MAX_OPTIONS_SIZE],
}

impl RawMessage {
    const SNAME_SIZE: usize = 64;

    const FILE_SIZE: usize = 128;

    const MAX_OPTIONS_SIZE: usize = 1024;

    const MAX_SIZE: usize = Self::MAX_OPTIONS_SIZE + 236;

    fn decode(buf: &[u8]) -> Result<RawMessage> {
        if buf.len() < 236 { // TODO This isn't right, as at least some data must be present in `options`
            Err(Error::MessageDecoding(String::from("Invalid buffer: buffer too small")))
        } else if buf.len() > 236 + Self::MAX_OPTIONS_SIZE {
            Err(Error::MessageDecoding(String::from("Invalid buffer: buffer too big")))
        } else {
            let mut options = [0; 1024];
            utils::copy_slice(&mut options, &buf[236..]);
            let mut sname = [0; 64];
            utils::copy_slice(&mut sname, &buf[44..108]);
            let mut file = [0; 128];
            utils::copy_slice(&mut file, &buf[108..236]);

            Ok(RawMessage {
                op: buf[0],
                htype: buf[1],
                hlen: buf[2],
                hops: buf[3],
                xid: u32::from_be_bytes(buf[4..8].try_into().unwrap()),
                secs: u16::from_be_bytes(buf[8..10].try_into().unwrap()),
                flags: u16::from_be_bytes(buf[10..12].try_into().unwrap()),
                ciaddr: buf[12..16].try_into().unwrap(),
                yiaddr: buf[16..20].try_into().unwrap(),
                siaddr: buf[20..24].try_into().unwrap(),
                giaddr: buf[24..28].try_into().unwrap(),
                chaddr: buf[28..44].try_into().unwrap(),
                sname,
                file,
                options,
            })
        }
    }

    fn encode(&self, buf: &mut [u8]) -> Result<()> {
        buf[0] = self.op;
        buf[1] = self.htype;
        buf[2] = self.hlen;
        buf[3] = self.hops;
        utils::copy_slice(&mut buf[4..], &self.xid.to_be_bytes());
        utils::copy_slice(&mut buf[8..], &self.secs.to_be_bytes());
        utils::copy_slice(&mut buf[10..], &self.flags.to_be_bytes());
        utils::copy_slice(&mut buf[12..], &self.ciaddr);
        utils::copy_slice(&mut buf[16..], &self.yiaddr);
        utils::copy_slice(&mut buf[20..], &self.siaddr);
        utils::copy_slice(&mut buf[24..], &self.giaddr);
        utils::copy_slice(&mut buf[28..], &self.chaddr);
        utils::copy_slice(&mut buf[44..], &self.sname);
        utils::copy_slice(&mut buf[108..], &self.file);
        utils::copy_slice(&mut buf[236..], &self.options);
        Ok(())
    }
}

struct Message {
    op: MessageOp,
    htype: u8,
    hlen: u8,
    xid: TransactionID,
    broadcast: bool,
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    siaddr: Ipv4Addr,
    giaddr: Ipv4Addr,
    options: MessageOptions,
}

impl Message {
    fn from_raw(raw: &RawMessage) -> Result<Message> {
        Ok(Message {
            op: if raw.op == MessageOp::Request as u8 {
                MessageOp::Request
            } else if raw.op == MessageOp::Reply as u8 {
                MessageOp::Reply
            } else {
                return Err(Error::MessageInterpretation(String::from("Op field is invalid")));
            },
            htype: raw.htype,
            hlen: raw.hlen,
            xid: TransactionID(raw.xid),
            broadcast: if raw.flags == 1 {
                true
            } else if raw.flags == 0 {
                false
            } else {
                return Err(Error::MessageInterpretation(String::from("Flags field is invalid")));
            },
            ciaddr: Ipv4Addr::new(raw.ciaddr[0], raw.ciaddr[1], raw.ciaddr[2], raw.ciaddr[3]),
            yiaddr: Ipv4Addr::new(raw.yiaddr[0], raw.yiaddr[1], raw.yiaddr[2], raw.yiaddr[3]),
            siaddr: Ipv4Addr::new(raw.siaddr[0], raw.siaddr[1], raw.siaddr[2], raw.siaddr[3]),
            giaddr: Ipv4Addr::new(raw.giaddr[0], raw.giaddr[1], raw.giaddr[2], raw.giaddr[3]),
            options: MessageOptions::decode(&raw.sname, &raw.file, &raw.options)?,
        })
    }

    fn decode(buf: &[u8]) -> Result<Message> {
        let raw = RawMessage::decode(buf)?;
        Ok(Message::from_raw(&raw)?)
    }

    fn to_raw(&self) -> RawMessage {
        unimplemented!()
    }

    fn encode(&self, buf: &mut [u8]) -> Result<()> {
        let raw = self.to_raw();
        Ok(raw.encode(buf)?)
    }
}

enum MessageOp {
    Request = 1,
    Reply = 2,
}

struct TransactionID(u32);

#[derive(Debug, Eq, PartialEq)]
struct MessageOptions {
    subnet_mask: Option<Ipv4Addr>,
    router: Option<Vec<Ipv4Addr>>,
    domain_name_server: Option<Vec<Ipv4Addr>>,
    host_name: Option<Vec<u8>>,
    requested_ip_addr: Option<Ipv4Addr>,
    lease_time: Option<u32>,
    option_overload: Option<OptionOverload>,
    message_type: MessageType,
    server_identifier: Option<u32>,
    parameter_request_list: Option<Vec<MessageOption>>,
    message: Option<Vec<u8>>,
    renewal_time: Option<u32>,
    rebinding_time: Option<u32>,
    client_identifier: Option<Vec<u8>>,
}

#[derive(Debug, Eq, PartialEq)]
#[repr(u8)]
enum MessageOption {
    Pad = 0,
    SubnetMask = 1,
    Router = 3,
    DomainNameServer = 6,
    HostName = 12,
    RequestedIpAddr = 50,
    LeaseTime = 51,
    OptionOverload = 52,
    MessageType = 53,
    ServerIdentifier = 54,
    ParameterRequestList = 55,
    Message = 56,
    RenewalTime = 58,
    RebindingTime = 59,
    ClientIdentifier = 61,
    End = 255,
}

impl MessageOptions {
    fn decode(
        _sname: &[u8; RawMessage::SNAME_SIZE],
        _file: &[u8; RawMessage::FILE_SIZE],
        raw_options: &[u8; RawMessage::MAX_OPTIONS_SIZE],
    ) -> Result<MessageOptions> {
        let mut options = MessageOptions {
            subnet_mask: None,
            router: None,
            domain_name_server: None,
            host_name: None,
            requested_ip_addr: None,
            lease_time: None,
            option_overload: None,
            message_type: MessageType::Discover,
            server_identifier: None,
            parameter_request_list: None,
            message: None,
            renewal_time: None,
            rebinding_time: None,
            client_identifier: None,
        };

        let mut seen_type = false;
        let mut seen_end = false;
        let mut raw_options = raw_options.iter();

        Self::check_magic_cookie(&mut raw_options)?;

        loop {
            use MessageOption::*;

            let raw_option = Self::next_byte(&mut raw_options)?;
            match Self::decode_raw_option(raw_option) {
                Some(Pad) => continue,
                Some(End) if seen_end => return Err(Error::InvalidOption),
                Some(End) => {
                    seen_end = true;
                    break;
                }
                Some(SubnetMask) =>
                    options.subnet_mask = Some(Self::load_ip_addr(&mut raw_options)?),
                Some(Router) =>
                    options.router = Some(Self::load_ip_addrs(&mut raw_options)?),
                Some(DomainNameServer) =>
                    options.domain_name_server = Some(Self::load_ip_addrs(&mut raw_options)?),
                Some(HostName) =>
                    options.host_name = Some(Self::load_byte_string(&mut raw_options)?),
                Some(RequestedIpAddr) =>
                    options.requested_ip_addr = Some(Self::load_ip_addr(&mut raw_options)?),
                Some(LeaseTime) =>
                    options.lease_time = Some(Self::load_u32(&mut raw_options)?),
                Some(OptionOverload) =>
                    unimplemented!(),
                Some(MessageType) if seen_type => return Err(Error::InvalidOption),
                Some(MessageType) => {
                    seen_type = true;
                    options.message_type = dbg!(Self::load_message_type(&mut raw_options))?;
                }
                Some(ServerIdentifier) =>
                    options.server_identifier = Some(Self::load_u32(&mut raw_options)?),
                Some(ParameterRequestList) => options.parameter_request_list =
                    Some(Self::load_parameter_request_list(&mut raw_options)?),
                Some(Message) =>
                    options.message = Some(Self::load_byte_string(&mut raw_options)?),
                Some(RenewalTime) =>
                    options.renewal_time = Some(Self::load_u32(&mut raw_options)?),
                Some(RebindingTime) =>
                    options.rebinding_time = Some(Self::load_u32(&mut raw_options)?),
                Some(ClientIdentifier) =>
                    options.client_identifier = Some(Self::load_byte_string(&mut raw_options)?),
                None => Self::skip_option_body(&mut raw_options)?,
            }
        }

        if dbg!(!seen_type) || dbg!(!seen_end) {
            return Err(Error::InvalidOption);
        }

        if options.option_overload.is_some() {
            unimplemented!() // TODO Implement this properly
        }

        Ok(options)
    }

    fn check_magic_cookie<'a>(raw_options: &mut impl Iterator<Item=&'a u8>) -> Result<()> {
        let cookie = [
            Self::next_byte(raw_options)?, Self::next_byte(raw_options)?,
            Self::next_byte(raw_options)?, Self::next_byte(raw_options)?,
        ];

        if cookie == [99, 130, 83, 99] {
            Ok(())
        } else {
            Err(Error::InvalidOption)
        }
    }

    fn decode_raw_option(raw_option: u8) -> Option<MessageOption> {
        use MessageOption::*;

        const PAD: u8 = Pad as u8;
        const SUBNET_MASK: u8 = SubnetMask as u8;
        const ROUTER: u8 = Router as u8;
        const DOMAIN_NAME_SERVER: u8 = DomainNameServer as u8;
        const HOST_NAME: u8 = HostName as u8;
        const REQUESTED_IP_ADDR: u8 = RequestedIpAddr as u8;
        const LEASE_TIME: u8 = LeaseTime as u8;
        const OPTION_OVERLOAD: u8 = OptionOverload as u8;
        const MESSAGE_TYPE: u8 = MessageType as u8;
        const SERVER_IDENTIFIER: u8 = ServerIdentifier as u8;
        const PARAMETER_REQUEST_LIST: u8 = ParameterRequestList as u8;
        const MESSAGE: u8 = Message as u8;
        const RENEWAL_TIME: u8 = RenewalTime as u8;
        const REBINDING_TIME: u8 = RebindingTime as u8;
        const CLIENT_IDENTIFIER: u8 = ClientIdentifier as u8;
        const END: u8 = End as u8;

        match raw_option {
            PAD => Some(Pad),
            SUBNET_MASK => Some(SubnetMask),
            ROUTER => Some(Router),
            DOMAIN_NAME_SERVER => Some(DomainNameServer),
            HOST_NAME => Some(HostName),
            REQUESTED_IP_ADDR => Some(RequestedIpAddr),
            LEASE_TIME => Some(LeaseTime),
            OPTION_OVERLOAD => Some(OptionOverload),
            MESSAGE_TYPE => Some(MessageType),
            SERVER_IDENTIFIER => Some(ServerIdentifier),
            PARAMETER_REQUEST_LIST => Some(ParameterRequestList),
            MESSAGE => Some(Message),
            RENEWAL_TIME => Some(RenewalTime),
            REBINDING_TIME => Some(RebindingTime),
            CLIENT_IDENTIFIER => Some(ClientIdentifier),
            END => Some(End),
            _ => None,
        }
    }

    fn skip_option_body<'a>(raw_options: &mut impl Iterator<Item=&'a u8>) -> Result<()> {
        let length = Self::next_byte(raw_options)?;
        for _ in 0..length {
            Self::next_byte(raw_options)?;
        }
        Ok(())
    }

    fn load_ip_addr<'a>(raw_options: &mut impl Iterator<Item=&'a u8>) -> Result<Ipv4Addr> {
        let length = Self::next_byte(raw_options)?;
        if length != 4 {
            Err(Error::InvalidOption)
        } else {
            let a = Self::next_byte(raw_options)?;
            let b = Self::next_byte(raw_options)?;
            let c = Self::next_byte(raw_options)?;
            let d = Self::next_byte(raw_options)?;
            Ok(Ipv4Addr::new(a, b, c, d))
        }
    }

    fn load_ip_addrs<'a>(raw_options: &mut impl Iterator<Item=&'a u8>) -> Result<Vec<Ipv4Addr>> {
        let length = Self::next_byte(raw_options)?;
        if length % 4 != 0 {
            Err(Error::InvalidOption)
        } else {
            let mut result = Vec::new();

            for mut ip_chunks in raw_options.take(length as usize).chunks(4).into_iter() {
                let a = Self::next_byte(&mut ip_chunks)?;
                let b = Self::next_byte(&mut ip_chunks)?;
                let c = Self::next_byte(&mut ip_chunks)?;
                let d = Self::next_byte(&mut ip_chunks)?;
                result.push(Ipv4Addr::new(a, b, c, d));
            }

            Ok(result)
        }
    }

    fn load_byte_string<'a>(raw_options: &mut impl Iterator<Item=&'a u8>) -> Result<Vec<u8>> {
        let length = Self::next_byte(raw_options)? as usize;
        let result: Vec<u8> = raw_options.take(length).map(|x| *x).collect();
        if result.len() == length {
            Ok(result)
        } else {
            Err(Error::InvalidOption)
        }
    }

    fn load_u32<'a>(raw_options: &mut impl Iterator<Item=&'a u8>) -> Result<u32> {
        let length = Self::next_byte(raw_options)?;
        if length != 4 {
            Err(Error::InvalidOption)
        } else {
            Ok(u32::from_be_bytes([
                Self::next_byte(raw_options)?,
                Self::next_byte(raw_options)?,
                Self::next_byte(raw_options)?,
                Self::next_byte(raw_options)?,
            ]))
        }
    }

    fn load_message_type<'a>(raw_options: &mut impl Iterator<Item=&'a u8>) -> Result<MessageType> {
        let length = *raw_options.next().ok_or(Error::InvalidOption)? as usize;
        if length == 0 {
            Err(Error::InvalidOption)
        } else {
            const DISCOVER: u8 = MessageType::Discover as u8;
            const OFFER: u8 = MessageType::Offer as u8;
            const REQUEST: u8 = MessageType::Request as u8;
            const DECLINE: u8 = MessageType::Decline as u8;
            const ACK: u8 = MessageType::ACK as u8;
            const NAK: u8 = MessageType::NAK as u8;
            const RELEASE: u8 = MessageType::Release as u8;

            match Self::next_byte(raw_options)? {
                DISCOVER => Ok(MessageType::Discover),
                OFFER => Ok(MessageType::Offer),
                REQUEST => Ok(MessageType::Request),
                DECLINE => Ok(MessageType::Decline),
                ACK => Ok(MessageType::ACK),
                NAK => Ok(MessageType::NAK),
                RELEASE => Ok(MessageType::Release),
                _ => Err(Error::InvalidOption),
            }
        }
    }

    fn load_parameter_request_list<'a>(
        raw_options: &mut impl Iterator<Item=&'a u8>
    ) -> Result<Vec<MessageOption>> {
        let length = Self::next_byte(raw_options)? as usize;
        let result: Vec<_> = raw_options
            .take(length)
            .filter_map(|&o| Self::decode_raw_option(o))
            .collect();

        if result.len() != length {
            Err(Error::InvalidOption)
        } else {
            Ok(result)
        }
    }

    fn next_byte<'a>(raw_options: &mut impl Iterator<Item=&'a u8>) -> Result<u8> {
        Ok(*raw_options.next().ok_or(Error::InvalidOption)?)
    }
}

#[derive(Debug, Eq, PartialEq)]
#[repr(u8)]
enum OptionOverload {
    File = 1,
    Sname = 2,
    FileAndSname = 3,
}

#[derive(Debug, Eq, PartialEq)]
#[repr(u8)]
enum MessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    ACK = 5,
    NAK = 6,
    Release = 7,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_message_decode_encode() {
        let mut buf = [0; RawMessage::MAX_SIZE];
        utils::copy_slice(&mut buf, &[
            1, // op
            1, // htype
            6, // hlen
            0, // hops
            42, 23, 15, 12, // xid
            0, 10, // secs
            0, 1, // flags
            127, 0, 0, 1, // ciaddr
            127, 0, 0, 1, // yiaddr
            127, 0, 0, 1, // siaddr
            0, 0, 0, 0, // giaddr
            12, 12, 13, 12, 12, 0, 0, 0, 12, 12, 13, 12, 12, 0, 0, 0, // chaddr
        ]);
        buf[44] = 9; // Start of sname
        buf[108] = 10; // Start of file
        buf[236] = 11; // Start of options

        let msg = RawMessage::decode(&buf).unwrap();
        assert_eq!(msg.op, 1);
        assert_eq!(msg.htype, 1);
        assert_eq!(msg.hlen, 6);
        assert_eq!(msg.hops, 0);
        assert_eq!(msg.xid, 706154252);
        assert_eq!(msg.secs, 10);
        assert_eq!(msg.flags, 1);
        assert_eq!(msg.ciaddr, [127, 0, 0, 1]);
        assert_eq!(msg.yiaddr, [127, 0, 0, 1]);
        assert_eq!(msg.siaddr, [127, 0, 0, 1]);
        assert_eq!(msg.giaddr, [0, 0, 0, 0]);
        assert_eq!(msg.chaddr, [12, 12, 13, 12, 12, 0, 0, 0, 12, 12, 13, 12, 12, 0, 0, 0]);
        assert_eq!(msg.sname[0], 9);
        assert!(msg.sname[1..].iter().all(|&x| x == 0u8));
        assert_eq!(msg.file[0], 10);
        assert!(msg.file[1..].iter().all(|&x| x == 0u8));
        assert_eq!(msg.options[0], 11);
        assert!(msg.options[1..].iter().all(|&x| x == 0u8));

        let mut encoded = [0; RawMessage::MAX_SIZE];
        msg.encode(&mut encoded);
        for (k, &v) in encoded.iter().enumerate() {
            assert_eq!(buf[k], v);
        }
    }

    #[test]
    fn options_decode() {
        let sname = [0; RawMessage::SNAME_SIZE];
        let file = [0; RawMessage::FILE_SIZE];
        let mut raw_options = [0; RawMessage::MAX_OPTIONS_SIZE];
        assert_eq!(
            MessageOptions::decode(&sname, &file, &raw_options),
            Err(Error::InvalidOption),
        );

        raw_options[0] = 99;
        raw_options[1] = 130;
        raw_options[2] = 83;
        raw_options[3] = 99;
        assert_eq!(
            MessageOptions::decode(&sname, &file, &raw_options),
            Err(Error::InvalidOption),
        );

        raw_options[4] = 255; // Missing message type
        assert_eq!(
            MessageOptions::decode(&sname, &file, &raw_options),
            Err(Error::InvalidOption),
        );

        raw_options[4] = 53;
        raw_options[5] = 1;
        raw_options[6] = 2; // Has message type, but now missing end
        assert_eq!(
            MessageOptions::decode(&sname, &file, &raw_options),
            Err(Error::InvalidOption),
        );

        raw_options[7] = 255;
        // TODO More precise check
        assert!(MessageOptions::decode(&sname, &file, &raw_options).is_ok());
    }
}
