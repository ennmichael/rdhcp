use std::convert::TryInto;
use std::net::Ipv4Addr;

use crate::utils::{self, Error, Result};

mod options_decoding;
mod options_encoding;

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

pub struct Message {
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
            ciaddr: Ipv4Addr::from(raw.ciaddr),
            yiaddr: Ipv4Addr::from(raw.yiaddr),
            siaddr: Ipv4Addr::from(raw.siaddr),
            giaddr: Ipv4Addr::from(raw.giaddr),
            options: MessageOptions::decode(&raw.sname, &raw.file, &raw.options)?,
        })
    }

    pub fn decode(buf: &[u8]) -> Result<Message> {
        let raw = RawMessage::decode(buf)?;
        Ok(Message::from_raw(&raw)?)
    }

    fn to_raw(&self, hardware_address: [u8; 16]) -> Result<RawMessage> {
        let mut msg = RawMessage {
            op: self.op as u8,
            htype: self.htype,
            hlen: self.hlen,
            hops: 0,
            xid: self.xid.0,
            secs: 0,
            flags: self.broadcast as u16,
            ciaddr: self.ciaddr.octets(),
            yiaddr: self.yiaddr.octets(),
            siaddr: self.siaddr.octets(),
            giaddr: self.giaddr.octets(),
            chaddr: hardware_address,
            sname: [0; RawMessage::SNAME_SIZE],
            file: [0; RawMessage::FILE_SIZE],
            options: [0; RawMessage::MAX_OPTIONS_SIZE],
        };
        self.options.encode(&mut msg.options)?;
        Ok(msg)
    }

    pub fn encode(&self, buf: &mut [u8], hardware_address: [u8; 16]) -> Result<()> {
        let raw = self.to_raw(hardware_address)?;
        Ok(raw.encode(buf)?)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MessageOp {
    Request = 1,
    Reply = 2,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct TransactionID(u32);

#[derive(Debug, Eq, PartialEq)]
pub struct MessageOptions {
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

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum MessageOption {
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
    fn empty(message_type: MessageType) -> Self {
        Self {
            subnet_mask: None,
            router: None,
            domain_name_server: None,
            host_name: None,
            requested_ip_addr: None,
            lease_time: None,
            option_overload: None,
            message_type,
            server_identifier: None,
            parameter_request_list: None,
            message: None,
            renewal_time: None,
            rebinding_time: None,
            client_identifier: None,
        }
    }

    fn decode(sname: &[u8], file: &[u8], raw_options: &[u8]) -> Result<Self> {
        options_decoding::decode_options(sname, file, raw_options)
    }

    fn encode(&self, buf: &mut [u8; RawMessage::MAX_OPTIONS_SIZE]) -> Result<()> {
        options_encoding::encode_options(buf, self)
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum OptionOverload {
    File = 1,
    Sname = 2,
    FileAndSname = 3,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum MessageType {
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
        msg.encode(&mut encoded).unwrap();
        for (k, &v) in encoded.iter().enumerate() {
            assert_eq!(buf[k], v);
        }
    }

    #[test]
    fn options_decode_simple() {
        let mut raw_options = [0; RawMessage::MAX_OPTIONS_SIZE]; // Missing magic cookie
        assert_eq!(
            MessageOptions::decode(&[], &[], &raw_options),
            Err(Error::OptionDecodingFailed),
        );

        raw_options[0] = 99;
        raw_options[1] = 130;
        raw_options[2] = 83;
        raw_options[3] = 99; // Has magic cookie, but now missing end
        assert_eq!(
            MessageOptions::decode(&[], &[], &raw_options),
            Err(Error::OptionDecodingFailed),
        );

        raw_options[4] = 255; // Has end, but now missing message type
        assert_eq!(
            MessageOptions::decode(&[], &[], &raw_options),
            Err(Error::OptionDecodingFailed),
        );

        raw_options[4] = 53;
        raw_options[5] = 1;
        raw_options[6] = 2; // Has message type DHCPOFFER, but now missing end
        assert_eq!(
            MessageOptions::decode(&[], &[], &raw_options),
            Err(Error::OptionDecodingFailed),
        );

        raw_options[7] = 255; // Now also has end
        assert_eq!(
            MessageOptions::decode(&[], &[], &raw_options),
            Ok(MessageOptions::empty(MessageType::Offer)),
        );
    }

    #[test]
    fn options_decode_encode_discover() {
        let raw_options = [
            0x63, 0x82, 0x53, 0x63, // Magic cookie
            0x35, 0x01, 0x01, // Message type: DHCPDISCOVER
            0x0c, 0x05, 0x64, 0x6f, 0x67, 0x67, 0x73, // Hostname: doggs
            0x37, 0x0d, 0x01, 0x1c, 0x02, 0x03, 0x0f, 0x06, 0x77, 0x0c, 0x2c, 0x2f, 0x1a, 0x79, 0x2a,
            // Parameter request list, including some options unknown to this implementation
            0xff, // End
        ];
        let mut expected_options = MessageOptions::empty(MessageType::Discover);
        expected_options.host_name = Some(Vec::from(b"doggs" as &[u8]));
        expected_options.parameter_request_list = Some(vec![
            MessageOption::SubnetMask,
            MessageOption::Router,
            MessageOption::DomainNameServer,
            MessageOption::HostName,
        ]);
        assert_eq!(
            &MessageOptions::decode(&[], &[], &raw_options).unwrap(),
            &expected_options,
        );

        let mut encoded_options = [0; RawMessage::MAX_OPTIONS_SIZE];
        expected_options.encode(&mut encoded_options).unwrap();
        let mut expected_encoded_options = [0; RawMessage::MAX_OPTIONS_SIZE];
        utils::copy_slice(&mut expected_encoded_options, &[
            0x63, 0x82, 0x53, 0x63, // Magic cookie
            0x0c, 0x05, 0x64, 0x6f, 0x67, 0x67, 0x73, // Hostname: doggs
            0x35, 0x01, 0x01, // Message type: DHCPDISCOVER
            0x37, 0x04, 0x01, 0x03, 0x06, 0x0c,
            // Parameter request list
            0xff, // End
        ]);
        assert_equal_bytes(&encoded_options, &expected_encoded_options);
    }

    #[test]
    fn options_decode_encode_offer() {
        let raw_options = [
            0x63, 0x82, 0x53, 0x63, // Magic cookie
            0x35, 0x01, 0x02, // Message type: DHCPOFFER
            0x36, 0x04, 0x00, 0x00, 0x00, 0x02, // Server identifier: 2
            0x33, 0x04, 0x00, 0x01, 0x51, 0x80, // Lease time: 86400s (1 day)
            0x3a, 0x04, 0x00, 0x00, 0xa8, 0xc0, // Renewal time: 43200s (12 hours)
            0x3b, 0x04, 0x00, 0x01, 0x27, 0x50, // Rebinding time: 75600s (21 hours)
            0x01, 0x04, 0xff, 0xff, 0xff, 0x00, // Subnet mask: 255.255.255.0
            0x1c, 0x04, 0xc0, 0xa8, 0x01, 0xff, // Broadcast address: 192.168.1.255
            0x06, 0x04, 0xc0, 0xa8, 0x01, 0x01, // Domain name server: 192.168.1.1
            0x03, 0x04, 0xc0, 0xa8, 0x01, 0x01, // Router: 192.168.1.1
            0xff // End
        ];
        let mut expected_options = MessageOptions::empty(MessageType::Offer);
        expected_options.server_identifier = Some(2);
        expected_options.lease_time = Some(86400);
        expected_options.renewal_time = Some(43200);
        expected_options.rebinding_time = Some(75600);
        expected_options.subnet_mask = Some(Ipv4Addr::new(255, 255, 255, 0));
        expected_options.domain_name_server = Some(vec![Ipv4Addr::new(192, 168, 1, 1)]);
        expected_options.router = Some(vec![Ipv4Addr::new(192, 168, 1, 1)]);
        assert_eq!(
            &MessageOptions::decode(&[], &[], &raw_options).unwrap(),
            &expected_options,
        );

        let mut encoded_options = [0; RawMessage::MAX_OPTIONS_SIZE];
        expected_options.encode(&mut encoded_options).unwrap();
        let mut expected_encoded_options = [0; RawMessage::MAX_OPTIONS_SIZE];
        utils::copy_slice(&mut expected_encoded_options, &[
            0x63, 0x82, 0x53, 0x63, // Magic cookie
            0x01, 0x04, 0xff, 0xff, 0xff, 0x00, // Subnet mask: 255.255.255.0
            0x03, 0x04, 0xc0, 0xa8, 0x01, 0x01, // Router: 192.168.1.1
            0x06, 0x04, 0xc0, 0xa8, 0x01, 0x01, // Domain name server: 192.168.1.1
            0x33, 0x04, 0x00, 0x01, 0x51, 0x80, // Lease time: 86400s (1 day)
            0x35, 0x01, 0x02, // Message type: DHCPOFFER
            0x36, 0x04, 0x00, 0x00, 0x00, 0x02, // Server identifier: 2
            0x3a, 0x04, 0x00, 0x00, 0xa8, 0xc0, // Renewal time: 43200s (12 hours)
            0x3b, 0x04, 0x00, 0x01, 0x27, 0x50, // Rebinding time: 75600s (21 hours)
            0xff // End
        ]);
        assert_equal_bytes(&encoded_options, &expected_encoded_options);
    }

    fn assert_equal_bytes(a: &[u8], b: &[u8]) {
        for ((k1, v1), (k2, v2)) in a
            .iter()
            .enumerate()
            .zip(b.iter().enumerate()) {
            assert_eq!((k1, v1), (k2, v2));
        }
    }
}
