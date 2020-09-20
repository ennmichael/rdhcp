use std::result;
use std::net::Ipv4Addr;
use std::convert::TryInto;
use crate::utils;

type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
enum Error {
    MessageDecoding(String),
}

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
    sname: [u8; 64],
    file: [u8; 128],
    options: [u8; Self::MAX_OPTIONS_SIZE],
}

impl RawMessage {
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
    option_overload: bool,
    options: MessageOptions,
}

impl Message {
    fn from_raw(raw: &RawMessage) -> Message {
        unimplemented!()
    }

    fn decode(buf: &[u8]) -> Result<Message> {
        let raw = RawMessage::decode(buf)?;
        Ok(Message::from_raw(&raw))
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

// A bunch of Option<T> fields
struct MessageOptions {}

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
}
