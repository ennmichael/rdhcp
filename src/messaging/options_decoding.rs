use std::net::Ipv4Addr;

use itertools::Itertools;

use crate::messaging::utils::{Error, Result};

use super::{MessageOption, MessageOptions, MessageType};

pub fn decode_options(
    _sname: &[u8],
    _file: &[u8],
    raw_options: &[u8],
) -> Result<MessageOptions> {
    let mut options = MessageOptions::empty(MessageType::Discover);
    let mut seen_type = false;
    let mut seen_end = false;
    let mut raw_options = raw_options.iter();

    check_magic_cookie(&mut raw_options)?;

    loop {
        use MessageOption::*;

        let raw_option = next_byte(&mut raw_options)?;
        match decode_raw_option(raw_option) {
            Some(Pad) => continue,
            Some(End) if seen_end => return Err(Error::OptionDecodingFailed),
            Some(End) => {
                seen_end = true;
                break;
            }
            Some(SubnetMask) =>
                options.subnet_mask = Some(decode_ip_addr(&mut raw_options)?),
            Some(Router) =>
                options.router = Some(decode_ip_addrs(&mut raw_options)?),
            Some(DomainNameServer) =>
                options.domain_name_server = Some(decode_ip_addrs(&mut raw_options)?),
            Some(HostName) =>
                options.host_name = Some(decode_byte_string(&mut raw_options)?),
            Some(RequestedIpAddr) =>
                options.requested_ip_addr = Some(decode_ip_addr(&mut raw_options)?),
            Some(LeaseTime) =>
                options.lease_time = Some(decode_u32(&mut raw_options)?),
            Some(OptionOverload) =>
                unimplemented!(),
            Some(MessageType) if seen_type => return Err(Error::OptionDecodingFailed),
            Some(MessageType) => {
                seen_type = true;
                options.message_type = decode_message_type(&mut raw_options)?;
            }
            Some(ServerIdentifier) =>
                options.server_identifier = Some(decode_u32(&mut raw_options)?),
            Some(ParameterRequestList) => options.parameter_request_list =
                Some(decode_parameter_request_list(&mut raw_options)?),
            Some(Message) =>
                options.message = Some(decode_byte_string(&mut raw_options)?),
            Some(RenewalTime) =>
                options.renewal_time = Some(decode_u32(&mut raw_options)?),
            Some(RebindingTime) =>
                options.rebinding_time = Some(decode_u32(&mut raw_options)?),
            Some(ClientIdentifier) =>
                options.client_identifier = Some(decode_byte_string(&mut raw_options)?),
            None => skip_option_body(&mut raw_options)?,
        }
    }

    if !seen_type || !seen_end {
        return Err(Error::OptionDecodingFailed);
    }

    if options.option_overload.is_some() {
        unimplemented!() // TODO Implement this properly
    }

    Ok(options)
}

fn check_magic_cookie<'a>(raw_options: &mut impl Iterator<Item=&'a u8>) -> Result<()> {
    let cookie = [
        next_byte(raw_options)?, next_byte(raw_options)?,
        next_byte(raw_options)?, next_byte(raw_options)?,
    ];

    if cookie == [99, 130, 83, 99] {
        Ok(())
    } else {
        Err(Error::OptionDecodingFailed)
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
    let length = next_byte(raw_options)?;
    for _ in 0..length {
        next_byte(raw_options)?;
    }
    Ok(())
}

fn decode_ip_addr<'a>(raw_options: &mut impl Iterator<Item=&'a u8>) -> Result<Ipv4Addr> {
    let length = next_byte(raw_options)?;
    if length != 4 {
        Err(Error::OptionDecodingFailed)
    } else {
        let a = next_byte(raw_options)?;
        let b = next_byte(raw_options)?;
        let c = next_byte(raw_options)?;
        let d = next_byte(raw_options)?;
        Ok(Ipv4Addr::new(a, b, c, d))
    }
}

fn decode_ip_addrs<'a>(raw_options: &mut impl Iterator<Item=&'a u8>) -> Result<Vec<Ipv4Addr>> {
    let length = next_byte(raw_options)?;
    if length % 4 != 0 {
        Err(Error::OptionDecodingFailed)
    } else {
        raw_options
            .take(length as usize)
            .chunks(4)
            .into_iter()
            .map(|mut ip_chunks| {
                let a = next_byte(&mut ip_chunks)?;
                let b = next_byte(&mut ip_chunks)?;
                let c = next_byte(&mut ip_chunks)?;
                let d = next_byte(&mut ip_chunks)?;
                Ok(Ipv4Addr::new(a, b, c, d))
            })
            .collect()
    }
}

fn decode_byte_string<'a>(raw_options: &mut impl Iterator<Item=&'a u8>) -> Result<Vec<u8>> {
    let length = next_byte(raw_options)? as usize;
    let result: Vec<u8> = raw_options.take(length).map(|x| *x).collect();
    if result.len() == length {
        Ok(result)
    } else {
        Err(Error::OptionDecodingFailed)
    }
}

fn decode_u32<'a>(raw_options: &mut impl Iterator<Item=&'a u8>) -> Result<u32> {
    let length = next_byte(raw_options)?;
    if length != 4 {
        Err(Error::OptionDecodingFailed)
    } else {
        Ok(u32::from_be_bytes([
            next_byte(raw_options)?,
            next_byte(raw_options)?,
            next_byte(raw_options)?,
            next_byte(raw_options)?,
        ]))
    }
}

fn decode_message_type<'a>(raw_options: &mut impl Iterator<Item=&'a u8>) -> Result<MessageType> {
    let length = *raw_options.next().ok_or(Error::OptionDecodingFailed)? as usize;
    if length == 0 {
        Err(Error::OptionDecodingFailed)
    } else {
        const DISCOVER: u8 = MessageType::Discover as u8;
        const OFFER: u8 = MessageType::Offer as u8;
        const REQUEST: u8 = MessageType::Request as u8;
        const DECLINE: u8 = MessageType::Decline as u8;
        const ACK: u8 = MessageType::ACK as u8;
        const NAK: u8 = MessageType::NAK as u8;
        const RELEASE: u8 = MessageType::Release as u8;

        match next_byte(raw_options)? {
            DISCOVER => Ok(MessageType::Discover),
            OFFER => Ok(MessageType::Offer),
            REQUEST => Ok(MessageType::Request),
            DECLINE => Ok(MessageType::Decline),
            ACK => Ok(MessageType::ACK),
            NAK => Ok(MessageType::NAK),
            RELEASE => Ok(MessageType::Release),
            _ => Err(Error::OptionDecodingFailed),
        }
    }
}

fn decode_parameter_request_list<'a>(
    raw_options: &mut impl Iterator<Item=&'a u8>
) -> Result<Vec<MessageOption>> {
    let length = next_byte(raw_options)? as usize;
    Ok(raw_options
        .take(length)
        .filter_map(|&o| decode_raw_option(o))
        .collect()
    )
}

fn next_byte<'a>(raw_options: &mut impl Iterator<Item=&'a u8>) -> Result<u8> {
    Ok(*raw_options.next().ok_or(Error::OptionDecodingFailed)?)
}
