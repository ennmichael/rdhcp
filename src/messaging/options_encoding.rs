use std::convert::TryInto;
use std::net::Ipv4Addr;

use crate::errors::{Error, Result};
use crate::messaging::{MessageOption, MessageOptions};

pub fn encode_options(buf: &mut [u8], options: &MessageOptions) -> Result<()> {
    use MessageOption::*;

    let mut buf = buf.iter_mut();

    write_magic_cookie(&mut buf)?;

    if let Some(subnet_mask) = options.subnet_mask {
        write_byte(&mut buf, SubnetMask as u8)?;
        encode_ip_addr(&mut buf, subnet_mask)?;
    }

    if let Some(router) = &options.router {
        write_byte(&mut buf, Router as u8)?;
        encode_ip_addrs(&mut buf, router)?;
    }

    if let Some(domain_name_server) = &options.domain_name_server {
        write_byte(&mut buf, DomainNameServer as u8)?;
        encode_ip_addrs(&mut buf, domain_name_server)?;
    }

    if let Some(host_name) = &options.host_name {
        write_byte(&mut buf, HostName as u8)?;
        encode_byte_string(&mut buf, host_name)?;
    }

    if let Some(requested_ip_addr) = options.requested_ip_addr {
        write_byte(&mut buf, RequestedIpAddr as u8)?;
        encode_ip_addr(&mut buf, requested_ip_addr)?;
    }

    if let Some(lease_time) = options.lease_time {
        write_byte(&mut buf, LeaseTime as u8)?;
        encode_u32(&mut buf, lease_time)?;
    }

    if let Some(option_overload) = options.option_overload {
        write_bytes(&mut buf, &[OptionOverload as u8, 1u8, option_overload as u8])?;
    }

    write_bytes(&mut buf, &[MessageType as u8, 1u8, options.message_type as u8])?;

    if let Some(server_identifier) = options.server_identifier {
        write_byte(&mut buf, ServerIdentifier as u8)?;
        encode_u32(&mut buf, server_identifier)?;
    }

    if let Some(parameter_request_list) = &options.parameter_request_list {
        write_byte(&mut buf, ParameterRequestList as u8)?;
        encode_parameter_request_list(&mut buf, parameter_request_list)?;
    }

    if let Some(message) = &options.message {
        write_byte(&mut buf, Message as u8)?;
        encode_byte_string(&mut buf, message)?;
    }

    if let Some(renewal_time) = options.renewal_time {
        write_byte(&mut buf, RenewalTime as u8)?;
        encode_u32(&mut buf, renewal_time)?;
    }

    if let Some(rebinding_time) = options.rebinding_time {
        write_byte(&mut buf, RebindingTime as u8)?;
        encode_u32(&mut buf, rebinding_time)?;
    }

    if let Some(client_identifier) = &options.client_identifier {
        write_byte(&mut buf, ClientIdentifier as u8)?;
        encode_byte_string(&mut buf, client_identifier)?;
    }

    write_byte(&mut buf, End as u8)?;

    Ok(())
}

fn write_magic_cookie<'a>(buf: &mut impl Iterator<Item=&'a mut u8>) -> Result<()> {
    write_bytes(buf, &[99, 130, 83, 99])
}

fn encode_ip_addr<'a>(buf: &mut impl Iterator<Item=&'a mut u8>, ip: Ipv4Addr) -> Result<()> {
    write_byte(buf, 4)?;
    write_bytes(buf, &ip.octets())
}

fn encode_ip_addrs<'a>(buf: &mut impl Iterator<Item=&'a mut u8>, ips: &[Ipv4Addr]) -> Result<()> {
    write_byte(buf, try_into(ips.len() * 4)?)?;
    for &ip in ips {
        write_bytes(buf, &ip.octets())?;
    }
    Ok(())
}

fn encode_byte_string<'a>(buf: &mut impl Iterator<Item=&'a mut u8>, bytes: &[u8]) -> Result<()> {
    write_byte(buf, try_into(bytes.len())?)?;
    write_bytes(buf, bytes)
}

fn encode_u32<'a>(buf: &mut impl Iterator<Item=&'a mut u8>, x: u32) -> Result<()> {
    write_byte(buf, 4)?;
    write_bytes(buf, &x.to_be_bytes())
}

fn encode_parameter_request_list<'a>(
    buf: &mut impl Iterator<Item=&'a mut u8>,
    parameter_request_list: &Vec<MessageOption>,
) -> Result<()> {
    let bytes: Vec<_> = parameter_request_list
        .iter()
        .map(|&p| p as u8)
        .collect();
    encode_byte_string(buf, &bytes)
}

fn write_byte<'a>(buf: &mut impl Iterator<Item=&'a mut u8>, byte: u8) -> Result<()> {
    *buf.next().ok_or(Error::OptionDecodingFailed)? = byte;
    Ok(())
}

fn write_bytes<'a>(buf: &mut impl Iterator<Item=&'a mut u8>, bytes: &[u8]) -> Result<()> {
    for &byte in bytes {
        write_byte(buf, byte)?;
    }
    Ok(())
}

fn try_into<T, U>(x: T) -> Result<U> where T: TryInto<U> {
    x.try_into().map_err(|_| Error::OptionEncodingFailed)
}
