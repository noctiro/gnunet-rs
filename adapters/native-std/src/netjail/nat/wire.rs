//! Linux nfnetlink and nftables messages for the single TESTING rule.

use super::super::Ipv4Prefix;
use crate::linux_netlink::{Header, aligned};
use std::{io, net::Ipv4Addr};

const NFGEN_LEN: usize = 4;
const NFTABLES: u16 = 10;
const BATCH_BEGIN: u16 = libc::NLMSG_MIN_TYPE as u16;
const BATCH_END: u16 = BATCH_BEGIN + 1;
const NEW_TABLE: u16 = NFTABLES << 8;
const GET_TABLE: u16 = NEW_TABLE + 1;
const NEW_CHAIN: u16 = NEW_TABLE + 3;
const NEW_RULE: u16 = NEW_TABLE + 6;

const TABLE_NAME: &[u8] = b"nat\0";
const CHAIN_NAME: &[u8] = b"postrouting\0";
const NFTA_TABLE_NAME: u16 = 1;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
const NFTA_DATA_VALUE: u16 = 1;

const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;
const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
const IPV4_SOURCE_OFFSET: u32 = 12;
const IPV4_ADDRESS_LEN: u32 = 4;
const NFT_REG_1: u32 = 1;
const NFTA_BITWISE_SREG: u16 = 1;
const NFTA_BITWISE_DREG: u16 = 2;
const NFTA_BITWISE_LEN: u16 = 3;
const NFTA_BITWISE_MASK: u16 = 4;
const NFTA_BITWISE_XOR: u16 = 5;
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFT_CMP_EQ: u32 = 0;

const FLAG_REQUEST: u16 = libc::NLM_F_REQUEST as u16;
const FLAG_ACK: u16 = libc::NLM_F_ACK as u16;
const FLAG_CREATE_EXCLUSIVE: u16 = (libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16;
const FLAG_NESTED: u16 = 1 << 15;
const NLA_HEADER_LEN: usize = 4;
const AF_IPV4: u8 = libc::NFPROTO_IPV4 as u8;

#[derive(Clone, Copy)]
struct Request {
    kind: u16,
    sequence: u32,
    flags: u16,
}

const BEGIN: Request = Request {
    kind: BATCH_BEGIN,
    sequence: 1,
    flags: FLAG_REQUEST,
};
const CREATE_TABLE: Request = Request {
    kind: NEW_TABLE,
    sequence: 2,
    flags: FLAG_REQUEST | FLAG_ACK | FLAG_CREATE_EXCLUSIVE,
};
const CREATE_CHAIN: Request = Request {
    kind: NEW_CHAIN,
    sequence: 3,
    flags: FLAG_REQUEST | FLAG_ACK | FLAG_CREATE_EXCLUSIVE,
};
const CREATE_RULE: Request = Request {
    kind: NEW_RULE,
    sequence: 4,
    flags: FLAG_REQUEST | FLAG_ACK | FLAG_CREATE_EXCLUSIVE,
};
const END: Request = Request {
    kind: BATCH_END,
    sequence: 5,
    flags: FLAG_REQUEST,
};
const READ_TABLE: Request = Request {
    kind: GET_TABLE,
    sequence: 6,
    flags: FLAG_REQUEST,
};
const BATCH_ACKS: [Request; 3] = [CREATE_TABLE, CREATE_CHAIN, CREATE_RULE];

pub(super) fn create_masquerade(
    port: u32,
    address: Ipv4Addr,
    prefix: Ipv4Prefix,
) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(512);
    let mask = u32::MAX
        .checked_shl(u32::from(32 - prefix.get()))
        .unwrap_or(0);
    let network = address.to_bits() & mask;
    append_message(&mut output, BEGIN, port, |_| Ok(()))?;
    append_message(&mut output, CREATE_TABLE, port, |attributes| {
        attribute(attributes, NFTA_TABLE_NAME, TABLE_NAME)
    })?;
    append_message(&mut output, CREATE_CHAIN, port, |attributes| {
        attribute(attributes, NFTA_CHAIN_TABLE, TABLE_NAME)?;
        attribute(attributes, NFTA_CHAIN_NAME, CHAIN_NAME)?;
        attribute(attributes, NFTA_CHAIN_TYPE, b"nat\0")?;
        nested(attributes, NFTA_CHAIN_HOOK, |hook| {
            attribute_u32(hook, NFTA_HOOK_HOOKNUM, libc::NF_INET_POST_ROUTING as u32)?;
            attribute_u32(hook, NFTA_HOOK_PRIORITY, 0)
        })
    })?;
    append_message(&mut output, CREATE_RULE, port, |attributes| {
        attribute(attributes, NFTA_RULE_TABLE, TABLE_NAME)?;
        attribute(attributes, NFTA_RULE_CHAIN, CHAIN_NAME)?;
        nested(attributes, NFTA_RULE_EXPRESSIONS, |expressions| {
            expression(expressions, b"payload\0", |fields| {
                attribute_u32(fields, NFTA_PAYLOAD_DREG, NFT_REG_1)?;
                attribute_u32(fields, NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER)?;
                attribute_u32(fields, NFTA_PAYLOAD_OFFSET, IPV4_SOURCE_OFFSET)?;
                attribute_u32(fields, NFTA_PAYLOAD_LEN, IPV4_ADDRESS_LEN)
            })?;
            expression(expressions, b"bitwise\0", |fields| {
                attribute_u32(fields, NFTA_BITWISE_SREG, NFT_REG_1)?;
                attribute_u32(fields, NFTA_BITWISE_DREG, NFT_REG_1)?;
                attribute_u32(fields, NFTA_BITWISE_LEN, IPV4_ADDRESS_LEN)?;
                data_value(fields, NFTA_BITWISE_MASK, mask)?;
                data_value(fields, NFTA_BITWISE_XOR, 0)
            })?;
            expression(expressions, b"cmp\0", |fields| {
                attribute_u32(fields, NFTA_CMP_SREG, NFT_REG_1)?;
                attribute_u32(fields, NFTA_CMP_OP, NFT_CMP_EQ)?;
                data_value(fields, NFTA_CMP_DATA, network)
            })?;
            expression(expressions, b"counter\0", |_| Ok(()))?;
            expression(expressions, b"masq\0", |_| Ok(()))
        })
    })?;
    append_message(&mut output, END, port, |_| Ok(()))?;
    Ok(output)
}

pub(super) fn get_table(port: u32) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(32);
    append_message(&mut output, READ_TABLE, port, |attributes| {
        attribute(attributes, NFTA_TABLE_NAME, TABLE_NAME)
    })?;
    Ok(output)
}

fn append_message(
    output: &mut Vec<u8>,
    request: Request,
    port: u32,
    attributes: impl FnOnce(&mut Vec<u8>) -> io::Result<()>,
) -> io::Result<()> {
    let start = output.len();
    output.resize(start + Header::SIZE, 0);
    let batch = matches!(request.kind, BATCH_BEGIN | BATCH_END);
    let family = if batch { 0 } else { AF_IPV4 };
    let resource = if batch { NFTABLES } else { 0 };
    output.extend_from_slice(&[family, 0]);
    output.extend_from_slice(&resource.to_be_bytes());
    attributes(output)?;
    let length = u32::try_from(output.len() - start).map_err(|_| malformed())?;
    Header {
        length,
        kind: request.kind,
        flags: request.flags,
        sequence: request.sequence,
        port,
    }
    .write(&mut output[start..start + Header::SIZE])
}

fn expression(
    output: &mut Vec<u8>,
    name: &[u8],
    fields: impl FnOnce(&mut Vec<u8>) -> io::Result<()>,
) -> io::Result<()> {
    nested(output, NFTA_LIST_ELEM, |element| {
        attribute(element, NFTA_EXPR_NAME, name)?;
        nested(element, NFTA_EXPR_DATA, fields)
    })
}

fn data_value(output: &mut Vec<u8>, kind: u16, value: u32) -> io::Result<()> {
    nested(output, kind, |data| {
        attribute_u32(data, NFTA_DATA_VALUE, value)
    })
}

fn attribute_u32(output: &mut Vec<u8>, kind: u16, value: u32) -> io::Result<()> {
    attribute(output, kind, &value.to_be_bytes())
}

fn attribute(output: &mut Vec<u8>, kind: u16, value: &[u8]) -> io::Result<()> {
    append_attribute(output, kind, |output| {
        output.extend_from_slice(value);
        Ok(())
    })
}

fn nested(
    output: &mut Vec<u8>,
    kind: u16,
    fields: impl FnOnce(&mut Vec<u8>) -> io::Result<()>,
) -> io::Result<()> {
    append_attribute(output, kind | FLAG_NESTED, fields)
}

fn append_attribute(
    output: &mut Vec<u8>,
    kind: u16,
    value: impl FnOnce(&mut Vec<u8>) -> io::Result<()>,
) -> io::Result<()> {
    let start = output.len();
    output.extend_from_slice(&[0; 2]);
    output.extend_from_slice(&kind.to_ne_bytes());
    value(output)?;
    let length = u16::try_from(output.len() - start).map_err(|_| malformed())?;
    output[start..start + 2].copy_from_slice(&length.to_ne_bytes());
    output.resize(aligned(output.len())?, 0);
    Ok(())
}

pub(super) struct BatchAck {
    port: u32,
    received: [bool; BATCH_ACKS.len()],
}

impl BatchAck {
    pub(super) fn new(port: u32) -> Self {
        Self {
            port,
            received: [false; BATCH_ACKS.len()],
        }
    }

    pub(super) fn accept(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() {
            return Err(malformed());
        }
        while !bytes.is_empty() {
            let (header, data) = Header::take(&mut bytes)?;
            if header.sequence == BEGIN.sequence {
                // Linux reports transaction-wide failures at the opening
                // marker even though it does not carry an ACK request.
                ack(header, data, self.port, BEGIN)?;
                return Err(malformed());
            }
            let index = BATCH_ACKS
                .iter()
                .position(|request| request.sequence == header.sequence)
                .ok_or_else(malformed)?;
            ack(header, data, self.port, BATCH_ACKS[index])?;
            if self.received[index] {
                return Err(malformed());
            }
            self.received[index] = true;
        }
        Ok(())
    }

    pub(super) fn is_complete(&self) -> bool {
        self.received.iter().all(|acknowledged| *acknowledged)
    }
}

pub(super) fn confirm_table(port: u32, mut bytes: &[u8]) -> io::Result<()> {
    let (header, body) = Header::take(&mut bytes)?;
    if header.kind == libc::NLMSG_ERROR as u16 {
        ack(header, body, port, READ_TABLE)?;
        return Err(malformed());
    }
    if header.kind != NEW_TABLE
        || header.sequence != READ_TABLE.sequence
        || header.port != port
        || !bytes.is_empty()
        || body
            .first_chunk::<NFGEN_LEN>()
            .is_none_or(|header| header[..2] != [AF_IPV4, 0])
    {
        return Err(malformed());
    }

    let mut attributes = &body[NFGEN_LEN..];
    let mut found = false;
    while !attributes.is_empty() {
        let (kind, value) = take_attribute(&mut attributes)?;
        if kind == NFTA_TABLE_NAME {
            if found || value != TABLE_NAME {
                return Err(malformed());
            }
            found = true;
        }
    }
    if found { Ok(()) } else { Err(malformed()) }
}

fn take_attribute<'a>(input: &mut &'a [u8]) -> io::Result<(u16, &'a [u8])> {
    let head = input
        .first_chunk::<NLA_HEADER_LEN>()
        .ok_or_else(malformed)?;
    let length = usize::from(u16::from_ne_bytes([head[0], head[1]]));
    let kind = u16::from_ne_bytes([head[2], head[3]]);
    let value = input.get(NLA_HEADER_LEN..length).ok_or_else(malformed)?;
    *input = input.get(aligned(length)?..).ok_or_else(malformed)?;
    Ok((kind, value))
}

fn ack(header: Header, body: &[u8], port: u32, request: Request) -> io::Result<()> {
    if header.kind != libc::NLMSG_ERROR as u16
        || header.port != port
        || header.sequence != request.sequence
    {
        return Err(malformed());
    }
    let (status, original) = body.split_first_chunk::<4>().ok_or_else(malformed)?;
    let echoed = Header::read(original)?;
    if echoed.kind != request.kind
        || echoed.sequence != request.sequence
        || echoed.port != port
        || echoed.flags != request.flags
    {
        return Err(malformed());
    }
    match i32::from_ne_bytes(*status) {
        0 => Ok(()),
        status if status < 0 => Err(io::Error::from_raw_os_error(
            status.checked_neg().ok_or_else(malformed)?,
        )),
        _ => Err(malformed()),
    }
}

fn malformed() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid nftables transaction message",
    )
}

#[cfg(test)]
mod tests;
