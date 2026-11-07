//! Full original DNS response inspection and one owned serialized GNS set.
use super::*;
use crate::core::conversion::{self, Buffers, Expected, Response, Slot, Storage};
use gnunet_dns::{Arena, Header, Name, Query, Record};
use gnunet_gnsrecord::RecordData;

pub(super) struct Records {
    pub bytes: Zeroizing<Vec<u8>>,
    pub count: u16,
}
impl Records {
    pub fn one(record: RecordData<'_>) -> Result<Self, Error> {
        Self::from_slice(&[record])
    }
    fn from_slice(records: &[RecordData<'_>]) -> Result<Self, Error> {
        let length = gnunet_gnsrecord::serialized_len(records)?;
        if length > 65535 {
            return Err(Fault::TooLarge.into());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(length)
            .map_err(|_| Fault::Capacity)?;
        bytes.resize(length, 0);
        gnunet_gnsrecord::serialize(records, &mut bytes)?;
        Ok(Self {
            bytes,
            count: u16::try_from(records.len()).map_err(|_| Fault::TooLarge)?,
        })
    }
    pub fn set(
        &self,
        label: &[u8],
        limits: namestore::Limits,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let set = namestore::ipc::StoreSet {
            label: namestore::ipc::CString::new(label)?,
            records: namestore::ipc::Records::new(&self.bytes, self.count)?,
            reserved: 0,
        };
        let length = namestore::ipc::encoded_sets_len(&[set])?;
        let total = namestore::ipc::STORE_PREFIX
            .checked_add(identity::ipc::KEY_LEN)
            .and_then(|prefix| prefix.checked_add(length))
            .ok_or(Fault::Overflow)?;
        if total > limits.frame_bytes || total > limits.source_bytes {
            return Err(Fault::TooLarge.into());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(length)
            .map_err(|_| Fault::Capacity)?;
        bytes.resize(length, 0);
        namestore::ipc::encode_sets(&[set], &mut bytes)?;
        Ok(bytes)
    }
}
pub(super) enum Reply {
    NeedTcp,
    Answer {
        records: Records,
        summary: conversion::Summary,
    },
}
pub(super) struct Inspection {
    pub expired: usize,
    pub result: Result<Reply, Error>,
}
/// One reusable payload/name arena. Typed parser object slots borrow it only
/// synchronously and are allocated fallibly under an explicit per-packet bound.
/// No typed packet/borrow is retained across the next native receive or await.
pub(super) struct Workspace {
    arena: Vec<u8>,
    output: Zeroizing<Vec<u8>>,
    slots: Vec<Slot>,
    name: [u8; 1024],
    text: [u8; 1024],
    records: usize,
    dns_limits: gnunet_dns::Limits,
}
impl Workspace {
    pub fn new(limits: Limits, records_per_set: usize) -> Result<Self, Error> {
        let mut arena = Vec::new();
        arena
            .try_reserve_exact(limits.dns_arena_bytes)
            .map_err(|_| Fault::Capacity)?;
        arena.resize(limits.dns_arena_bytes, 0);
        let mut output = Zeroizing::new(Vec::new());
        output
            .try_reserve_exact(limits.namestore.frame_bytes)
            .map_err(|_| Fault::Capacity)?;
        output.resize(limits.namestore.frame_bytes, 0);
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(records_per_set)
            .map_err(|_| Fault::Capacity)?;
        slots.resize(records_per_set, Slot::EMPTY);
        Ok(Self {
            arena,
            output,
            slots,
            name: [0; 1024],
            text: [0; 1024],
            records: limits.dns_records,
            dns_limits: gnunet_dns::Limits {
                maximum_packet_bytes: limits.response_bytes,
                maximum_queries: 1,
                maximum_records: limits.dns_records,
                ..gnunet_dns::Limits::DNS
            },
        })
    }
    pub fn inspect(
        &mut self,
        bytes: &[u8],
        original_query: &[u8],
        hostname: &str,
        now: gnunet_wire::official::AbsoluteTime,
        policy: core::Policy,
        names: &mut Names,
    ) -> Inspection {
        let mut expired = 0;
        let result = (|| -> Result<Reply, Error> {
            if original_query.len() < 17 {
                return Err(Fault::Malformed.into());
            }
            let header = Header::decode(original_query)?;
            let name = Name::from_wire(&original_query[12..original_query.len() - 4])?;
            let query = Query {
                name,
                kind: gnunet_dns::Type::NS,
                class: gnunet_dns::class::INTERNET,
            };
            let mut arena = Arena::new(&mut self.arena);
            let mut questions = [Query::EMPTY];
            let mut parsed = Vec::new();
            parsed
                .try_reserve_exact(self.records)
                .map_err(|_| Fault::Capacity)?;
            parsed.resize(self.records, Record::EMPTY);
            let response = conversion::inspect(
                bytes,
                Expected {
                    id: header.id,
                    question: query,
                },
                now,
                Storage {
                    arena: &mut arena,
                    questions: &mut questions,
                    records: &mut parsed,
                },
                self.dns_limits,
            )
            .map_err(Error::Conversion)?;
            let Response::Answer(answer) = response else {
                return Ok(Reply::NeedTcp);
            };
            expired = answer.expired_matching_records(now);
            let backend = names.backend();
            let converted = conversion::convert(
                &answer,
                hostname,
                now,
                conversion::Policy {
                    minimum_expiration: policy.minimum_expiration,
                    empty_refresh: policy.empty_refresh,
                },
                Buffers {
                    slots: &mut self.slots,
                    bytes: &mut self.output,
                    name: &mut self.name,
                    text: &mut self.text,
                    idna: &backend,
                    maximum_work: 64 * 1024 * 1024,
                },
            )
            .map_err(Error::Conversion)?;
            let summary = converted.summary();
            let mut rows = Vec::new();
            rows.try_reserve_exact(summary.records)
                .map_err(|_| Fault::Capacity)?;
            rows.extend(converted.records());
            let records = Records::from_slice(&rows)?;
            Ok(Reply::Answer { records, summary })
        })();
        Inspection { expired, result }
    }
}
/// One immutable original NS/IN wire query. No raw integer key substitutes for
/// the actual Core job or native request/source binding retained by Runtime.
pub(super) fn query(hostname: &str, id: [u8; 2]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut name_bytes = [0; 256];
    let mut arena = Arena::new(&mut name_bytes);
    let name = Name::from_dotted(hostname.as_bytes(), &mut arena)?;
    let question = Query {
        name,
        kind: gnunet_dns::Type::NS,
        class: gnunet_dns::class::INTERNET,
    };
    let questions = [question];
    let packet = gnunet_dns::Packet::new(id, 0, &questions, &[], &[], &[]);
    let length = packet.encoded_len()?;
    if length > 512 {
        return Err(Fault::TooLarge.into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Fault::Capacity)?;
    bytes.resize(length, 0);
    packet.encode(gnunet_wire::official::AbsoluteTime::UNIX_EPOCH, &mut bytes)?;
    Ok(bytes)
}
