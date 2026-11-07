use crate::{
    Context, Error, OwnedRequest, Response,
    output::{Json, bytes, copy, decoded, parse, service},
};
use gnunet_gnsrecord::{RecordData, RecordFlags, RecordType};
use gnunet_namestore_client_host::{Client, Outcome, Progress, Reply, ZoneIterator, ipc};
use gnunet_rest::route::Endpoint;
use gnunet_types::Error as Fault;
use std::future::poll_fn;
use tokio::time::Instant;
use zeroize::Zeroizing;
struct Set {
    name: Zeroizing<Vec<u8>>,
    records: Zeroizing<Vec<u8>>,
    count: u16,
}
impl Set {
    fn view(&self) -> Result<ipc::StoreSet<'_>, Error> {
        Ok(ipc::StoreSet {
            label: ipc::CString::new(&self.name)?,
            records: ipc::Records::new(&self.records, self.count)?,
            reserved: 0,
        })
    }
}
impl<I: gnunet_dns::Idna> Context<'_, I> {
    pub(crate) async fn namestore(
        &self,
        request: OwnedRequest,
        until: u64,
        hard: Instant,
    ) -> Result<Response, Error> {
        // The public NAMESTORE route chooses its zone from the first path
        // segment. A slash-bearing longer ego must never adopt this request.
        let split = request
            .suffix
            .iter()
            .position(|byte| *byte == b'/')
            .unwrap_or(request.suffix.len());
        if split == 0 {
            return Err(service(5002));
        }
        let directory = self.directory(hard).await?;
        let key = subject(&directory, &request.suffix[..split])?;
        let label = if split == request.suffix.len() {
            &[][..]
        } else {
            &request.suffix[split + 1..]
        };
        // GET/DELETE use the remaining label. POST/PUT/import choose their
        // record labels from the validated body, as the actual plugin does.
        if request.endpoint == Endpoint::Names {
            let filter = filter(&request, self.limits.bytes)?;
            let record_type = match request.query(b"record_type", self.limits.bytes)? {
                None => None,
                Some(text) => Some(
                    gnunet_gnsrecord_text::typename_to_number(
                        std::str::from_utf8(&text).map_err(|_| Fault::Malformed)?,
                    )
                    .ok_or(Fault::Unsupported)?,
                ),
            };
            if !label.is_empty() {
                let mut client = Client::new(
                    self.instances.namestore,
                    self.sources.namestore.duplicate()?,
                    self.limits.namestore,
                )?;
                let op = client.lookup(&key, label, filter, until)?;
                let reply = ns_reply(&mut client, op, hard).await?;
                let (actual, records) = match reply.view()? {
                    ipc::Response::Lookup {
                        label,
                        records,
                        found: 1,
                        ..
                    } => (label, records),
                    ipc::Response::Lookup { found: 0, .. } => return Err(service(5003)),
                    ipc::Response::Lookup { .. } => return Err(service(5006)),
                    _ => return Err(Fault::Malformed.into()),
                };
                let mut json = Json::new(self.limits.output_bytes)?;
                if !self.record_json(&mut json, actual.bytes(), records, record_type)? {
                    return Err(service(5003));
                }
                return Ok(Response::json(json.bytes));
            }
            let mut iterator = ZoneIterator::new(
                self.instances.namestore,
                self.sources.namestore.duplicate()?,
                Some(&key),
                filter,
                until,
                self.limits.namestore,
            )?;
            let mut json = Json::new(self.limits.output_bytes)?;
            json.raw(b"[")?;
            let mut emitted = 0;
            let mut seen = 0;
            loop {
                match poll_fn(|cx| iterator.poll(cx, Some(hard))).await? {
                    Progress::Record { reply, .. } => {
                        seen += 1;
                        if seen > self.limits.items {
                            return Err(Fault::Capacity.into());
                        }
                        let mut item = Json::new(self.limits.output_bytes)?;
                        match reply.view()? {
                            ipc::Response::Records { label, records, .. } => {
                                if self.record_json(
                                    &mut item,
                                    label.bytes(),
                                    records,
                                    record_type,
                                )? {
                                    if emitted != 0 {
                                        json.raw(b",")?
                                    }
                                    json.raw(&item.bytes)?;
                                    emitted += 1;
                                }
                            }
                            _ => return Err(Fault::Malformed.into()),
                        }
                        iterator.next(1, until)?;
                    }
                    Progress::Completed(c) => {
                        match c.outcome {
                            Outcome::Reply(reply) => {
                                if !matches!(reply.view()?, ipc::Response::End { .. }) {
                                    return Err(Fault::Malformed.into());
                                }
                            }
                            Outcome::Local { reason, submission } => {
                                return Err(Error::NamestoreRetired { reason, submission });
                            }
                        }
                        if emitted == 0 {
                            return Err(service(5005));
                        }
                        json.raw(b"]")?;
                        return Ok(Response::json(json.bytes));
                    }
                    Progress::Lost { cause, .. } => return Err(Error::NamestoreSource(cause)),
                    Progress::Unavailable(error) => return Err(Error::Native(error)),
                    Progress::ConnectRetry { error, .. } => return Err(Error::Io(error)),
                    Progress::Closed => return Err(Error::SourceLost),
                    Progress::WaitDeadline => return Err(Error::Deadline),
                    _ => {}
                }
            }
        }
        let mut sets = if request.endpoint == Endpoint::NameDelete {
            if label.is_empty() {
                return Err(service(5009));
            }
            let mut sets = Vec::new();
            sets.try_reserve_exact(1).map_err(|_| Fault::Capacity)?;
            sets.push(Set {
                name: copy(label)?,
                records: copy(&[])?,
                count: 0,
            });
            sets
        } else {
            parse(&request.body, self.limits.json, |root| {
                let mut sets = Vec::new();
                if request.endpoint == Endpoint::NameImport {
                    for value in root.elements()? {
                        if sets.len() >= self.limits.items {
                            return Err(Fault::Capacity.into());
                        }
                        sets.try_reserve(1).map_err(|_| Fault::Capacity)?;
                        sets.push(
                            self.input_set(gnunet_rest::contracts::RecordSet::parse(value)?)?,
                        );
                    }
                } else {
                    sets.try_reserve_exact(1).map_err(|_| Fault::Capacity)?;
                    sets.push(self.input_set(gnunet_rest::contracts::RecordSet::parse(root)?)?);
                }
                if sets.is_empty() {
                    return Err(service(5007));
                }
                Ok(sets)
            })?
        };
        let mut client = Client::new(
            self.instances.namestore,
            self.sources.namestore.duplicate()?,
            self.limits.namestore,
        )?;
        if request.endpoint == Endpoint::NameAppend {
            let first = sets.first_mut().ok_or(Fault::InvalidInput)?;
            let op = client.lookup(&key, &first.name, 0, until)?;
            let reply = ns_reply(&mut client, op, hard).await?;
            match reply.view()? {
                ipc::Response::Lookup {
                    found: 1, records, ..
                } => {
                    let count = first
                        .count
                        .checked_add(records.count())
                        .ok_or(Fault::Overflow)?;
                    if usize::from(count) > self.limits.items {
                        return Err(Fault::Capacity.into());
                    }
                    let mut merged = Json::new(self.limits.bytes)?;
                    merged.raw(records.records().record_bytes())?;
                    merged.raw(&first.records)?;
                    first.records = merged.bytes;
                    first.count = count;
                }
                ipc::Response::Lookup { found: 0, .. } => {}
                _ => return Err(service(5006)),
            }
        }
        // All sets must fit ONE actual STORE frame before any mutation is admitted.
        // Import never silently commits a prefix and returns an all-or-nothing claim.
        let mut encoded = Json::new(self.limits.bytes)?;
        for set in &sets {
            let view = set.view()?;
            let mut frame = bytes(view.encoded_len()?)?;
            view.encode(&mut frame)?;
            encoded.raw(&frame)?;
        }
        let count = u16::try_from(sets.len()).map_err(|_| Fault::TooLarge)?;
        let records = ipc::RecordSets::new(&encoded.bytes, count)?;
        let op = client.store(&key, records, true, until)?;
        let reply = ns_reply(&mut client, op, hard).await?;
        match reply.view()? {
            ipc::Response::Generic { code: 0, .. } => Ok(Response::empty(204)),
            ipc::Response::Generic { code, .. } => Err(service(code)),
            _ => Err(Fault::Malformed.into()),
        }
    }
    fn input_set(&self, set: gnunet_rest::contracts::RecordSet<'_>) -> Result<Set, Error> {
        let name = decoded(set.name)?;
        let mut records = Json::new(self.limits.bytes)?;
        let mut count = 0u16;
        for item in set.records()? {
            if usize::from(count) >= self.limits.items {
                return Err(Fault::Capacity.into());
            }
            let item = item?;
            let kind = decoded(item.kind)?;
            let kind = gnunet_gnsrecord_text::typename_to_number(
                std::str::from_utf8(&kind).map_err(|_| Fault::Malformed)?,
            )
            .ok_or(Fault::Unsupported)?;
            let text = decoded(item.value)?;
            let mut data = bytes(self.limits.bytes)?;
            let n = self.record_value(kind, &text, &mut data, true)?;
            let record = RecordData {
                expiration_time: item.expiration,
                record_type: kind,
                flags: item.flags,
                data: &data[..n],
            };
            let mut encoded = bytes(record.encoded_len()?)?;
            record.encode(&mut encoded)?;
            records.raw(&encoded)?;
            count = count.checked_add(1).ok_or(Fault::Overflow)?;
        }
        Ok(Set {
            name,
            records: records.bytes,
            count,
        })
    }
    fn record_value(
        &self,
        kind: RecordType,
        input: &[u8],
        out: &mut [u8],
        parse: bool,
    ) -> Result<usize, Error> {
        let mut stage = bytes(self.limits.text_bytes)?;
        let mut names = bytes(510)?;
        let mut work = bytes(1024)?;
        let limits = gnunet_gnsrecord_text::Limits {
            input_bytes: self.limits.bytes.max(self.limits.text_bytes),
            output_bytes: self.limits.text_bytes,
            ..Default::default()
        };
        let mut codec = gnunet_gnsrecord_text::Codec::new(
            self.idna,
            gnunet_gnsrecord_text::Workspace::new(&mut stage, &mut names, &mut work),
            self.profile,
            limits,
        )?;
        Ok(if parse {
            codec.string_to_value(
                kind,
                std::str::from_utf8(input).map_err(|_| Fault::Malformed)?,
                out,
            )?
        } else {
            codec.value_to_string(kind, input, out)?
        })
    }
    pub(crate) fn record_json(
        &self,
        json: &mut Json,
        label: &[u8],
        records: ipc::Records<'_>,
        filter: Option<RecordType>,
    ) -> Result<bool, Error> {
        let mut body = Json::new(self.limits.output_bytes)?;
        let mut count = 0;
        for record in records.records().iter() {
            let record = record?;
            if filter.is_some_and(|f| f.value() != 0 && f != record.record_type) {
                continue;
            }
            if count >= self.limits.items {
                return Err(Fault::Capacity.into());
            }
            if count != 0 {
                body.raw(b",")?
            }
            let mut value = bytes(self.limits.text_bytes)?;
            let n = self.record_value(record.record_type, record.data, &mut value, false)?;
            body.raw(b"{\"value\":")?;
            body.string(&value[..n])?;
            body.raw(b",\"record_type\":")?;
            body.string(
                gnunet_gnsrecord_text::type_name(record.record_type)
                    .ok_or(Fault::Unsupported)?
                    .as_bytes(),
            )?;
            let relative = record.flags.contains(RecordFlags::RELATIVE_EXPIRATION);
            body.raw(if relative {
                b",\"relative_expiration\":"
            } else {
                b",\"absolute_expiration\":"
            })?;
            body.number(record.expiration_time)?;
            for (name, flag) in [
                (b",\"is_maintenance\":".as_slice(), RecordFlags::MAINTENANCE),
                (b",\"is_private\":", RecordFlags::PRIVATE),
                (b",\"is_supplemental\":", RecordFlags::SUPPLEMENTAL),
                (
                    b",\"is_relative_expiration\":",
                    RecordFlags::RELATIVE_EXPIRATION,
                ),
                (b",\"is_shadow\":", RecordFlags::SHADOW),
            ] {
                body.raw(name)?;
                body.boolean(record.flags.contains(flag))?;
            }
            body.raw(b"}")?;
            count += 1;
        }
        if count == 0 {
            return Ok(false);
        }
        json.raw(b"{\"record_name\":")?;
        json.string(label)?;
        json.raw(b",\"data\":[")?;
        json.raw(&body.bytes)?;
        json.raw(b"]}")?;
        Ok(true)
    }
}
fn subject(
    directory: &gnunet_identity_client_host::Client<'_>,
    name: &[u8],
) -> Result<gnunet_identity::SecretKey, Error> {
    let ego = directory
        .egos()
        .find(|ego| ego.name().eq_ignore_ascii_case(name))
        .ok_or_else(|| service(5002))?;
    Ok(ego.secret().try_clone_secret())
}
fn filter(request: &OwnedRequest, cap: usize) -> Result<u16, Error> {
    let yes = |value: Option<Zeroizing<Vec<u8>>>| {
        value.is_some_and(|v| matches!(v.as_slice(), b"1" | b"yes" | b"true"))
    };
    Ok(u16::from(yes(request.query(b"include_maintenance", cap)?))
        | if yes(request.query(b"omit_private", cap)?) {
            2
        } else {
            0
        })
}
async fn ns_reply<'id>(
    client: &mut Client<'id>,
    operation: gnunet_namestore_client_host::Operation<'id>,
    hard: Instant,
) -> Result<Reply, Error> {
    loop {
        match poll_fn(|cx| client.poll(cx, Some(hard))).await? {
            Progress::Completed(c) if c.operation == operation => {
                return match c.outcome {
                    Outcome::Reply(reply) => Ok(reply),
                    Outcome::Local { reason, submission } => {
                        Err(Error::NamestoreRetired { reason, submission })
                    }
                };
            }
            Progress::Lost { cause, .. } => return Err(Error::NamestoreSource(cause)),
            Progress::Unavailable(error) => return Err(Error::Native(error)),
            Progress::ConnectRetry { error, .. } => return Err(Error::Io(error)),
            Progress::Closed => return Err(Error::SourceLost),
            Progress::WaitDeadline => return Err(Error::Deadline),
            _ => {}
        }
    }
}
