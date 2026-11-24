//! Original NAMESTORE administration requests and one bounded observation window.
mod args;
mod display;
mod inventory;

use crate::{
    control::Control,
    namestore::{
        Client, EncodedSets, EndpointSource, Instance, Limits, Monitor, Operation as Ticket,
        Outcome, Progress, RecordData, RecordFlags, RecordType, Result, SecretKey, Stream,
        ZoneIterator, ZoneKey, gnsrecord, identity, ipc, orphans, recordline::Buffers,
    },
};
pub(super) use args::Arguments;
use gnunet::clients::namestore::Reply;
use inventory::{Inventory, Names};
use std::{
    io::{self, Write},
    time::Duration,
};
use zeroize::Zeroizing;

const TIMEOUT: Duration = Duration::from_secs(30);
const INCLUDE_MAINTENANCE: u16 = 1;
const OMIT_PRIVATE: u16 = 2;
const REVERSE_NO_RESULTS: u32 = 5010;

struct Display {
    label: Option<Vec<u8>>,
    kind: Option<RecordType>,
    recordline: bool,
    filter: u16,
}

struct Record {
    kind: RecordType,
    expiration: u64,
    flags: RecordFlags,
    value: Zeroizing<Vec<u8>>,
}

impl Record {
    fn from_text(
        codec: &mut Buffers,
        kind: RecordType,
        expiration: u64,
        flags: RecordFlags,
        input: &[u8],
    ) -> Result<Self> {
        let data = codec.parse_value(kind, std::str::from_utf8(input)?)?;
        let mut value = storage(data.len())?;
        value.copy_from_slice(data);
        Ok(Self {
            kind,
            expiration,
            flags,
            value,
        })
    }
}

struct Selector {
    kind: Option<RecordType>,
    value: Option<Zeroizing<Vec<u8>>>,
    filter: u16,
}

enum Operation {
    Edit {
        label: Vec<u8>,
        edit: Edit,
    },
    Import(Delegation),
    Display(Display),
    Maintenance {
        action: orphans::Action,
        display: Display,
    },
    Reverse {
        target: ZoneKey,
        spelling: Vec<u8>,
    },
}

pub(super) struct Command {
    owner: Option<Vec<u8>>,
    operations: Vec<Operation>,
    monitor: Option<Display>,
}

pub(super) struct Delegation {
    pub(super) owner: Vec<u8>,
    pub(super) sets: EncodedSets,
}

struct Owner {
    name: Vec<u8>,
    key: SecretKey,
}

struct Session {
    control: Control,
    until: u64,
    limits: Limits,
}

impl Session {
    fn new(source: &EndpointSource) -> Result<Self> {
        let now = source.clock().sample()?.now.as_micros();
        let until = now
            .checked_add(u64::try_from(TIMEOUT.as_micros())?)
            .filter(|time| *time != u64::MAX)
            .ok_or("NAMESTORE clock deadline overflow")?;
        Ok(Self {
            control: Control::new(TIMEOUT, "NAMESTORE administration")?,
            until,
            limits: Limits {
                reconnect: false,
                operations: 1,
                ..Limits::default()
            },
        })
    }

    async fn owners(
        &mut self,
        source: EndpointSource,
        name: Option<Vec<u8>>,
    ) -> Result<Vec<Owner>> {
        let instance = identity::Instance::new();
        let limits = identity::Limits {
            reconnect: false,
            initialization_timeout: TIMEOUT,
            ..Default::default()
        };
        let hard = self.control.hard();
        if let Some(name) = name {
            let mut lookup = identity::Lookup::exact(&instance, source, &name, self.until, limits)?;
            let result = async {
                loop {
                    match self.control.drive(lookup.drive(Some(hard))).await? {
                        identity::LookupProgress::Finished {
                            outcome: identity::LookupOutcome::Found(ego),
                            ..
                        } => {
                            return Ok(vec![Owner {
                                name,
                                key: ego.into_secret(),
                            }]);
                        }
                        identity::LookupProgress::Finished { outcome, .. } => {
                            return match outcome {
                                identity::LookupOutcome::ResultCode(code) => {
                                    Err(format!("IDENTITY ego lookup returned code {code}").into())
                                }
                                _ => Err("IDENTITY ended before resolving the original ego".into()),
                            };
                        }
                        identity::LookupProgress::Source(identity::Progress::Unavailable(
                            error,
                        )) => return Err(error.into()),
                        identity::LookupProgress::Source(identity::Progress::Lost {
                            cause,
                            ..
                        }) => return Err(format!("IDENTITY source lost: {cause:?}").into()),
                        identity::LookupProgress::Source(identity::Progress::WaitDeadline)
                        | identity::LookupProgress::Closed => {
                            return Err(
                                "IDENTITY closed before the original ego lookup result".into()
                            );
                        }
                        _ => {}
                    }
                }
            }
            .await;
            let _close = lookup.close();
            return result;
        }
        let mut monitor = identity::Client::monitor(&instance, source, limits)?;
        let result = async {
            loop {
                match self.control.drive(monitor.drive(Some(hard))).await? {
                    identity::Progress::Initialized(_) => {
                        let mut owners = Vec::new();
                        owners.try_reserve_exact(monitor.egos().count())?;
                        for ego in monitor.egos() {
                            owners.push(Owner {
                                name: ego.name().to_vec(),
                                key: ego.secret().try_clone_secret(),
                            });
                        }
                        return Ok(owners);
                    }
                    identity::Progress::Unavailable(error) => return Err(error.into()),
                    identity::Progress::Lost { cause, .. } => {
                        return Err(format!("IDENTITY source lost: {cause:?}").into());
                    }
                    identity::Progress::WaitDeadline | identity::Progress::Closed => {
                        return Err(
                            "IDENTITY closed before the initial ego inventory was complete".into(),
                        );
                    }
                    _ => {}
                }
            }
        }
        .await;
        let _close = monitor.close();
        result
    }

    async fn reply<'id>(&mut self, client: &mut Client<'id>, ticket: Ticket<'id>) -> Result<Reply> {
        let hard = self.control.hard();
        loop {
            match self.control.drive(client.drive(Some(hard))).await? {
                Progress::Completed(completion) if completion.operation == ticket => {
                    return match completion.outcome {
                        Outcome::Reply(reply) => Ok(reply),
                        Outcome::Local { reason, submission } => Err(format!(
                            "NAMESTORE ended locally ({reason:?}, {submission:?})"
                        )
                        .into()),
                    };
                }
                Progress::Completed(_) => return Err("foreign NAMESTORE completion".into()),
                Progress::Lost { cause, .. } => {
                    return Err(format!("original NAMESTORE connection lost: {cause:?}").into());
                }
                Progress::Unavailable(error) => return Err(error.into()),
                Progress::WaitDeadline | Progress::Closed => {
                    return Err("NAMESTORE ended before its original reply".into());
                }
                _ => {}
            }
        }
    }

    async fn store(
        &mut self,
        client: &mut Client<'_>,
        key: &SecretKey,
        label: &[u8],
        records: &[RecordData<'_>],
    ) -> Result<()> {
        if records.len() > self.limits.records {
            return Err("NAMESTORE record count exceeds the configured bound".into());
        }
        let length = gnsrecord::serialized_len(records)?;
        if length > self.limits.frame_bytes {
            return Err("NAMESTORE record set exceeds one official store frame".into());
        }
        let mut data = storage(length)?;
        gnsrecord::serialize(records, &mut data)?;
        let set = [ipc::StoreSet {
            label: ipc::CString::new(label)?,
            records: ipc::Records::new(&data, u16::try_from(records.len())?)?,
            reserved: 0,
        }];
        let length = ipc::encoded_sets_len(&set)?;
        if length + ipc::STORE_PREFIX + crate::namestore::KEY_BYTES > self.limits.frame_bytes {
            return Err(
                "NAMESTORE record set and request headers exceed one official store frame".into(),
            );
        }
        let mut encoded = storage(length)?;
        ipc::encode_sets(&set, &mut encoded)?;
        self.store_sets(client, key, ipc::RecordSets::new(&encoded, 1)?)
            .await
    }

    async fn store_sets(
        &mut self,
        client: &mut Client<'_>,
        key: &SecretKey,
        sets: ipc::RecordSets<'_>,
    ) -> Result<()> {
        self.control.gate().await?;
        let operation = client.store(key, sets, true, self.until)?;
        match self.reply(client, operation).await?.view()? {
            ipc::Response::Generic { code: 0, .. } => Ok(()),
            ipc::Response::Generic { code, .. } => {
                Err(format!("NAMESTORE store returned code {code}").into())
            }
            _ => Err("unexpected NAMESTORE store reply".into()),
        }
    }
}

pub(super) async fn execute(
    command: Command,
    source: EndpointSource,
    identity: EndpointSource,
    out: &mut impl Write,
) -> Result<()> {
    let mut session = Session::new(&source)?;
    let needs_inventory = command.monitor.is_some() && command.owner.is_some()
        || command.operations.iter().any(|operation| {
            !matches!(
                operation,
                Operation::Maintenance { .. } | Operation::Import(_)
            )
        });
    let owners = if needs_inventory {
        session
            .owners(identity.duplicate()?, command.owner.clone())
            .await?
    } else {
        Vec::new()
    };
    let owner = if command.owner.is_some() {
        owners.first()
    } else {
        None
    };
    let needs_client = command.operations.iter().any(|operation| {
        matches!(
            operation,
            Operation::Edit { .. }
                | Operation::Import(_)
                | Operation::Reverse { .. }
                | Operation::Display(Display { label: Some(_), .. })
        )
    });
    let instance = Instance::new();
    let mut client = if needs_client {
        Some(Client::new(&instance, source.duplicate()?, session.limits)?)
    } else {
        None
    };
    let result = async {
        for operation in command.operations {
            session.control.gate().await?;
            match operation {
                Operation::Maintenance { action, display } => {
                    let maintenance_owner = command
                        .owner
                        .clone()
                        .filter(|_| action == orphans::Action::PurgeZone);
                    maintenance(
                        action,
                        display,
                        maintenance_owner,
                        [source.duplicate()?, identity.duplicate()?],
                        out,
                    )
                    .await?;
                }
                Operation::Import(delegation) => {
                    let resolved;
                    let key =
                        if let Some(owner) = owner.filter(|owner| owner.name == delegation.owner) {
                            &owner.key
                        } else {
                            resolved = session
                                .owners(identity.duplicate()?, Some(delegation.owner))
                                .await?;
                            &resolved
                                .first()
                                .ok_or("missing original delegation zone")?
                                .key
                        };
                    let sets = ipc::RecordSets::new(&delegation.sets.bytes, delegation.sets.count)?;
                    session
                        .store_sets(
                            client.as_mut().ok_or("missing NAMESTORE client")?,
                            key,
                            sets,
                        )
                        .await?;
                }
                Operation::Display(spec) if spec.label.is_none() => {
                    subscribe(
                        &mut session,
                        source.duplicate()?,
                        owner.map_or(Names::Snapshot(&owners), Names::Zone),
                        spec,
                        false,
                        out,
                    )
                    .await?;
                }
                Operation::Display(spec) => {
                    show_label(
                        &mut session,
                        client.as_mut().ok_or("missing NAMESTORE client")?,
                        owner.ok_or("missing selected NAMESTORE zone")?,
                        &spec,
                        out,
                    )
                    .await?;
                }
                Operation::Edit { label, edit } => {
                    mutate(
                        &mut session,
                        client.as_mut().ok_or("missing NAMESTORE client")?,
                        owner.ok_or("missing selected NAMESTORE zone")?,
                        &label,
                        edit,
                    )
                    .await?;
                }
                Operation::Reverse { target, spelling } => {
                    reverse(
                        &mut session,
                        client.as_mut().ok_or("missing NAMESTORE client")?,
                        owner.ok_or("missing selected NAMESTORE zone")?,
                        target,
                        &spelling,
                        out,
                    )
                    .await?;
                }
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    if let Some(mut client) = client {
        let _close = client.close();
    }
    result?;
    if let Some(spec) = command.monitor {
        let identity_instance = identity::Instance::new();
        let mut inventory;
        let names = match owner {
            Some(owner) => Names::Zone(owner),
            None => {
                inventory =
                    Inventory::open(&identity_instance, identity, &mut session.control).await?;
                Names::Live(&mut inventory)
            }
        };
        subscribe(&mut session, source, names, spec, true, out).await?;
    }
    Ok(())
}

async fn maintenance(
    action: orphans::Action,
    display: Display,
    owner: Option<Vec<u8>>,
    endpoints: [EndpointSource; 2],
    out: &mut impl Write,
) -> Result<()> {
    if action != orphans::Action::List {
        return orphans::run_configured(action, owner, display.filter, endpoints, None).await;
    }
    let mut writer = display::Writer::new(out, &display)?;
    let mut list = |zone: &SecretKey, label: &[u8], records: ipc::Records<'_>| -> Result<()> {
        if display
            .label
            .as_ref()
            .is_some_and(|name| name.as_slice() != label)
        {
            return Ok(());
        }
        let mut encoded = Zeroizing::new([0; 58]);
        let size = gnsrecord::encode_base32(zone.expose_serialized(), &mut *encoded)?;
        writer.records(&encoded[..size], label, records)
    };
    orphans::run_configured(action, owner, display.filter, endpoints, Some(&mut list)).await
}

fn storage(length: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.try_reserve_exact(length)?;
    bytes.resize(length, 0);
    Ok(bytes)
}

enum Edit {
    Add(Record),
    Delete(Selector),
}

async fn mutate(
    session: &mut Session,
    client: &mut Client<'_>,
    owner: &Owner,
    label: &[u8],
    edit: Edit,
) -> Result<()> {
    let operation = client.lookup(&owner.key, label, INCLUDE_MAINTENANCE, session.until)?;
    let reply = session.reply(client, operation).await?;
    let ipc::Response::Lookup {
        label,
        found: 0 | 1,
        records,
        ..
    } = reply.view()?
    else {
        return Err("NAMESTORE lookup failed; record set was not changed".into());
    };
    let capacity = usize::from(records.count()) + usize::from(matches!(edit, Edit::Add(_)));
    let mut replacement = Vec::new();
    replacement.try_reserve_exact(capacity)?;
    match edit {
        Edit::Add(addition) => {
            replacement.push(RecordData {
                expiration_time: addition.expiration,
                record_type: addition.kind,
                flags: addition.flags,
                data: &addition.value,
            });
            for record in records.records().iter() {
                let record = record?;
                if record.record_type == RecordType::SOA && addition.kind == RecordType::SOA {
                    return Err("A SOA record already exists under this name".into());
                }
                if record.record_type == RecordType::NICK
                    && addition.kind == RecordType::NICK
                    && label.bytes() == b"@"
                {
                    continue;
                }
                if retain_record(label.bytes(), record) {
                    replacement.push(record);
                }
            }
            session
                .store(client, &owner.key, label.bytes(), &replacement)
                .await
        }
        Edit::Delete(selector) => {
            let mut codec = Buffers::new()?;
            let mut removed = false;
            for record in records.records().iter() {
                let record = record?;
                if !retain_record(label.bytes(), record) {
                    continue;
                }
                let selected = matches_selector(&selector, record, &mut codec);
                removed |= selected;
                if !selected {
                    replacement.push(record);
                }
            }
            if !removed {
                return Err("No records under this label match the deletion request".into());
            }
            session
                .store(client, &owner.key, label.bytes(), &replacement)
                .await
        }
    }
}

fn retain_record(label: &[u8], record: RecordData<'_>) -> bool {
    label == b"@" || record.record_type != RecordType::NICK
}

fn matches_selector(selector: &Selector, record: RecordData<'_>, codec: &mut Buffers) -> bool {
    if selector.kind.is_some_and(|kind| kind != record.record_type)
        || (selector.filter & OMIT_PRIVATE != 0 && record.flags.contains(RecordFlags::PRIVATE))
        || (selector.filter & INCLUDE_MAINTENANCE == 0
            && record.flags.contains(RecordFlags::MAINTENANCE))
    {
        return false;
    }
    selector.value.as_ref().is_none_or(|value| {
        codec
            .display_value(record)
            .is_ok_and(|text| text.as_bytes() == value.as_slice())
    })
}

async fn show_label(
    session: &mut Session,
    client: &mut Client<'_>,
    owner: &Owner,
    spec: &Display,
    out: &mut impl Write,
) -> Result<()> {
    let label = spec
        .label
        .as_ref()
        .ok_or("NAMESTORE display label is required")?;
    let operation = client.lookup(&owner.key, label, spec.filter, session.until)?;
    let reply = session.reply(client, operation).await?;
    match reply.view()? {
        ipc::Response::Lookup {
            found: 1,
            label,
            records,
            ..
        } => display::Writer::new(out, spec)?.records(&owner.name, label.bytes(), records),
        ipc::Response::Lookup { found: 0, .. } => Ok(()),
        ipc::Response::Lookup { found, .. } => {
            Err(format!("NAMESTORE lookup returned status {found}").into())
        }
        _ => Err("unexpected NAMESTORE lookup reply".into()),
    }
}

async fn reverse(
    session: &mut Session,
    client: &mut Client<'_>,
    owner: &Owner,
    target: ZoneKey,
    spelling: &[u8],
    out: &mut impl Write,
) -> Result<()> {
    let operation = client.zone_to_name(&owner.key, target, session.until)?;
    let reply = session.reply(client, operation).await?;
    match reply.view()? {
        ipc::Response::ZoneToName {
            code: 0,
            label: Some(label),
            ..
        } => {
            out.write_all(label.bytes())?;
            out.write_all(b".")?;
            out.write_all(&owner.name)?;
        }
        ipc::Response::ZoneToName {
            code: REVERSE_NO_RESULTS,
            label: None,
            ..
        } => {
            out.write_all(spelling)?;
            out.write_all(b".zkey")?;
        }
        ipc::Response::ZoneToName {
            code: 0,
            label: None,
            ..
        } => out.write_all(spelling)?,
        ipc::Response::ZoneToName { code, .. } => {
            return Err(format!("NAMESTORE reverse lookup returned code {code}").into());
        }
        _ => return Err("unexpected NAMESTORE reverse lookup reply".into()),
    }
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

async fn subscribe(
    session: &mut Session,
    source: EndpointSource,
    mut names: Names<'_, '_>,
    spec: Display,
    monitor: bool,
    out: &mut impl Write,
) -> Result<()> {
    let instance = Instance::new();
    let zone = names.zone();
    let clock = source.clock();
    let mut stream = if monitor {
        Stream::Monitor(Monitor::follow(
            &instance,
            source,
            zone,
            true,
            spec.filter,
            session.until,
            session.limits,
        )?)
    } else {
        Stream::Iterator(ZoneIterator::new(
            &instance,
            source,
            zone,
            spec.filter,
            session.until,
            session.limits,
        )?)
    };
    let operation = stream.operation();
    let mut hard = Some(session.control.hard());
    let mut writer = display::Writer::new(out, &spec)?;
    let result = async {
        let mut synchronized = false;
        loop {
            let progress = match inventory::step(&mut names, &mut stream, &mut session.control, hard).await {
                Ok(progress) => progress,
                Err(error) if monitor && error.downcast_ref::<io::Error>().is_some_and(|error| error.kind() == io::ErrorKind::Interrupted) => return Ok(()),
                Err(error) => return Err(error),
            };
            match progress {
                Progress::Record { operation: original, reply, .. } if original == operation => {
                    let ipc::Response::Records { zone, label, records, .. } = reply.view()? else {
                        return Err("unexpected NAMESTORE subscription response".into());
                    };
                    let matching = spec.label.as_ref().is_none_or(|name| name.as_slice() == label.bytes());
                    if matching {
                        names.with_name(zone, |name| {
                            if synchronized {
                                writer.replenish();
                            }
                            writer.records(name, label.bytes(), records)
                        })?;
                    }
                    let until = if synchronized {
                        clock.sample()?.now.as_micros()
                            .checked_add(u64::try_from(TIMEOUT.as_micros())?)
                            .filter(|time| *time != u64::MAX)
                            .ok_or("NAMESTORE monitor control deadline overflow")?
                    } else {
                        session.until
                    };
                    stream.next(until)?;
                }
                Progress::Record { .. } => return Err("foreign NAMESTORE subscription record".into()),
                Progress::Synchronized { operation: original, .. } if monitor && original == operation => {
                    writer.synchronized()?;
                    synchronized = true;
                    hard = None;
                    session.control.release_deadline();
                }
                Progress::Synchronized { .. } => return Err("foreign NAMESTORE monitor synchronization".into()),
                Progress::Completed(completion) if completion.operation == operation => match completion.outcome {
                    Outcome::Reply(reply) if !monitor && matches!(reply.view()?, ipc::Response::End { .. }) => return Ok(()),
                    _ => return Err("NAMESTORE subscription ended without the expected terminal observation".into()),
                },
                Progress::Completed(_) => return Err("foreign NAMESTORE subscription completion".into()),
                Progress::Lost { cause, .. } => return Err(format!("NAMESTORE subscription lost: {cause:?}").into()),
                Progress::Unavailable(error) => return Err(error.into()),
                Progress::Closed | Progress::WaitDeadline => return Err("NAMESTORE subscription ended before completion or synchronization".into()),
                _ => {}
            }
        }
    }.await;
    let _close = stream.close();
    names.close();
    result
}
