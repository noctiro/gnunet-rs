#![expect(
    clippy::panic_in_result_fn,
    reason = "Focused ownership/credit model asserts original tokens and exact official bytes"
)]
use super::*;
#[derive(Clone, Copy)]
struct Entry {
    seq: u64,
    peer: [u8; 32],
    expiry: u64,
    value: [u8; 8],
    len: usize,
}
impl Entry {
    fn record(&self) -> Record<'_> {
        Record {
            peer: self.peer,
            expiry: self.expiry,
            subsystem: Some(b"t"),
            key: Some(b"k"),
            value: &self.value[..self.len],
        }
    }
}
struct Memory {
    rows: [Option<Entry>; 4],
    next: u64,
}
impl Storage for Memory {
    fn store(&mut self, r: Record<'_>, replace: bool) -> Result<u64, Error> {
        if r.value.len() > 8 || r.subsystem != Some(b"t") || r.key != Some(b"k") {
            return Err(Error::InvalidInput);
        }
        if replace {
            self.rows = [None; 4]
        }
        let slot = self
            .rows
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let seq = self.next.checked_add(1).ok_or(Error::Overflow)?;
        let mut value = [0; 8];
        value[..r.value.len()].copy_from_slice(r.value);
        self.rows[slot] = Some(Entry {
            seq,
            peer: r.peer,
            expiry: r.expiry,
            value,
            len: r.value.len(),
        });
        self.next = seq;
        Ok(seq)
    }
    fn next(&self, filter: Filter<'_>, after: u64) -> Result<Option<Row<'_>>, Error> {
        Ok(self
            .rows
            .iter()
            .flatten()
            .filter(|r| r.seq > after && filter.matches(r.record()))
            .min_by_key(|r| r.seq)
            .map(|r| Row {
                sequence: r.seq,
                record: r.record(),
            }))
    }
    fn expire(&mut self, now: u64) -> Result<u64, Error> {
        let mut n = 0;
        for row in &mut self.rows {
            if row.is_some_and(|r| r.expiry < now) {
                *row = None;
                n += 1
            }
        }
        Ok(n)
    }
}
fn record(value: &[u8]) -> Record<'_> {
    Record {
        peer: [9; 32],
        expiry: u64::MAX,
        subsystem: Some(b"t"),
        key: Some(b"k"),
        value,
    }
}
fn consume<'id>(
    service: &mut Service<'id, '_, '_>,
    client: Client<'id>,
    check: impl FnOnce(Response<'_>),
) -> Result<(), Error> {
    let prepared = service.output(client)?.ok_or(Error::NotReady)?;
    let output = prepared.output;
    check(Response::decode(prepared.bytes)?);
    service.queued(output)?;
    service.exposed(output)?;
    service.written(output)
}
#[test]
fn official_credit_cancel_original_scan_and_lost_store_are_distinct() -> Result<(), Error> {
    let stop = Request::IterateStop { rid: 0x1234_5678 };
    let mut bytes = [0; 8];
    stop.encode(&mut bytes)?;
    assert_eq!(bytes, [0, 8, 3, 61, 0x12, 0x34, 0x56, 0x78]);
    assert_eq!(Request::decode(&bytes)?, stop);
    let request = Request::Store(Envelope {
        rid: 0x12345678,
        options: 1,
        reserved: 0,
        record: record(b"a"),
    });
    assert_eq!(request.encoded_len()?, 65);
    let mut short = [0xa5; 64];
    assert_eq!(request.encode(&mut short), Err(Error::Capacity));
    assert_eq!(short, [0xa5; 64]);
    let mut full = [0; 65];
    request.encode(&mut full)?;
    assert_eq!(Request::decode(&full)?, request);
    assert_eq!(&full[44..48], &0x12345678_u32.to_be_bytes());
    let mut instance = Instance::new();
    let mut clients = [ClientSlot::new(); 2];
    let mut filter_bytes = [[0; 32]; 4];
    let mut operations = filter_bytes.each_mut().map(|b| OperationSlot::new(b));
    let mut frames = [[0; 256]; 2];
    let mut messages = frames.each_mut().map(|b| MessageSlot::new(b));
    let mut service = Service::new(
        &mut instance,
        &mut clients,
        &mut operations,
        &mut messages,
        Limits { record_bytes: 256 },
    )?;
    let writer = service.attach()?;
    let watcher = service.attach()?;
    let mut storage = Memory {
        rows: [None; 4],
        next: 0,
    };
    let filter = Filter {
        peer: Some([9; 32]),
        subsystem: Some(b"t"),
        key: Some(b"k"),
    };
    service.receive_control(
        watcher,
        Request::MonitorStart(Monitor {
            rid: 7,
            filter,
            iterate_first: false,
        }),
    )?;
    assert!(service.progress()?);
    consume(&mut service, watcher, |r| {
        assert_eq!(r, Response::MonitorSync)
    })?;
    service.receive(
        writer,
        Request::Store(Envelope {
            rid: 1,
            options: 0,
            reserved: 0,
            record: record(b"a"),
        }),
        &mut storage,
    )?;
    consume(&mut service, writer, |r| {
        assert_eq!(r, Response::StoreResult { rid: 1, result: 1 })
    })?;
    consume(&mut service, watcher, |r| {
        assert!(matches!(r, Response::Record(_)));
        if let Response::Record(e) = r {
            assert_eq!(e.rid, 0);
            assert_eq!(e.record.value, b"a")
        }
    })?;
    service.receive(
        writer,
        Request::Store(Envelope {
            rid: 2,
            options: 0,
            reserved: 0,
            record: record(b"b"),
        }),
        &mut storage,
    )?;
    consume(&mut service, writer, |r| {
        assert_eq!(r, Response::StoreResult { rid: 2, result: 1 })
    })?;
    assert!(service.output(watcher)?.is_none());
    service.receive_control(watcher, Request::MonitorNext { limit: 1 })?;
    assert!(!service.pump(&storage)?);
    assert!(service.output(watcher)?.is_none());
    service.receive_control(
        writer,
        Request::IterateStart(Iteration {
            rid: 0x1122_3344,
            filter,
            reserved: 0,
        }),
    )?;
    let request = service.scan_request().ok_or(Error::NotReady)?;
    let old = request.scan;
    let row = storage.next(request.filter, old.after())?;
    service.scan_started(old)?;
    service.receive_control(writer, Request::IterateStop { rid: 0x1122_3344 })?;
    service.receive_control(
        writer,
        Request::IterateStart(Iteration {
            rid: 0x1122_3344,
            filter,
            reserved: 0,
        }),
    )?;
    assert_eq!(
        service.complete_scan(old, Ok(row)),
        Err(Error::StaleGeneration)
    );
    assert!(service.pump(&storage)?);
    consume(&mut service, writer, |r| {
        assert!(matches!(r, Response::Record(_)));
        if let Response::Record(e) = r {
            assert_eq!(e.rid, 0x1122_3344);
            assert_eq!(e.record.value, b"a")
        }
    })?;
    service.receive_control(
        writer,
        Request::IterateNext {
            rid: 0x1122_3344,
            limit: 256,
        },
    )?;
    assert!(service.pump(&storage)?);
    consume(&mut service, writer, |r| {
        assert!(matches!(r, Response::Record(_)));
        if let Response::Record(e) = r {
            assert_eq!(e.record.value, b"b")
        }
    })?;
    assert!(service.pump(&storage)?);
    consume(&mut service, writer, |r| {
        assert_eq!(
            r,
            Response::IterateEnd {
                rid: 0x1122_3344,
                result: 1
            }
        )
    })?;
    service.receive(
        writer,
        Request::Store(Envelope {
            rid: 3,
            options: 0,
            reserved: 0,
            record: record(b"c"),
        }),
        &mut storage,
    )?;
    consume(&mut service, writer, |r| {
        assert_eq!(r, Response::StoreResult { rid: 3, result: 1 })
    })?;
    let pending = service.output(watcher)?.ok_or(Error::NotReady)?.output;
    service.queued(pending)?;
    service.exposed(pending)?;
    let loss = service.detach(watcher)?;
    assert_eq!(loss.pending, Some(pending));
    assert!(loss.exposed);
    let fresh = service.attach()?;
    assert_ne!(fresh, watcher);
    assert_eq!(service.written(pending), Err(Error::StaleGeneration));
    assert!(service.output(fresh)?.is_none());
    let effect = service.begin_store(
        writer,
        Envelope {
            rid: 0x500,
            options: 0,
            reserved: 0,
            record: record(b"d"),
        },
    )?;
    assert_eq!(
        service.complete_store(effect, record(b"x"), Ok(4)),
        Err(Error::Conflict)
    );
    assert_eq!(
        service.complete_store(effect, record(b"d"), Err(Error::OutcomeUnknown)),
        Err(Error::OutcomeUnknown)
    );
    let loss = service.detach(writer)?;
    assert_eq!(loss.pending_store, Some(effect));
    assert_eq!(loss.unknown_store, Some(0x500));
    assert_eq!(storage.next, 3);
    Ok(())
}

#[test]
fn pending_initial_sync_never_emits_a_live_record_or_spends_its_credit() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut clients = [ClientSlot::new(); 2];
    let mut filter_bytes = [[0; 32]; 2];
    let mut operations = filter_bytes.each_mut().map(|b| OperationSlot::new(b));
    let mut frames = [[0; 256]; 2];
    let mut messages = frames.each_mut().map(|b| MessageSlot::new(b));
    let mut service = Service::new(
        &mut instance,
        &mut clients,
        &mut operations,
        &mut messages,
        Limits { record_bytes: 256 },
    )?;
    let writer = service.attach()?;
    let watcher = service.attach()?;
    let mut storage = Memory {
        rows: [None; 4],
        next: 0,
    };
    service.receive_control(
        watcher,
        Request::MonitorStart(Monitor {
            rid: 7,
            filter: Filter {
                peer: Some([9; 32]),
                subsystem: Some(b"t"),
                key: Some(b"k"),
            },
            iterate_first: false,
        }),
    )?;
    // Deliberately leave the original SYNC unprepared. Native must call
    // progress before its worker class; the core independently refuses to
    // emit a live record if that original barrier still remains blocked.
    service.receive(
        writer,
        Request::Store(Envelope {
            rid: 19,
            options: 0,
            reserved: 0,
            record: record(b"a"),
        }),
        &mut storage,
    )?;
    consume(&mut service, writer, |response| {
        assert_eq!(response, Response::StoreResult { rid: 19, result: 1 });
    })?;
    assert!(service.output(watcher)?.is_none());
    assert_eq!(service.fault(), Some((watcher, Error::Capacity)));
    assert_eq!(
        service.receive_control(watcher, Request::MonitorNext { limit: 1 }),
        Err(Error::Cancelled)
    );
    assert!(!service.progress()?);
    Ok(())
}
