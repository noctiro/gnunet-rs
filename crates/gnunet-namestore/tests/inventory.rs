//! One pure inventory/credit model. Every key/address is a published fixed mock.
//! Receipt calls below are explicit controlled provider/queue facts; this model
//! claims no actual durability, native MQ, encryption, entropy or key-file test.
#![cfg(feature = "alloc")]
#![forbid(unsafe_code)]
use gnunet_namestore::*;
use gnunet_types::Error;
use gnunet_wire::official::namestore::{CString, RecordSets, Records, StoreSet, encode_sets};
fn critical(_: RecordType) -> bool {
    false
}
fn limits() -> Limits {
    Limits {
        rows: 8,
        zones: 4,
        record_bytes: 1024,
        records_per_set: 8,
        batch: 8,
        image_bytes: 65536,
        retained_bytes: 524288,
        ..Limits::default()
    }
}
#[cfg(target_has_atomic = "ptr")]
fn owned_records_stay_send_sync<T: Send + Sync>() {}
fn mock() -> Result<SecretKey, Error> {
    let mut bytes = [0x42; 36];
    bytes[..4].copy_from_slice(&gnunet_identity::KeyType::Eddsa.value().to_be_bytes());
    SecretKey::new(bytes)
}
fn batch(
    core: &mut Core,
    key: &SecretKey,
    items: &[(&[u8], &[RecordData<'_>])],
    atomic: bool,
) -> Result<Decision, Error> {
    let mut payloads = Vec::new();
    for (_, records) in items {
        payloads.push(OwnedRecords::serialize(records, 1024)?);
    }
    let mut sets = Vec::new();
    for ((name, _), records) in items.iter().zip(&payloads) {
        sets.push(StoreSet {
            label: CString::new(name)?,
            records: records.view()?,
            reserved: 0,
        });
    }
    let mut bytes = [0; 4096];
    let n = encode_sets(&sets, &mut bytes)?;
    core.store(
        key.view()?,
        RecordSets::new(
            &bytes[..n],
            u16::try_from(items.len()).map_err(|_| Error::Capacity)?,
        )?,
        atomic,
        100,
    )
}
fn committed(core: &mut Core, decision: Decision) -> Result<Committed, Error> {
    let Decision::Prepared(t) = decision else {
        return Err(Error::NotReady);
    };
    if !matches!(core.commit(&t), Err(Error::NotReady)) {
        return Err(Error::Conflict);
    }
    core.queued(&t)?;
    core.commit(&t)
}
fn generic(reply: &Reply, code: Code) -> Result<(), Error> {
    match reply {
        Reply::Generic { code: actual } => {
            if *actual == code {
                Ok(())
            } else {
                Err(Error::Malformed)
            }
        }
        _ => Err(Error::Malformed),
    }
}
fn admitted_monitor(m: &mut Monitor) -> Result<(), Error> {
    let write = m.prepared().ok_or(Error::NotReady)?.write.clone();
    m.can_queue(&write)?;
    m.queued(&write)?;
    m.exposed(&write)?;
    m.written(&write)
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "One controlled pure model asserts original transaction and queue-state invariants with public fixed mock values"
)]
fn inventory_original_transactions_credits_hints_atomicity_and_unknown() -> Result<(), Error> {
    #[cfg(target_has_atomic = "ptr")]
    owned_records_stay_send_sync::<OwnedRecords>();
    let key = mock()?;
    let mut core = Core::new(limits(), Vec::new(), critical)?;
    let mut monitor = Monitor::new(&core, None, false, Filter::NONE, StreamLimits::default())?;
    assert_eq!(monitor.prepare(&core, 100)?, StreamProgress::Prepared);
    assert!(matches!(
        monitor.prepared().ok_or(Error::NotReady)?.item,
        Item::Sync
    ));
    admitted_monitor(&mut monitor)?;
    assert!(monitor.synchronized());
    let value = [192, 0, 2, 1];
    let rd = [RecordData {
        expiration_time: 1000,
        record_type: RecordType::A,
        flags: RecordFlags::from_bits_preserve(0),
        data: &value,
    }];
    let decision = batch(&mut core, &key, &[(b"MiXeD", &rd)], true)?;
    let c = committed(&mut core, decision)?;
    generic(&c.reply, Code::NONE)?;
    monitor.offer(c.change).map_err(|(e, _)| e)?;
    let actual = core.lookup(key.view()?, b"MiXeD", Filter::NONE, 100)?;
    assert!(actual.found());
    assert_eq!(actual.records()?.count(), 1);
    assert!(
        !core
            .lookup(key.view()?, b"mixed", Filter::NONE, 100)?
            .found()
    );
    assert_eq!(monitor.prepare(&core, 100)?, StreamProgress::Prepared);
    admitted_monitor(&mut monitor)?;
    assert_eq!(monitor.queued_revision(), 1);
    // One historical immutable image pins the original public record allocation.
    // A hint edit must copy neither its label nor its unchanged record payload.
    let historical = core.snapshot()?;
    let original = &historical.rows()[0];
    let original_records = original.records().view()?.bytes().as_ptr();
    let original_label = original.label().as_ptr();
    let d = core.edit_begin(key.view()?, b"MiXeD", b"editor", 100)?;
    let stage = core.staged().ok_or(Error::NotReady)?;
    assert!(core::ptr::eq(
        stage.after.rows()[0].records().view()?.bytes().as_ptr(),
        original_records
    ));
    assert!(core::ptr::eq(
        stage.after.rows()[0].label().as_ptr(),
        original_label
    ));
    assert!(original.hint().is_none());
    assert_eq!(stage.after.rows()[0].hint(), Some(b"editor".as_slice()));
    let c = committed(&mut core, d)?;
    assert!(historical.rows()[0].hint().is_none());
    match &c.reply {
        Reply::Edit { code, query } => {
            assert_eq!(*code, Code::NONE);
            assert!(query.hint().is_none());
            assert_eq!(query.records()?.count(), 1);
        }
        _ => return Err(Error::Malformed),
    }
    monitor.offer(c.change).map_err(|(e, _)| e)?;
    assert_eq!(monitor.prepare(&core, 100)?, StreamProgress::Idle);
    assert_eq!(
        core.lookup(key.view()?, b"MiXeD", Filter::NONE, 100)?
            .hint(),
        Some(b"editor".as_slice())
    );
    let d = core.edit_cancel(key.view()?, b"MiXeD", b"wrong", b"")?;
    let Decision::Immediate(reply) = d else {
        return Err(Error::Conflict);
    };
    generic(&reply, Code::NONE)?;
    assert!(core.staged().is_none());
    let d = core.edit_cancel(key.view()?, b"MiXeD", b"editor", b"")?;
    let c = committed(&mut core, d)?;
    monitor.offer(c.change).map_err(|(e, _)| e)?;
    assert_eq!(monitor.prepare(&core, 100)?, StreamProgress::Idle);
    assert!(
        core.lookup(key.view()?, b"MiXeD", Filter::NONE, 100)?
            .hint()
            .is_none()
    );
    let mut iterator = ZoneIterator::new(
        &core,
        9,
        Some(key.view()?),
        Filter::NONE,
        StreamLimits::default(),
    )?;
    assert_eq!(iterator.prepare(&core, 100)?, StreamProgress::Prepared);
    let first = iterator.prepared().ok_or(Error::NotReady)?.write.clone();
    iterator.can_queue(&first)?;
    iterator.queued(&first)?;
    iterator.exposed(&first)?;
    iterator.written(&first)?;
    assert_eq!(iterator.prepare(&core, 100)?, StreamProgress::Prepared);
    assert!(matches!(
        iterator.prepared().ok_or(Error::NotReady)?.item,
        Item::End { request: 9 }
    ));
    let end = iterator.prepared().ok_or(Error::NotReady)?.write.clone();
    iterator.queued(&end)?;
    iterator.exposed(&end)?;
    iterator.written(&end)?;
    assert_eq!(iterator.prepare(&core, 100)?, StreamProgress::Finished);
    let atomic = batch(
        &mut core,
        &key,
        &[(b"new", &rd), (b"invalid.dot", &rd)],
        true,
    )?;
    let Decision::Immediate(reply) = atomic else {
        return Err(Error::Conflict);
    };
    generic(&reply, Code::LABEL_INVALID)?;
    assert!(!core.lookup(key.view()?, b"new", Filter::NONE, 100)?.found());
    let nonatomic = batch(
        &mut core,
        &key,
        &[(b"new", &rd), (b"invalid.dot", &rd)],
        false,
    )?;
    let c = committed(&mut core, nonatomic)?;
    generic(&c.reply, Code::LABEL_INVALID)?;
    // The transaction that adds a different label shares every unchanged byte
    // with the original snapshot, including through both intervening hint edits.
    let grown = core.snapshot()?;
    let unchanged = grown
        .rows()
        .iter()
        .find(|r| r.label() == b"MiXeD")
        .ok_or(Error::NotFound)?;
    assert!(core::ptr::eq(
        unchanged.records().view()?.bytes().as_ptr(),
        original_records
    ));
    assert!(core::ptr::eq(unchanged.label().as_ptr(), original_label));
    drop(grown);
    assert!(core.lookup(key.view()?, b"new", Filter::NONE, 100)?.found());
    monitor.offer(c.change).map_err(|(e, _)| e)?;
    assert_eq!(monitor.prepare(&core, 100)?, StreamProgress::WaitCredit);
    monitor.grant(1)?;
    assert_eq!(monitor.prepare(&core, 100)?, StreamProgress::Prepared);
    admitted_monitor(&mut monitor)?;
    let d = batch(&mut core, &key, &[(b"MiXeD", &[])], true)?;
    let c = committed(&mut core, d)?;
    // A real record replacement installs independent immutable bytes. The old
    // snapshot still contains its original A record after the current deletion.
    if let Some(changed) = c
        .change
        .after()
        .rows()
        .iter()
        .find(|r| r.label() == b"MiXeD")
    {
        assert!(!core::ptr::eq(
            changed.records().view()?.bytes().as_ptr(),
            original_records
        ));
    }
    assert_eq!(
        historical.rows()[0]
            .records()
            .view()?
            .records()
            .iter()
            .next()
            .ok_or(Error::NotFound)??
            .data,
        &value
    );
    assert!(historical.rows()[0].hint().is_none());
    monitor.offer(c.change).map_err(|(e, _)| e)?;
    monitor.grant(1)?;
    assert_eq!(monitor.prepare(&core, 100)?, StreamProgress::Prepared);
    match monitor.prepared().ok_or(Error::NotReady)?.item {
        Item::Record { query, .. } => assert_eq!(query.records()?.count(), 0),
        _ => return Err(Error::Malformed),
    }
    let draining = monitor.prepared().ok_or(Error::NotReady)?.write.clone();
    monitor.queued(&draining)?;
    monitor.stop();
    assert_eq!(monitor.prepare(&core, 100)?, StreamProgress::Draining);
    monitor.exposed(&draining)?;
    monitor.written(&draining)?;
    assert_eq!(monitor.prepare(&core, 100)?, StreamProgress::Stopped);
    let target = gnunet_gnsrecord::ZoneKey::new(gnunet_gnsrecord::ZoneKeyType::Edkey, [0x24; 32]);
    let delegation = [RecordData {
        expiration_time: 2000,
        record_type: RecordType::EDKEY,
        flags: RecordFlags::from_bits_preserve(0),
        data: target.key(),
    }];
    let d = batch(&mut core, &key, &[(b"child", &delegation)], true)?;
    let _c = committed(&mut core, d)?;
    assert_eq!(
        core.zone_to_name(key.view()?, target)?
            .ok_or(Error::NotReady)?
            .label(),
        b"child"
    );
    let mut old = ZoneIterator::new(&core, 9, None, Filter::NONE, StreamLimits::default())?;
    while old.prepare(&core, 100)? == StreamProgress::Advanced {}
    let write = old.prepared().ok_or(Error::NotReady)?.write.clone();
    assert!(old.queued(&first).is_err());
    let d = batch(&mut core, &key, &[(b"unknown", &rd)], true)?;
    let Decision::Prepared(t) = d else {
        return Err(Error::Conflict);
    };
    core.queued(&t)?;
    core.unknown(&t)?;
    assert!(matches!(core.snapshot(), Err(Error::OutcomeUnknown)));
    assert!(matches!(old.can_queue(&write), Err(Error::OutcomeUnknown)));
    assert!(old.source_lost().prepared);
    let fresh = Core::new(limits(), Vec::new(), critical)?;
    assert_eq!(old.prepare(&fresh, 100)?, StreamProgress::Stopped);
    let mut low = limits();
    low.retained_bytes = low.image_bytes;
    let mut low = Core::new(low, Vec::new(), critical)?;
    assert!(matches!(
        batch(&mut low, &key, &[(b"a", &rd)], true),
        Err(Error::Capacity)
    ));
    assert_eq!(low.snapshot()?.rows().len(), 0);
    assert!(low.staged().is_none());
    let _empty = Records::empty()?;
    Ok(())
}
