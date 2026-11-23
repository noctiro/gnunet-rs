//! Complete same-zone label sets carried by one original atomic STORE frame.
use super::{Failure, Group, Result, Zone, row};
use crate::control::Control;
use gnunet::clients::namestore as ns;
use serde_json::json;
use std::io::Write;
use tokio::time::Instant;
use zeroize::{Zeroize, Zeroizing};

struct Receipt {
    label: String,
    owner: String,
    first_line: u64,
    last_line: u64,
}

pub(super) struct Batch {
    bytes: Zeroizing<Vec<u8>>,
    receipts: Vec<Receipt>,
    zone: Option<usize>,
    records: usize,
    maximum_sets: usize,
    maximum_bytes: usize,
}

impl Batch {
    pub(super) fn new(maximum_sets: usize, maximum_bytes: usize) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
            receipts: Vec::new(),
            zone: None,
            records: 0,
            maximum_sets,
            maximum_bytes,
        }
    }

    pub(super) fn accepts(&self, zone: usize, zones: &[Zone], bytes: usize) -> bool {
        self.zone
            .is_none_or(|original| zones[original].key.constant_time_eq(&zones[zone].key))
            && bytes <= self.maximum_bytes.saturating_sub(self.bytes.len())
            && !self.full()
    }

    pub(super) fn full(&self) -> bool {
        self.receipts.len() == self.maximum_sets
    }

    pub(super) fn groups(&self) -> usize {
        self.receipts.len()
    }

    pub(super) fn records(&self) -> usize {
        self.records
    }

    pub(super) fn stage(&mut self, zone: usize, group: Group, packed: &[u8]) -> Result<()> {
        if self.full() || packed.len() > self.maximum_bytes.saturating_sub(self.bytes.len()) {
            return Err("complete record-line set cannot fit one original STORE frame".into());
        }
        let records = self
            .records
            .checked_add(group.records.len())
            .ok_or("record-line batch count overflow")?;
        if self.bytes.capacity() == 0 {
            self.bytes.try_reserve_exact(self.maximum_bytes)?;
        }
        self.receipts.try_reserve(1)?;
        self.bytes.extend_from_slice(packed);
        self.records = records;
        self.receipts.push(Receipt {
            label: group.label,
            owner: group.owner,
            first_line: group.start_line,
            last_line: group.end_line,
        });
        self.zone.get_or_insert(zone);
        Ok(())
    }

    fn clear(&mut self) {
        self.bytes.as_mut_slice().zeroize();
        self.bytes.clear();
        self.receipts.clear();
        self.zone = None;
        self.records = 0;
    }
}

pub(super) struct Sender<'a, 'id, W> {
    pub(super) client: &'a mut ns::Client<'id>,
    pub(super) control: &'a mut Control,
    pub(super) failure: &'a mut Failure,
    pub(super) out: &'a mut W,
    pub(super) until: u64,
}

impl<'id, W: Write> Sender<'_, 'id, W> {
    pub(super) async fn flush(&mut self, batch: &mut Batch, zones: &[Zone]) -> Result<()> {
        let Some(zone) = batch.zone else {
            return Ok(());
        };
        let count = u16::try_from(batch.groups())?;
        self.control.gate().await?;
        let operation = self.client.store(
            &zones[zone].key,
            ns::ipc::RecordSets::new(&batch.bytes, count)?,
            true,
            self.until,
        )?;
        self.failure.report.admitted_sets += u64::from(count);
        self.failure.report.pending_store = true;
        self.failure.report.local = None;
        let result = self.observe(operation, batch).await;
        if result.is_err() && self.failure.report.pending_store {
            self.settle_closed(operation, batch).await;
        }
        if result.is_ok() {
            batch.clear();
        }
        result
    }

    async fn observe(&mut self, operation: ns::Operation<'id>, batch: &Batch) -> Result<()> {
        loop {
            match self
                .control
                .drive(self.client.drive(Some(self.control.hard())))
                .await?
            {
                ns::Progress::Completed(completion)
                    if completion.operation == operation && completion.kind == ns::Kind::Store =>
                {
                    let result = completion_result(completion, batch, self.failure);
                    for receipt in &batch.receipts {
                        if let Err(error) = row(
                            self.out,
                            json!({"event":"namestore_recordline_store_result",
                                "first_line":receipt.first_line,"last_line":receipt.last_line,"label":receipt.label,"owner":receipt.owner,
                                "result":self.failure.report.local,"stored_sets":self.failure.report.stored_sets,"stored_records":self.failure.report.stored_records,
                                "failed_sets":self.failure.report.failed_sets,"unknown_sets":self.failure.report.unknown_sets
                            }),
                        ) {
                            self.failure.diagnostic.get_or_insert(error);
                            return result.and(Err(
                                "record-line receipt output failed after actual STORE result"
                                    .into(),
                            ));
                        }
                    }
                    return result;
                }
                ns::Progress::Completed(_) => {
                    return Err("foreign record-line STORE completion".into());
                }
                ns::Progress::Lost { report, cause } => {
                    self.failure.report.close_exposed =
                        self.failure.report.close_exposed.max(report.exposed);
                    self.failure.store_loss.get_or_insert(cause);
                    return Err(
                        "original record-line NAMESTORE source lost; no mutation replay".into(),
                    );
                }
                ns::Progress::Unavailable(error) => return Err(error.into()),
                ns::Progress::WaitDeadline => {
                    return Err("original record-line STORE observation deadline".into());
                }
                ns::Progress::Closed => {
                    return Err("record-line STORE closed before its original outcome".into());
                }
                _ => {}
            }
        }
    }

    async fn settle_closed(&mut self, operation: ns::Operation<'id>, batch: &Batch) {
        if let Some(report) = self.client.close() {
            self.failure.report.close_exposed =
                self.failure.report.close_exposed.max(report.exposed);
        }
        // Closing leaves one original callback to settle and performs no more IO.
        for _ in 0..4 {
            match self.client.drive(Some(Instant::now())).await {
                Ok(ns::Progress::Completed(completion))
                    if completion.operation == operation && completion.kind == ns::Kind::Store =>
                {
                    let _terminal = completion_result(completion, batch, self.failure);
                    break;
                }
                Ok(ns::Progress::Lost { cause, .. }) => {
                    self.failure.store_loss.get_or_insert(cause);
                }
                Ok(ns::Progress::Closed | ns::Progress::WaitDeadline) => break,
                Err(error) => {
                    self.failure.cleanup.get_or_insert(Box::new(error));
                    break;
                }
                _ => {}
            }
        }
        if self.failure.report.pending_store {
            self.failure.report.unknown_sets += batch.groups() as u64;
        }
    }
}

fn completion_result(
    completion: ns::Completion<'_>,
    batch: &Batch,
    failure: &mut Failure,
) -> Result<()> {
    if !failure.report.pending_store {
        return Err("duplicate original record-line STORE result".into());
    }
    let count = batch.groups() as u64;
    match completion.outcome {
        ns::Outcome::Reply(reply) => {
            let ns::ipc::Response::Generic { code, .. } = reply.view()? else {
                return Err("unexpected original record-line STORE reply".into());
            };
            failure.report.pending_store = false;
            failure.report.local = Some(format!("service_code={code}"));
            if code == 0 {
                failure.report.stored_sets += count;
                failure.report.stored_records += batch.records() as u64;
                failure.report.staged_records = 0;
                Ok(())
            } else {
                failure.report.failed_sets += count;
                Err(format!("record-line STORE returned actual code {code}").into())
            }
        }
        ns::Outcome::Local { reason, submission } => {
            failure.report.pending_store = false;
            failure.report.local = Some(format!("{reason:?}, {submission:?}"));
            if matches!(submission, ns::Submission::Unsent) {
                failure.report.unapplied_sets += count;
            } else {
                failure.report.unknown_sets += count;
            }
            Err("record-line STORE retired locally; exposed outcome is not replayed".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namestore::recordline::{Buffers, RecordFlags, RecordType};

    fn zone(owner: &str, byte: u8) -> Result<Zone> {
        let mut material = [byte; 36];
        material[..4].copy_from_slice(&[0, 1, 0, 20]);
        Ok(Zone {
            owner: owner.to_owned(),
            key: ns::SecretKey::from_serialized(&material)?,
        })
    }

    fn address_set(label: &str, owner: &str, line: u64) -> Result<Group> {
        let mut group = Group::new(label, owner, line, 1)?;
        group.push(RecordType::A, u64::MAX, RecordFlags::NONE, &[127, 0, 0, 1])?;
        Ok(group)
    }

    #[test]
    fn packs_complete_sets_for_one_authority_into_a_bounded_frame() -> Result<()> {
        let zones = [zone("first", 3)?, zone("different", 4)?, zone("alias", 3)?];
        let mut buffers = Buffers::new()?;
        let a = address_set("a", "first", 1)?;
        let b = address_set("b", "alias", 3)?;
        let next_length = b.encode(&mut buffers)?;
        let first_length = a.encode(&mut buffers)?;
        let mut batch = Batch::new(2, first_length + next_length);
        batch.stage(0, a, &buffers.sets[..first_length])?;
        assert!(!batch.accepts(1, &zones, next_length));
        assert!(!batch.accepts(2, &zones, next_length + 1));
        assert!(batch.accepts(2, &zones, next_length));
        let length = b.encode(&mut buffers)?;
        batch.stage(2, b, &buffers.sets[..length])?;
        assert!(batch.full());
        assert_eq!(batch.zone, Some(0));
        assert_eq!(batch.records(), 2);
        let packed = ns::ipc::RecordSets::new(&batch.bytes, 2)?;
        let mut labels = packed.iter();
        assert_eq!(
            labels.next().ok_or("missing first label")??.label.bytes(),
            b"a"
        );
        assert_eq!(
            labels.next().ok_or("missing second label")??.label.bytes(),
            b"b"
        );
        assert!(labels.next().is_none());
        Ok(())
    }
}
