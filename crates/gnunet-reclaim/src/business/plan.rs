use super::{
    engine::{Job, Mode, OwnedId, Phase, Rotation},
    memory::Table,
    records::*,
    *,
};
use crate::{
    Attribute, AttributeList, Credential, Identifier, ListLimits, Presentation, PresentationList,
    Ticket, Uri,
    ipc::{Iteration, Request, Response},
};
use gnunet_gnsrecord::{RecordFlags, RecordType};
use gnunet_types::Error;
// A transformation of one original record; retaining its original bytes and
// removing it are distinct, so deleted references cannot reappear by fallback.
enum Rewrite {
    Retain,
    Replace(Blob),
    Remove,
}
impl Job {
    pub(super) fn initialize(&mut self) -> Result<(), Error> {
        match self.mode {
            Mode::StoreAttribute => {
                let Request::StoreAttribute { attribute, .. } = self.request()? else {
                    return Err(Error::Conflict);
                };
                if attribute.id.is_zero() {
                    self.transition(Phase::Scan)
                } else {
                    self.prepare_object(attribute.id)
                }
            }
            Mode::StoreCredential => {
                let Request::StoreCredential { credential, .. } = self.request()? else {
                    return Err(Error::Conflict);
                };
                if credential.id.is_zero() {
                    self.transition(Phase::Scan)
                } else {
                    self.prepare_object(credential.id)
                }
            }
            Mode::DeleteAttribute | Mode::DeleteCredential => self.transition(Phase::Scan),
            Mode::Issue | Mode::Revoke | Mode::Iterate(_) => self.transition(Phase::Public),
            Mode::Consume => {
                let Request::ConsumeTicket { ticket, .. } = self.request()? else {
                    return Err(Error::Conflict);
                };
                self.issuer = Some(capability(ticket)?.1);
                self.transition(Phase::ConsumeAuth)
            }
        }
    }
    pub(super) fn action(&self) -> Result<Action<'_>, Error> {
        Ok(match self.phase {
            Phase::Public => Action::PublicKey { key: self.key()? },
            Phase::Scan => Action::Scan { key: self.key()? },
            Phase::GenerateStore | Phase::GenerateTicket | Phase::GenerateRotation(_) => {
                Action::Identifier
            }
            Phase::Writing(index) => {
                let row = self.changes.get(index).ok_or(Error::Stale)?;
                Action::Store {
                    key: self.key()?,
                    label: row.label.expose(),
                    records: row.view()?,
                }
            }
            Phase::Present(index) => {
                let row = self.rows.get(index).ok_or(Error::Stale)?;
                let credential = row.credential()?.ok_or(Error::NotFound)?;
                let Request::IssueTicket { attributes, .. } = self.request()? else {
                    return Err(Error::Conflict);
                };
                Action::Presentation {
                    credential,
                    selected: attributes,
                }
            }
            Phase::ConsumeAuth => {
                let Request::ConsumeTicket { ticket, .. } = self.request()? else {
                    return Err(Error::Conflict);
                };
                let (label, zone) = capability(ticket)?;
                Action::Lookup {
                    zone,
                    label,
                    record_type: RecordType::new(0),
                }
            }
            Phase::ConsumeRef(index) => {
                let row = self.changes.get(index).ok_or(Error::Stale)?;
                Action::Lookup {
                    zone: self.issuer.ok_or(Error::NotReady)?,
                    label: row.label.expose(),
                    record_type: RecordType::new(0),
                }
            }
            Phase::Idle => return Err(Error::NotReady),
        })
    }
    pub(super) fn result_matches(&self, result: &Completion<'_>) -> bool {
        match result {
            Completion::Failed(_) | Completion::Unknown => true,
            Completion::PublicKey(_) => self.phase == Phase::Public,
            Completion::Identifier(_) => matches!(
                self.phase,
                Phase::GenerateStore | Phase::GenerateTicket | Phase::GenerateRotation(_)
            ),
            Completion::ScanEnd => self.phase == Phase::Scan,
            Completion::Records(_) => {
                matches!(self.phase, Phase::ConsumeAuth | Phase::ConsumeRef(_))
            }
            Completion::Stored(_) => matches!(self.phase, Phase::Writing(_)),
            Completion::Presentation(_) => matches!(self.phase, Phase::Present(_)),
        }
    }
    pub(super) fn apply(&mut self, result: Completion<'_>) -> Result<(), Error> {
        match result {
            Completion::PublicKey(key) => {
                if let Request::RevokeTicket { ticket, .. } = self.request()? {
                    let (label, zone) = capability(ticket)?;
                    if zone != key || label.contains(&b'.') {
                        return Err(Error::Authentication);
                    }
                }
                self.issuer = Some(key);
                self.transition(Phase::Scan)
            }
            Completion::ScanEnd => self.scan_finished(),
            Completion::Identifier(id) => {
                self.fresh_identifier(id)?;
                match self.phase {
                    Phase::GenerateStore => self.prepare_object(id),
                    Phase::GenerateTicket => {
                        self.ticket = Some(new_ticket(
                            &self.quota,
                            id,
                            self.issuer.ok_or(Error::NotReady)?,
                        )?);
                        self.prepare_ticket_store()
                    }
                    Phase::GenerateRotation(index) => {
                        self.rotations.get_mut(index).ok_or(Error::Stale)?.new =
                            Some(OwnedId::new(id));
                        self.next_rotation(index + 1)
                    }
                    _ => Err(Error::Conflict),
                }
            }
            Completion::Presentation(p) => {
                let Phase::Present(index) = self.phase else {
                    return Err(Error::Conflict);
                };
                let credential = self
                    .rows
                    .get(index)
                    .ok_or(Error::Stale)?
                    .credential()?
                    .ok_or(Error::NotFound)?;
                if p.credential != credential.id || p.kind != credential.kind {
                    return Err(Error::Authentication);
                }
                let owned = presentation_blob(&self.quota, p)?;
                self.presentations.push(owned)?;
                self.next_presentation()
            }
            Completion::Records(records) => match self.phase {
                Phase::ConsumeAuth => self.consume_authorization(records),
                Phase::ConsumeRef(index) => self.consume_attribute(index, records),
                _ => Err(Error::Conflict),
            },
            Completion::Stored(code) => {
                if code != 0 {
                    return Err(Error::Io);
                }
                self.committed = self.committed.checked_add(1).ok_or(Error::Overflow)?;
                let Phase::Writing(index) = self.phase else {
                    return Err(Error::Conflict);
                };
                if index + 1 < self.changes.len() {
                    self.transition(Phase::Writing(index + 1))
                } else {
                    self.transition(Phase::Idle)?;
                    self.success()
                }
            }
            Completion::Failed(error) => Err(error),
            Completion::Unknown => Err(Error::OutcomeUnknown),
        }
    }
    fn scan_finished(&mut self) -> Result<(), Error> {
        if matches!(
            self.mode,
            Mode::DeleteAttribute | Mode::DeleteCredential | Mode::Revoke
        ) {
            if self.snapshot.is_some() {
                return Err(Error::Conflict);
            }
            self.snapshot = Some(super::snapshot::Snapshot::build(
                &self.quota,
                &self.rows,
                &self.work_left,
            )?);
        } else {
            let records = self.rows.iter().try_fold(0usize, |n, row| {
                n.checked_add(usize::from(row.count)).ok_or(Error::Overflow)
            })?;
            let multiplier = if self.mode == Mode::Issue {
                let count = self
                    .attributes_requested()?
                    .len()
                    .checked_add(1)
                    .ok_or(Error::Overflow)?;
                count
                    .checked_mul(count)
                    .and_then(|n| n.checked_mul(4))
                    .ok_or(Error::Overflow)?
            } else if matches!(self.mode, Mode::Iterate(_)) {
                0
            } else {
                1
            };
            self.work(
                records
                    .checked_mul(multiplier)
                    .and_then(|n| n.checked_add(self.rows.len()))
                    .ok_or(Error::Overflow)?,
            )?;
        }
        match self.mode {
            Mode::StoreAttribute | Mode::StoreCredential => self.transition(Phase::GenerateStore),
            Mode::DeleteAttribute | Mode::DeleteCredential => self.prepare_deletion(),
            Mode::Issue => self.issue_after_scan(),
            Mode::Revoke => self.revoke_after_scan(),
            Mode::Iterate(_) => {
                self.transition(Phase::Idle)?;
                self.iteration_output()
            }
            Mode::Consume => Err(Error::Conflict),
        }
    }
    fn fresh_identifier(&self, id: Identifier) -> Result<(), Error> {
        self.work(
            self.rows
                .len()
                .checked_add(self.rotations.len())
                .ok_or(Error::Overflow)?,
        )?;
        if id.is_zero() {
            return Err(Error::InvalidInput);
        }
        let mut label = [0; IDENTIFIER_LABEL_BYTES];
        identifier_label(id, &mut label)?;
        if self.rows.iter().any(|r| r.label.expose() == label)
            || self
                .rotations
                .iter()
                .any(|r| r.new.as_ref().is_some_and(|n| n.value() == id))
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn prepare_object(&mut self, id: Identifier) -> Result<(), Error> {
        let mut label = [0; IDENTIFIER_LABEL_BYTES];
        identifier_label(id, &mut label)?;
        let row = match self.request()? {
            Request::StoreAttribute {
                mut attribute,
                expiration,
                ..
            } => {
                attribute.id = id;
                let data = attribute_blob(&self.quota, attribute)?;
                Row::build(
                    &self.quota,
                    &label,
                    &[object_record(
                        RecordType::RECLAIM_ATTRIBUTE,
                        expiration.as_micros(),
                        data.expose(),
                    )],
                )?
            }
            Request::StoreCredential {
                mut credential,
                expiration,
                ..
            } => {
                credential.id = id;
                let data = credential_blob(&self.quota, credential)?;
                Row::build(
                    &self.quota,
                    &label,
                    &[object_record(
                        RecordType::RECLAIM_CREDENTIAL,
                        expiration.as_micros(),
                        data.expose(),
                    )],
                )?
            }
            _ => return Err(Error::Conflict),
        };
        self.changes.push(row)?;
        self.transition(Phase::Writing(0))
    }
    fn attributes_requested(&self) -> Result<AttributeList<'_>, Error> {
        if let Request::IssueTicket { attributes, .. } = self.request()? {
            Ok(attributes)
        } else {
            Err(Error::Conflict)
        }
    }
    fn issue_after_scan(&mut self) -> Result<(), Error> {
        // An exact set match reuses a real observed capability. Prefix matches,
        // duplicate refs or extra disclosed attributes are never treated as equal.
        let requested = self.attributes_requested()?;
        for attribute in requested.iter() {
            let a = attribute;
            if a.id.is_zero() {
                return Err(Error::InvalidInput);
            }
            let mut seen = 0;
            for other in requested.iter() {
                if other.id == a.id {
                    seen += 1
                }
            }
            if seen != 1 {
                return Err(Error::Conflict);
            }
        }
        if let Some(index) = self.matching_ticket()? {
            let mut ticket = None;
            let mut presentations = Table::new(&self.quota, self.quota.limits.items)?;
            for record in self.rows[index].view()?.records().iter() {
                let r = record?;
                if r.record_type == RecordType::RECLAIM_TICKET {
                    ticket = Some(Blob::copy(&self.quota, r.data)?)
                } else if r.record_type == RecordType::RECLAIM_PRESENTATION {
                    presentations.push(presentation_blob(
                        &self.quota,
                        Presentation::decode(r.data)?,
                    )?)?
                }
            }
            self.ticket = ticket;
            self.presentations = presentations;
            self.transition(Phase::Idle)?;
            return self.success();
        }
        self.next_presentation()
    }
    fn matching_ticket(&self) -> Result<Option<usize>, Error> {
        let Request::IssueTicket {
            uri, attributes, ..
        } = self.request()?
        else {
            return Err(Error::Conflict);
        };
        for (index, row) in self.rows.iter().enumerate() {
            let (mut ticket, mut rp, mut refs, mut pres) = (None, None, 0usize, 0usize);
            let mut matching = true;
            for r in row.view()?.records().iter() {
                let r = r?;
                match r.record_type {
                    RecordType::RECLAIM_TICKET => {
                        let parsed = Ticket::decode(r.data)?;
                        let (name, zone) = capability(parsed)?;
                        if Some(zone) != self.issuer || name != row.label.expose() {
                            matching = false
                        }
                        ticket = Some(parsed)
                    }
                    RecordType::TXT => {
                        if rp.is_some() {
                            matching = false
                        }
                        rp = Some(r.data)
                    }
                    RecordType::RECLAIM_ATTRIBUTE_REF => {
                        let id = Identifier::decode(r.data)?;
                        refs += 1;
                        if !attributes.iter().any(|a| a.id == id) {
                            matching = false
                        }
                    }
                    RecordType::RECLAIM_PRESENTATION => {
                        let p = Presentation::decode(r.data)?;
                        if !attributes
                            .iter()
                            .any(|a| !a.credential.is_zero() && a.credential == p.credential)
                        {
                            matching = false
                        }
                        pres += 1
                    }
                    _ => {}
                }
            }
            if !matching || ticket.is_none() || rp != Some(uri.expose()) || refs != attributes.len()
            {
                continue;
            }
            let mut required = 0;
            for (i, a) in attributes.iter().enumerate() {
                if a.credential.is_zero() {
                    continue;
                }
                if !attributes
                    .iter()
                    .take(i)
                    .any(|b| b.credential == a.credential)
                {
                    required += 1
                }
            }
            if pres != required {
                continue;
            }
            // Validate that each required credential and each selected reference
            // appears exactly once, not merely the total count.
            for a in attributes.iter() {
                let (mut ar, mut pr) = (0, 0);
                for r in row.view()?.records().iter() {
                    let r = r?;
                    if r.record_type == RecordType::RECLAIM_ATTRIBUTE_REF
                        && Identifier::decode(r.data)? == a.id
                    {
                        ar += 1
                    }
                    if r.record_type == RecordType::RECLAIM_PRESENTATION
                        && Presentation::decode(r.data)?.credential == a.credential
                    {
                        pr += 1
                    }
                }
                if ar != 1 || !a.credential.is_zero() && pr != 1 {
                    matching = false
                }
            }
            if matching {
                return Ok(Some(index));
            }
        }
        Ok(None)
    }
    fn next_presentation(&mut self) -> Result<(), Error> {
        let mut next = None;
        for a in self.attributes_requested()?.iter() {
            if a.credential.is_zero() {
                continue;
            }
            if self.presentations.iter().any(|p| {
                Presentation::decode(p.expose()).is_ok_and(|p| p.credential == a.credential)
            }) {
                continue;
            }
            let mut found = None;
            for (index, row) in self.rows.iter().enumerate() {
                if row.credential()?.is_some_and(|c| c.id == a.credential) {
                    found = Some(index);
                    break;
                }
            }
            next = Some(found.ok_or(Error::NotFound)?);
            break;
        }
        self.transition(next.map_or(Phase::GenerateTicket, Phase::Present))
    }
    fn prepare_ticket_store(&mut self) -> Result<(), Error> {
        let ticket = Ticket::decode(self.ticket.as_ref().ok_or(Error::NotReady)?.expose())?;
        let (label, _) = capability(ticket)?;
        let Request::IssueTicket {
            uri, attributes, ..
        } = self.request()?
        else {
            return Err(Error::Conflict);
        };
        let mut records = Table::new(&self.quota, self.quota.limits.records)?;
        let mut identifiers = Table::new(&self.quota, self.quota.limits.items)?;
        for a in attributes.iter() {
            identifiers.push(Blob::copy(&self.quota, a.id.bytes())?)?;
        }
        for id in identifiers.iter() {
            records.push(object_record(
                RecordType::RECLAIM_ATTRIBUTE_REF,
                self.quota.limits.refresh_micros,
                id.expose(),
            ))?;
        }
        for p in self.presentations.iter() {
            records.push(object_record(
                RecordType::RECLAIM_PRESENTATION,
                self.quota.limits.refresh_micros,
                p.expose(),
            ))?;
        }
        let mut private = object_record(
            RecordType::RECLAIM_TICKET,
            self.quota.limits.refresh_micros,
            self.ticket.as_ref().ok_or(Error::NotReady)?.expose(),
        );
        private.flags = RecordFlags::RELATIVE_EXPIRATION.union(RecordFlags::PRIVATE);
        records.push(private)?;
        records.push(object_record(
            RecordType::TXT,
            self.quota.limits.refresh_micros,
            uri.expose(),
        ))?;
        let row = Row::build(&self.quota, label, &records)?;
        drop(records);
        drop(identifiers);
        self.changes.push(row)?;
        self.transition(Phase::Writing(0))
    }
    fn surviving_object(&self, kind: RecordType, id: Identifier) -> Result<bool, Error> {
        let snapshot = self.snapshot.as_ref().ok_or(Error::NotReady)?;
        let Some(slot) = snapshot.find(id, &self.work_left)? else {
            return Ok(false);
        };
        let bit = match kind {
            RecordType::RECLAIM_ATTRIBUTE => super::snapshot::ATTRIBUTE,
            RecordType::RECLAIM_CREDENTIAL => super::snapshot::CREDENTIAL,
            _ => return Ok(false),
        };
        let object = snapshot.object(slot)?;
        Ok(!object.removed && object.kinds & bit != 0)
    }
    fn row_records<'a>(
        &self,
        row: &'a Row,
    ) -> Result<gnunet_wire::official::namestore::Records<'a>, Error> {
        // Records::new validates the full explicit-count serialization before
        // its iterator is used; count that traversal as well as visited items.
        self.work(usize::from(row.count))?;
        row.view()
    }
    fn final_row(
        &self,
        label: &[u8],
        records: &[gnunet_gnsrecord::RecordData<'_>],
    ) -> Result<Row, Error> {
        // Row::build sizes once; serialization sizes again before writing each
        // record. Payload extents remain independently bounded by frame/Quota.
        self.work(
            records
                .len()
                .checked_mul(3)
                .and_then(|n| n.checked_add(1))
                .ok_or(Error::Overflow)?,
        )?;
        Row::build(&self.quota, label, records)
    }
    fn is_removed(&self, id: Identifier) -> Result<bool, Error> {
        let snapshot = self.snapshot.as_ref().ok_or(Error::NotReady)?;
        Ok(match snapshot.find(id, &self.work_left)? {
            Some(slot) => snapshot.object(slot)?.removed,
            None => snapshot
                .missing_removed
                .as_ref()
                .is_some_and(|old| old.value() == id),
        })
    }
    fn remove_group(&mut self, id: Identifier) -> Result<(), Error> {
        if self.is_removed(id)? {
            return Ok(());
        }
        let slot = self
            .snapshot
            .as_ref()
            .ok_or(Error::NotReady)?
            .find(id, &self.work_left)?;
        self.removed.push(OwnedId::new(id))?;
        let snapshot = self.snapshot.as_mut().ok_or(Error::NotReady)?;
        if let Some(slot) = slot {
            snapshot.object_mut(slot)?.removed = true;
        } else {
            if snapshot.missing_removed.is_some() {
                return Err(Error::Conflict);
            }
            snapshot.missing_removed = Some(OwnedId::new(id));
        }
        Ok(())
    }
    fn close_removed_dependencies(&mut self, purge_orphans: bool) -> Result<(), Error> {
        if purge_orphans {
            for row in 0..self.rows.len() {
                self.work(1)?;
                let snapshot = self.snapshot.as_ref().ok_or(Error::NotReady)?;
                let indexed = snapshot.rows.get(row).ok_or(Error::Stale)?;
                if indexed.orphan {
                    let slot = indexed.object.ok_or(Error::Malformed)?;
                    let id = snapshot.object(slot)?.id();
                    self.remove_group(id)?;
                }
            }
        }
        let mut cursor = 0;
        while cursor < self.removed.len() {
            self.work(1)?;
            let id = self.removed[cursor].value();
            cursor += 1;
            let snapshot = self.snapshot.as_ref().ok_or(Error::NotReady)?;
            let Some(slot) = snapshot.find(id, &self.work_left)? else {
                continue;
            };
            let object = snapshot.object(slot)?;
            if object.kinds & super::snapshot::CREDENTIAL == 0 {
                continue;
            }
            let mut edge = object.dependents;
            while let Some(index) = edge {
                self.work(1)?;
                let snapshot = self.snapshot.as_ref().ok_or(Error::NotReady)?;
                let current = *snapshot.edges.get(index).ok_or(Error::Stale)?;
                edge = current.next;
                let slot = snapshot
                    .rows
                    .get(current.row)
                    .ok_or(Error::Stale)?
                    .object
                    .ok_or(Error::Malformed)?;
                let id = snapshot.object(slot)?.id();
                self.remove_group(id)?;
            }
        }
        Ok(())
    }
    fn mutation_ready(&mut self) -> Result<(), Error> {
        // The final rows now own every exact STORE body. No original snapshot
        // or dependency/rotation lookup is needed while native effects settle.
        self.transition(Phase::Writing(0))?;
        self.snapshot = None;
        self.rows.release();
        self.removed.release();
        self.rotations.release();
        Ok(())
    }
    fn prepare_deletion(&mut self) -> Result<(), Error> {
        let target = match self.request()? {
            Request::DeleteAttribute { attribute, .. } => attribute.id,
            Request::DeleteCredential { credential, .. } => credential.id,
            _ => return Err(Error::Conflict),
        };
        if target.is_zero() {
            return Err(Error::InvalidInput);
        }
        if !self.changes.is_empty() {
            return Err(Error::Conflict);
        }
        let mut target_label = [0; IDENTIFIER_LABEL_BYTES];
        identifier_label(target, &mut target_label)?;
        // A NAMESTORE deletion removes the complete label, including any
        // colocated objects. Compute that final set before generating writes.
        self.remove_group(target)?;
        self.close_removed_dependencies(true)?;
        for id in self.removed.iter() {
            self.work(1)?;
            let mut label = [0; IDENTIFIER_LABEL_BYTES];
            identifier_label(id.value(), &mut label)?;
            self.changes.push(self.final_row(&label, &[])?)?;
        }
        for (index, row) in self.rows.iter().enumerate() {
            self.work(1)?;
            let snapshot = self.snapshot.as_ref().ok_or(Error::NotReady)?;
            if let Some(slot) = snapshot.rows.get(index).ok_or(Error::Stale)?.object
                && snapshot.object(slot)?.removed
            {
                // This label's sole final change is DELETE. In particular a
                // colocated TICKET/REF cannot bring its old objects back.
                continue;
            }
            // The original target may be a pure authorization/extension group
            // without an object payload; its canonical label still stays dead.
            if row.label.expose() == target_label {
                continue;
            }
            let mut changed = false;
            let mut kept = Table::new(&self.quota, self.quota.limits.records)?;
            for record in self.row_records(row)?.records().iter() {
                self.work(1)?;
                let record = record?;
                let retain = match record.record_type {
                    RecordType::RECLAIM_ATTRIBUTE_REF => {
                        let id = Identifier::decode(record.data)?;
                        self.surviving_object(RecordType::RECLAIM_ATTRIBUTE, id)?
                    }
                    RecordType::RECLAIM_PRESENTATION => {
                        let presentation = Presentation::decode(record.data)?;
                        self.surviving_object(
                            RecordType::RECLAIM_CREDENTIAL,
                            presentation.credential,
                        )?
                    }
                    _ => true,
                };
                if retain {
                    kept.push(record)?;
                } else {
                    changed = true;
                }
            }
            if changed {
                self.changes
                    .push(self.final_row(row.label.expose(), &kept)?)?;
            }
        }
        self.mutation_ready()
    }
    fn revoke_after_scan(&mut self) -> Result<(), Error> {
        let index = {
            let Request::RevokeTicket { ticket, .. } = self.request()? else {
                return Err(Error::Conflict);
            };
            let (label, zone) = capability(ticket)?;
            if Some(zone) != self.issuer {
                return Err(Error::Authentication);
            }
            let mut found = None;
            for (index, row) in self.rows.iter().enumerate() {
                self.work(1)?;
                if row.label.expose() == label {
                    found = Some(index);
                    break;
                }
            }
            found.ok_or(Error::NotFound)?
        };
        let snapshot = self.snapshot.as_ref().ok_or(Error::NotReady)?;
        if let Some(slot) = snapshot.rows.get(index).ok_or(Error::Stale)?.object {
            let id = snapshot.object(slot)?.id();
            self.remove_group(id)?;
            self.close_removed_dependencies(false)?;
        }
        for record in self.row_records(&self.rows[index])?.records().iter() {
            self.work(1)?;
            let record = record?;
            if record.record_type != RecordType::RECLAIM_ATTRIBUTE_REF {
                continue;
            }
            let old = Identifier::decode(record.data)?;
            let snapshot = self.snapshot.as_ref().ok_or(Error::NotReady)?;
            let Some(slot) = snapshot.find(old, &self.work_left)? else {
                continue;
            };
            let object = snapshot.object(slot)?;
            if object.removed || object.rotation.is_some() {
                continue;
            }
            let rotation = self.rotations.len();
            self.rotations.push(Rotation {
                old: OwnedId::new(old),
                new: None,
                moves_credential: object.kinds & super::snapshot::CREDENTIAL != 0,
            })?;
            self.snapshot
                .as_mut()
                .ok_or(Error::NotReady)?
                .object_mut(slot)?
                .rotation = Some(rotation);
        }
        self.next_rotation(0)
    }
    fn next_rotation(&mut self, index: usize) -> Result<(), Error> {
        if index < self.rotations.len() {
            self.transition(Phase::GenerateRotation(index))
        } else {
            self.prepare_revocation()
        }
    }
    fn rotated_identifier(
        &self,
        old: Identifier,
        credential_only: bool,
    ) -> Result<Identifier, Error> {
        let snapshot = self.snapshot.as_ref().ok_or(Error::NotReady)?;
        let Some(slot) = snapshot.find(old, &self.work_left)? else {
            return Ok(old);
        };
        let Some(index) = snapshot.object(slot)?.rotation else {
            return Ok(old);
        };
        let rotation = self.rotations.get(index).ok_or(Error::Stale)?;
        if credential_only && !rotation.moves_credential {
            return Ok(old);
        }
        Ok(rotation.new.as_ref().ok_or(Error::NotReady)?.value())
    }
    // Materialize the final contents of one surviving destination exactly once.
    // Temporary transformed payloads stay quota-owned until Row::build has
    // copied their exact record spans; unknown bytes/duplicates/expiry/flags and
    // source order remain unchanged. No provider mutation has started yet.
    fn revocation_row(
        &self,
        row: &Row,
        destination: &[u8],
        moved: Option<(Identifier, Identifier)>,
    ) -> Result<Option<Row>, Error> {
        let mut rewritten = Table::new(&self.quota, self.quota.limits.records)?;
        let mut changed = false;
        for record in self.row_records(row)?.records().iter() {
            self.work(1)?;
            let record = record?;
            let data = match record.record_type {
                RecordType::RECLAIM_ATTRIBUTE => {
                    let mut attribute = Attribute::decode(record.data)?;
                    let original_id = attribute.id;
                    let original_credential = attribute.credential;
                    if self.is_removed(original_id)? || self.is_removed(original_credential)? {
                        // Dependency closure must remove this entire group,
                        // never turn it into an orphan at a fresh location.
                        return Err(Error::Conflict);
                    }
                    if let Some((old, new)) = moved {
                        if original_id != old {
                            return Err(Error::Malformed);
                        }
                        attribute.id = new;
                    }
                    attribute.credential = self.rotated_identifier(attribute.credential, true)?;
                    if attribute.id != original_id || attribute.credential != original_credential {
                        Rewrite::Replace(attribute_blob(&self.quota, attribute)?)
                    } else {
                        Rewrite::Retain
                    }
                }
                RecordType::RECLAIM_CREDENTIAL => {
                    let mut credential = Credential::decode(record.data)?;
                    if let Some((old, new)) = moved {
                        if credential.id != old {
                            return Err(Error::Malformed);
                        }
                        credential.id = new;
                        Rewrite::Replace(credential_blob(&self.quota, credential)?)
                    } else {
                        Rewrite::Retain
                    }
                }
                RecordType::RECLAIM_ATTRIBUTE_REF => {
                    let old = Identifier::decode(record.data)?;
                    if self.is_removed(old)? {
                        Rewrite::Remove
                    } else {
                        let new = self.rotated_identifier(old, false)?;
                        if new != old {
                            Rewrite::Replace(Blob::copy(&self.quota, new.bytes())?)
                        } else {
                            Rewrite::Retain
                        }
                    }
                }
                RecordType::RECLAIM_PRESENTATION => {
                    let mut presentation = Presentation::decode(record.data)?;
                    if self.is_removed(presentation.credential)? {
                        Rewrite::Remove
                    } else {
                        let new = self.rotated_identifier(presentation.credential, true)?;
                        if new != presentation.credential {
                            presentation.credential = new;
                            Rewrite::Replace(presentation_blob(&self.quota, presentation)?)
                        } else {
                            Rewrite::Retain
                        }
                    }
                }
                _ => Rewrite::Retain,
            };
            changed |= !matches!(&data, Rewrite::Retain);
            rewritten.push(data)?;
        }
        if !changed {
            return Ok(None);
        }
        let mut records = Table::new(&self.quota, self.quota.limits.records)?;
        for (index, record) in self.row_records(row)?.records().iter().enumerate() {
            self.work(1)?;
            let mut record = record?;
            match rewritten.get(index).ok_or(Error::Stale)? {
                Rewrite::Retain => {}
                Rewrite::Replace(data) => record.data = data.expose(),
                Rewrite::Remove => continue,
            }
            records.push(record)?;
        }
        self.final_row(destination, &records).map(Some)
    }
    fn prepare_revocation(&mut self) -> Result<(), Error> {
        let Request::RevokeTicket { ticket, .. } = self.request()? else {
            return Err(Error::Conflict);
        };
        if !self.changes.is_empty() {
            return Err(Error::Conflict);
        }
        let ticket_label = Blob::copy(&self.quota, capability(ticket)?.0)?;
        self.changes
            .push(self.final_row(ticket_label.expose(), &[])?)?;
        for rotation in self.rotations.iter() {
            let old = rotation.old.value();
            let new = rotation.new.as_ref().ok_or(Error::NotReady)?.value();
            let mut old_label = [0; IDENTIFIER_LABEL_BYTES];
            identifier_label(old, &mut old_label)?;
            self.work(1)?;
            let snapshot = self.snapshot.as_ref().ok_or(Error::NotReady)?;
            let slot = snapshot
                .find(old, &self.work_left)?
                .ok_or(Error::NotFound)?;
            let row = self
                .rows
                .get(snapshot.object(slot)?.row)
                .ok_or(Error::Stale)?;
            let mut new_label = [0; IDENTIFIER_LABEL_BYTES];
            identifier_label(new, &mut new_label)?;
            let moved = self
                .revocation_row(row, &new_label, Some((old, new)))?
                .ok_or(Error::Malformed)?;
            self.changes.push(moved)?;
            // The original new-location whole STORE must be acknowledged before
            // exposing this DELETE. Failure/Unknown fences the unchanged Job.
            self.changes.push(self.final_row(&old_label, &[])?)?;
        }
        for id in self.removed.iter() {
            self.work(1)?;
            let mut label = [0; IDENTIFIER_LABEL_BYTES];
            identifier_label(id.value(), &mut label)?;
            if label != ticket_label.expose() {
                self.changes.push(self.final_row(&label, &[])?)?;
            }
        }
        for (index, row) in self.rows.iter().enumerate() {
            self.work(1)?;
            let snapshot = self.snapshot.as_ref().ok_or(Error::NotReady)?;
            let selected = match snapshot.rows.get(index).ok_or(Error::Stale)?.object {
                Some(slot) => {
                    let object = snapshot.object(slot)?;
                    object.removed || object.rotation.is_some()
                }
                None => false,
            };
            if row.label.expose() == ticket_label.expose() || selected {
                // Deleted/migrated source labels have their unique final
                // DELETE above. Never rebuild them from the original snapshot.
                continue;
            }
            if let Some(final_row) = self.revocation_row(row, row.label.expose(), None)? {
                self.changes.push(final_row)?;
            }
        }
        self.mutation_ready()
    }
    fn consume_authorization(
        &mut self,
        records: gnunet_wire::official::namestore::Records<'_>,
    ) -> Result<(), Error> {
        if usize::from(records.count()) > self.quota.limits.records {
            return Err(Error::Capacity);
        }
        let count = usize::from(records.count());
        self.work(
            count
                .checked_add(1)
                .and_then(|n| n.checked_mul(n))
                .and_then(|n| n.checked_mul(4))
                .ok_or(Error::Overflow)?,
        )?;
        let Request::ConsumeTicket { uri, .. } = self.request()? else {
            return Err(Error::Conflict);
        };
        let mut rp = None;
        let mut references = Table::new(&self.quota, self.quota.limits.items)?;
        let mut presentations = Table::new(&self.quota, self.quota.limits.items)?;
        for record in records.records().iter() {
            let r = record?;
            match r.record_type {
                RecordType::TXT => {
                    if rp.is_some() {
                        return Err(Error::Malformed);
                    }
                    rp = Some(r.data)
                }
                RecordType::RECLAIM_ATTRIBUTE_REF => {
                    let id = Identifier::decode(r.data)?;
                    if id.is_zero()
                        || references
                            .iter()
                            .any(|reference: &OwnedId| reference.value() == id)
                    {
                        return Err(Error::Malformed);
                    }
                    references.push(OwnedId::new(id))?;
                }
                RecordType::RECLAIM_PRESENTATION => {
                    let p = Presentation::decode(r.data)?;
                    if presentations.iter().any(|b: &Blob| {
                        Presentation::decode(b.expose()).is_ok_and(|q| q.credential == p.credential)
                    }) {
                        return Err(Error::Malformed);
                    }
                    presentations.push(presentation_blob(&self.quota, p)?)?;
                }
                _ => {}
            }
        }
        // Compare exact bounded TXT bytes; do not inherit C strcmp overread or
        // prefix audience matching. No cryptographic JWT assertion is added.
        if rp != Some(uri.expose()) {
            return Err(Error::Authentication);
        }
        let mut lookups = Table::new(&self.quota, self.quota.limits.items)?;
        for id in references.iter() {
            let mut name = [0; IDENTIFIER_LABEL_BYTES];
            identifier_label(id.value(), &mut name)?;
            lookups.push(Row::build(&self.quota, &name, &[])?)?;
        }
        self.references = references;
        self.presentations = presentations;
        self.changes = lookups;
        if self.references.is_empty() {
            self.transition(Phase::Idle)?;
            self.success()
        } else {
            self.transition(Phase::ConsumeRef(0))
        }
    }
    fn consume_attribute(
        &mut self,
        index: usize,
        records: gnunet_wire::official::namestore::Records<'_>,
    ) -> Result<(), Error> {
        if usize::from(records.count()) > self.quota.limits.records {
            return Err(Error::Capacity);
        }
        self.work(
            usize::from(records.count())
                .checked_add(1)
                .ok_or(Error::Overflow)?,
        )?;
        let expected = self.references.get(index).ok_or(Error::Stale)?.value();
        for record in records.records().iter() {
            let r = record?;
            if r.record_type != RecordType::RECLAIM_ATTRIBUTE {
                continue;
            }
            let attribute = Attribute::decode(r.data)?;
            if attribute.id != expected {
                return Err(Error::Malformed);
            }
            self.attributes
                .push(attribute_blob(&self.quota, attribute)?)?;
        }
        // An actually empty scoped result contributes no fabricated attribute.
        if index + 1 < self.references.len() {
            self.transition(Phase::ConsumeRef(index + 1))
        } else {
            self.transition(Phase::Idle)?;
            self.success()
        }
    }
    pub(super) fn success(&mut self) -> Result<(), Error> {
        let rid = self.request_id()?;
        let bytes = match self.mode {
            Mode::StoreAttribute
            | Mode::StoreCredential
            | Mode::DeleteAttribute
            | Mode::DeleteCredential => {
                self.encode_response(Response::Success { rid, result: 1 })?
            }
            Mode::Revoke => self.encode_response(Response::Revoked { rid, result: 1 })?,
            Mode::Issue => {
                let list = serialized_list(&self.quota, &self.presentations)?;
                let presentations = PresentationList::new(list.expose(), ListLimits::IPC)?;
                let ticket = Ticket::decode(self.ticket.as_ref().ok_or(Error::NotReady)?.expose())?;
                self.encode_response(Response::Ticket {
                    rid,
                    ticket: Some(ticket),
                    uri: None,
                    presentations,
                })?
            }
            Mode::Consume => {
                let a = serialized_list(&self.quota, &self.attributes)?;
                let p = serialized_list(&self.quota, &self.presentations)?;
                self.encode_response(Response::Consumed {
                    rid,
                    result: 1,
                    reserved: 0,
                    identity: self.issuer,
                    attributes: AttributeList::new(a.expose(), ListLimits::IPC)?,
                    presentations: PresentationList::new(p.expose(), ListLimits::IPC)?,
                })?
            }
            Mode::Iterate(_) => return Err(Error::Conflict),
        };
        self.install_output(bytes, true)
    }
    fn encode_response(&self, response: Response<'_>) -> Result<Blob, Error> {
        Blob::encode(&self.quota, response.encoded_len()?, |out| {
            response.encode(out)
        })
    }
    fn install_output(&mut self, bytes: Blob, final_item: bool) -> Result<(), Error> {
        if self.output.is_some() {
            return Err(Error::WouldBlock);
        }
        self.serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        self.output = Some(super::engine::PendingOutput {
            token: Output {
                domain: self.domain.clone(),
                serial: self.serial,
            },
            bytes,
            stage: 0,
            exposed: 0,
            final_item,
        });
        Ok(())
    }
    pub(super) fn fail(&mut self, error: Error) -> Result<(), Error> {
        if self.end.is_some() {
            return Ok(());
        }
        self.end = Some(End::Failed(error));
        self.phase = Phase::Idle;
        self.pending = None;
        self.rows.clear();
        self.changes.clear();
        self.attributes.clear();
        self.presentations.clear();
        self.references.clear();
        self.rotations.clear();
        self.removed.clear();
        self.snapshot = None;
        self.ticket = None;
        if matches!(self.mode, Mode::Iterate(_)) {
            // No error field exists in the iterator's normal END. Its host must
            // close the original app source; inventing END would claim a real
            // complete snapshot that the provider never supplied.
            return Ok(());
        }
        let rid = self.request_id()?;
        let response = match self.mode {
            Mode::Issue => Response::Ticket {
                rid,
                ticket: None,
                uri: None,
                presentations: PresentationList::empty(),
            },
            Mode::Revoke => Response::Revoked {
                rid,
                result: u32::MAX,
            },
            Mode::Consume => Response::Consumed {
                rid,
                result: if error == Error::Authentication {
                    0
                } else {
                    u32::MAX
                },
                reserved: 0,
                identity: self.issuer,
                attributes: AttributeList::empty(),
                presentations: PresentationList::empty(),
            },
            _ => Response::Success { rid, result: -1 },
        };
        let bytes = self.encode_response(response)?;
        self.install_output(bytes, true)
    }
    pub(super) fn iteration_output(&mut self) -> Result<(), Error> {
        let Mode::Iterate(kind) = self.mode else {
            return Err(Error::Conflict);
        };
        if self.credit == 0 || self.output.is_some() || self.end.is_some() {
            return Ok(());
        }
        let rid = self.request_id()?;
        while self.cursor.0 < self.rows.len() {
            let row = &self.rows[self.cursor.0];
            let mut found = None;
            if kind == Iteration::Tickets {
                if self.cursor.1 == 0 {
                    let (mut ticket, mut uri) = (None, None);
                    for r in self.row_records(row)?.records().iter() {
                        self.work(1)?;
                        let r = r?;
                        if r.record_type == RecordType::RECLAIM_TICKET {
                            ticket = Some(Ticket::decode(r.data)?)
                        } else if r.record_type == RecordType::TXT {
                            uri = Some(Uri::new(r.data)?);
                        }
                    }
                    if let (Some(ticket), Some(uri)) = (ticket, uri) {
                        found = Some(Response::Ticket {
                            rid,
                            ticket: Some(ticket),
                            uri: Some(uri),
                            presentations: PresentationList::empty(),
                        });
                    }
                }
                self.cursor.1 = usize::from(row.count);
            } else {
                self.work(self.cursor.1.checked_add(1).ok_or(Error::Overflow)?)?;
                let record = self
                    .row_records(row)?
                    .records()
                    .iter()
                    .nth(self.cursor.1)
                    .transpose()?;
                if let Some(record) = record {
                    self.cursor.1 += 1;
                    match (kind, record.record_type) {
                        (Iteration::Attributes, RecordType::RECLAIM_ATTRIBUTE) => {
                            found = Some(Response::Attribute {
                                rid,
                                reserved: 0,
                                credential_len: 0,
                                identity: self.issuer,
                                attribute: Some(Attribute::decode(record.data)?),
                            })
                        }
                        (Iteration::Credentials, RecordType::RECLAIM_CREDENTIAL) => {
                            found = Some(Response::Credential {
                                rid,
                                identity: self.issuer,
                                credential: Some(Credential::decode(record.data)?),
                            })
                        }
                        _ => {}
                    }
                } else {
                    self.cursor.1 = usize::from(row.count);
                }
            }
            let output = found.map(|r| self.encode_response(r)).transpose()?;
            if self.cursor.1 >= usize::from(row.count) {
                self.cursor = (self.cursor.0 + 1, 0);
            }
            if let Some(bytes) = output {
                self.credit -= 1;
                return self.install_output(bytes, false);
            }
        }
        let response = match kind {
            Iteration::Attributes => Response::Attribute {
                rid,
                reserved: 0,
                credential_len: 0,
                identity: None,
                attribute: None,
            },
            Iteration::Credentials => Response::Credential {
                rid,
                identity: None,
                credential: None,
            },
            Iteration::Tickets => Response::Ticket {
                rid,
                ticket: None,
                uri: None,
                presentations: PresentationList::empty(),
            },
        };
        let bytes = self.encode_response(response)?;
        self.install_output(bytes, true)
    }
}
