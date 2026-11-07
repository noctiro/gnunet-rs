use super::{Control, SharedFacts};
use crate::{
    Failure,
    text::{Expiration, bytes},
};
use gnunet_gnsrecord::{RecordData, RecordFlags, RecordType};
use gnunet_namestore_client_host as ns;
use std::task::{Context, Poll, Waker};
use subtle::ConstantTimeEq;

struct Original<'a> {
    client: ns::Client<'a>,
    operation: Option<ns::Operation<'a>>,
    facts: SharedFacts,
    closed: bool,
    store_phase: bool,
}
fn retain(facts: &SharedFacts, completion: &ns::Completion<'_>) {
    let mut facts = facts.borrow_mut();
    match &completion.outcome {
        ns::Outcome::Reply(reply) => {
            if let Ok(ns::ipc::Response::Generic { code, .. }) = reply.view() {
                if completion.kind == ns::Kind::Store {
                    facts.store_code = Some(code);
                } else {
                    facts.lookup_code = Some(code);
                }
            }
            if let Ok(ns::ipc::Response::Lookup { found, .. }) = reply.view() {
                facts.lookup_found = Some(found);
            }
        }
        ns::Outcome::Local { reason, submission } => {
            facts.namestore_local = Some((completion.kind, *reason, *submission))
        }
    }
}
impl Original<'_> {
    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        if let Some(loss) = self.client.close() {
            self.facts.borrow_mut().namestore_retired = Some((loss.operations, loss.exposed));
        }
        let mut cx = Context::from_waker(Waker::noop());
        let mut drained = false;
        for _ in 0..16 {
            match self.client.poll(&mut cx, None) {
                Poll::Ready(Ok(ns::Progress::Closed)) => {
                    drained = true;
                    break;
                }
                Poll::Ready(Ok(ns::Progress::Completed(completion))) => {
                    if self.operation == Some(completion.operation) {
                        retain(&self.facts, &completion);
                    }
                }
                Poll::Ready(Ok(ns::Progress::Lost { cause, .. })) => {
                    self.facts.borrow_mut().namestore_loss.get_or_insert(cause);
                }
                Poll::Ready(Err(e)) => {
                    self.facts
                        .borrow_mut()
                        .namestore_loss
                        .get_or_insert(ns::LossCause::Ports(e));
                    break;
                }
                _ => {}
            }
        }
        if !drained {
            self.facts.borrow_mut().undrained += 1;
        }
    }
}
impl Drop for Original<'_> {
    fn drop(&mut self) {
        self.close();
    }
}
async fn completion<'a>(
    control: &mut Control,
    native: &mut Original<'a>,
    original: ns::Operation<'a>,
) -> Result<ns::Completion<'a>, Failure> {
    loop {
        let hard = control.original.hard.into();
        match control
            .next(|cx| native.client.poll(cx, Some(hard)))
            .await?
        {
            ns::Progress::Completed(completion) => {
                if completion.operation != original {
                    return Err("foreign original NAMESTORE completion".into());
                }
                retain(&control.facts, &completion);
                return Ok(completion);
            }
            ns::Progress::Written { operation, .. } if operation == original => {
                if native.store_phase && matches!(native.client.request_id(operation), Ok(Some(_)))
                {
                    control.facts.borrow_mut().store_written = true;
                }
            }
            ns::Progress::Lost { report, cause } => {
                control.facts.borrow_mut().namestore_retired =
                    Some((report.operations, report.exposed));
                control
                    .facts
                    .borrow_mut()
                    .namestore_loss
                    .get_or_insert(cause);
                return Err(
                    "original NAMESTORE source lost; exposed mutation is never replayed".into(),
                );
            }
            ns::Progress::ConnectRetry { error, .. } => {
                control
                    .facts
                    .borrow_mut()
                    .namestore_retry
                    .get_or_insert(error);
            }
            ns::Progress::Unavailable(e) => return Err(e.into()),
            ns::Progress::WaitDeadline | ns::Progress::Closed => {
                return Err("NAMESTORE source ended before original actual result".into());
            }
            _ => {}
        }
    }
}
#[expect(
    clippy::too_many_arguments,
    reason = "original authority, record fields and same whole operation are explicit independent inputs"
)]
pub(super) async fn prepend(
    control: &mut Control,
    source: ns::EndpointSource,
    secret: ns::SecretKey,
    label: &[u8],
    record: &[u8],
    kind: RecordType,
    expiration: Expiration,
    private: bool,
) -> Result<(), Failure> {
    control.gate().await?;
    let domain = ns::Instance::new();
    let client = ns::Client::new(&domain, source, control.settings.namestore)?;
    let mut native = Original {
        client,
        operation: None,
        facts: control.facts.clone(),
        closed: false,
        store_phase: false,
    };
    let result = async {
        // Include maintenance and private values to preserve the actual complete
        // preexisting record set; this is an explicit public lookup filter.
        let lookup = native
            .client
            .lookup(&secret, label, 1, control.original.expires)?;
        native.operation = Some(lookup);
        let lookup = completion(control, &mut native, lookup).await?;
        let ns::Outcome::Reply(reply) = lookup.outcome else {
            return Err("NAMESTORE lookup had no real original service reply".into());
        };
        let ns::ipc::Response::Lookup {
            zone,
            label: actual,
            found,
            records,
            ..
        } = reply.view()?
        else {
            return Err("unexpected original NAMESTORE lookup response".into());
        };
        if !bool::from(zone.expose_serialized().ct_eq(secret.expose_serialized())) {
            return Err("NAMESTORE lookup returned another original authority".into());
        }
        // The original matching completion supplies the service-normalized name.
        // As in the official callback, preserve that name for the replacement.
        if found != 0 && found != 1 {
            return Err(format!("NAMESTORE actual lookup failed with found={found}").into());
        }
        if found == 0 && records.count() != 0 {
            return Err("NAMESTORE miss carried unexpected records".into());
        }
        let count = usize::from(records.count())
            .checked_add(1)
            .ok_or("record count overflow")?;
        if count > control.settings.records {
            return Err(
                "new record plus original records exceed the configured group bound".into(),
            );
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(count)?;
        if rows.capacity() > control.settings.records {
            return Err("record metadata capacity exceeds the configured group bound".into());
        }
        let mut flags = if private {
            RecordFlags::PRIVATE.bits()
        } else {
            0
        };
        if expiration.relative {
            flags |= RecordFlags::RELATIVE_EXPIRATION.bits();
        }
        rows.push(RecordData {
            expiration_time: expiration.value,
            record_type: kind,
            flags: RecordFlags::from_bits_preserve(flags),
            data: record,
        });
        for existing in records.records().iter() {
            rows.push(existing?);
        }
        let size = gnunet_gnsrecord::serialized_len(&rows)?;
        if size > 65535 {
            return Err("the complete replacement record set cannot fit one official STORE".into());
        }
        let label = ns::ipc::CString::new(actual.bytes())?;
        let frame = ns::ipc::STORE_PREFIX
            .checked_add(secret.expose_serialized().len())
            .and_then(|n| n.checked_add(ns::ipc::SET_PREFIX))
            .and_then(|n| n.checked_add(label.encoded_len()))
            .and_then(|n| n.checked_add(size))
            .ok_or(gnunet_types::Error::Overflow)?;
        if frame > control.settings.namestore.frame_bytes {
            return Err(
                "the full authority/label/record set exceeds one official STORE frame".into(),
            );
        }
        let mut encoded = bytes(size)?;
        gnunet_gnsrecord::serialize(&rows, &mut encoded)?;
        let set = ns::ipc::StoreSet {
            label,
            records: ns::ipc::Records::new(&encoded, u16::try_from(count)?)?,
            reserved: 0,
        };
        let mut batch = bytes(set.encoded_len()?)?;
        set.encode(&mut batch)?;
        control.gate().await?;
        if kind == RecordType::DELEGATE && !expiration.relative {
            control.time()?.valid_until(expiration.value)?;
        }
        let store = native.client.store(
            &secret,
            ns::ipc::RecordSets::new(&batch, 1)?,
            true,
            control.original.expires,
        )?;
        native.operation = Some(store);
        native.store_phase = true;
        let store = completion(control, &mut native, store).await?;
        match store.outcome {
            ns::Outcome::Reply(reply) => match reply.view()? {
                ns::ipc::Response::Generic { code: 0, .. } => Ok(()),
                ns::ipc::Response::Generic { code, .. } => {
                    Err(format!("NAMESTORE actual STORE returned code {code}").into())
                }
                _ => Err("unexpected original STORE response".into()),
            },
            ns::Outcome::Local { .. } => Err(
                "original STORE retired locally; exposed outcome is not a service confirmation"
                    .into(),
            ),
        }
    }
    .await;
    native.close();
    drop(secret);
    result
}
