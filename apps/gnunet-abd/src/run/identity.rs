use super::{Control, SharedFacts};
use crate::Failure;
use gnunet_identity_client_host as id;
use std::task::{Context, Poll, Waker};

struct Original<'a> {
    lookup: id::Lookup<'a>,
    facts: SharedFacts,
    closed: bool,
}
fn outcome(facts: &SharedFacts, value: &id::LookupOutcome) {
    let mut facts = facts.borrow_mut();
    match value {
        id::LookupOutcome::Found(_) => facts.identity_found = true,
        id::LookupOutcome::ResultCode(code) => facts.identity_result = Some(*code),
        id::LookupOutcome::Local {
            reason,
            submission,
            result_code,
        } => facts.identity_local = Some((*reason, *submission, *result_code)),
    }
}
impl Original<'_> {
    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        if let Some(loss) = self.lookup.close() {
            self.facts.borrow_mut().identity_retired =
                Some((loss.operations, loss.exposed, loss.egos));
        }
        // Only the already physically closed original source is drained. Its
        // local yield turn may be Pending; no new attachment/read/write occurs.
        let mut cx = Context::from_waker(Waker::noop());
        let mut drained = false;
        for _ in 0..16 {
            match self.lookup.poll(&mut cx, None) {
                Poll::Ready(Ok(id::LookupProgress::Closed)) => {
                    drained = true;
                    break;
                }
                Poll::Ready(Ok(id::LookupProgress::Finished { outcome: value, .. })) => {
                    outcome(&self.facts, &value)
                }
                Poll::Ready(Ok(id::LookupProgress::Source(id::Progress::Lost {
                    cause, ..
                }))) => {
                    self.facts.borrow_mut().identity_loss.get_or_insert(cause);
                }
                Poll::Ready(Err(e)) => {
                    self.facts
                        .borrow_mut()
                        .identity_loss
                        .get_or_insert(id::LossCause::Ports(e));
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
pub(super) async fn lookup(
    control: &mut Control,
    source: id::EndpointSource,
    name: &[u8],
) -> Result<id::Identity, Failure> {
    control.gate().await?;
    let domain = id::Instance::new();
    let lookup = id::Lookup::exact(
        &domain,
        source,
        name,
        control.original.expires,
        control.settings.identity,
    )?;
    let original = lookup.operation();
    let mut native = Original {
        lookup,
        facts: control.facts.clone(),
        closed: false,
    };
    let result = async {
        loop {
            let hard = control.original.hard.into();
            let event = control
                .next(|cx| native.lookup.poll(cx, Some(hard)))
                .await?;
            match event {
                id::LookupProgress::Finished {
                    operation,
                    outcome: value,
                    ..
                } => {
                    if operation != original {
                        return Err("foreign original IDENTITY completion".into());
                    }
                    outcome(&control.facts, &value);
                    return match value {
                        id::LookupOutcome::Found(identity) => Ok(identity),
                        other => Err(format!(
                            "original IDENTITY lookup did not return an ego: {other:?}"
                        )
                        .into()),
                    };
                }
                id::LookupProgress::Source(id::Progress::Lost { report, cause }) => {
                    control.facts.borrow_mut().identity_retired =
                        Some((report.operations, report.exposed, report.egos));
                    control
                        .facts
                        .borrow_mut()
                        .identity_loss
                        .get_or_insert(cause);
                    return Err("original IDENTITY lookup source lost; no replay".into());
                }
                id::LookupProgress::Source(id::Progress::ConnectRetry { error, .. }) => {
                    control
                        .facts
                        .borrow_mut()
                        .identity_retry
                        .get_or_insert(error);
                }
                id::LookupProgress::Source(id::Progress::Unavailable(e)) => return Err(e.into()),
                id::LookupProgress::Source(id::Progress::WaitDeadline)
                | id::LookupProgress::Closed => {
                    return Err("IDENTITY lookup ended before its real original result".into());
                }
                _ => {}
            }
        }
    }
    .await;
    native.close();
    result
}
