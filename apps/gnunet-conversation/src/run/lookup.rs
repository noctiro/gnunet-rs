use super::{
    Bounds, Control, Failure, Shared,
    state::{Event, Next, State},
};
use gnunet_gns_client_host as gns;
use gnunet_gns_host::tld;
use gnunet_identity_client_host as identity;
use std::task::Poll;

struct Original<'g, 'id> {
    query: tld::Lookup<'g, 'id>,
    facts: Shared,
}
impl Original<'_, '_> {
    fn retain(&self, report: tld::Report<'_, '_>) {
        let mut facts = self.facts.borrow_mut();
        facts.gns_attempts = facts.gns_attempts.saturating_add(1);
        facts.gns_last = Some(report.into_diagnostics());
    }
}
impl Drop for Original<'_, '_> {
    fn drop(&mut self) {
        if let Some(report) = self.query.close() {
            self.retain(report);
        }
    }
}
enum Tick {
    Query,
    Ui(Event),
}
/// Ordinary full user-name API: direct zTLD, [gns] mapping and actual IDENTITY
/// suffix selection all belong to the shared owner, without a private parser.
pub(super) async fn call(
    state: &mut State<'_, '_>,
    control: &mut Control,
    name: &[u8],
    bounds: Bounds,
) -> Result<bool, Failure> {
    let mut gns_instance = gns::Instance::new();
    let identity_instance = identity::Instance::new();
    let query = tld::Lookup::new(
        &mut gns_instance,
        &identity_instance,
        tld::Sources {
            gns: state.selectors.gns.duplicate()?,
            identity: state.selectors.identity.duplicate()?,
        },
        &state.config,
        tld::Request {
            name,
            record_type: gns::RecordType::PHONE,
            options: gns::LocalOptions::DEFAULT,
            recursion_depth: 128,
        },
        tld::Bounds::bounded(bounds.expires, bounds.hard.into()),
        tld::Limits::default(),
    )?;
    let mut owner = Original {
        query,
        facts: state.history(),
    };
    state.resolving = true;
    state.cancel_resolution = false;
    state.notice(
        b"Resolving PHONE through the original full-name GNS owner: ",
        name,
    )?;
    let result=async {
        let mut query_first=true;
        loop {
            if state.cancel_resolution {
                if let Some(report)=owner.query.cancel(){owner.retain(report);}
                state.notice(b"Original GNS callback canceled locally: ",name)?;
                return Ok(false);
            }
            // Move the original large owned callback into this stack slot;
            // the scheduling tag neither clones it nor allocates after read.
            let mut observed=None;
            let event=control.next(|cx| {
                let first=query_first;
                query_first = !first;
                for query in [first,!first] {
                    if query {
                        match owner.query.poll(cx) {
                            Poll::Pending=>{},
                            Poll::Ready(Ok(event))=>{observed=Some(event);return Poll::Ready(Ok(Tick::Query));},
                            Poll::Ready(Err(failure))=>{
                                let(cause,report)=failure.into_diagnostics();
                                let mut facts=owner.facts.borrow_mut();
                                facts.gns_attempts=facts.gns_attempts.saturating_add(1);
                                facts.gns_last=Some(report);
                                return Poll::Ready(Err(Box::new(cause)as Failure));
                            },
                        }
                    } else {
                        match state.poll(cx) {
                            Poll::Pending=>{},
                            Poll::Ready(Ok(event))=>return Poll::Ready(Ok(Tick::Ui(event))),
                            Poll::Ready(Err(e))=>return Poll::Ready(Err(e)),
                        }
                    }
                }
                Poll::Pending
            }).await?;
            match event {
                Tick::Ui(event)=>{
                    match state.handle(event,control)? {
                        Next::Continue=>{},
                        Next::Quit=>{
                            if let Some(report)=owner.query.cancel(){owner.retain(report);}
                            return Ok(true);
                        },
                        Next::Call(_)=>state.notice(b"Nested /call refused while the original query is retained: ",name)?,
                    }
                },
                Tick::Query=>{
                    match observed.take().ok_or("original GNS scheduling tag lost its owned callback")? {
                        tld::Progress::Finished(outcome)=>{
                            match outcome {
                                tld::Outcome::NotGns{report}=>{
                                    owner.retain(report);
                                    state.notice(b"Actual configured/ego full-name route was not GNS: ",name)?;
                                    return Ok(false);
                                },
                                tld::Outcome::Answer{answer,report}=>{
                                    owner.retain(report);
                                    bounds.check(control.clock.as_ref())?;
                                    let now=control.clock.sample()?.now.as_micros();
                                    let records=answer.result()?.records();
                                    let mut selected=None;
                                    for record in records.iter() {
                                        let record=record?;
                                        if record.record_type!=gnunet_gnsrecord::RecordType::PHONE||record.has_relative_expiration()||record.expiration_time<=now{continue;}
                                        let phone=gnunet_wire::official::conversation::PhoneRecord::decode(record.data)?;
                                        if phone.version==1&&phone.reserved==0{selected=Some(phone);break;}
                                    }
                                    if let Some(phone)=selected{state.begin_call(phone,bounds)?;}else{state.notice(b"Actual GNS result contained no currently usable version1 PHONE record: ",name)?;}
                                    return Ok(false);
                                },
                            }
                        },
                        tld::Progress::Closed=>return Err("original GNS owner closed without its actual terminal result".into()),
                        _=>{},
                    }
                },
            }
        }
    }.await;
    state.resolving = false;
    state.cancel_resolution = false;
    result
}
