//! Original-source CLI orchestration; no key generation, derivation or key files.
use super::*;
use gnunet::types::Error as Fault;

pub(super) async fn ego<W: Write>(
    command: &Command,
    source: EndpointSource,
    window: Window,
    mut signal: Pin<&mut impl Future<Output = io::Result<()>>>,
    out: &mut Output<'_, W>,
) -> Result<SecretKey> {
    let instance = identity::Instance::new();
    let mut lookup = Lookup::exact(
        &instance,
        source,
        &command.ego,
        window.until,
        identity::Limits {
            reconnect: false,
            initialization_timeout: command.timeout,
            ..identity::Limits::default()
        },
    )?;
    let result=async{
        loop {
            if Instant::now()>=window.hard {return Err("IDENTITY deadline before RECLAIM admission".into());}
            let Some(p)=observed(lookup.drive(Some(window.hard)),signal.as_mut()).await? else{return Err("interrupted before RECLAIM admission".into());};
            match p {
                LookupProgress::Finished{operation,epoch,outcome:LookupOutcome::Found(identity)}=>{
                    out.emit(json!({"event":"reclaim_ego_resolved","identity_operation":format!("{operation:?}"),"identity_epoch":epoch.map(|e|format!("{e:?}")),"private_key_exposed":false}))?;
                    return Ok(identity.into_secret());
                },
                LookupProgress::Finished{outcome:LookupOutcome::ResultCode(code),..}=>{
                    out.emit(json!({"event":"reclaim_ego_result","raw_code":code}))?;return Err("IDENTITY ego was not found; RECLAIM not sent".into());
                },
                LookupProgress::Finished{outcome:LookupOutcome::Local{reason,submission,result_code},..}=>{
                    out.emit(json!({"event":"reclaim_ego_local_end","reason":format!("{reason:?}"),"submission":format!("{submission:?}"),"result_code":result_code}))?;
                    return Err("IDENTITY ended without an ego; RECLAIM not sent".into());
                },
                LookupProgress::Source(identity::Progress::Unavailable(e))=>return Err(e.into()),
                LookupProgress::Source(identity::Progress::WaitDeadline)=>return Err("IDENTITY observation deadline".into()),
                LookupProgress::Source(identity::Progress::Lost{cause,..})=>return Err(format!("IDENTITY original source lost: {cause:?}").into()),
                LookupProgress::Closed=>return Err("IDENTITY lookup closed without a result".into()),_=>{},
            }
        }
    }.await;
    let _physical = lookup.close(); // Always no-clock, including output/signal/clock errors.
    result
}
struct Selected {
    index: usize,
    bytes: Zeroizing<Vec<u8>>,
}
fn selected(command: &Command, response: ipc::Response<'_>) -> Option<usize> {
    let id = data::object_id(response)?;
    match command.action {
        Action::AttributeStore if command.id.is_none() => data::object_name(response)
            .filter(|name| name.eq_ignore_ascii_case(&command.name))
            .map(|_| 0),
        Action::AttributeStore
        | Action::AttributeDelete
        | Action::AttributeGet
        | Action::CredentialStore
        | Action::CredentialDelete
        | Action::CredentialGet => command.id.filter(|v| *v == id).map(|_| 0),
        Action::TicketIssue => {
            if !command.ids.is_empty() {
                command.ids.iter().position(|v| *v == id)
            } else {
                data::object_name(response).and_then(|name| {
                    command
                        .names
                        .iter()
                        .position(|v| name.eq_ignore_ascii_case(v))
                })
            }
        }
        _ => None,
    }
}
async fn stop_stream<W: Write>(
    iterator: &mut ReclaimIterator<'_>,
    window: Window,
    out: &mut Output<'_, W>,
    grace: Duration,
) -> Result<()> {
    let finish = Instant::now()
        .min(window.hard)
        .checked_add(grace)
        .ok_or("STOP retirement overflow")?;
    let mut stop = None;
    loop {
        if stop.is_none() {
            match iterator.stop(window.until) {
                Ok(Some(control)) => stop = Some(control),
                Ok(None) => return Ok(()),
                Err(native::Error::Protocol(Fault::WouldBlock)) => {}
                Err(native::Error::Protocol(Fault::Closed | Fault::NotReady | Fault::Deadline)) => {
                    return Ok(());
                }
                Err(e) => return Err(e.into()),
            }
        }
        if Instant::now() >= finish {
            return Ok(());
        }
        let p = iterator.drive(Some(finish)).await?;
        data::observe(out, &p)?;
        match p {
            Progress::ControlWritten {
                control,
                kind: ControlKind::Stop,
                ..
            } if stop == Some(control) => return Ok(()),
            Progress::Completed(_)
            | Progress::Closed
            | Progress::Lost { .. }
            | Progress::WaitDeadline => return Ok(()),
            Progress::Unavailable(e) => return Err(e.into()),
            _ => {}
        }
    }
}
async fn scan<W: Write>(
    command: &Command,
    source: EndpointSource,
    key: &SecretKey,
    window: Window,
    mut signal: Pin<&mut impl Future<Output = io::Result<()>>>,
    out: &mut Output<'_, W>,
) -> Result<Vec<Selected>> {
    let instance = Instance::new();
    let kind = command
        .action
        .iteration()
        .ok_or("command has no iterator")?;
    let mut iterator = ReclaimIterator::new(
        &instance,
        source,
        key.view()?,
        kind,
        window.until,
        command.limits,
    )?;
    let operation = iterator.operation();
    let mut stop_token = None;
    let result=async{
        let mut rows=Vec::new();let mut held=0usize;let mut received=0u64;let mut printed=0u64;
        let mut next=None;let mut want_next=false;let mut stopping=false;
        loop {
            if Instant::now()>=window.hard{return Err("RECLAIM iterator deadline before actual END/STOP; no complete snapshot".into());}
            if stopping&&stop_token.is_none(){match iterator.stop(window.until){
                Ok(Some(token))=>stop_token=Some(token),
                Ok(None)=>{out.emit(json!({"event":"reclaim_iterator_local_stop","natural_end":false,"service_ack":false,"records":printed}))?;return Ok(rows);},
                Err(native::Error::Protocol(Fault::WouldBlock))=>{},Err(e)=>return Err(e.into()),
            }}else if !stopping&&want_next&&next.is_none()&&iterator.credit()==0 {
                match iterator.next(window.until) {Ok(control)=>{next=Some(control);want_next=false;},Err(native::Error::Protocol(Fault::WouldBlock))=>{},Err(e)=>return Err(e.into())}
            }
            let Some(p)=observed(iterator.drive(Some(window.hard)),signal.as_mut()).await? else{return Err("RECLAIM iterator interrupted; original source stopping".into());};
            data::observe(out,&p)?;
            match p {
                Progress::Item{epoch,operation:actual,reply}=>{
                    if actual!=operation{return Err("foreign RECLAIM iterator item".into());}
                    if stopping {continue;}
                    received=received.checked_add(1).ok_or("iterator count overflow")?;
                    if received>command.scan_limit{return Err("scan limit before actual END; no mutation/issue was authorized by this partial scan".into());}
                    let response=reply.view()?;
                    if data::is_end(response,kind){return Err("terminal sentinel misclassified as item".into());}
                    let index=selected(command,response);
                    if let Some(index)=index {
                        if rows.iter().any(|r:&Selected|r.index==index){return Err("selected ID/name is ambiguous in the actual scan".into());}
                        let bytes=data::object(response)?;
                        held=held.checked_add(bytes.len()).filter(|n|*n<=command.limits.frame_bytes).ok_or("selected objects exceed one official request frame; refusing before mutation/issue")?;
                        rows.try_reserve(1)?;rows.push(Selected{index,bytes});
                    }
                    let listing=matches!(command.action,Action::AttributeList|Action::CredentialList|Action::TicketList);
                    if command.action.visible()&&(listing||index.is_some()) {
                        out.emit(json!({"event":"reclaim_item_source","epoch":epoch.diagnostic(),"operation":actual.diagnostic(),"ordinal":received,"complete_snapshot":false}))?;
                        data::reply(out,response)?;printed+=1;
                    }
                    if listing&&printed>=command.limit {stopping=true;}else{want_next=true;}
                },
                Progress::ControlWritten{control,kind:ControlKind::Next,..}=>{
                    if next!=Some(control){return Err("foreign iterator NEXT write".into());}next=None;
                },
                Progress::ControlWritten{control,kind:ControlKind::Stop,..}=>{
                    if stop_token!=Some(control){return Err("foreign iterator STOP write".into());}
                    out.emit(json!({"event":"reclaim_iterator_stopped","whole_stop_written":true,"service_ack":false,"natural_end":false,"records":printed}))?;
                    return Ok(rows);
                },
                Progress::Completed(c)=>{
                    if c.operation!=operation{return Err("foreign iterator completion".into());}
                    match c.outcome {
                        Outcome::Reply(reply)=>{
                            if !data::is_end(reply.view()?,kind){return Err("iterator completion is not actual END".into());}
                            out.emit(json!({"event":"reclaim_iterator_complete","operation":operation.diagnostic(),"epoch":c.epoch.map(|e|e.diagnostic()),"rid":c.request_id,"records":received,"printed":printed,"natural_end":true}))?;
                            return Ok(rows);
                        },
                        Outcome::Local{reason,submission}=>{
                            out.emit(json!({"event":"reclaim_iterator_local_end","reason":format!("{reason:?}"),"submission":format!("{submission:?}"),"natural_end":false,"complete_snapshot":false}))?;
                            return Err("iterator ended locally before actual END/whole STOP".into());
                        }
                    }
                },
                Progress::Unavailable(e)=>return Err(e.into()),
                Progress::WaitDeadline=>return Err("iterator observation deadline; not END".into()),
                Progress::Closed=>return Err("iterator closed without actual END/whole STOP".into()),_=>{},
            }
        }
    }.await;
    let cleanup = if result.is_err() {
        stop_stream(&mut iterator, window, out, command.limits.retirement_grace).await
    } else {
        Ok(())
    };
    let report = iterator.close().or_else(|| iterator.take_close_report());
    let physical = data::loss(out, report);
    result.and_then(|rows| cleanup.and(physical).map(|()| rows))
}
async fn drain<'id, W: Write>(
    client: &mut Client<'id>,
    operation: Operation<'id>,
    window: Window,
    out: &mut Output<'_, W>,
    grace: Duration,
) -> Result<()> {
    let how = client.cancel(operation)?;
    out.emit(json!({"event":"reclaim_callback_cancelled","operation":operation.diagnostic(),"cancellation":format!("{how:?}"),"wire_cancel_exists":false,"remote_rollback":false}))?;
    let finish = Instant::now()
        .min(window.hard)
        .checked_add(grace)
        .ok_or("retirement deadline overflow")?;
    loop {
        if client.pending() == 0 || Instant::now() >= finish {
            return Ok(());
        }
        let p = client.drive(Some(finish)).await?;
        data::observe(out, &p)?;
        match p {
            Progress::Completed(c) => {
                if c.operation != operation {
                    return Err("foreign cancellation completion".into());
                }
                match c.outcome {
                    Outcome::Local{reason,submission}=>out.emit(json!({"event":"reclaim_cancel_retired","reason":format!("{reason:?}"),"submission":format!("{submission:?}"),"service_result":false}))?,
                    Outcome::Reply(reply)=>{data::reply(out,reply.view()?)?;},
                }
                return Ok(());
            }
            Progress::WaitDeadline | Progress::Closed => return Ok(()),
            Progress::Unavailable(e) => return Err(e.into()),
            _ => {}
        }
    }
}
async fn single<W: Write>(
    command: &Command,
    source: EndpointSource,
    key: Option<&SecretKey>,
    window: Window,
    mut signal: Pin<&mut impl Future<Output = io::Result<()>>>,
    out: &mut Output<'_, W>,
    rows: &[Selected],
) -> Result<()> {
    let instance = Instance::new();
    let mut client = Client::new(&instance, source, command.limits)?;
    let mut pending = None;
    let result=async{
        let key=key.map(SecretKey::view).transpose()?;
        let old=rows.first().map(|r|r.bytes.as_slice());
        let op=match command.action {
            Action::AttributeStore=>client.store_attribute(key.ok_or("missing ego")?,command.attribute(old.map(Attribute::decode).transpose()?)?,command.expiration,window.until)?,
            Action::CredentialStore=>client.store_credential(key.ok_or("missing ego")?,command.credential(old.map(Credential::decode).transpose()?)?,command.expiration,window.until)?,
            Action::AttributeDelete=>client.delete_attribute(key.ok_or("missing ego")?,Attribute::decode(old.ok_or("attribute ID not found in complete scan")?)?,window.until)?,
            Action::CredentialDelete=>client.delete_credential(key.ok_or("missing ego")?,Credential::decode(old.ok_or("credential ID not found in complete scan")?)?,window.until)?,
            Action::TicketRevoke=>client.revoke_ticket(key.ok_or("missing ego")?,Ticket::new(&command.ticket)?,window.until)?,
            Action::TicketConsume=>client.consume_ticket(Ticket::new(&command.ticket)?,Uri::new(&command.uri)?,window.until)?,
            Action::TicketIssue=>{
                let count=command.ids.len().checked_add(command.names.len()).ok_or("selection count overflow")?;if rows.len()!=count{return Err("some requested attributes absent in complete scan; no ticket issue sent".into());}
                let overhead=ipc::ISSUE_PREFIX.checked_add(gnunet::wire::identity::KEY_LEN)
                    .and_then(|n|n.checked_add(command.uri.len())).and_then(|n|n.checked_add(1))
                    .ok_or("ticket issue size overflow")?;
                let capacity=command.limits.frame_bytes.checked_sub(overhead).ok_or("ticket issue prefix exceeds frame limit")?;
                let mut selected=Zeroizing::new(Vec::new());
                selected.try_reserve_exact(capacity)?;
                for index in 0..count {
                    let original=rows.iter().find(|r|r.index==index).ok_or("missing selected attribute")?;
                    selected.len().checked_add(original.bytes.len()).filter(|n|*n<=capacity).ok_or("selected attributes exceed one original ticket-issue frame")?;
                    selected.extend_from_slice(&original.bytes);
                }
                let list=AttributeList::new(&selected,ListLimits{bytes:command.limits.frame_bytes,items:command.limits.list_items})?;
                client.issue_ticket(key.ok_or("missing ego")?,Uri::new(&command.uri)?,list,window.until)?
            },_=>return Err("not a one-shot RECLAIM operation".into()),
        };pending=Some(op);
        out.emit(json!({"event":"reclaim_operation_prepared","operation":op.diagnostic(),"rid":client.request_id(op)?,"physical_queue_admitted":false,"service_result":false}))?;
        loop {
            if Instant::now()>=window.hard{return Err("RECLAIM deadline; exposed mutating outcome can be unknown".into());}
            let Some(p)=observed(client.drive(Some(window.hard)),signal.as_mut()).await? else{return Err("RECLAIM interrupted; original callback canceled, no rollback receipt".into());};
            data::observe(out,&p)?;
            match p {
                Progress::Completed(c)=>{
                    if c.operation!=op{return Err("foreign original RECLAIM completion".into());}
                    out.emit(json!({"event":"reclaim_completion","operation":c.operation.diagnostic(),"epoch":c.epoch.map(|e|e.diagnostic()),"rid":c.request_id,"kind":format!("{:?}",c.kind)}))?;
                    return match c.outcome {
                        Outcome::Reply(reply)=>if data::reply(out,reply.view()?)?{Ok(())}else{Err("actual RECLAIM result was unsuccessful; see raw response fields".into())},
                        Outcome::Local{reason,submission}=>{out.emit(json!({"event":"reclaim_local_end","reason":format!("{reason:?}"),"submission":format!("{submission:?}"),"service_result":false}))?;Err("RECLAIM ended without an actual service result".into())},
                    };
                },
                Progress::Unavailable(e)=>return Err(e.into()),Progress::WaitDeadline=>return Err("RECLAIM observation deadline, not service failure/success".into()),
                Progress::Closed=>return Err("RECLAIM source closed without actual result".into()),Progress::Item{..}=>return Err("unexpected iterator item on general MQ".into()),_=>{},
            }
        }
    }.await;
    let cleanup = if result.is_err() && client.pending() != 0 {
        if let Some(op) = pending {
            drain(
                &mut client,
                op,
                window,
                out,
                command.limits.retirement_grace,
            )
            .await
        } else {
            Ok(())
        }
    } else {
        Ok(())
    };
    let physical = data::loss(out, client.close());
    result.and(cleanup).and(physical)
}
pub(super) async fn execute<W: Write>(
    command: &Command,
    source: EndpointSource,
    key: Option<&SecretKey>,
    window: Window,
    mut signal: Pin<&mut impl Future<Output = io::Result<()>>>,
    out: &mut Output<'_, W>,
) -> Result<()> {
    let needs_scan = command.action.visible()
        || matches!(
            command.action,
            Action::AttributeDelete | Action::CredentialDelete | Action::TicketIssue
        )
        || command.action == Action::AttributeStore && command.id.is_none_or(|id| !id.is_zero())
        || command.action == Action::CredentialStore && command.id.is_some_and(|id| !id.is_zero());
    let rows = if needs_scan {
        scan(
            command,
            source.duplicate()?,
            key.ok_or("missing original ego")?,
            window,
            signal.as_mut(),
            out,
        )
        .await?
    } else {
        Vec::new()
    };
    if command.action.visible() {
        if matches!(command.action, Action::AttributeGet | Action::CredentialGet) && rows.is_empty()
        {
            out.emit(json!({"event":"reclaim_object_not_found","complete_scan":true,"request_sent_for_mutation":false}))?;
            return Err("object ID absent in the complete original iterator".into());
        }
        return Ok(());
    }
    if command.id.is_some_and(|id| !id.is_zero())
        && matches!(
            command.action,
            Action::AttributeStore | Action::CredentialStore
        )
        && rows.is_empty()
    {
        return Err("explicit update ID absent in complete scan; no store sent".into());
    }
    single(command, source, key, window, signal.as_mut(), out, &rows).await
}
