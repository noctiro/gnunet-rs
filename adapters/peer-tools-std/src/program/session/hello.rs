//! Current real HELLO export/import/dump and public PILS observation behavior.
use super::{
    ADDRESS_BYTES, Arc, Driver, Duration, Failure, INPUT_BYTES, Instant, Io, Mode, Owners,
    RuntimeClock, Settings, Signals, URL_BYTES, Wake, Zeroizing, base32, buffer, choose,
    diagnostic, hello_limits, input, output, peer_text, pils, print_pils, print_ps, ps,
};
use gnunet_hello::{AbsoluteTime, Hello};
use gnunet_peerstore_client_host::hello::{AddOutcome, AddProgress, HelloAdd};
use gnunet_pils::client::{Completion, Inbound, KeyTarget, LocalKeyStatus, OperationId};
use std::io::Write;
fn encoded(hello: Hello<'_>, binary: bool) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let n = if binary {
        hello.message_len()?
    } else {
        hello.url_len()?
    };
    if n > if binary { 65535 } else { URL_BYTES } {
        return Err("public HELLO output exceeds configured native/text width".into());
    }
    let mut out = buffer(n + usize::from(!binary))?;
    if binary {
        hello.encode_message(&mut out)?;
    } else {
        hello.write_url(&mut out[..n])?;
        out[n] = b'\n';
    }
    Ok(out)
}
struct SignedJob<'id> {
    operation: OperationId<'id>,
    identity: gnunet_pils::client::Identity<'id>,
    expiry: AbsoluteTime,
    announcement: gnunet_service_runtime::framing::OwnedFrame,
}
pub(super) async fn observe_pils<'id>(
    owners: &mut Owners<'id>,
    signals: &mut Signals,
    stdout: &mut Io,
    clock: &Arc<dyn RuntimeClock>,
    settings: &Settings,
    until: Instant,
) -> Result<(), Failure> {
    let mut scratch = buffer(if settings.mode == Mode::Export {
        ADDRESS_BYTES
    } else {
        0
    })?;
    let mut builder_bytes = buffer(
        if settings.mode == Mode::Export && settings.expiry.is_some() {
            ADDRESS_BYTES
        } else {
            0
        },
    )?;
    let mut job: Option<SignedJob<'id>> = None;
    let mut observations = 0u64;
    let mut first = false;
    loop {
        let client = owners.pils.as_mut().ok_or("PILS owner absent")?;
        let event = match choose(
            client.drive(Some(until)),
            &mut owners.resolver,
            Some(signals),
            until,
            first,
        )
        .await?
        {
            Wake::Provider(event) => event?,
            Wake::Resolver => {
                first = !first;
                continue;
            }
            Wake::Signal => return Ok(()),
            Wake::Deadline => {
                return if settings.mode == Mode::Identity && !settings.once {
                    Ok(())
                } else {
                    Err("actual PILS public observation/signature was not received before original deadline".into())
                };
            }
        };
        first = !first;
        print_pils(&event);
        match event {
            pils::Progress::Inbound(Inbound::Identity {
                identity,
                identity_changed,
                local_key,
            }) => {
                if local_key != LocalKeyStatus::Disabled {
                    return Err("public-only CLI unexpectedly obtained local-key authority".into());
                }
                observations = observations.saturating_add(1);
                diagnostic(format_args!(
                    "actual PILS public observation epoch={:?} revision={} changed={} coverage={:?}; observation-count={observations}",
                    identity.epoch(),
                    identity.revision(),
                    identity_changed,
                    identity.coverage()
                ));
                if settings.mode == Mode::Identity {
                    let text = peer_text(identity.peer().as_bytes())?;
                    output(stdout, &text, &mut owners.resolver, signals, until).await?;
                    if settings.once {
                        return Ok(());
                    }
                    continue;
                }
                if let Some(original) = &job {
                    if original.identity.peer() != identity.peer()
                        || original.identity.epoch() != identity.epoch()
                    {
                        return Err("original PILS signer source/key changed; original request is not replayed".into());
                    }
                    continue;
                }
                let client = owners.pils.as_mut().ok_or("PILS owner absent")?;
                if client.identity() != Some(identity) {
                    return Err("PILS identity event is not the current original source".into());
                }
                let bytes = client
                    .announcement()
                    .ok_or("current PILS announcement missing")?;
                let announced = gnunet_wire::official::pils::PeerUpdate::decode(bytes)?;
                let hello = Hello::parse_block(announced.block, &mut scratch, hello_limits())?;
                if hello.peer() != identity.peer() {
                    return Err("public HELLO/PILS identity mismatch".into());
                }
                if let Some(relative) = settings.expiry {
                    let expiration = AbsoluteTime::from_micros(
                        clock.sample()?.now.as_micros().saturating_add(relative),
                    );
                    // Fallible retention precedes original SIGN admission.
                    let announcement =
                        gnunet_service_runtime::framing::OwnedFrame::copy_from(bytes)?;
                    let builder = hello.to_builder(&mut builder_bytes, hello_limits())?;
                    let operation =
                        client.sign_hello(&builder, expiration, KeyTarget::Exact(identity))?;
                    diagnostic(format_args!(
                        "actual PILS HELLO purpose7 admitted operation={operation:?} epoch={:?}; no signature result yet",
                        identity.epoch()
                    ));
                    job = Some(SignedJob {
                        operation,
                        identity,
                        expiry: expiration,
                        announcement,
                    });
                } else {
                    let bytes = encoded(hello, settings.binary)?;
                    output(stdout, &bytes, &mut owners.resolver, signals, until).await?;
                    return Ok(());
                }
            }
            pils::Progress::Inbound(Inbound::Complete(completion)) => {
                let original = job
                    .take()
                    .ok_or("unexpected crypto result on public-only PILS observation")?;
                match completion{
                    Completion::Signature{operation,peer,signature,announced}=>{
                        if operation!=original.operation||peer!=original.identity.peer()||!announced.is_some_and(|id|id.peer()==peer&&id.epoch()==original.identity.epoch()){
                            return Err("original PILS signature/source/signer binding refused".into());
                        }
                        let current=owners.pils.as_ref().and_then(pils::Client::identity).ok_or("PILS original signer no longer current")?;
                        if current.peer()!=peer||current.epoch()!=original.identity.epoch(){return Err("original PILS signer retired before export".into());}
                        let update=gnunet_wire::official::pils::PeerUpdate::decode(original.announcement.bytes())?;
                        let original_hello=Hello::parse_block(update.block,&mut scratch,hello_limits())?;
                        let builder=original_hello.to_builder(&mut builder_bytes,hello_limits())?;
                        // Actual SDK Completion already verified exact retained purpose bytes.
                        // Merely attaching metadata here never manufactures a signature receipt.
                        let hello=builder.with_signature(peer,signature,original.expiry);
                        let bytes=encoded(hello,settings.binary)?;
                        output(stdout,&bytes,&mut owners.resolver,signals,until).await?;return Ok(());
                    }
                    Completion::Failed{operation,kind,reason}=>return Err(format!("actual original PILS operation={operation:?} kind={kind:?} failed={reason:?}").into()),
                    // No secret operation was admitted, and no unexpected secret is printed.
                    Completion::Decapsulated{..}|Completion::Ecdh{..}=>return Err("unexpected non-signature completion on public HELLO export".into()),
                }
            }
            pils::Progress::Lost { .. } if job.is_some() => {
                return Err(
                    "original PILS signing MQ lost before result; no automatic sign replay".into(),
                );
            }
            pils::Progress::Closed => {
                return Err("PILS source closed before requested public result".into());
            }
            _ => {}
        }
    }
}
async fn cancel_scan<'id>(
    client: &mut ps::Client<'id>,
    operation: ps::Operation<'id>,
    resolver: &mut Driver<8, 256>,
    hard: Instant,
) -> Result<(), Failure> {
    let cancel = client.cancel(operation)?;
    diagnostic(format_args!(
        "actual original iterator cancellation={cancel:?}; STOP has no processing ACK"
    ));
    let until = Instant::now().min(hard) + Duration::from_secs(5);
    let mut first = false;
    loop {
        if !client.live(operation) && client.pending() == 0 {
            return Ok(());
        }
        match choose(client.drive(Some(until)),resolver,None,until,first).await?{
            Wake::Provider(event)=>{let event=event?;print_ps(&event);if matches!(event,ps::Progress::Completed{operation:op,..}if op==operation){return Ok(());}},
            Wake::Resolver=>{},Wake::Signal=>{},Wake::Deadline=>return Err("original PEERSTORE STOP/suffix not retired within fixed grace; physical source close follows".into()),
        }
        first = !first;
    }
}
fn listing(
    hello: Hello<'_>,
    coverage: gnunet_hello::SignatureCoverage,
) -> Result<Vec<u8>, Failure> {
    let capacity = hello
        .address_bytes()
        .len()
        .checked_mul(4)
        .and_then(|n| n.checked_add(256))
        .ok_or("public HELLO listing bound overflow")?;
    let mut text = Vec::new();
    text.try_reserve_exact(capacity)?;
    let peer = base32(hello.peer().as_bytes());
    writeln!(
        text,
        "{} expires={} coverage={coverage:?}:",
        std::str::from_utf8(&peer)?,
        hello.expiration().as_micros()
    )?;
    for address in hello.addresses() {
        text.write_all(b"|- ")?;
        for byte in address.as_bytes() {
            for escaped in std::ascii::escape_default(*byte) {
                text.push(escaped);
            }
        }
        text.push(b'\n');
    }
    Ok(text)
}
pub(super) async fn dump<'id>(
    owners: &mut Owners<'id>,
    signals: &mut Signals,
    stdout: &mut Io,
    clock: &Arc<dyn RuntimeClock>,
    settings: &Settings,
    until: Instant,
) -> Result<(), Failure> {
    let now = clock.sample()?.now.as_micros();
    let duration = u64::try_from(settings.duration.as_micros())?;
    let expires = now
        .checked_add(duration)
        .filter(|n| *n != u64::MAX)
        .ok_or("original PEERSTORE deadline overflow")?;
    let operation = owners
        .peerstore
        .as_mut()
        .ok_or("PEERSTORE owner absent")?
        .iterate(
            ps::Filter {
                peer: None,
                subsystem: Some(ps::hello::SUBSYSTEM),
                key: Some(ps::hello::KEY),
            },
            expires,
        )?;
    let mut scratch = buffer(ADDRESS_BYTES)?;
    let mut first = false;
    let mut records = 0u64;
    let mut epoch = None;
    loop {
        let client = owners.peerstore.as_mut().ok_or("PEERSTORE owner absent")?;
        let event=match choose(client.drive(Some(until)),&mut owners.resolver,Some(signals),until,first).await?{
            Wake::Provider(event)=>event?,Wake::Resolver=>{first = !first;continue;},Wake::Signal=>{cancel_scan(client,operation,&mut owners.resolver,until).await?;return Ok(());},
            Wake::Deadline=>return Err(format!("HELLO enumeration deadline after{records} records; authoritative END was not received").into()),
        };
        first = !first;
        print_ps(&event);
        match event {
            ps::Progress::Connected(source) => {
                if epoch.is_some_and(|old| old != source) {
                    return Err("HELLO iterator changed original physical source".into());
                }
                epoch = Some(source);
            }
            ps::Progress::Record(observation) => {
                if observation.operation() != operation
                    || epoch.is_some_and(|old| old != observation.epoch())
                {
                    return Err("HELLO original iterator/source mismatch".into());
                }
                epoch = Some(observation.epoch());
                let record = observation.record()?.record;
                if record.subsystem != Some(ps::hello::SUBSYSTEM)
                    || record.key != Some(ps::hello::KEY)
                {
                    return Err("HELLO record selector mismatch".into());
                }
                let now = clock.sample()?.now;
                match Hello::parse_message(record.value, None, &mut scratch, hello_limits())
                    .and_then(|hello| {
                        if hello.peer().as_bytes() != &record.peer {
                            return Err(gnunet_types::Error::Authentication);
                        }
                        let checked = hello.verify_at(settings.profile.hello(), now)?;
                        Ok((hello, checked.coverage()))
                    }) {
                    Ok((hello, coverage)) => {
                        let bytes = listing(hello, coverage)?;
                        output(stdout, &bytes, &mut owners.resolver, signals, until).await?;
                        records = records.saturating_add(1);
                    }
                    Err(reason) => diagnostic(format_args!(
                        "invalid/expired public HELLO record skipped: {reason}"
                    )),
                }
                let client = owners.peerstore.as_mut().ok_or("PEERSTORE owner absent")?;
                if client.credit(operation)? == 0 {
                    client.next(operation, 1)?;
                }
            }
            ps::Progress::Completed {
                operation: original,
                outcome,
                ..
            } if original == operation => {
                diagnostic(format_args!(
                    "actual HELLO iterator terminal={outcome:?} listed={records}"
                ));
                return if matches!(outcome, ps::Outcome::IterationEnd(1)) {
                    Ok(())
                } else {
                    Err(format!("HELLO enumeration interrupted with original{outcome:?}").into())
                };
            }
            ps::Progress::Lost { .. } => return Err(format!(
                "original HELLO iteration source lost after{records} records; no snapshot replay"
            )
            .into()),
            ps::Progress::Closed => {
                return Err("HELLO iteration closed without original END".into());
            }
            _ => {}
        }
    }
}
fn import_result(done: ps::hello::Completion<'_>, cancelled: bool) -> Result<(), Failure> {
    diagnostic(format_args!(
        "actual HELLO add completion scan={:?} store={:?} epoch={:?} coverage={:?} outcome={:?}",
        done.scan, done.store, done.epoch, done.coverage, done.outcome
    ));
    match done.outcome {
        AddOutcome::StoreResult(1) => Ok(()),
        AddOutcome::ExistingNewer { .. } => Ok(()),
        AddOutcome::Interrupted { .. } if cancelled => Ok(()),
        other => Err(format!("HELLO not saved: original{other:?}").into()),
    }
}
async fn import_complete(
    done: ps::hello::Completion<'_>,
    user_cancelled: bool,
    stdout: &mut Io,
    resolver: &mut Driver<8, 256>,
    signals: &mut Signals,
    until: Instant,
) -> Result<(), Failure> {
    let message = match done.outcome {
        AddOutcome::StoreResult(1) => Some(b"HELLO stored.\n".as_slice()),
        AddOutcome::ExistingNewer { .. } => {
            Some(b"Newer HELLO already present; no STORE submitted.\n".as_slice())
        }
        _ => None,
    };
    import_result(done, user_cancelled)?;
    if let Some(message) = message {
        output(stdout, message, resolver, signals, until).await?;
    }
    Ok(())
}
pub(super) async fn import<'id>(
    owners: &mut Owners<'id>,
    signals: &mut Signals,
    stdout: &mut Io,
    clock: &Arc<dyn RuntimeClock>,
    settings: &Settings,
    until: Instant,
) -> Result<(), Failure> {
    let raw = input(&mut owners.resolver, signals, until).await?;
    let mut scratch = buffer(ADDRESS_BYTES)?;
    let is_url = raw
        .get(..15)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"gnunet://hello/"));
    let mut canonical = buffer(if is_url { INPUT_BYTES } else { 0 })?;
    let frame: &[u8] = if raw
        .get(..15)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"gnunet://hello/"))
    {
        let mut end = raw.len();
        while end > 0 && matches!(raw[end - 1], b'\n' | b'\r') {
            end -= 1;
        }
        let hello = Hello::parse_url(&raw[..end], &mut scratch, hello_limits())?;
        let n = hello.encode_message(&mut canonical)?;
        &canonical[..n]
    } else {
        &raw
    };
    let now = clock.sample()?.now.as_micros();
    let duration = u64::try_from(until.saturating_duration_since(Instant::now()).as_micros())?;
    let expires = now
        .checked_add(duration)
        .filter(|n| *n != u64::MAX)
        .ok_or("original HELLO import deadline overflow")?;
    let client = owners.peerstore.as_mut().ok_or("PEERSTORE owner absent")?;
    let mut add = HelloAdd::start(
        client,
        frame,
        &mut scratch,
        ps::hello::Options {
            profile: settings.profile.hello(),
            hello: hello_limits(),
            now: AbsoluteTime::from_micros(now),
            until: expires,
            hard: until,
            grace: Duration::from_secs(5),
        },
    )?;
    // The concrete helper retained an immutable exact-length original copy.
    // Do not hold redundant caller input/encoding slabs throughout the scan.
    drop(raw);
    drop(canonical);
    let mut first = false;
    let mut cancelling = false;
    let mut cancelled_by_user = false;
    let mut wait = until;
    loop {
        if let Some(done) = add.take_completion() {
            return import_complete(
                done,
                cancelled_by_user,
                stdout,
                &mut owners.resolver,
                signals,
                wait,
            )
            .await;
        }
        let signal = if cancelling {
            None
        } else {
            Some(&mut *signals)
        };
        match choose(
            add.drive(Some(wait)),
            &mut owners.resolver,
            signal,
            wait,
            first,
        )
        .await?
        {
            Wake::Provider(event) => match event? {
                AddProgress::Native(event) => print_ps(&event),
                AddProgress::Admitted => {}
                AddProgress::Finished(done) => {
                    return import_complete(
                        done,
                        cancelled_by_user,
                        stdout,
                        &mut owners.resolver,
                        signals,
                        wait,
                    )
                    .await;
                }
                AddProgress::WaitDeadline => {}
                AddProgress::Closed => {
                    return Err("HELLO add closed without original result".into());
                }
            },
            Wake::Resolver => {}
            Wake::Signal if !cancelling => {
                cancelled_by_user = true;
                let cancel = add.cancel()?;
                diagnostic(format_args!(
                    "HELLO import original user cancellation={cancel:?}; no STORE rollback/ACK inferred"
                ));
                cancelling = true;
                wait = Instant::now().min(until) + Duration::from_secs(5);
            }
            Wake::Deadline if !cancelling => {
                let cancel = add.cancel()?;
                diagnostic(format_args!(
                    "HELLO import original cancellation={cancel:?}; no STORE rollback/ACK inferred"
                ));
                cancelling = true;
                wait = Instant::now().min(until) + Duration::from_secs(5);
            }
            Wake::Deadline => {
                if let Some(event) = add.close()? {
                    print_ps(&event);
                }
                return Err("HELLO original scan/STORE suffix retirement unconfirmed by fixed grace; MQ physically closed".into());
            }
            Wake::Signal => {}
        }
        first = !first;
    }
}
