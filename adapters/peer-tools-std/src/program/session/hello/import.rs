//! HELLO input validation and original PEERSTORE hello_add completion.
use super::super::{
    ADDRESS_BYTES, Duration, Failure, Instant, Io, Owners, Resolver, RuntimeClock, Settings,
    Signals, Wake, buffer, choose, diagnostic, hello_limits, input, output, print_ps, ps,
};
use gnunet_hello::{AbsoluteTime, Hello};
use gnunet_peerstore_client_host::hello::{AddOutcome, AddProgress, HelloAdd};
use gnunet_program_host::reporting::Reporter;
use std::sync::Arc;
fn import_result(
    done: ps::hello::Completion<'_>,
    cancelled: bool,
    reports: &Reporter,
) -> Result<(), Failure> {
    diagnostic(
        reports,
        format_args!(
            "actual HELLO add completion scan={:?} store={:?} epoch={:?} coverage={:?} outcome={:?}",
            done.scan, done.store, done.epoch, done.coverage, done.outcome
        ),
    );
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
    resolver: &mut Resolver,
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
    import_result(done, user_cancelled, &resolver.reports)?;
    if let Some(message) = message {
        output(stdout, message, resolver, signals, until).await?;
    }
    Ok(())
}
pub(crate) async fn import<'id>(
    owners: &mut Owners<'id>,
    signals: &mut Signals,
    stdout: &mut Io,
    clock: &Arc<dyn RuntimeClock>,
    settings: &Settings,
    until: Instant,
) -> Result<(), Failure> {
    let reports = owners.resolver.reports.clone();
    let raw = input(&mut owners.resolver, signals, until).await?;
    let mut scratch = buffer(ADDRESS_BYTES)?;
    let is_url = raw
        .get(..15)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"gnunet://hello/"));
    let mut canonical = buffer(0)?;
    let frame: &[u8] = if is_url {
        let mut end = raw.len();
        while end > 0 && matches!(raw[end - 1], b'\n' | b'\r') {
            end -= 1;
        }
        let hello = Hello::parse_url(&raw[..end], &mut scratch, hello_limits())?;
        canonical = buffer(hello.message_len()?)?;
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
                AddProgress::Native(event) => print_ps(&reports, &event),
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
                diagnostic(
                    &reports,
                    format_args!(
                        "HELLO import original user cancellation={cancel:?}; no STORE rollback/ACK inferred"
                    ),
                );
                cancelling = true;
                wait = Instant::now().min(until) + Duration::from_secs(5);
            }
            Wake::Deadline if !cancelling => {
                let cancel = add.cancel()?;
                diagnostic(
                    &reports,
                    format_args!(
                        "HELLO import original cancellation={cancel:?}; no STORE rollback/ACK inferred"
                    ),
                );
                cancelling = true;
                wait = Instant::now().min(until) + Duration::from_secs(5);
            }
            Wake::Deadline => {
                if let Some(event) = add.close()? {
                    print_ps(&reports, &event);
                }
                return Err("HELLO original scan/STORE suffix retirement unconfirmed by fixed grace; MQ physically closed".into());
            }
            Wake::Signal => {}
        }
        first = !first;
    }
}
