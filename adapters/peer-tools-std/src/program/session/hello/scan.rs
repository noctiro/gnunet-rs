//! Original PEERSTORE iteration, record validation and bounded cancellation.
use super::super::{
    ADDRESS_BYTES, Duration, Failure, Instant, Io, Owners, Resolver, RuntimeClock, Settings,
    Signals, Wake, buffer, choose, diagnostic, hello_limits, output, print_ps, ps,
};
use gnunet_hello::Hello;
use gnunet_program_host::logging::base32;
use std::{io::Write, sync::Arc};
async fn cancel_scan<'id>(
    client: &mut ps::Client<'id>,
    operation: ps::Operation<'id>,
    resolver: &mut Resolver,
    hard: Instant,
) -> Result<(), Failure> {
    let reports = resolver.reports.clone();
    let cancel = client.cancel(operation)?;
    diagnostic(
        &reports,
        format_args!(
            "actual original iterator cancellation={cancel:?}; STOP has no processing ACK"
        ),
    );
    let until = Instant::now().min(hard) + Duration::from_secs(5);
    let mut first = false;
    loop {
        if !client.live(operation) && client.pending() == 0 {
            return Ok(());
        }
        match choose(client.drive(Some(until)), resolver, None, until, first).await? {
            Wake::Provider(event) => {
                let event = event?;
                print_ps(&reports, &event);
                if matches!(event, ps::Progress::Completed { operation: original, .. }
                    if original == operation)
                {
                    return Ok(());
                }
            }
            Wake::Resolver | Wake::Signal => {}
            Wake::Deadline => {
                return Err("original PEERSTORE STOP/suffix did not retire within grace".into());
            }
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
pub(crate) async fn dump<'id>(
    owners: &mut Owners<'id>,
    signals: &mut Signals,
    stdout: &mut Io,
    clock: &Arc<dyn RuntimeClock>,
    settings: &Settings,
    until: Instant,
) -> Result<(), Failure> {
    let reports = owners.resolver.reports.clone();
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
            Wake::Signal => {
                cancel_scan(client, operation, &mut owners.resolver, until).await?;
                return Ok(());
            }
            Wake::Deadline => {
                return Err(format!(
                    "HELLO enumeration expired after {records} records without END"
                )
                .into());
            }
        };
        first = !first;
        print_ps(&reports, &event);
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
                    Err(reason) => diagnostic(
                        &reports,
                        format_args!("invalid/expired public HELLO record skipped: {reason}"),
                    ),
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
                diagnostic(
                    &reports,
                    format_args!("actual HELLO iterator terminal={outcome:?} listed={records}"),
                );
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
