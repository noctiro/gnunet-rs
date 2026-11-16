//! Keep the actual MQ/datagram owners and frozen packets through native EOF.
use super::*;

fn snapshot(runtime: &Runtime<'_>) -> Vec<(u32, *const u8, usize, u64, Instant, SendOutcome)> {
    runtime
        .queues
        .iter()
        .flatten()
        .filter_map(|queue| {
            queue.send.as_ref().map(|send| {
                (
                    queue.id,
                    send.packet.as_ptr(),
                    send.packet.len(),
                    send.bound.until,
                    send.bound.hard,
                    send.outcome,
                )
            })
        })
        .collect()
}
pub(super) async fn restore(
    runtime: &mut Runtime<'_>,
    trace: &mut Trace,
    listener: &UnixListener,
    pils: UnixStream,
    producer: &mut gnunet_pils::Service<4096>,
    destinations: (&UnixDatagram, &UnixDatagram),
    changed: bool,
) -> Result<UnixStream, Failure> {
    let epoch = runtime.epoch;
    let socket = runtime.socket_epoch;
    let original = runtime.pils.epoch().ok_or("missing original PILS epoch")?;
    let parent = (
        runtime.parent.until,
        runtime.parent.hard,
        runtime.startup.until,
        runtime.startup.hard,
    );
    let packets = snapshot(runtime);
    let output = runtime.outputs.front().map(|output| {
        (
            output.id,
            output.bytes,
            output.bound.until,
            output.bound.hard,
        )
    });
    let paused = trace.paused;
    drop(pils);
    while trace.paused == paused {
        let now = runtime.clock.sample()?.now.as_micros();
        poll_fn(|cx| runtime.poll_pils(cx, now, &mut |event| trace.observe(event))).await?;
    }
    check(runtime.identity.paused() && runtime.peer().is_none() && !runtime.ready())?;
    let bound = runtime
        .identity
        .bound()
        .ok_or("missing source recovery bound")?;
    // Drive the public scheduler while its new socket has no announcement.
    // No old ACK suffix or native datagram may advance during this pause.
    for _ in 0..12 {
        if let Poll::Ready(result) = runtime.poll(
            &mut Context::from_waker(std::task::Waker::noop()),
            None,
            &mut |event| trace.observe(event),
        ) {
            result?;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let (unsigned, _) = listener.accept().await?;
    check(
        runtime.identity.paused()
            && snapshot(runtime) == packets
            && runtime.outputs.front().map(|output| {
                (
                    output.id,
                    output.bytes,
                    output.bound.until,
                    output.bound.hard,
                )
            }) == output,
    )?;
    let mut buffer = [0; 2048];
    for destination in [destinations.0, destinations.1] {
        check(
            matches!(destination.try_recv(&mut buffer),Err(error) if error.kind()==io::ErrorKind::WouldBlock),
        )?;
    }
    drop(unsigned);
    while trace.paused == paused + 1 {
        let now = runtime.clock.sample()?.now.as_micros();
        poll_fn(|cx| runtime.poll_pils(cx, now, &mut |event| trace.observe(event))).await?;
    }
    check(
        runtime
            .identity
            .bound()
            .is_some_and(|current| current.hard == bound.hard && current.until == bound.until),
    )?;
    if changed {
        conditional_update(
            producer,
            b"unix:///replaced-source",
            runtime.clock.sample()?.now.as_micros(),
        )?;
    }
    let expected = *producer.identity().public_key().as_bytes();
    while runtime.pils.epoch().is_none() {
        let now = runtime.clock.sample()?.now.as_micros();
        poll_fn(|cx| runtime.poll_pils(cx, now, &mut |event| trace.observe(event))).await?;
    }
    let (mut fresh, _) = listener.accept().await?;
    fresh.write_all(producer.announcement()).await?;
    let resumed = trace.resumed;
    identity(runtime, trace).await?;
    check(
        trace.resumed == resumed + 1
            && runtime.peer() == Some(expected)
            && runtime.ready()
            && runtime
                .pils
                .epoch()
                .is_some_and(|epoch| epoch.is_successor_of(original))
            && runtime.epoch == epoch
            && runtime.socket_epoch == socket
            && snapshot(runtime) == packets
            && runtime.outputs.front().map(|output| {
                (
                    output.id,
                    output.bytes,
                    output.bound.until,
                    output.bound.hard,
                )
            }) == output
            && (
                runtime.parent.until,
                runtime.parent.hard,
                runtime.startup.until,
                runtime.startup.hard,
            ) == parent
            && trace.transport_losses == 0
            && trace.retired.is_empty(),
    )?;
    Ok(fresh)
}
