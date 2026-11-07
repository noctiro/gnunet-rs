//! One bounded bidirectional packet pump; stream cursors never split a TUN packet.
use crate::{
    failure::{Failure, Report, protocol},
    native::{self, Streams, Tun},
};
use gnunet_native::nat_helper::Signals;
use gnunet_wire::{MessageHeader, message_type, vpn::Helper};
use std::{
    io,
    os::fd::AsRawFd,
    time::{Duration, Instant},
};
const FRAME: usize = u16::MAX as usize;
// One extra full IPv4 maximum plus PI can be observed and rejected without
// truncating into a seemingly complete 16-bit helper frame.
const TUN_READ: usize = 65540;
const LIFETIME: Duration = Duration::from_secs(30);
const CADENCE: i32 = 500;
fn buffer(length: usize) -> Result<Vec<u8>, Failure> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(length)
        .map_err(|_| Failure::invalid("pump allocation", "bounded packet allocation failed"))?;
    value.resize(length, 0);
    Ok(value)
}
fn pending(started: Instant) -> Result<Instant, Failure> {
    started
        .checked_add(LIFETIME)
        .ok_or_else(|| Failure::invalid("packet deadline", "native target overflow"))
}
fn blocked(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
    )
}
fn timed(input: Option<Instant>, output: Option<Instant>) -> Result<(), Failure> {
    if input.is_some_and(|hard| Instant::now() >= hard)
        || output.is_some_and(|hard| Instant::now() >= hard)
    {
        Err(Failure::new(
            "original packet deadline",
            io::Error::new(
                io::ErrorKind::TimedOut,
                "original packet cursor did not settle",
            ),
        ))
    } else {
        Ok(())
    }
}
fn timeout(input: Option<Instant>, output: Option<Instant>) -> i32 {
    let next = input.into_iter().chain(output).min();
    next.map_or(CADENCE, |hard| {
        i32::try_from(
            hard.saturating_duration_since(Instant::now())
                .as_millis()
                .clamp(1, CADENCE as u128),
        )
        .unwrap_or(CADENCE)
    })
}
fn entry(fd: i32, events: i16) -> libc::pollfd {
    libc::pollfd {
        fd: if events == 0 { -1 } else { fd },
        events,
        revents: 0,
    }
}
fn invalid(events: libc::pollfd) -> Result<(), Failure> {
    if events.revents & libc::POLLNVAL != 0 {
        Err(Failure::new(
            "original descriptor",
            io::Error::from_raw_os_error(libc::EBADF),
        ))
    } else {
        Ok(())
    }
}
pub(super) fn run(
    tun: &Tun,
    streams: &Streams,
    signals: &Signals,
    parent: i32,
    report: &mut Report,
) -> Result<(), Failure> {
    let original_mtu =
        usize::try_from(tun.mtu).map_err(|_| Failure::invalid("MTU", "native MTU overflow"))?;
    let mut input = buffer(FRAME)?;
    let mut output = buffer(TUN_READ + 4)?;
    let mut input_used = 0;
    let mut target = 4;
    let mut complete = false;
    let mut output_used = 0;
    let mut output_total = 0;
    let mut input_hard = None;
    let mut output_hard = None;
    let mut cursor = 0usize;
    loop {
        report.input_bytes = input_used;
        report.input_target = target;
        report.output_written = output_used;
        report.output_total = output_total;
        if signals.stopped() {
            report.stopped = Some("original stop signal");
            return Ok(());
        }
        if native::parent() != parent {
            report.stopped = Some("original parent retired");
            return Ok(());
        }
        timed(input_hard, output_hard)?;
        let mut events = [
            entry(
                streams.input.as_raw_fd(),
                if complete { 0 } else { libc::POLLIN },
            ),
            entry(
                tun.fd.as_raw_fd(),
                if complete { libc::POLLOUT } else { 0 }
                    | if output_total == 0 { libc::POLLIN } else { 0 },
            ),
            entry(
                streams.output.as_raw_fd(),
                if output_total == 0 { 0 } else { libc::POLLOUT },
            ),
        ];
        match native::poll(&mut events, timeout(input_hard, output_hard)) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Failure::new("packet poll", error)),
            Ok(_) => {}
        }
        for offset in 0..4 {
            report.input_bytes = input_used;
            report.input_target = target;
            report.output_written = output_used;
            report.output_total = output_total;
            if signals.stopped() {
                report.stopped = Some("original stop signal");
                return Ok(());
            }
            if native::parent() != parent {
                report.stopped = Some("original parent retired");
                return Ok(());
            }
            timed(input_hard, output_hard)?;
            for event in events {
                invalid(event)?;
            }
            match (cursor + offset) % 4 {
                0 if !complete
                    && events[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 =>
                {
                    let started = Instant::now();
                    let end = target.min(input_used + 8192);
                    match native::read(&streams.input, &mut input[input_used..end]) {
                        Ok(0) if input_used == 0 => {
                            report.stopped = Some("original stdin EOF");
                            return Ok(());
                        }
                        Ok(0) => {
                            return Err(Failure::new(
                                "stdin frame",
                                io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "partial original helper frame",
                                ),
                            ));
                        }
                        Ok(count) => {
                            if input_hard.is_none() {
                                input_hard = Some(pending(started)?);
                            }
                            input_used += count;
                            report.input_bytes = input_used;
                            if input_used == 4 && target == 4 {
                                let header = MessageHeader::decode(&input[..4])
                                    .map_err(|error| protocol("stdin header", error))?;
                                if header.message_type() != message_type::VPN_HELPER
                                    || header.size() < 8
                                {
                                    return Err(Failure::invalid(
                                        "stdin header",
                                        "expected official VPN_HELPER185 with original PI",
                                    ));
                                }
                                target = header.size();
                                report.input_target = target;
                            }
                            if input_used == target {
                                let _original = Helper::decode(&input[..target])
                                    .map_err(|error| protocol("stdin frame", error))?;
                                complete = true;
                            }
                        }
                        Err(error) if blocked(&error) => {}
                        Err(error) => return Err(Failure::new("stdin read", error)),
                    }
                }
                1 if complete
                    && events[1].revents & (libc::POLLOUT | libc::POLLERR | libc::POLLHUP) != 0 =>
                {
                    let packet = &input[4..target];
                    report.injection_total = packet.len();
                    match native::write(&tun.fd, packet) {
                        Ok(count) => {
                            report.injection_bytes = count;
                            if count != packet.len() {
                                return Err(Failure::new(
                                    "atomic TUN packet write",
                                    io::Error::new(
                                        io::ErrorKind::WriteZero,
                                        "short TUN packet write cannot be resumed as another packet",
                                    ),
                                ));
                            }
                            report.injected = report.injected.saturating_add(1);
                            report.injection_bytes = 0;
                            report.injection_total = 0;
                            input_used = 0;
                            target = 4;
                            complete = false;
                            input_hard = None;
                        }
                        Err(error) if blocked(&error) => {}
                        Err(error) => return Err(Failure::new("TUN packet write", error)),
                    }
                }
                2 if output_total == 0
                    && events[1].revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 =>
                {
                    let started = Instant::now();
                    match native::read(&tun.fd, &mut output[4..]) {
                        Ok(0) => {
                            return Err(Failure::new(
                                "TUN packet read",
                                io::Error::new(io::ErrorKind::UnexpectedEof, "original TUN EOF"),
                            ));
                        }
                        Ok(count) => {
                            if !(4..=FRAME - 4).contains(&count) || count - 4 > original_mtu {
                                return Err(Failure::invalid(
                                    "TUN packet read",
                                    "packet is not representable by one original helper frame",
                                ));
                            }
                            // Linux tun_pi.flags is native-endian; its protocol
                            // and every PI byte are forwarded unchanged.
                            let flags = u16::from_ne_bytes([output[4], output[5]]);
                            if flags & libc::TUN_PKT_STRIP as u16 != 0 {
                                return Err(Failure::invalid(
                                    "TUN packet read",
                                    "kernel reported a truncated packet",
                                ));
                            }
                            output_total = count + 4;
                            output_used = 0;
                            report.output_total = output_total;
                            report.output_written = 0;
                            MessageHeader::from_total_size(message_type::VPN_HELPER, output_total)
                                .and_then(|header| header.encode(&mut output[..4]))
                                .map_err(|error| protocol("TUN helper header", error))?;
                            output_hard = Some(pending(started)?);
                        }
                        Err(error) if blocked(&error) => {}
                        Err(error) => return Err(Failure::new("TUN packet read", error)),
                    }
                }
                3 if output_total > 0
                    && events[2].revents & (libc::POLLOUT | libc::POLLERR | libc::POLLHUP) != 0 =>
                {
                    // At most Linux PIPE_BUF per actual call, retaining the
                    // original stream cursor; no inherited OFD flags change.
                    let end = output_total.min(output_used + 4096);
                    match native::write(&streams.output, &output[output_used..end]) {
                        Ok(0) => {
                            return Err(Failure::new(
                                "stdout frame",
                                io::Error::new(
                                    io::ErrorKind::WriteZero,
                                    "zero original stdout write",
                                ),
                            ));
                        }
                        Ok(count) => {
                            output_used += count;
                            report.output_written = output_used;
                            if output_used == output_total {
                                report.emitted = report.emitted.saturating_add(1);
                                output_used = 0;
                                output_total = 0;
                                output_hard = None;
                            }
                        }
                        Err(error) if blocked(&error) => {}
                        Err(error) => return Err(Failure::new("stdout frame", error)),
                    }
                }
                _ => {}
            }
        }
        cursor = (cursor + 1) % 4;
    }
}
