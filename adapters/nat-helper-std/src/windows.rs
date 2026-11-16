//! Winsock raw ICMP with original byte-pipe lifetime and finite native waits.
use crate::{Cause, Failure, failure, text::Text};
use gnunet_nat::icmp::{self, IpLengthProfile};
use gnunet_native::{
    nat_helper::{self, Output, Signals, State},
    network::SocketInterest,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    fmt::Write as _,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddrV4},
    os::windows::io::AsSocket,
    time::{Duration, Instant},
};
const FREQUENCY: Duration = Duration::from_millis(500);
const CLIENT_SEND: Duration = Duration::from_secs(5);
const LINE_LIFETIME: Duration = Duration::from_secs(2);
const STOP_QUANTUM: Duration = Duration::from_millis(50);
const OUTPUT_QUANTUM: Duration = Duration::from_millis(20);
const TTL: u8 = 64;
fn os(code: u8, action: &'static str, error: io::Error) -> Failure {
    failure(code, Cause::Io(action, error))
}
fn target(duration: Duration, code: u8) -> Result<Instant, Failure> {
    Instant::now()
        .checked_add(duration)
        .ok_or_else(|| failure(code, Cause::Deadline("native target overflow")))
}
fn raw(code: u8) -> Result<Socket, Failure> {
    // Both official reversal variants have outer protocol ICMP. IPPROTO_RAW
    // wildcard semantics are unnecessary and differ between native providers.
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
        .map_err(|error| os(code, "open original Winsock raw ICMP socket", error))?;
    socket
        .set_nonblocking(true)
        .map_err(|error| os(code, "raw socket nonblocking mode", error))?;
    Ok(socket)
}
fn configure(socket: &Socket, code: u8) -> Result<(), Failure> {
    socket
        .set_header_included_v4(true)
        .map_err(|error| os(code, "raw IPv4 header inclusion", error))?;
    socket
        .set_broadcast(true)
        .map_err(|error| os(code, "raw broadcast option", error))
}
fn pause(until: Instant) {
    std::thread::sleep(
        until
            .saturating_duration_since(Instant::now())
            .min(OUTPUT_QUANTUM),
    );
}
fn send(
    socket: &Socket,
    destination: &SockAddr,
    packet: &[u8],
    until: Instant,
    signals: &Signals,
    mut output: Option<&mut Output>,
) -> Result<(), Failure> {
    loop {
        if signals.stopped() {
            return Err(failure(12, Cause::Stopped));
        }
        if Instant::now() >= until {
            return Err(failure(12, Cause::Deadline("original raw packet write")));
        }
        if let Some(output) = &mut output {
            match output
                .state()
                .map_err(|error| os(11, "original output reader lifetime", error))?
            {
                State::Closed => return Err(failure(12, Cause::Stopped)),
                State::Connected => {}
            }
        }
        match socket.send_to(packet, destination) {
            Ok(written) if written == packet.len() => return Ok(()),
            Ok(actual) => {
                return Err(failure(
                    12,
                    Cause::ShortPacket {
                        expected: packet.len(),
                        actual,
                    },
                ));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                nat_helper::wait_socket(
                    socket.as_socket(),
                    SocketInterest::Writable,
                    until
                        .saturating_duration_since(Instant::now())
                        .min(STOP_QUANTUM),
                )
                .map_err(|error| os(12, "original raw socket write wait", error))?;
            }
            Err(error) => return Err(os(12, "send original raw packet", error)),
        }
    }
}
fn cleanup(
    result: Result<(), Failure>,
    output: Option<&mut Output>,
    signals: &mut Signals,
) -> Result<(), Failure> {
    let output_cleanup = output.and_then(|output| output.restore().err());
    let signal_cleanup = signals.restore().err();
    match result {
        Err(mut error) => {
            error.output_cleanup = output_cleanup;
            error.signal_cleanup = signal_cleanup;
            Err(error)
        }
        Ok(()) if output_cleanup.is_some() || signal_cleanup.is_some() => Err(Failure {
            code: 13,
            cause: Cause::Cleanup,
            secondary: None,
            output_cleanup,
            signal_cleanup,
        }),
        Ok(()) => Ok(()),
    }
}
pub(super) fn client() -> Result<(), Failure> {
    // Windows has no set-ID executable transition: raw creation uses the real
    // invoking token, and no elevation, alternate credentials or input precedes it.
    let raw = raw(3)?;
    configure(&raw, 5)?;
    let crate::arguments::Client {
        local,
        remote,
        advertised,
    } = crate::arguments::client()?;
    let mut echo = [0; 56];
    let mut udp = [0; 56];
    let echo_len = icmp::reversal_icmp(
        local.octets(),
        remote.octets(),
        advertised,
        TTL,
        IpLengthProfile::Network,
        &mut echo,
    )
    .map_err(|error| failure(9, Cause::Packet(error)))?;
    let udp_len = icmp::reversal_udp(
        local.octets(),
        remote.octets(),
        advertised,
        IpLengthProfile::Network,
        &mut udp,
    )
    .map_err(|error| failure(9, Cause::Packet(error)))?;
    let mut signals =
        Signals::install().map_err(|error| os(1, "install helper stop callback", error))?;
    let result = (|| {
        let until = target(CLIENT_SEND, 12)?;
        let destination = SockAddr::from(SocketAddrV4::new(remote, 0));
        let first = send(&raw, &destination, &echo[..echo_len], until, &signals, None);
        let second = send(&raw, &destination, &udp[..udp_len], until, &signals, None);
        match (first, second) {
            (Err(mut primary), Err(second)) => {
                primary.secondary = Some(Box::new(second.cause));
                Err(primary)
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
            _ => Ok(()),
        }
    })();
    drop(raw);
    cleanup(result, None, &mut signals)
}
struct Line {
    bytes: Text<22>,
    cursor: usize,
    until: Instant,
}
fn line(remote: [u8; 4], port: u16) -> Result<Line, Failure> {
    let mut bytes = Text::new();
    let address = Ipv4Addr::from(remote);
    let result = if port == 0 {
        writeln!(&mut bytes, "{address}")
    } else {
        writeln!(&mut bytes, "{address}:{port}")
    };
    result.map_err(|_| failure(11, Cause::Packet(gnunet_types::Error::Capacity)))?;
    Ok(Line {
        bytes,
        cursor: 0,
        until: target(LINE_LIFETIME, 11)?,
    })
}
fn server_loop(
    raw: &Socket,
    input: &Socket,
    udp: &Socket,
    local: Ipv4Addr,
    output: &mut Output,
    signals: &Signals,
) -> Result<(), Failure> {
    let mut receive = [0; 65535];
    let mut pending: Option<Line> = None;
    let mut next = target(FREQUENCY, 11)?;
    let mut echo_next = false;
    let mut probe = [0; 28];
    let probe_len = icmp::echo_probe(local.octets(), TTL, IpLengthProfile::Network, &mut probe)
        .map_err(|error| failure(5, Cause::Packet(error)))?;
    let dummy = SockAddr::from(SocketAddrV4::new(Ipv4Addr::from(icmp::DUMMY), 0));
    let dummy_udp = SockAddr::from(SocketAddrV4::new(
        Ipv4Addr::from(icmp::DUMMY),
        icmp::TRAVERSAL_PORT,
    ));
    loop {
        if signals.stopped() {
            return Ok(());
        }
        if pending
            .as_ref()
            .is_some_and(|line| Instant::now() >= line.until)
        {
            return Err(failure(
                11,
                Cause::Deadline("original stdout endpoint line"),
            ));
        }
        match output
            .state()
            .map_err(|error| os(11, "original output reader lifetime", error))?
        {
            State::Closed => return Ok(()),
            State::Connected => {}
        }
        if Instant::now() >= next {
            let probe_until = target(FREQUENCY, 11)?;
            let until = pending
                .as_ref()
                .map_or(probe_until, |line| line.until.min(probe_until));
            let result = if echo_next {
                send(
                    raw,
                    &dummy,
                    &probe[..probe_len],
                    until,
                    signals,
                    Some(output),
                )
            } else {
                send(udp, &dummy_udp, &[], until, signals, Some(output))
            };
            if let Err(error) = result {
                return if matches!(error.cause, Cause::Stopped) {
                    Ok(())
                } else {
                    Err(error)
                };
            }
            echo_next = !echo_next;
            next = target(FREQUENCY, 11)?;
        }
        if let Some(line) = &mut pending {
            match output.write(&line.bytes.bytes()[line.cursor..]) {
                Ok(written) => {
                    line.cursor += written;
                    if line.cursor == line.bytes.bytes().len() {
                        pending = None;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    pause(line.until.min(next))
                }
                Err(error) if gnunet_native::pipe::is_peer_closed(&error) => return Ok(()),
                Err(error) => return Err(os(11, "original endpoint line write", error)),
            }
            continue;
        }
        let mut input = input;
        match input.read(&mut receive) {
            Ok(0) => {
                return Err(os(
                    11,
                    "original raw ICMP receive",
                    io::ErrorKind::UnexpectedEof.into(),
                ));
            }
            Ok(used) => {
                if let Ok(Some(observation)) = icmp::observe(&receive[..used]) {
                    pending = Some(line(observation.remote, observation.port)?);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                nat_helper::wait_socket(
                    input.as_socket(),
                    SocketInterest::Readable,
                    next.saturating_duration_since(Instant::now())
                        .min(STOP_QUANTUM),
                )
                .map_err(|error| os(11, "raw ICMP receive wait", error))?;
            }
            Err(error) => return Err(os(11, "original raw ICMP receive", error)),
        }
    }
}
pub(super) fn server() -> Result<(), Failure> {
    let input = raw(6)?;
    let raw = raw(8)?;
    configure(&raw, 9)?;
    let local = crate::arguments::server()?;
    input
        .bind(&SockAddr::from(SocketAddrV4::new(local, 0)))
        .map_err(|error| os(9, "bind original raw ICMP reader", error))?;
    let udp = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|error| os(10, "open UDP probe socket", error))?;
    udp.bind(&SockAddr::from(SocketAddrV4::new(
        local,
        icmp::TRAVERSAL_PORT,
    )))
    .map_err(|error| os(10, "bind original UDP traversal port", error))?;
    udp.set_nonblocking(true)
        .map_err(|error| os(10, "UDP probe nonblocking mode", error))?;
    gnunet_native::network::suppress_udp_connection_resets(udp.as_socket())
        .map_err(|error| os(10, "UDP asynchronous error policy", error))?;
    let mut signals =
        Signals::install().map_err(|error| os(1, "install helper stop callback", error))?;
    let mut output = match Output::stdout() {
        Ok(output) => output,
        Err(error) => {
            return cleanup(
                Err(os(11, "capture original output pipe", error)),
                None,
                &mut signals,
            );
        }
    };
    let result = server_loop(&raw, &input, &udp, local, &mut output, &signals);
    drop(raw);
    drop(input);
    drop(udp);
    cleanup(result, Some(&mut output), &mut signals)
}
pub(super) fn diagnostic(error: &Failure) {
    let mut line = Text::<512>::new();
    let _formatted = writeln!(&mut line, "{error}");
    if let Ok(mut output) = gnunet_native::stdio::Output::stderr() {
        let _written = output.write(line.bytes());
    }
}
