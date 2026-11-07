use super::{Cause, Failure, failure};
use crate::platform::{PROFILE, observe};
use gnunet_nat::icmp;
use gnunet_native::nat_helper::{self, Output, Signals};
use nix::{
    poll::{PollFd, PollFlags, poll},
    unistd::{getppid, read},
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    ffi::OsString,
    fmt, io,
    net::{Ipv4Addr, SocketAddrV4},
    os::fd::AsFd,
    time::{Duration, Instant},
};
const FREQUENCY: Duration = Duration::from_millis(500);
const CLIENT_SEND: Duration = Duration::from_secs(5);
const LINE_LIFETIME: Duration = Duration::from_secs(2);
const TTL: u8 = 64; // IPDEFTTL of the qualified Linux/Darwin/modern FreeBSD profiles.
/// Fixed text storage for official endpoint lines and bounded diagnostics.
pub(crate) struct Text<const N: usize> {
    bytes: [u8; N],
    len: usize,
}
impl<const N: usize> Text<N> {
    pub fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl<const N: usize> fmt::Write for Text<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len.checked_add(s.len()).ok_or(fmt::Error)?;
        if end > N {
            return Err(fmt::Error);
        }
        self.bytes[self.len..end].copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}
fn os(code: u8, action: &'static str, error: io::Error) -> Failure {
    failure(code, Cause::Io(action, error))
}
fn next_arg(args: &mut impl Iterator<Item = OsString>, code: u8) -> Result<OsString, Failure> {
    args.next()
        .ok_or_else(|| failure(code, Cause::Usage("missing official helper argument")))
}
fn ipv4(arg: &OsString, code: u8) -> Result<Ipv4Addr, Failure> {
    arg.to_str()
        .filter(|s| s.len() <= 15)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| failure(code, Cause::Usage("expected a numeric IPv4 address")))
}
fn port(arg: &OsString) -> Result<u16, Failure> {
    let port = arg
        .to_str()
        .filter(|s| s.len() <= 16)
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|n| *n != 0);
    port.ok_or_else(|| failure(8, Cause::Usage("port must be decimal1..65535")))
}
fn no_more(args: &mut impl Iterator<Item = OsString>, code: u8) -> Result<(), Failure> {
    if args.next().is_some() {
        return Err(failure(code, Cause::Usage("unexpected helper argument")));
    }
    Ok(())
}
fn timeout(until: Instant) -> u16 {
    let micros = until.saturating_duration_since(Instant::now()).as_micros();
    u16::try_from(micros.div_ceil(1000).clamp(1, 500)).unwrap_or(500)
}
fn parent_current(original: i32) -> bool {
    original > 1 && getppid().as_raw() == original
}
fn wait_write(
    socket: &Socket,
    until: Instant,
    signals: &Signals,
    alive: &impl Fn() -> bool,
) -> Result<(), Failure> {
    loop {
        if signals.stopped() || !alive() {
            return Err(failure(12, Cause::Stopped));
        }
        if Instant::now() >= until {
            return Err(failure(12, Cause::Deadline("original packet write")));
        }
        let mut fds = [PollFd::new(socket.as_fd(), PollFlags::POLLOUT)];
        match poll(&mut fds, timeout(until)) {
            Ok(0) => {}
            Ok(_) => {
                let flags = fds[0].revents().unwrap_or(PollFlags::empty());
                if flags.intersects(PollFlags::POLLNVAL | PollFlags::POLLHUP) {
                    return Err(os(
                        12,
                        "raw packet poll",
                        io::Error::new(io::ErrorKind::BrokenPipe, "original socket retired"),
                    ));
                }
                if flags.intersects(PollFlags::POLLOUT | PollFlags::POLLERR) {
                    return Ok(());
                }
            }
            Err(nix::errno::Errno::EINTR) => {}
            Err(e) => return Err(os(12, "raw packet poll", io::Error::from(e))),
        }
    }
}
fn send_packet(
    socket: &Socket,
    to: &SockAddr,
    packet: &[u8],
    until: Instant,
    signals: &Signals,
    alive: &impl Fn() -> bool,
) -> Result<(), Failure> {
    loop {
        if signals.stopped() || !alive() {
            return Err(failure(12, Cause::Stopped));
        }
        if Instant::now() >= until {
            return Err(failure(12, Cause::Deadline("original packet write")));
        }
        match socket.send_to(packet, to) {
            Ok(n) if n == packet.len() => return Ok(()),
            Ok(n) => {
                return Err(failure(
                    12,
                    Cause::ShortPacket {
                        expected: packet.len(),
                        actual: n,
                    },
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                wait_write(socket, until, signals, alive)?
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                wait_write(socket, until, signals, alive)?;
            }
            Err(e) => return Err(os(12, "sendto original packet", e)),
        }
    }
}
fn cleanup(
    result: Result<(), Failure>,
    output: Option<&mut Output>,
    signals: &mut Signals,
) -> Result<(), Failure> {
    let output_cleanup = output.and_then(|o| o.restore().err());
    let signal_cleanup = signals.restore().err();
    match result {
        Err(mut failure) => {
            failure.output_cleanup = output_cleanup;
            failure.signal_cleanup = signal_cleanup;
            Err(failure)
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
    // The only privileged operation precedes every CLI/environment/diagnostic use.
    let parent = getppid().as_raw();
    let raw = nat_helper::open_raw_send();
    let _drop = nat_helper::drop_to_real_ids()
        .map_err(|e| os(1, "permanent credential/capability drop", e))?;
    if !nat_helper::watch_parent(parent).map_err(|e| os(1, "original parent death guard", e))? {
        return Err(failure(12, Cause::Stopped));
    }

    let raw = Socket::from(raw.map_err(|e| os(3, "open raw IPv4 writer", e))?);
    nat_helper::configure_raw(&raw).map_err(|e| os(5, "SO_BROADCAST/IP_HDRINCL", e))?;
    raw.set_nonblocking(true)
        .map_err(|e| os(5, "raw writer O_NONBLOCK", e))?;
    let mut args = std::env::args_os();
    let _name = args.next();
    let local = ipv4(&next_arg(&mut args, 6)?, 7)?;
    let remote = ipv4(&next_arg(&mut args, 6)?, 7)?;
    let advertised = port(&next_arg(&mut args, 6)?)?;
    no_more(&mut args, 6)?;
    let mut echo = [0; 56];
    let en = icmp::reversal_icmp(
        local.octets(),
        remote.octets(),
        advertised,
        TTL,
        PROFILE,
        &mut echo,
    )
    .map_err(|e| failure(9, Cause::Packet(e)))?;
    let mut udp = [0; 56];
    let un = icmp::reversal_udp(
        local.octets(),
        remote.octets(),
        advertised,
        PROFILE,
        &mut udp,
    )
    .map_err(|e| failure(9, Cause::Packet(e)))?;
    let mut signals =
        Signals::install().map_err(|e| os(1, "install original helper stop handlers", e))?;
    let until = Instant::now().checked_add(CLIENT_SEND).ok_or_else(|| {
        failure(
            12,
            Cause::Deadline("unrepresentable original send deadline"),
        )
    })?;
    let destination = SockAddr::from(SocketAddrV4::new(remote, 0));
    let first = send_packet(&raw, &destination, &echo[..en], until, &signals, &|| {
        parent_current(parent)
    });
    let second = send_packet(&raw, &destination, &udp[..un], until, &signals, &|| {
        parent_current(parent)
    });
    let result = match (first, second) {
        (Err(mut primary), Err(second)) => {
            primary.secondary = Some(Box::new(second.cause));
            Err(primary)
        }
        (Err(e), _) | (_, Err(e)) => Err(e),
        _ => Ok(()),
    };
    // Both actual owned datagram sources close before cleanup diagnostics/return.
    drop(raw);
    cleanup(result, None, &mut signals)
}
struct Line {
    bytes: Text<22>,
    cursor: usize,
    until: Instant,
}
fn endpoint(remote: [u8; 4], port: u16) -> Result<Line, Failure> {
    use fmt::Write;
    let mut bytes = Text::new();
    let ip = Ipv4Addr::from(remote);
    let formatted = if port == 0 {
        writeln!(&mut bytes, "{ip}")
    } else {
        writeln!(&mut bytes, "{ip}:{port}")
    };
    formatted.map_err(|_| failure(11, Cause::Packet(gnunet_types::Error::Capacity)))?;
    Ok(Line {
        bytes,
        cursor: 0,
        until: Instant::now()
            .checked_add(LINE_LIFETIME)
            .ok_or_else(|| failure(11, Cause::Deadline("endpoint line bound overflow")))?,
    })
}
fn line_write(line: &mut Line, out: &Output) -> Result<bool, Failure> {
    if Instant::now() >= line.until {
        return Err(failure(
            11,
            Cause::Deadline("original stdout endpoint line"),
        ));
    }
    match out.write(&line.bytes.bytes()[line.cursor..]) {
        Ok(0) => Err(os(
            11,
            "stdout original line",
            io::Error::new(io::ErrorKind::WriteZero, "zero-byte stdout progress"),
        )),
        Ok(n) => {
            line.cursor = line
                .cursor
                .checked_add(n)
                .ok_or_else(|| failure(11, Cause::Packet(gnunet_types::Error::Overflow)))?;
            Ok(line.cursor == line.bytes.bytes().len())
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(os(11, "stdout original line", e)),
    }
}
fn server_loop(
    raw: &Socket,
    input: &Socket,
    udp: &Socket,
    local: Ipv4Addr,
    parent: i32,
    out: &Output,
    signals: &Signals,
) -> Result<(), Failure> {
    let mut receive = [0u8; 65535];
    let mut pending: Option<Line> = None;
    let mut echo_next = false;
    let mut next = Instant::now()
        .checked_add(FREQUENCY)
        .ok_or_else(|| failure(11, Cause::Deadline("probe timer overflow")))?;
    let dummy = SockAddr::from(SocketAddrV4::new(Ipv4Addr::from(icmp::DUMMY), 0));
    let dummy_udp = SockAddr::from(SocketAddrV4::new(
        Ipv4Addr::from(icmp::DUMMY),
        icmp::TRAVERSAL_PORT,
    ));
    let mut probe = [0u8; 28];
    let size = icmp::echo_probe(local.octets(), TTL, PROFILE, &mut probe)
        .map_err(|e| failure(5, Cause::Packet(e)))?;
    loop {
        if signals.stopped() || !parent_current(parent) {
            return Ok(());
        }
        let now = Instant::now();
        if let Some(line) = &mut pending
            && now >= line.until
        {
            return Err(failure(
                11,
                Cause::Deadline("original stdout endpoint line"),
            ));
        }
        if now >= next {
            // One alternating packet per500ms, independent of inbound readiness. A late
            // wake skips missed probes instead of creating a catch-up packet burst.
            let until = now
                .checked_add(FREQUENCY)
                .ok_or_else(|| failure(11, Cause::Deadline("probe write bound overflow")))?;
            let sent = if echo_next {
                send_packet(raw, &dummy, &probe[..size], until, signals, &|| {
                    parent_current(parent)
                })
            } else {
                send_packet(udp, &dummy_udp, &[], until, signals, &|| {
                    parent_current(parent)
                })
            };
            if let Err(error) = sent {
                if signals.stopped() || !parent_current(parent) {
                    return Ok(());
                }
                return Err(error);
            }
            echo_next = !echo_next;
            next = Instant::now()
                .checked_add(FREQUENCY)
                .ok_or_else(|| failure(11, Cause::Deadline("probe timer overflow")))?;
        }
        let until = pending.as_ref().map_or(next, |line| next.min(line.until));
        // Poll only the descriptor whose current immutable state can progress. An
        // unrequested raw POLLERR must not spin while the original stdout line waits.
        let (read_flags, write_flags) = {
            let writing = pending.is_some();
            let descriptor = if writing { out.as_fd() } else { input.as_fd() };
            let mut fds = [PollFd::new(
                descriptor,
                if writing {
                    PollFlags::POLLOUT
                } else {
                    PollFlags::POLLIN
                },
            )];
            match poll(&mut fds, timeout(until)) {
                Ok(0) => continue,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => return Err(os(11, "server poll", io::Error::from(e))),
                Ok(_) => {}
            }
            let flags = fds[0].revents().unwrap_or(PollFlags::empty());
            if writing {
                (PollFlags::empty(), flags)
            } else {
                (flags, PollFlags::empty())
            }
        };
        if signals.stopped() || !parent_current(parent) {
            return Ok(());
        }
        if read_flags.intersects(PollFlags::POLLNVAL | PollFlags::POLLHUP) {
            return Err(os(
                11,
                "raw input poll",
                io::Error::new(io::ErrorKind::BrokenPipe, "original raw descriptor retired"),
            ));
        }
        if write_flags.intersects(PollFlags::POLLNVAL | PollFlags::POLLHUP | PollFlags::POLLERR) {
            return Err(os(
                11,
                "stdout poll",
                io::Error::new(io::ErrorKind::BrokenPipe, "original stdout source retired"),
            ));
        }
        if let Some(line) = &mut pending
            && write_flags.contains(PollFlags::POLLOUT)
            && line_write(line, out)?
        {
            pending = None;
        }
        if pending.is_none() && read_flags.intersects(PollFlags::POLLIN | PollFlags::POLLERR) {
            match read(input, &mut receive) {
                Ok(0) => {
                    return Err(os(
                        11,
                        "raw input",
                        io::Error::new(io::ErrorKind::UnexpectedEof, "zero-byte raw IPv4 input"),
                    ));
                }
                Ok(n) => {
                    if let Ok(Some(observation)) = observe(&mut receive[..n]) {
                        pending = Some(endpoint(observation.remote, observation.port)?)
                    }
                }
                Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => {}
                Err(e) => return Err(os(11, "read original raw ICMP packet", io::Error::from(e))),
            }
        }
    }
}
pub(super) fn server() -> Result<(), Failure> {
    // Preserve both actual socket-open results, then drop before any CLI parsing.
    let parent = getppid().as_raw();
    let input = nat_helper::open_raw_icmp();
    let raw = nat_helper::open_raw_send();
    let _drop = nat_helper::drop_to_real_ids()
        .map_err(|e| os(1, "permanent credential/capability drop", e))?;
    if !nat_helper::watch_parent(parent).map_err(|e| os(1, "original parent death guard", e))? {
        return Ok(());
    }

    let mut args = std::env::args_os();
    let _name = args.next();
    let local = ipv4(&next_arg(&mut args, 3)?, 4)?;
    no_more(&mut args, 3)?;
    let input = Socket::from(input.map_err(|e| os(6, "open raw ICMP reader", e))?);
    let raw = Socket::from(raw.map_err(|e| os(8, "open raw IPv4 writer", e))?);
    nat_helper::configure_raw(&raw).map_err(|e| os(9, "SO_BROADCAST/IP_HDRINCL", e))?;
    raw.set_nonblocking(true)
        .map_err(|e| os(9, "raw writer O_NONBLOCK", e))?;
    input
        .set_nonblocking(true)
        .map_err(|e| os(9, "raw input O_NONBLOCK", e))?;
    let udp = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| os(10, "open UDP probe socket", e))?;
    udp.bind(&SockAddr::from(SocketAddrV4::new(
        local,
        icmp::TRAVERSAL_PORT,
    )))
    .map_err(|e| os(10, "bind original UDP traversal port22225", e))?;
    udp.set_nonblocking(true)
        .map_err(|e| os(10, "UDP O_NONBLOCK", e))?;
    let mut signals = Signals::install().map_err(|e| os(1, "install helper stop handlers", e))?;
    let mut output = match Output::stdout() {
        Ok(out) => out,
        Err(e) => {
            let primary = Err(os(11, "capture original nonblocking stdout", e));
            return cleanup(primary, None, &mut signals);
        }
    };
    let result = server_loop(&raw, &input, &udp, local, parent, &output, &signals);
    drop(raw);
    drop(input);
    drop(udp);
    cleanup(result, Some(&mut output), &mut signals)
}
