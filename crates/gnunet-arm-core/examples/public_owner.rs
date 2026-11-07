//! Explicit owned-Unix observation adapter, not production ARM host/runtime.
use gnunet_arm_core::{
    ConnectionEpoch, FrameSlot, FrameTicket,
    client::{
        Client, ConnectionStatus, Effect, Event, Inbound, OperationId, OperationSlot,
        StdioInheritance,
    },
    monitor::Monitor,
    wire::{ArmAbi, List, RequestStatus, ResultCode},
};
use gnunet_types::{AbsoluteTime, Error};
use gnunet_wire::official::MessageHeader;
use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn require(value: bool, reason: &str) -> Result<()> {
    if !value {
        return Err(io::Error::other(reason).into());
    }
    Ok(())
}
trait Outgoing {
    fn take(&mut self) -> std::result::Result<Option<FrameTicket>, Error>;
    fn view(&self, t: FrameTicket) -> std::result::Result<&[u8], Error>;
    fn written(&mut self, t: FrameTicket) -> std::result::Result<(), Error>;
}
impl Outgoing for Client<'_> {
    fn take(&mut self) -> std::result::Result<Option<FrameTicket>, Error> {
        self.take_frame()
    }
    fn view(&self, t: FrameTicket) -> std::result::Result<&[u8], Error> {
        self.frame(t)
    }
    fn written(&mut self, t: FrameTicket) -> std::result::Result<(), Error> {
        self.frame_written(t)
    }
}
impl Outgoing for Monitor<'_> {
    fn take(&mut self) -> std::result::Result<Option<FrameTicket>, Error> {
        self.take_frame()
    }
    fn view(&self, t: FrameTicket) -> std::result::Result<&[u8], Error> {
        self.frame(t)
    }
    fn written(&mut self, t: FrameTicket) -> std::result::Result<(), Error> {
        self.frame_written(t)
    }
}
struct Tx {
    ticket: FrameTicket,
    bytes: Vec<u8>,
    offset: usize,
}
struct Net {
    stream: UnixStream,
    epoch: ConnectionEpoch,
    rx: Vec<u8>,
    tx: Option<Tx>,
}
impl Net {
    fn connect(path: &str, epoch: ConnectionEpoch) -> Result<Self> {
        let stream = UnixStream::connect(path)?;
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            epoch,
            rx: Vec::with_capacity(65535),
            tx: None,
        })
    }
    fn send(&mut self, core: &mut impl Outgoing) -> Result<()> {
        for _ in 0..32 {
            if self.tx.is_none() {
                let Some(ticket) = core.take()? else {
                    break;
                };
                let bytes = core.view(ticket)?.to_vec();
                require(bytes.len() <= 65535, "oversized core frame")?;
                self.tx = Some(Tx {
                    ticket,
                    bytes,
                    offset: 0,
                });
            }
            let tx = self.tx.as_mut().ok_or(Error::NotReady)?;
            match self.stream.write(&tx.bytes[tx.offset..]) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "Unix frame").into()),
                Ok(n) => tx.offset += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
            if tx.offset == tx.bytes.len() {
                core.written(tx.ticket)?;
                self.tx = None;
            }
        }
        Ok(())
    }
    fn read(&mut self) -> Result<bool> {
        let mut buf = [0; 8192];
        for _ in 0..32 {
            match self.stream.read(&mut buf) {
                Ok(0) => return Ok(true),
                Ok(n) => {
                    require(self.rx.len() + n <= 65535, "bounded RX overflow")?;
                    self.rx.extend_from_slice(&buf[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(false)
    }
    fn ready_len(&self) -> Result<Option<usize>> {
        if self.rx.len() < 4 {
            return Ok(None);
        }
        let n = MessageHeader::decode(&self.rx)?.size();
        Ok((self.rx.len() >= n).then_some(n))
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Start,
    Stop,
    List,
    Already,
    StopArm,
}
struct Context {
    phase: u8,
    active: Option<(OperationId, Kind)>,
    monitor_started: bool,
    monitor_count: usize,
    repeat: bool,
    stopped: bool,
}
impl Context {
    fn event(
        &mut self,
        core: &mut Client<'_>,
        event: Event,
        now: AbsoluteTime,
        out: &mut impl Write,
    ) -> Result<()> {
        match event {
            Event::Connection(status) => {
                let value = match status {
                    ConnectionStatus::Connected => 1,
                    ConnectionStatus::Disconnected => 0,
                    ConnectionStatus::Error => -1,
                };
                writeln!(out, "{{\"event\":\"connection\",\"connected\":{value}}}")?;
                match status {
                    ConnectionStatus::Error => return Err(Error::Unavailable.into()),
                    ConnectionStatus::Disconnected => require(self.stopped, "early owner loss")?,
                    ConnectionStatus::Connected => {
                        if self.phase == 0 {
                            self.phase = 1;
                            self.monitor_started = true;
                            let op =
                                core.request_service_start(b"svc", StdioInheritance(6), now)?;
                            self.active = Some((op, Kind::Start));
                        } else {
                            self.repeat = true;
                        }
                    }
                }
            }
            Event::Result {
                operation,
                status,
                result,
            } => {
                let (original, kind) = self.active.take().ok_or(Error::StaleGeneration)?;
                require(
                    operation == original && status == RequestStatus::SentOk,
                    "wrong result operation/status",
                )?;
                let code = result.ok_or(Error::Malformed)?;
                let (label, expected) = match kind {
                    Kind::Start => ("start_service", ResultCode::STARTING),
                    Kind::Stop => ("stop_service", ResultCode::STOPPED),
                    Kind::Already => ("local_arm_already", ResultCode::IS_STARTED_ALREADY),
                    Kind::StopArm => ("stop_arm", ResultCode::STOPPED),
                    Kind::List => return Err(Error::Malformed.into()),
                };
                require(code == expected, "wrong real result")?;
                writeln!(
                    out,
                    "{{\"event\":\"{label}\",\"rs\":0,\"result\":{}}}",
                    code.0
                )?;
                match kind {
                    Kind::Start => {
                        self.phase = 2;
                        self.active = Some((core.request_service_stop(b"svc")?, Kind::Stop));
                    }
                    Kind::Stop => {
                        self.phase = 3;
                        self.active = Some((core.request_service_list()?, Kind::List));
                    }
                    Kind::Already => {
                        self.phase = 5;
                        self.active = Some((core.request_service_stop(b"arm")?, Kind::StopArm));
                    }
                    Kind::StopArm => {
                        self.phase = 6;
                        self.stopped = true;
                    }
                    Kind::List => return Err(Error::Malformed.into()),
                }
            }
            Event::ListDisconnected { .. } => return Err(Error::Io.into()),
        }
        Ok(())
    }
    fn list(
        &mut self,
        core: &mut Client<'_>,
        operation: OperationId,
        list: List<'_>,
        now: AbsoluteTime,
        out: &mut impl Write,
    ) -> Result<()> {
        require(
            self.active.take() == Some((operation, Kind::List)),
            "wrong list operation",
        )?;
        require(list.len() == 1, "wrong list count")?;
        let row = list.get(0)?.ok_or(Error::NotFound)?;
        require(
            row.name == b"svc" && row.binary == b"bn",
            "wrong borrowed strings",
        )?;
        writeln!(
            out,
            "{{\"event\":\"list\",\"rs\":0,\"count\":{},\"name\":\"svc\",\"binary\":\"bn\",\"status\":{},\"exit\":{},\"restart\":{},\"last_start\":{}}}",
            list.len(),
            row.status.0,
            row.public_exit_status(),
            row.restart_at,
            row.last_started_at
        )?;
        let cancel = core.request_service_stop(b"cancel")?;
        core.operation_cancel(cancel)?;
        writeln!(out, "{{\"event\":\"cancel_queued\"}}")?;
        self.phase = 4;
        self.active = Some((
            core.request_service_start(b"arm", StdioInheritance(6), now)?,
            Kind::Already,
        ));
        Ok(())
    }
    fn drain(
        &mut self,
        core: &mut Client<'_>,
        now: AbsoluteTime,
        out: &mut impl Write,
    ) -> Result<()> {
        while let Some(event) = core.next_event() {
            self.event(core, event, now, out)?;
        }
        Ok(())
    }
}
fn run(path: &str, out: &mut impl Write) -> Result<()> {
    let mut ops = [OperationSlot::EMPTY; 8];
    let mut frames = [FrameSlot::EMPTY; 16];
    let mut txbytes = vec![0; 4096];
    let mut owner = Client::new(&mut ops, &mut frames, &mut txbytes, 1, ArmAbi::U64Align8)?;
    let mut mframes = [FrameSlot::EMPTY; 1];
    let mut mbytes = [0; 16];
    let mut monitor = Monitor::new(&mut mframes, &mut mbytes, 2)?;
    let mut control: Option<Net> = None;
    let mut mon: Option<Net> = None;
    let mut ctx = Context {
        phase: 0,
        active: None,
        monitor_started: false,
        monitor_count: 0,
        repeat: false,
        stopped: false,
    };
    let start = Instant::now();
    loop {
        require(
            start.elapsed() < Duration::from_secs(5),
            "probe budget elapsed",
        )?;
        let now = AbsoluteTime::from_micros(u64::try_from(start.elapsed().as_micros())?);
        owner.tick(now)?;
        ctx.drain(&mut owner, now, out)?;
        if ctx.stopped && ctx.repeat && ctx.monitor_count == 4 {
            break;
        }
        if let Some(effect) = owner.take_effect(now)? {
            match effect {
                Effect::Connect(epoch) => {
                    require(control.is_none(), "duplicate physical MQ")?;
                    let net = Net::connect(path, epoch)?;
                    owner.connection_admitted(epoch)?;
                    control = Some(net);
                }
                Effect::StartArm { .. } | Effect::CloseStartupSignal { .. } => {
                    return Err(io::Error::other(
                        "unexpected real spawn/signal effect; observer never executes programs",
                    )
                    .into());
                }
            }
        }
        if ctx.monitor_started
            && mon.is_none()
            && let Some(epoch) = monitor.take_connect(now)?
        {
            let net = Net::connect(path, epoch)?;
            monitor.connection_admitted(epoch)?;
            mon = Some(net);
        }
        if let Some(net) = control.as_mut() {
            net.send(&mut owner)?;
        }
        if let Some(net) = mon.as_mut() {
            net.send(&mut monitor)?;
        }
        let mut loss = None;
        if let Some(net) = control.as_mut() {
            let eof = net.read()?;
            while let Some(n) = net.ready_len()? {
                match owner.receive(net.epoch, &net.rx[..n], now)? {
                    Some(Inbound::Event(event)) => ctx.event(&mut owner, event, now, out)?,
                    Some(Inbound::List { operation, list }) => {
                        ctx.list(&mut owner, operation, list, now, out)?
                    }
                    None => {}
                }
                net.rx.drain(..n);
            }
            if eof {
                require(net.rx.is_empty(), "truncated EOF")?;
                loss = Some(net.epoch);
            }
        }
        if let Some(epoch) = loss {
            control.take();
            owner.connection_lost(epoch, now)?;
            ctx.drain(&mut owner, now, out)?;
        }
        if let Some(net) = mon.as_mut() {
            let eof = net.read()?;
            require(!eof, "early monitor EOF")?;
            while let Some(n) = net.ready_len()? {
                if let Some(status) = monitor.receive(net.epoch, &net.rx[..n], now)? {
                    let service = std::str::from_utf8(status.service)?;
                    require(
                        ["arm", "svc", "future"].contains(&service),
                        "unknown monitor name",
                    )?;
                    ctx.monitor_count += 1;
                    writeln!(
                        out,
                        "{{\"event\":\"monitor\",\"service\":\"{service}\",\"status\":{}}}",
                        status.status.0
                    )?;
                }
                net.rx.drain(..n);
            }
        }
        owner.tick(now)?;
        ctx.drain(&mut owner, now, out)?;
        if ctx.stopped && ctx.repeat && ctx.monitor_count == 4 {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let _retired = owner.disconnect();
    ctx.drain(
        &mut owner,
        AbsoluteTime::from_micros(u64::try_from(start.elapsed().as_micros())?),
        out,
    )?;
    let _monitor_close = monitor.stop();
    drop(control.take());
    drop(mon.take());
    require(
        owner.is_closed() && monitor.is_closed(),
        "logical owners not closed",
    )?;
    writeln!(
        out,
        "{{\"event\":\"done\",\"failed\":0,\"monitor_count\":{},\"repeat\":1,\"stopped\":1}}",
        ctx.monitor_count
    )?;
    Ok(())
}
fn main() -> Result<()> {
    let path = std::env::args().nth(1).ok_or(Error::InvalidInput)?;
    run(&path, &mut io::stdout().lock())
}
