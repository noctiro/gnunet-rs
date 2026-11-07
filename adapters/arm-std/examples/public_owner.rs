//! The actual persistent ARM host against the normal C public-owner fixture.
use gnunet_arm_core::{
    FrameSlot,
    client::{
        Client, ConnectionStatus, Event, Inbound, OperationId, OperationSlot, StdioInheritance,
    },
    monitor::Monitor,
    wire::{ArmAbi, List, RequestStatus, ResultCode},
};
use gnunet_arm_host::{
    CallbackContext, ChildRegistry, ClientHost, Clock, LaunchLimits, Limits, LocalLauncher,
    MonitorEvent, MonitorHost, Progress,
};
use gnunet_config::Configuration;
use gnunet_types::Error;
use std::{
    future::{Future, poll_fn},
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};
use tokio::time::Instant;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn require(value: bool, reason: &str) -> Result<()> {
    if !value {
        return Err(io::Error::other(reason).into());
    }
    Ok(())
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
    repeat: bool,
    stopped: bool,
}
impl Context {
    fn event(
        &mut self,
        core: &mut CallbackContext<'_, '_>,
        event: Event,
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
                            let op = core.request_service_start(b"svc", StdioInheritance(6))?;
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
        core: &mut CallbackContext<'_, '_>,
        operation: OperationId,
        list: List<'_>,
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
            core.request_service_start(b"arm", StdioInheritance(6))?,
            Kind::Already,
        ));
        Ok(())
    }
}

async fn run(path: PathBuf) -> Result<()> {
    let mut operations = [OperationSlot::EMPTY; 8];
    let mut frames = [FrameSlot::EMPTY; 16];
    let mut pool = vec![0; 4096];
    let mut mframes = [FrameSlot::EMPTY; 2];
    let mut mpool = [0; 16];
    let core = Client::new(
        &mut operations,
        &mut frames,
        &mut pool,
        1,
        ArmAbi::U64Align8,
    )?;
    let mut mcore = Some(Monitor::new(&mut mframes, &mut mpool, 2)?);
    let mut registry = ChildRegistry::new(8)?;
    let config = Configuration::new(Default::default());
    let helper = std::env::current_exe()?
        .parent()
        .ok_or(Error::NotFound)?
        .parent()
        .ok_or(Error::NotFound)?
        .join("gnunet-arm-spawn-helper");
    let launcher = LocalLauncher::new(config, helper, LaunchLimits::default(), &mut registry)?;
    let mut owner = ClientHost::connect_unix(
        core,
        path.clone(),
        launcher,
        Limits::default(),
        Clock::system()?,
        |_| {},
    )?;
    let mut mon = None;
    let mut ctx = Context {
        phase: 0,
        active: None,
        monitor_started: false,
        repeat: false,
        stopped: false,
    };
    let mut monitor_count = 0usize;
    let until = Instant::now() + Duration::from_secs(5);
    let mut first = true;
    loop {
        if ctx.stopped && ctx.repeat && monitor_count == 4 {
            break;
        }
        if ctx.monitor_started && mon.is_none() {
            mon = Some(MonitorHost::start_unix(
                mcore.take().ok_or(Error::Closed)?,
                path.clone(),
                Limits::default(),
                Clock::system()?,
                |_| {},
            )?);
        }
        let mut control_error = None;
        let mut monitor_error = None;
        {
            let mut c = Box::pin(owner.drive(Some(until), |inbound, port| {
                let r = match inbound {
                    Inbound::Event(event) => ctx.event(port, event, &mut io::stdout().lock()),
                    Inbound::List { operation, list } => {
                        ctx.list(port, operation, list, &mut io::stdout().lock())
                    }
                };
                if let Err(e) = r {
                    control_error = Some(e);
                    port.disconnect();
                }
            }));
            if let Some(monitor) = &mut mon {
                let mut m = Box::pin(monitor.drive(Some(until), |event, port| match event {
                    MonitorEvent::Status(status) => {
                        let r = (|| -> Result<()> {
                            let service = std::str::from_utf8(status.service)?;
                            require(
                                ["arm", "svc", "future"].contains(&service),
                                "unknown monitor name",
                            )?;
                            monitor_count += 1;
                            writeln!(
                                io::stdout().lock(),
                                "{{\"event\":\"monitor\",\"service\":\"{service}\",\"status\":{}}}",
                                status.status.0
                            )?;
                            Ok(())
                        })();
                        if let Err(e) = r {
                            monitor_error = Some(e);
                            port.stop();
                        }
                    }
                    MonitorEvent::Unavailable(_) => {
                        monitor_error =
                            Some(io::Error::other("unexpected monitor unavailable").into());
                        port.stop();
                    }
                }));
                let progress = poll_fn(|cx| {
                    if first {
                        if let std::task::Poll::Ready(r) = c.as_mut().poll(cx) {
                            return std::task::Poll::Ready(r);
                        }
                        m.as_mut().poll(cx)
                    } else {
                        if let std::task::Poll::Ready(r) = m.as_mut().poll(cx) {
                            return std::task::Poll::Ready(r);
                        }
                        c.as_mut().poll(cx)
                    }
                })
                .await?;
                require(progress != Progress::WaitDeadline, "probe budget elapsed")?;
            } else {
                require(c.await? != Progress::WaitDeadline, "probe budget elapsed")?;
            }
        }
        if let Some(e) = control_error.or(monitor_error) {
            return Err(e);
        }
        first = !first;
    }
    owner.disconnect(|_, _| {})?;
    if let Some(monitor) = &mut mon {
        monitor.stop();
    }
    owner.launcher_mut().drain_children().await?;
    writeln!(
        io::stdout().lock(),
        "{{\"event\":\"done\",\"failed\":0,\"monitor_count\":{monitor_count},\"repeat\":1,\"stopped\":1}}"
    )?;
    Ok(())
}
fn main() -> Result<()> {
    let path = std::env::args_os().nth(1).ok_or(Error::InvalidInput)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(path.into()))
}
