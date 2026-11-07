//! Real ARM ClientHost and MonitorHost against a separately started normal C daemon.
#[path = "../../resolver-broker-std/tests/support/domain.rs"]
mod resolution_domain;
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
use gnunet_config::{Configuration, ProjectData};
use std::{
    future::{Future, poll_fn},
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn require(value: bool, message: &str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(io::Error::other(message).into())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Initial,
    UnknownStart,
    UnknownStop,
    Stopped,
    Failed,
    StartFinished,
    ListFinished,
    StartRunning,
    StopRunning,
    Already,
    StopArm,
}
struct State {
    active: Option<(OperationId, Kind)>,
    first: Option<OperationId>,
    connected: usize,
    waiting_monitor: bool,
    poll_list: bool,
    done: bool,
    results: usize,
    lists: usize,
    canceled: bool,
}
impl State {
    fn event(&mut self, port: &mut CallbackContext<'_, '_>, event: Event) -> Result<()> {
        match event {
            Event::Connection(status) => {
                writeln!(
                    io::stdout().lock(),
                    "{{\"event\":\"connection\",\"status\":{}}}",
                    match status {
                        ConnectionStatus::Connected => 1,
                        ConnectionStatus::Disconnected => 0,
                        ConnectionStatus::Error => -1,
                    }
                )?;
                match status {
                    ConnectionStatus::Connected => {
                        self.connected += 1;
                    }
                    ConnectionStatus::Error => {
                        return Err("actual configuration unavailable".into());
                    }
                    ConnectionStatus::Disconnected => {
                        require(self.done, "unexpected physical EOF")?
                    }
                }
            }
            Event::ListDisconnected { .. } => return Err("actual list disconnected".into()),
            Event::Result {
                operation,
                status,
                result,
            } => {
                let (id, kind) = self.active.take().ok_or("unsolicited/canceled callback")?;
                require(id == operation, "wrong original operation")?;
                self.results += 1;
                if kind == Kind::StopArm {
                    require(
                        (status == RequestStatus::SentOk && result == Some(ResultCode::STOPPED))
                            || (status == RequestStatus::Disconnected && result.is_none()),
                        "invalid actual ARM EOF result",
                    )?;
                    writeln!(
                        io::stdout().lock(),
                        "{{\"event\":\"stop-arm\",\"status\":{},\"result\":{}}}",
                        status as u32,
                        result.map_or_else(|| "null".into(), |value| value.0.to_string())
                    )?;
                    self.done = true;
                    return Ok(());
                }
                let expected = match kind {
                    Kind::UnknownStart | Kind::UnknownStop => ResultCode::IS_NOT_KNOWN,
                    Kind::Stopped => ResultCode::IS_STOPPED_ALREADY,
                    Kind::Failed => ResultCode::START_FAILED,
                    Kind::StartFinished | Kind::StartRunning => ResultCode::STARTING,
                    Kind::StopRunning => ResultCode::STOPPED,
                    Kind::Already => ResultCode::IS_STARTED_ALREADY,
                    Kind::Initial | Kind::ListFinished | Kind::StopArm => {
                        return Err("wrong result kind".into());
                    }
                };
                require(
                    status == RequestStatus::SentOk && result == Some(expected),
                    "wrong actual native result",
                )?;
                writeln!(
                    io::stdout().lock(),
                    "{{\"event\":\"result\",\"kind\":\"{kind:?}\",\"status\":0,\"result\":{}}}",
                    expected.0
                )?;
                self.active = Some(match kind {
                    Kind::UnknownStart => {
                        require(
                            port.operation_cancel(self.first.ok_or("no first ID")?)
                                .is_err(),
                            "stale original ID accepted",
                        )?;
                        (port.request_service_stop(b"missing")?, Kind::UnknownStop)
                    }
                    Kind::UnknownStop => (port.request_service_stop(b"finished")?, Kind::Stopped),
                    Kind::Stopped => (
                        port.request_service_start(b"empty-prefix", StdioInheritance(0))?,
                        Kind::Failed,
                    ),
                    Kind::Failed => (
                        port.request_service_start(b"FiNiShEd", StdioInheritance(0))?,
                        Kind::StartFinished,
                    ),
                    Kind::StartFinished => (port.request_service_list()?, Kind::ListFinished),
                    Kind::StartRunning => {
                        (port.request_service_stop(b"RuNnInG")?, Kind::StopRunning)
                    }
                    Kind::StopRunning => {
                        self.waiting_monitor = true;
                        return Ok(());
                    }
                    Kind::Already => (port.request_service_stop(b"ARM")?, Kind::StopArm),
                    _ => return Err("wrong transition".into()),
                });
            }
        }
        Ok(())
    }
    fn list(
        &mut self,
        port: &mut CallbackContext<'_, '_>,
        operation: OperationId,
        list: List<'_>,
    ) -> Result<()> {
        let (id, kind) = self.active.take().ok_or("unsolicited list")?;
        require(id == operation, "wrong original list ID")?;
        require(
            list.len() == 3,
            "unexpected normal daemon service inventory",
        )?;
        self.lists += 1;
        let mut finished = false;
        let mut names = Vec::new();
        for index in 0..list.len() {
            let row = list.get(index)?.ok_or("missing checked row")?;
            let name = std::str::from_utf8(row.name)?;
            names.push(name.to_owned());
            writeln!(
                io::stdout().lock(),
                "{{\"event\":\"row\",\"kind\":\"{kind:?}\",\"name\":\"{name}\",\"binary\":\"{}\",\"status\":{},\"exit\":{},\"restart\":{},\"last_start\":{}}}",
                std::str::from_utf8(row.binary)?,
                row.status.0,
                row.public_exit_status(),
                row.restart_at,
                row.last_started_at
            )?;
            if kind == Kind::Initial {
                require(
                    row.status.0 == 0 && row.last_started_at == 0 && row.restart_at == u64::MAX,
                    "unexpected initial child state",
                )?;
            }
            if name == "finished" && row.status.0 == 3 {
                require(
                    row.last_started_at > 0 && row.restart_at == 0,
                    "real finished child timestamps missing",
                )?;
                finished = true;
            }
        }
        names.sort();
        require(
            names == ["empty-prefix", "finished", "running"],
            "wrong actual list names",
        )?;
        match kind {
            Kind::Initial => {
                self.active = Some((
                    port.request_service_start(b"missing", StdioInheritance(0))?,
                    Kind::UnknownStart,
                ));
            }
            Kind::ListFinished if finished => {
                let canceled = port.request_service_stop(b"missing")?;
                port.operation_cancel(canceled)?;
                self.canceled = true;
                self.active = Some((
                    port.request_service_start(b"running", StdioInheritance(0))?,
                    Kind::StartRunning,
                ));
            }
            Kind::ListFinished => {
                require(self.lists < 200, "native child did not finish")?;
                self.poll_list = true;
            }
            _ => return Err("wrong native list phase".into()),
        }
        Ok(())
    }
}
async fn run(config_path: PathBuf, helper: PathBuf) -> Result<()> {
    let mut domain = resolution_domain::Domain::new(Configuration::default())?;
    domain.start()?;
    let mut cfg = Configuration::create(Arc::new(ProjectData::default()), Default::default())?;
    cfg.parse(config_path)?;
    domain.context.connect(cfg.duplicate()?)?;
    let mut ops = [OperationSlot::EMPTY; 16];
    let mut frames = [FrameSlot::EMPTY; 32];
    let mut pool = [0; 65536];
    let core = Client::new(&mut ops, &mut frames, &mut pool, 11, ArmAbi::U64Align8)?;
    let mut registry = ChildRegistry::new(4)?;
    let launcher = LocalLauncher::new(
        cfg.duplicate()?,
        helper,
        LaunchLimits::default(),
        &mut registry,
    )?;
    let mut owner = ClientHost::connect(
        core,
        cfg.duplicate()?,
        domain.resolution(),
        launcher,
        Limits {
            io_slice_bytes: 1,
            ..Limits::default()
        },
        Clock::system()?,
        |_| {},
    )?;
    let mut mframes = [FrameSlot::EMPTY; 2];
    let mut mpool = [0; 16];
    let mcore = Monitor::new(&mut mframes, &mut mpool, 12)?;
    let mut monitor = MonitorHost::start(
        mcore,
        cfg,
        domain.resolution(),
        Limits {
            io_slice_bytes: 1,
            ..Limits::default()
        },
        Clock::system()?,
        |_| {},
    )?;
    let mut state = State {
        active: None,
        first: None,
        connected: 0,
        waiting_monitor: false,
        poll_list: false,
        done: false,
        results: 0,
        lists: 0,
        canceled: false,
    };
    let mut statuses = Vec::new();
    let until = Instant::now() + Duration::from_secs(12);
    let mut first = true;
    while !state.done {
        if state.connected > 0 && state.first.is_none() && statuses.contains(&(0, b"arm".to_vec()))
        {
            let id = owner.request_service_list()?;
            state.first = Some(id);
            state.active = Some((id, Kind::Initial));
        }
        if state.poll_list {
            tokio::time::sleep(Duration::from_millis(5)).await;
            state.poll_list = false;
            state.active = Some((owner.request_service_list()?, Kind::ListFinished));
        }
        if state.waiting_monitor
            && [
                (2, b"finished".to_vec()),
                (1, b"finished".to_vec()),
                (2, b"running".to_vec()),
                (3, b"RuNnInG".to_vec()),
                (1, b"running".to_vec()),
            ]
            .iter()
            .all(|value| statuses.contains(value))
        {
            state.waiting_monitor = false;
            state.active = Some((
                owner.request_service_start(b"ArM", StdioInheritance(0))?,
                Kind::Already,
            ));
        }
        let mut control_error = None;
        let mut monitor_error = None;
        {
            let mut c = Box::pin(owner.drive(Some(until), |event, port| {
                let result = match event {
                    Inbound::Event(event) => state.event(port, event),
                    Inbound::List { operation, list } => state.list(port, operation, list),
                };
                if let Err(error) = result {
                    control_error = Some(error);
                    port.disconnect();
                }
            }));
            let mut m = Box::pin(monitor.drive(Some(until), |event, port| {
                let result = (|| -> Result<()> {
                    match event {
                        MonitorEvent::Status(value) => {
                            writeln!(
                                io::stdout().lock(),
                                "{{\"event\":\"monitor\",\"name\":\"{}\",\"status\":{}}}",
                                std::str::from_utf8(value.service)?,
                                value.status.0
                            )?;
                            statuses.push((value.status.0, value.service.to_vec()));
                        }
                        MonitorEvent::Unavailable(_) => {
                            return Err("monitor actual configuration unavailable".into());
                        }
                    }
                    Ok(())
                })();
                if let Err(error) = result {
                    monitor_error = Some(error);
                    port.stop();
                }
            }));
            let progress = poll_fn(|cx| {
                if first {
                    if let std::task::Poll::Ready(value) = c.as_mut().poll(cx) {
                        return std::task::Poll::Ready(value);
                    }
                    m.as_mut().poll(cx)
                } else {
                    if let std::task::Poll::Ready(value) = m.as_mut().poll(cx) {
                        return std::task::Poll::Ready(value);
                    }
                    c.as_mut().poll(cx)
                }
            })
            .await?;
            require(
                progress != Progress::WaitDeadline,
                "real C daemon probe budget elapsed",
            )?;
        }
        if let Some(error) = control_error.or(monitor_error) {
            return Err(error);
        }
        first = !first;
    }
    owner.disconnect(|_, _| {})?;
    monitor.stop();
    require(
        owner.launcher_mut().pending_children() == 0,
        "AlreadyUp incorrectly created a helper",
    )?;
    require(
        state.connected >= 2 && state.canceled,
        "native repeat/cancel missing",
    )?;
    writeln!(
        io::stdout().lock(),
        "{{\"event\":\"done\",\"results\":{},\"lists\":{},\"monitor_count\":{},\"repeat_connections\":{},\"canceled_callback_suppressed\":true,\"helper_children\":0}}",
        state.results,
        state.lists,
        statuses.len(),
        state.connected
    )?;
    Ok(())
}
fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let config = args.next().ok_or("config")?;
    let helper = args.next().ok_or("helper")?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(config.into(), helper.into()))
}
