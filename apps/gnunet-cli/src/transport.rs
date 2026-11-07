//! Ordinary configured TRANSPORT observations over the real native CLIENT.
//! Each record carries its actual source epoch. Only a real END plus complete
//! output/flush is a completed snapshot; local stop never manufactures END.
use gnunet::transport_observation::{self as native, Client, Query, Response};
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
    logging::Logger,
    program::{self, Defaults, Invocation, NlsDisabled, Preparation},
    reporting::Reporter,
    shared_clock::SharedClock,
};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::{ControlReceiver, ParentControl};
use std::{
    cell::{Cell, RefCell},
    error::Error,
    ffi::{OsStr, OsString},
    future::{Future, poll_fn},
    io::{self, Write},
    os::{fd::AsFd, unix::ffi::OsStrExt},
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    signal::unix::{Signal, SignalKind},
    time::{Instant, Sleep},
};
type Failure = Box<dyn Error>;
const ROW: Duration = Duration::from_secs(30);
const CADENCE: Duration = Duration::from_millis(10);
// The complete single IPC frame can carry a long address/prefix. Exact hex plus
// JSON escaping has an explicit8x expansion cap; no aggregate record queue exists.
const OUTPUT_BYTES: usize = 8 * 65535 + 8192;
#[derive(Clone, Copy)]
struct Command {
    query: Query,
    continuous: bool,
    duration: Duration,
}
struct Inherited {
    parent: Option<ParentControl>,
    notice: Option<String>,
}
#[expect(
    unsafe_code,
    reason = "Sole first operation adopts explicitly inherited descriptors before any logger/runtime/socket or competing descriptor owner"
)]
fn capture() -> Result<Inherited, Failure> {
    use gnunet_service_startup::{InheritedMode, InheritedResources};
    // SAFETY: this command is routed before the outer stdout lock; first native
    // action in a fresh process with no concurrent descriptor/environment owner.
    let captured = unsafe {
        gnunet_service_startup::capture_from_environment(InheritedMode::CloseAfterConfiguredBind)?
    };
    match captured.inherited {
        InheritedResources::CloseAfterBind(hold) => {
            let nonempty = !hold.is_empty();
            let actual = hold.abort();
            if nonempty {
                return Err(format!(
                    "TRANSPORT observation CLI owns no SERVICE listener: {actual:?}"
                )
                .into());
            }
        }
        InheritedResources::Listeners(_) => {
            return Err("unexpected TRANSPORT CLI listener route".into());
        }
    }
    Ok(Inherited {
        parent: captured.parent_control,
        notice: captured
            .control_notice
            .map(|v| format!("parent control declaration: {v:?}")),
    })
}
struct Signals {
    parent: Option<ControlReceiver>,
    interrupt: Signal,
    terminate: Signal,
}
impl Signals {
    fn new(parent: Option<ParentControl>) -> io::Result<Self> {
        Ok(Self {
            parent: parent
                .map(|p| p.register().map_err(|e| e.error))
                .transpose()?,
            interrupt: tokio::signal::unix::signal(SignalKind::interrupt())?,
            terminate: tokio::signal::unix::signal(SignalKind::terminate())?,
        })
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(parent) = &mut self.parent {
            match parent.poll_signal(cx) {
                Poll::Ready(Ok(Some(n)))
                    if i32::from(n) == SignalKind::interrupt().as_raw_value()
                        || i32::from(n) == SignalKind::terminate().as_raw_value() =>
                {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(Some(_))) => cx.waker().wake_by_ref(),
                Poll::Ready(Ok(None)) => self.parent = None,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
        }
        for signal in [&mut self.interrupt, &mut self.terminate] {
            match signal.poll_recv(cx) {
                Poll::Ready(Some(())) => return Poll::Ready(Ok(())),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "TRANSPORT CLI signal stream ended",
                    )));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}
#[derive(Clone, Copy, Debug)]
enum End {
    Service,
    Duration,
    Cancelled,
}
#[derive(Default)]
struct Report {
    epochs: u64,
    current_epoch: Option<u64>,
    request_bytes_written: usize,
    records_received: u64,
    rows_written: u64,
    losses: u64,
    first_loss: Option<Rc<native::Loss>>,
    last_loss: Option<Rc<native::Loss>>,
    retries: u64,
    last_retry: Option<io::Error>,
    service_end_received: bool,
    complete_line_written: bool,
    stdout_flushed: bool,
    output_prefix: usize,
    output_total: usize,
    end: Option<End>,
    physical_cleanup: Option<native::Loss>,
}
impl std::fmt::Debug for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportObservation")
            .field("epochs", &self.epochs)
            .field("current_epoch", &self.current_epoch)
            .field("request_bytes_written", &self.request_bytes_written)
            .field("records_received", &self.records_received)
            .field("rows_written", &self.rows_written)
            .field("losses", &self.losses)
            .field(
                "first_loss",
                &self.first_loss.as_ref().map(|v| v.to_string()),
            )
            .field("last_loss", &self.last_loss.as_ref().map(|v| v.to_string()))
            .field("retries", &self.retries)
            .field("last_retry", &self.last_retry)
            .field("service_end_received", &self.service_end_received)
            .field("complete_line_written", &self.complete_line_written)
            .field("stdout_flushed", &self.stdout_flushed)
            .field("output_prefix", &self.output_prefix)
            .field("output_total", &self.output_total)
            .field("end", &self.end)
            .field(
                "physical_cleanup",
                &self.physical_cleanup.as_ref().map(ToString::to_string),
            )
            .finish()
    }
}
#[derive(Default)]
struct State {
    report: Report,
    original: Option<Failure>,
    foreground: Option<Failure>,
    output: Option<Failure>,
    resolver: Option<Failure>,
    flush: Option<io::Error>,
    logging: Option<io::Error>,
}
type Shared = Rc<RefCell<State>>;
struct Failed(State);
impl std::fmt::Debug for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TRANSPORT observation original={:?}; foreground={:?}; output={:?}; Resolver cleanup={:?}; stdout flush={:?}; logging={:?}; actual report={:?}",
            self.0.original,
            self.0.foreground,
            self.0.output,
            self.0.resolver,
            self.0.flush,
            self.0.logging,
            self.0.report
        )
    }
}
impl Error for Failed {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0
            .original
            .as_deref()
            .or(self.0.foreground.as_deref())
            .or(self.0.output.as_deref())
            .or(self.0.resolver.as_deref())
            .or_else(|| self.0.flush.as_ref().map(|e| e as &dyn Error))
            .or_else(|| self.0.logging.as_ref().map(|e| e as &dyn Error))
            .or_else(|| {
                self.0
                    .report
                    .first_loss
                    .as_ref()
                    .map(|loss| loss.as_ref() as &dyn Error)
            })
    }
}
#[derive(Debug)]
struct Selected(Failure);
impl std::fmt::Display for Selected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.0.as_ref(), f)
    }
}
impl Error for Selected {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}
pub(super) fn selected(error: &(dyn Error + 'static)) -> bool {
    error.is::<Selected>()
}
struct Native {
    client: Option<Client>,
    shared: Shared,
}
impl Native {
    fn get(&mut self) -> Result<&mut Client, Failure> {
        self.client
            .as_mut()
            .ok_or_else(|| "original TRANSPORT client already retired".into())
    }
    fn close(&mut self) {
        if let Some(mut client) = self.client.take() {
            self.shared.borrow_mut().report.physical_cleanup = Some(client.close());
            drop(client);
        }
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        self.close();
    }
}
struct Resolver {
    driver: Option<gnunet_resolver_broker::Driver<4, 256>>,
    shared: Shared,
}
impl Resolver {
    fn get(&mut self) -> Result<&mut gnunet_resolver_broker::Driver<4, 256>, Failure> {
        self.driver
            .as_mut()
            .ok_or_else(|| "original Resolver already retired".into())
    }
    fn close(&mut self) {
        if let Some(mut driver) = self.driver.take() {
            if let Err(e) = driver.disconnect() {
                self.shared.borrow_mut().resolver = Some(Box::new(e));
            }
            drop(driver);
        }
    }
}
impl Drop for Resolver {
    fn drop(&mut self) {
        self.close();
    }
}
struct Output {
    bytes: Vec<u8>,
    used: usize,
    stdout: io::Stdout,
    regular: bool,
}
struct Limited<'a>(&'a mut Vec<u8>);
impl Write for Limited<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(data.len())
            .is_none_or(|n| n > OUTPUT_BYTES)
        {
            return Err(io::Error::other(
                "one TRANSPORT output record exceeds its finite JSON expansion bound",
            ));
        }
        self.0.try_reserve(data.len()).map_err(io::Error::other)?;
        self.0.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Output {
    fn new() -> Result<Self, Failure> {
        use nix::sys::stat::{self, SFlag};
        let stdout = io::stdout();
        let metadata = stat::fstat(stdout.as_fd())?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(4096)?;
        Ok(Self {
            bytes,
            used: 0,
            stdout,
            regular: SFlag::from_bits_truncate(metadata.st_mode) & SFlag::S_IFMT == SFlag::S_IFREG,
        })
    }
    fn stage(&mut self, value: serde_json::Value) -> Result<(), Failure> {
        if !self.bytes.is_empty() {
            return Err("previous actual TRANSPORT row still owns stdout".into());
        }
        self.used = 0;
        let mut output = Limited(&mut self.bytes);
        serde_json::to_writer(&mut output, &value)?;
        output.write_all(b"\n")?;
        Ok(())
    }
    /// No flags are changed on borrowed stdout. Readiness is sampled before a
    /// small pipe write; synchronous filesystem/TTY calls cannot be preempted.
    fn step(&mut self) -> io::Result<Option<bool>> {
        use nix::poll::{PollFd, PollFlags, PollTimeout};
        if !self.regular {
            let mut descriptors = [PollFd::new(self.stdout.as_fd(), PollFlags::POLLOUT)];
            match nix::poll::poll(&mut descriptors, PollTimeout::ZERO) {
                Ok(_) => {
                    let events = descriptors[0]
                        .revents()
                        .ok_or_else(|| io::Error::other("unknown stdout poll bits"))?;
                    if events.contains(PollFlags::POLLNVAL) {
                        return Err(io::Error::from_raw_os_error(nix::libc::EBADF));
                    }
                    if !events
                        .intersects(PollFlags::POLLOUT | PollFlags::POLLERR | PollFlags::POLLHUP)
                    {
                        return Ok(None);
                    }
                }
                Err(nix::errno::Errno::EINTR) => return Ok(None),
                Err(e) => return Err(e.into()),
            }
        }
        let end = if self.regular {
            self.bytes.len()
        } else {
            self.used.saturating_add(512).min(self.bytes.len())
        };
        match nix::unistd::write(self.stdout.as_fd(), &self.bytes[self.used..end]) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "zero original TRANSPORT stdout write",
            )),
            Ok(n) => {
                self.used += n;
                Ok(Some(self.used == self.bytes.len()))
            }
            Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    fn pending(&self) -> bool {
        !self.bytes.is_empty()
    }
    fn release(&mut self) {
        self.bytes.clear();
        self.used = 0;
    }
}
fn hex(bytes: &[u8]) -> Result<String, Failure> {
    let mut out = String::new();
    out.try_reserve_exact(
        bytes
            .len()
            .checked_mul(2)
            .ok_or("TRANSPORT hex length overflow")?,
    )?;
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 15)]));
    }
    Ok(out)
}
fn record(observation: &native::Observation) -> Result<serde_json::Value, Failure> {
    let epoch = observation.epoch().value();
    let ordinal = observation.ordinal();
    Ok(match observation.response()? {
        Response::Monitor(m) => {
            serde_json::json!({"event":"transport_monitor","epoch":epoch,"ordinal":ordinal,"peer_hex":hex(&m.peer)?,"network":m.network,"last_validation":m.last_validation,"valid_until":m.valid_until,"next_validation":m.next_validation,"rtt":m.rtt,"status":m.status,"pending_messages":m.pending_messages,"pending_bytes":m.pending_bytes,"address":std::str::from_utf8(m.address).ok(),"address_hex":hex(m.address)?})
        }
        Response::Link(l) => {
            serde_json::json!({"event":"transport_link","epoch":epoch,"ordinal":ordinal,"peer_hex":hex(&l.target)?,"confirmed":l.confirmed,"route":l.route,"distance":l.distance,"queues":l.queues,"core_receive_window":l.core_receive_window,"stalled":l.stalled,"pending":l.pending,"flow_retransmissions":l.flow_retransmissions,"available_window":l.available_window,"incoming_ram":l.incoming_ram,"incoming_window":l.incoming_window,"incoming_used":l.incoming_used,"incoming_loss":l.incoming_loss,"outbound_window":l.outbound_window,"outbound_used":l.outbound_used,"flow_rtt":l.flow_rtt,"other_rtt":l.other_rtt,"last_flow_transmission":l.last_flow_transmission,"communicators":std::str::from_utf8(l.communicators).ok(),"communicators_hex":hex(l.communicators)?})
        }
        Response::MonitorEnd | Response::LinksEnd => {
            return Err("native record unexpectedly contained END".into());
        }
    })
}
fn transient(loss: &native::Loss) -> bool {
    match &loss.cause {
        native::Cause::Eof => true,
        native::Cause::Failure(gnunet_client_host::ConnectError::Io(e)) => {
            gnunet_client_host::resolution::PortError::from_io(e).is_none()
        }
        native::Cause::Failure(gnunet_client_host::ConnectError::Protocol(
            gnunet_types::Error::Deadline,
        )) => true,
        _ => false,
    }
}
struct Inputs {
    command: Command,
    parent: Option<ParentControl>,
    endpoint: EndpointSource,
    clock: Arc<dyn RuntimeClock>,
    stop: Rc<Cell<bool>>,
    reports: Reporter,
    resolver: gnunet_resolver_broker::Driver<4, 256>,
    shared: Shared,
}
async fn run_command(inputs: Inputs) -> Result<(), Failure> {
    let Inputs {
        command,
        parent,
        endpoint,
        clock,
        stop,
        reports,
        resolver,
        shared,
    } = inputs;
    let mut resolver = Resolver {
        driver: Some(resolver),
        shared: shared.clone(),
    };
    let mut signals = Signals::new(parent)?;
    let original = native::Bounds::new(clock.as_ref(), command.duration)?;
    let hard = Instant::from_std(original.hard);
    let client = Client::new(endpoint, command.query, native::Limits::default(), original)?;
    let mut owner = Native {
        client: Some(client),
        shared: shared.clone(),
    };
    let mut output = Output::new()?;
    let mut global = Box::pin(tokio::time::sleep_until(hard));
    let mut cadence = Box::pin(tokio::time::sleep_until(Instant::now()));
    let mut row_hard: Option<Instant> = None;
    let mut row_alarm: Option<Pin<Box<Sleep>>> = None;
    let mut restart = false;
    let mut complete_output = false;
    let mut data_row = false;
    let mut source_active = true;
    let outcome = async {
        loop {
            enum Turn { Native(native::Progress), Output(io::Result<Option<bool>>), Restart, Stop, Deadline, RowDeadline, Activity }
            let mut driving = std::pin::pin!(resolver.get()?.drive_waiting(Some(hard), |_| {}));
            let turn = poll_fn(|cx| -> Poll<Result<Turn, Failure>> {
                reports.register(cx);
                if stop.get() || reports.failed() { return Poll::Ready(Ok(Turn::Stop)); }
                match signals.poll(cx) { Poll::Ready(Ok(())) => return Poll::Ready(Ok(Turn::Stop)), Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())), Poll::Pending => {} }
                if global.as_mut().poll(cx).is_ready() { return Poll::Ready(Ok(Turn::Deadline)); }
                if let Some(loss) = owner.get()?.poll_native_guard(cx) { return Poll::Ready(Ok(Turn::Native(native::Progress::Lost(loss)))); }
                if let Some(alarm) = &mut row_alarm && alarm.as_mut().poll(cx).is_ready() { return Poll::Ready(Ok(Turn::RowDeadline)); }
                let activity = match driving.as_mut().poll(cx) { Poll::Ready(Ok(_)) => true, Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())), Poll::Pending => false };
                if reports.failed() { return Poll::Ready(Ok(Turn::Stop)); }
                if output.pending() {
                    if row_hard.is_some_and(|at| Instant::now() >= at) { return Poll::Ready(Ok(Turn::RowDeadline)); }
                    if cadence.as_mut().poll(cx).is_ready() { return Poll::Ready(Ok(Turn::Output(output.step()))); }
                    return if activity { Poll::Ready(Ok(Turn::Activity)) } else { Poll::Pending };
                }
                if restart { return Poll::Ready(Ok(Turn::Restart)); }
                match owner.get()?.poll_progress(cx) { Poll::Ready(Ok(p)) => Poll::Ready(Ok(Turn::Native(p))), Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())), Poll::Pending if activity => Poll::Ready(Ok(Turn::Activity)), Poll::Pending => Poll::Pending }
            }).await?;
            match turn {
                Turn::Stop => {
                    shared.borrow_mut().report.end = Some(End::Cancelled);
                    if output.pending() { shared.borrow_mut().output=Some(io::Error::new(io::ErrorKind::Interrupted,"stop interrupted the held stdout row").into()); return Err(io::Error::new(io::ErrorKind::Interrupted, "TRANSPORT local stop before output completion").into()); }
                    if command.continuous { return Ok(()) }
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "TRANSPORT snapshot cancelled before actual END/output completion").into());
                }
                Turn::Deadline => {
                    shared.borrow_mut().report.end = Some(End::Duration);
                    if command.continuous && !output.pending() { return Ok(()) }
                    if output.pending() { shared.borrow_mut().output=Some(io::Error::new(io::ErrorKind::TimedOut,"whole operation deadline interrupted the held stdout row").into()); }
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "TRANSPORT original complete operation/output deadline; no END invented").into());
                }
                Turn::RowDeadline => {
                    shared.borrow_mut().output = Some(io::Error::new(io::ErrorKind::TimedOut, "original TRANSPORT stdout row deadline").into());
                    return Ok(());
                }
                Turn::Restart => { owner.get()?.restart()?; source_active = true; restart = false; }
                Turn::Activity => {}
                Turn::Output(Err(e)) => { shared.borrow_mut().output = Some(Box::new(e)); return Ok(()); }
                Turn::Output(Ok(progress)) => {
                    let mut state = shared.borrow_mut();
                    state.report.output_prefix = output.used;
                    state.report.output_total = output.bytes.len();
                    let late = row_hard.is_some_and(|at| Instant::now() >= at);
                    if progress == Some(true) {
                        if data_row { state.report.rows_written = state.report.rows_written.checked_add(1).ok_or("TRANSPORT output count overflow")?; }
                        output.release(); row_hard = None; row_alarm = None; data_row = false;
                        if complete_output { state.report.complete_line_written = true; }
                    }
                    if late { state.output=Some(io::Error::new(io::ErrorKind::TimedOut,"actual stdout write returned after its unchanged original row/native deadline").into());return Ok(()) }
                    if complete_output && progress == Some(true) { return Ok(()) }
                    cadence.as_mut().reset(Instant::now().checked_add(CADENCE).ok_or("TRANSPORT output cadence overflow")?);
                }
                Turn::Native(native::Progress::Attached(epoch)) => {
                    { let mut state=shared.borrow_mut();state.report.epochs=state.report.epochs.checked_add(1).ok_or("TRANSPORT epoch count overflow")?;state.report.current_epoch=Some(epoch.value());state.report.request_bytes_written=0; }
                    if let Err(e)=output.stage(serde_json::json!({"event":"transport_epoch","epoch":epoch.value(),"continuous":command.continuous,"request_whole_written":false,"snapshot_complete":false})){shared.borrow_mut().output=Some(e);return Ok(())}
                }
                Turn::Native(native::Progress::Written { epoch, bytes }) => { let mut state=shared.borrow_mut();state.report.current_epoch=Some(epoch.value());state.report.request_bytes_written=bytes; }
                Turn::Native(native::Progress::Record(observation)) => {
                    { let mut state=shared.borrow_mut();state.report.records_received=state.report.records_received.checked_add(1).ok_or("TRANSPORT record count overflow")?; }
                    let value=record(&observation)?;if let Err(e)=output.stage(value){shared.borrow_mut().output=Some(e);return Ok(())}data_row=true;
                }
                Turn::Native(native::Progress::Complete { epoch, records }) => {
                    source_active = false;
                    if command.continuous { return Err("unexpected END for continuous TRANSPORT monitor".into()) }
                    { let mut state=shared.borrow_mut();state.report.service_end_received=true;state.report.current_epoch=Some(epoch.value());state.report.end=Some(End::Service); }
                    if let Err(e)=output.stage(serde_json::json!({"event":"transport_end","epoch":epoch.value(),"records":records,"actual_service_end":true})){shared.borrow_mut().output=Some(e);return Ok(())}complete_output=true;
                }
                Turn::Native(native::Progress::Lost(loss)) => {
                    source_active = false;
                    let recover=command.continuous&&transient(&loss);
                    let loss=Rc::new(loss);
                    { let mut state=shared.borrow_mut();state.report.losses=state.report.losses.checked_add(1).ok_or("TRANSPORT source loss count overflow")?;if state.report.first_loss.is_none(){state.report.first_loss=Some(loss.clone())}else{state.report.last_loss=Some(loss.clone())}state.report.current_epoch=None; }
                    reports.warning("transport.observation.source",format_args!("original source retired: {loss}; old snapshot is incomplete"));
                    if output.pending() { shared.borrow_mut().output = Some(io::Error::new(io::ErrorKind::Interrupted, "known original source loss interrupted the held stdout row").into()); return Ok(()) }
                    if !recover { return Ok(()); }
                    if let Err(e)=output.stage(serde_json::json!({"event":"transport_lost","epoch":loss.epoch.as_ref().map(|e|e.value()),"cause":loss.to_string(),"records":loss.records,"request_written":loss.request_written,"partial_input":loss.partial_input,"snapshot_complete":false})){shared.borrow_mut().output=Some(e);return Ok(())}
                    restart=true;
                }
                Turn::Native(native::Progress::Retry { error }) => {
                    reports.warning("transport.observation.retry",format_args!("actual original connect retry: {error}"));
                    let mut state=shared.borrow_mut();state.report.retries=state.report.retries.checked_add(1).ok_or("TRANSPORT retry count overflow")?;state.report.last_retry=Some(error);
                }
                Turn::Native(native::Progress::Activity) => {}
            }
            if output.pending() && row_hard.is_none() {
                let mut at=Instant::now().checked_add(ROW).ok_or("TRANSPORT row hard overflow")?.min(hard);
                if source_active { at=at.min(Instant::from_std(owner.get()?.native_deadline())); }
                row_hard=Some(at);row_alarm=Some(Box::pin(tokio::time::sleep_until(at)));cadence.as_mut().reset(Instant::now());
                let mut state=shared.borrow_mut();state.report.output_prefix=0;state.report.output_total=output.bytes.len();
            }
            tokio::task::yield_now().await;
        }
    }.await;
    if let Err(error) = outcome {
        shared.borrow_mut().original.get_or_insert(error);
    }
    owner.close();
    resolver.close();
    let flush = output.stdout.flush();
    {
        let mut state = shared.borrow_mut();
        match flush {
            Ok(()) => state.report.stdout_flushed = true,
            Err(e) => state.flush = Some(e),
        }
        if state.report.service_end_received && Instant::now() >= hard && state.output.is_none() {
            state.output = Some(
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "actual END/output flush observed after the original TRANSPORT deadline",
                )
                .into(),
            );
        }
    }
    Ok(())
}
fn milliseconds(value: Option<Vec<u8>>, default: u64) -> Result<Duration, Failure> {
    let value = value
        .map(|v| {
            std::str::from_utf8(&v)
                .map_err(|e| Box::new(e) as Failure)?
                .parse::<u64>()
                .map_err(|e| Box::new(e) as Failure)
        })
        .transpose()?
        .unwrap_or(default);
    if value == 0 || value > u64::MAX / 1000 {
        return Err("TRANSPORT duration must be positive and finite".into());
    }
    let duration = Duration::from_millis(value);
    if std::time::Instant::now().checked_add(duration).is_none() {
        return Err("TRANSPORT duration target overflow".into());
    }
    Ok(duration)
}
struct Selection {
    peer: Option<Vec<u8>>,
    continuous: bool,
    one_shot: bool,
    unconfirmed: bool,
    duration: Option<Vec<u8>>,
    timeout: Option<Vec<u8>>,
}
pub(super) fn run(args: &[OsString]) -> Result<(), Failure> {
    let inherited = capture()?;
    let clock = SharedClock::native(64)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let peer = Target::new(None::<Vec<u8>>);
    let continuous = Target::new(0i32);
    let one_shot = Target::new(0i32);
    let unconfirmed = Target::new(0i32);
    let duration = Target::new(None::<Vec<u8>>);
    let timeout = Target::new(None::<Vec<u8>>);
    let mut options = Options::new();
    options.add(helpers::string(
        b'p',
        b"peer",
        b"PEER",
        b"select one GNUnet peer; default all peers",
        peer.clone(),
    ));
    options.add(helpers::flag(
        0,
        b"continuous",
        b"monitor fresh source epochs until local duration/cancel",
        continuous.clone(),
    ));
    options.add(helpers::flag(
        0,
        b"one-shot",
        b"require actual MONITOR_END (default monitor mode)",
        one_shot.clone(),
    ));
    options.add(helpers::flag(
        b'a',
        b"include-unconfirmed",
        b"include current unconfirmed links",
        unconfirmed.clone(),
    ));
    options.add(helpers::string(
        0,
        b"duration-ms",
        b"N",
        b"continuous monitor original whole lifetime (default300000)",
        duration.clone(),
    ));
    options.add(helpers::string(
        0,
        b"timeout-ms",
        b"N",
        b"one-shot connect/END/output deadline (default30000)",
        timeout.clone(),
    ));
    let mut logger = Logger::new(b"gnunet-cli.transport", std::process::id(), false)?;
    let prepared=program::prepare(config,Invocation{binary_name:b"gnunet-cli transport",help:Some(b"Observe actual TRANSPORT queues or virtual links. Arguments: monitor|links <UNIXPATH|->. '-' selects standard configured TRANSPORT Unix/TCP endpoint; common -c/-L/-l apply. monitor is one-shot unless --continuous. Only actual END plus written/flushed output completes a snapshot. SIGINT/SIGTERM closes the original source. Continuous reconnect prints source boundaries and retains gap/failure; an interrupted stream exits nonzero. No route/delivery/publication authority is granted."),select_default_filename:true,defaults:Defaults::Native},options,std::iter::once(OsString::from("gnunet-cli transport")).chain(args.iter().cloned()),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock())?;
    let prepared = match prepared {
        Preparation::Ready(p) => *p,
        Preparation::Stopped(s)
            if s.code == 0 && matches!(s.reason, program::StoppedReason::Options) =>
        {
            return Ok(());
        }
        Preparation::Stopped(s) => {
            return Err(
                format!("TRANSPORT PROGRAM stopped: {:?}, code{}", s.reason, s.code).into(),
            );
        }
    };
    let reports = Reporter::new(logger, clock.clone());
    let shared = Rc::new(RefCell::new(State::default()));
    let result = (|| -> Result<(), Failure> {
        let selection = Selection {
            peer: peer.get()?,
            continuous: continuous.get()? != 0,
            one_shot: one_shot.get()? != 0,
            unconfirmed: unconfirmed.get()? != 0,
            duration: duration.get()?,
            timeout: timeout.get()?,
        };
        run_selected(
            prepared,
            inherited,
            clock,
            reports.clone(),
            shared.clone(),
            selection,
        )
    })();
    if let Err(error) = result {
        let mut state = shared.borrow_mut();
        if state.original.is_none() {
            state.original = Some(error)
        } else {
            state.foreground = Some(error)
        }
    }
    let failed = {
        let s = shared.borrow();
        s.original.is_some()
            || s.foreground.is_some()
            || s.output.is_some()
            || s.resolver.is_some()
            || s.flush.is_some()
            || s.logging.is_some()
            || s.report.losses != 0
    };
    if failed {
        let state = shared.borrow();
        reports.warning("transport.observation.failed",format_args!("original={:?}; foreground={:?}; output={:?}; Resolver cleanup={:?}; flush={:?}; actual local facts={:?}",state.original,state.foreground,state.output,state.resolver,state.flush,state.report));
    } else {
        reports.debug(
            "transport.observation.stopped",
            format_args!(
                "actual local observation facts={:?}; remote receipt/complete window unclaimed",
                shared.borrow().report
            ),
        );
    }
    if let Some(error) = reports.take_error() {
        shared.borrow_mut().logging = Some(error)
    }
    let state = std::mem::take(&mut *shared.borrow_mut());
    if state.original.is_some()
        || state.foreground.is_some()
        || state.output.is_some()
        || state.resolver.is_some()
        || state.flush.is_some()
        || state.logging.is_some()
        || state.report.losses != 0
    {
        Err(Box::new(Selected(Box::new(Failed(state)))))
    } else {
        Ok(())
    }
}
fn run_selected(
    prepared: program::Prepared,
    inherited: Inherited,
    clock: SharedClock,
    reports: Reporter,
    shared: Shared,
    selection: Selection,
) -> Result<(), Failure> {
    let Selection {
        peer,
        continuous,
        one_shot,
        unconfirmed,
        duration,
        timeout,
    } = selection;
    let args = prepared.main().arguments;
    if args.len() != 2 {
        return Err("expected transport monitor|links [common/options] <UNIXPATH|->".into());
    }
    if continuous && one_shot {
        return Err("--continuous and --one-shot conflict".into());
    }
    let peer = peer
        .map(|p| {
            if p.len() > 128 {
                return Err("peer selector exceeds128bytes".into());
            }
            super::peer::parse(OsStr::from_bytes(&p))
        })
        .transpose()?
        .unwrap_or([0; 32]);
    let continuous = match args[0].as_slice() {
        b"monitor" => continuous,
        b"links" if !continuous && !one_shot => false,
        b"links" => return Err("links is always one-shot; monitor mode flags do not apply".into()),
        _ => return Err("expected transport monitor|links".into()),
    };
    let query = if args[0] == b"monitor" {
        if unconfirmed {
            return Err("--include-unconfirmed applies only to links".into());
        }
        Query::Monitor {
            one_shot: !continuous,
            peer,
        }
    } else {
        Query::Links {
            include_unconfirmed: unconfirmed,
            peer,
        }
    };
    if continuous && timeout.is_some() || !continuous && duration.is_some() {
        return Err(
            "use --duration-ms only for continuous monitor, --timeout-ms for one-shot".into(),
        );
    }
    let command = Command {
        query,
        continuous,
        duration: if continuous {
            milliseconds(duration, 300000)?
        } else {
            milliseconds(timeout, 30000)?
        },
    };
    let mut config = prepared.main().config.duplicate()?;
    if args[1] != b"-" {
        if args[1].is_empty() || args[1].contains(&0) {
            return Err("invalid explicit TRANSPORT Unix path".into());
        }
        config.set_value(b"transport", b"UNIXPATH", Some(&args[1]))?;
        config.set_value(b"transport", b"HOSTNAME", Some(b"localhost"))?;
        config.set_number(b"transport", b"PORT", 0)?;
    }
    if let Some(notice) = inherited.notice {
        reports.warning("transport.observation.parent", format_args!("{notice}"))
    }
    if reports.failed() {
        return Err("selected TRANSPORT Logger failed before startup".into());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let source: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let live = LiveConfiguration::new(config);
    let (mut context, resolver) = gnunet_resolver_broker::broker::<4, 256>(
        live.clone(),
        gnunet_resolver_broker::Limits {
            max_frame_bytes: 4096,
            io_chunk_bytes: 4096,
            max_queued_frames: 4,
        },
        gnunet_resolver_broker::native_profile()?,
        source.clone(),
    )?;
    let endpoint = EndpointSource::live(live, b"transport", context.resolution_context());
    let stop = Rc::new(Cell::new(false));
    let task = run_command(Inputs {
        command,
        parent: inherited.parent,
        endpoint,
        clock: source,
        stop: stop.clone(),
        reports,
        resolver,
        shared,
    });
    runtime.block_on(gnunet_program_host::foreground::run(
        prepared,
        &mut context,
        clock,
        stop,
        task,
    ))
}
