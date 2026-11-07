//! Exact source phases/results and native-byte C-locale output.
use crate::options::Options;
use gnunet_arm_core::wire::{RequestStatus, ResultCode, ServiceInfo};
/// One outstanding command category; the host retains its real OperationId.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Named service kill.
    Term,
    /// ARM shutdown/restart stop.
    End,
    /// ARM startup.
    Start,
    /// Named service initialization.
    Init,
    /// List request.
    List,
}
/// An action emitted once per source phase. Presence checks occur at the action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    /// Stop the exact service name for this kind.
    Stop(Vec<u8>, Kind),
    /// Start the exact service with the source stdio bit mask.
    Start(Vec<u8>, u32, Kind),
    /// Request the official service list.
    List,
    /// All finite actions finished; remain in monitor mode.
    MonitorOnly,
    /// Ordinary source shutdown.
    Finish,
}
/// Source callback observations and unprocessed command flags.
#[derive(Debug)]
pub struct State {
    /// Remaining original flags and native names.
    pub options: Options,
    /// Next source phase counter.
    pub phase: u8,
    /// Exact source process status.
    pub ret: u8,
    /// Shutdown has been requested.
    pub done: bool,
    /// Current status quiet flag, force-cleared in monitor phase.
    pub quiet: bool,
    /// The final monitor phase has been entered.
    pub monitoring: bool,
    /// Original outstanding command category.
    pub waiting: Option<Kind>,
    /// Pending source stdout bytes.
    pub stdout: Vec<u8>,
    /// Pending source stderr bytes.
    pub stderr: Vec<u8>,
    /// Pending source warning messages for the logging sink.
    pub warnings: Vec<Vec<u8>>,
}
fn sentence(out: &mut Vec<u8>, prefix: &[u8], name: &[u8], suffix: &[u8]) {
    out.extend_from_slice(prefix);
    out.extend_from_slice(name);
    out.extend_from_slice(suffix);
}
/// Original request-status string; it does not infer processing acknowledgement.
pub fn req_string(status: u32) -> &'static [u8] {
    match status {
        0 => b"Message was sent successfully",
        2 => b"We disconnected from ARM before we could send a request",
        _ => b"Unknown request status",
    }
}
/// Original ARM result string, including punctuation for an unknown future code.
pub fn ret_string(result: u32) -> &'static [u8] {
    match result {
        0 => b"is stopped",
        1 => b"is stopping",
        2 => b"is starting",
        3 => b"is starting already",
        4 => b"is stopping already",
        5 => b"is started already",
        6 => b"is stopped already",
        7 => b"service is not known to ARM",
        8 => b"service failed to start",
        9 => b"service cannot be manipulated because ARM is shutting down",
        _ => b"Unknown result code.",
    }
}
impl State {
    /// Initialize source globals from parsed options.
    pub fn new(options: Options) -> Self {
        let quiet = options.quiet;
        Self {
            options,
            phase: 0,
            ret: 0,
            done: false,
            quiet,
            monitoring: false,
            waiting: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            warnings: Vec::new(),
        }
    }
    /// Advance source action_loop. Presence is queried at most once for a phase,
    /// and never grants the actual ARM TEST authority held by the host core.
    pub fn next(&mut self, mut presence: impl FnMut() -> bool) -> Option<Action> {
        if self.done || self.monitoring || self.waiting.is_some() {
            return None;
        }
        loop {
            let phase = self.phase;
            self.phase = self.phase.saturating_add(1);
            let action = match phase {
                0 => {
                    if let Some(name) = self.options.term.clone() {
                        if !presence() {
                            sentence(
                                &mut self.stderr,
                                b"Cannot stop the `",
                                &name,
                                b"' service: ARM is not running.\n",
                            );
                            self.ret = 4;
                            self.done = true;
                            return None;
                        }
                        Some(Action::Stop(name, Kind::Term))
                    } else {
                        None
                    }
                }
                1 => {
                    if self.options.end || self.options.restart {
                        if !presence() {
                            self.warnings
                                .push(b"GNUnet not running, cannot stop the peer\n".to_vec());
                            if self.options.restart {
                                self.options.restart = false;
                                self.options.start = true;
                            }
                            None
                        } else {
                            Some(Action::Stop(b"arm".to_vec(), Kind::End))
                        }
                    } else {
                        None
                    }
                }
                2 => {
                    if self.options.start {
                        Some(Action::Start(
                            b"arm".to_vec(),
                            if self.options.no_stdout { 0 } else { 2 }
                                | if self.options.no_stderr { 0 } else { 4 },
                            Kind::Start,
                        ))
                    } else {
                        None
                    }
                }
                3 => {
                    if let Some(name) = self.options.init.clone() {
                        if !presence() {
                            sentence(
                                &mut self.stderr,
                                b"Cannot start the `",
                                &name,
                                b"' service: ARM is not running.\n",
                            );
                            self.ret = 4;
                            self.done = true;
                            return None;
                        }
                        Some(Action::Start(name, 0, Kind::Init))
                    } else {
                        None
                    }
                }
                4 => {
                    if self.options.list {
                        if !presence() {
                            self.stderr
                                .extend_from_slice(b"Cannot list services: ARM is not running.\n");
                            self.ret = 4;
                            self.done = true;
                            return None;
                        }
                        Some(Action::List)
                    } else {
                        None
                    }
                }
                5 => {
                    if self.options.monitor {
                        if !self.quiet {
                            self.stderr
                                .extend_from_slice(b"Now only monitoring, press CTRL-C to stop.\n");
                        }
                        self.quiet = false;
                        self.monitoring = true;
                        return Some(Action::MonitorOnly);
                    } else {
                        None
                    }
                }
                _ => {
                    self.done = true;
                    return Some(Action::Finish);
                }
            };
            if let Some(action) = action {
                self.waiting = Some(match &action {
                    Action::Stop(_, kind) | Action::Start(_, _, kind) => *kind,
                    Action::List => Kind::List,
                    _ => return Some(action),
                });
                return Some(action);
            }
        }
    }
    /// Source callbacks normally leave ret0 on failure; only list changes it to3.
    pub fn result(&mut self, kind: Kind, status: RequestStatus, result: Option<ResultCode>) {
        self.waiting = None;
        let sent = status == RequestStatus::SentOk;
        let value = result.map(|r| r.0).unwrap_or(0);
        let accepted = sent
            && match kind {
                Kind::Start | Kind::Init => matches!(value, 2 | 5),
                Kind::End => matches!(value, 0 | 1 | 6),
                Kind::Term => matches!(value, 0 | 6),
                Kind::List => false,
            };
        if !accepted {
            let reason = if sent {
                ret_string(value)
            } else {
                req_string(2)
            };
            match kind {
                Kind::Start => {
                    self.stdout
                        .extend_from_slice(b"Failed to start the ARM service: ");
                    self.stdout.extend_from_slice(reason);
                    self.stdout.push(b'\n');
                }
                Kind::End => {
                    self.stdout.extend_from_slice(if sent {
                        b"Failed to stop the ARM service: "
                    } else {
                        b"Failed to send a stop request to the ARM service: "
                    });
                    self.stdout.extend_from_slice(reason);
                    self.stdout.push(b'\n');
                }
                Kind::Init | Kind::Term => {
                    let name = if kind == Kind::Init {
                        self.options.init.as_deref().unwrap_or_default()
                    } else {
                        self.options.term.as_deref().unwrap_or_default()
                    };
                    let prefix: &[u8] = match (kind, sent) {
                        (Kind::Init, true) => b"Failed to start the `",
                        (Kind::Init, false) => b"Failed to send a request to start the `",
                        (Kind::Term, true) => b"Failed to kill the `",
                        _ => b"Failed to send a request to kill the `",
                    };
                    sentence(&mut self.stdout, prefix, name, b"' service: ");
                    self.stdout.extend_from_slice(reason);
                    self.stdout.push(b'\n');
                }
                Kind::List => self.list_disconnected(),
            }
            self.done = true;
            return;
        }
        match kind {
            Kind::Start => self.options.start = false,
            Kind::End => {
                self.options.end = false;
                if self.options.restart {
                    self.options.restart = false;
                    self.options.start = true;
                }
            }
            Kind::Init => self.options.init = None,
            Kind::Term => self.options.term = None,
            Kind::List => {}
        }
    }
    /// Match the failed request plus NULL list callback path.
    pub fn list_disconnected(&mut self) {
        self.waiting = None;
        self.stdout.extend_from_slice(b"Failed to request a list of services: We disconnected from ARM before we could send a request\n");
        self.stderr
            .extend_from_slice(b"Error communicating with ARM. ARM not running?\n");
        self.ret = 3;
        self.done = true;
    }
    /// Both list passes are intentional. Stopping/unknown rows print twice.
    pub fn list(&mut self, rows: &[ServiceInfo<'_>], now: u64) {
        self.waiting = None;
        let mut counts = [0usize; 5];
        for row in rows {
            if let Some(n) = counts.get_mut(row.status.0 as usize) {
                *n += 1;
            }
            if row.status.0 >= 4 {
                self.row(row, now);
            }
        }
        if !self.quiet {
            self.stdout.extend_from_slice(if self.options.all {
                b"All services:\n"
            } else {
                b"Services (excluding stopped services):\n"
            });
            if counts.iter().any(|n| *n != 0) {
                self.stdout.push(b'(');
                let mut first = true;
                for (index, name) in [
                    (1, "started"),
                    (2, "failed"),
                    (4, "stopping"),
                    (0, "stopped"),
                    (3, "finished"),
                ] {
                    if counts[index] != 0 {
                        if !first {
                            self.stdout.extend_from_slice(b" / ");
                        }
                        self.stdout
                            .extend_from_slice(format!("{name}: {}", counts[index]).as_bytes());
                        first = false;
                    }
                }
                self.stdout.extend_from_slice(b")\n");
            } else {
                self.stdout
                    .extend_from_slice(b"(No services configured.)\n");
            }
        }
        for row in rows {
            if row.status.0 != 0 || self.options.all {
                self.row(row, now);
            }
        }
    }
    fn row(&mut self, row: &ServiceInfo<'_>, now: u64) {
        sentence(&mut self.stdout, b"", row.name, b" (binary='");
        self.stdout.extend_from_slice(row.binary);
        self.stdout.extend_from_slice(b"', status=");
        let name: &[u8] = match row.status.0 {
            0 => b"stopped",
            1 => b"started",
            2 => b"failed",
            3 => b"finished",
            4 => b"stopping",
            _ => b"unknown",
        };
        self.stdout.extend_from_slice(name);
        if row.status.0 == 2 {
            let remaining = if row.restart_at == u64::MAX {
                u64::MAX
            } else {
                row.restart_at.saturating_sub(now)
            };
            self.stdout.extend_from_slice(
                format!(
                    ", exit_status={}, restart_delay='{}'",
                    row.public_exit_status(),
                    relative_time(remaining)
                )
                .as_bytes(),
            );
        }
        self.stdout.extend_from_slice(b")\n");
    }
    /// MONITORING_STARTED is silent; quiet is force-cleared by the monitor phase.
    pub fn monitor(&mut self, service: &[u8], status: u32) {
        if status == 0 || self.quiet {
            return;
        }
        match status {
            1 => sentence(&mut self.stderr, b"Stopped ", service, b".\n"),
            2 => sentence(&mut self.stderr, b"Starting ", service, b"...\n"),
            3 => sentence(&mut self.stderr, b"Stopping ", service, b"...\n"),
            _ => {
                self.stderr
                    .extend_from_slice(format!("Unknown status {status} for service ").as_bytes());
                self.stderr.extend_from_slice(service);
                self.stderr.extend_from_slice(b".\n");
            }
        }
    }
    /// Source timeout task changes ret to2 and requests shutdown.
    pub fn timeout(&mut self) {
        self.ret = 2;
        self.done = true;
    }
    /// Source cleanup checks the remaining end/delete flags, not past success.
    pub fn should_delete(&self) -> bool {
        self.options.end && self.options.delete
    }
}
/// Source relative_time_to_string(delta,YES), with original integer thresholds.
pub fn relative_time(mut value: u64) -> String {
    if value == u64::MAX {
        return "forever".into();
    }
    if value == 0 {
        return "0 ms".into();
    }
    let mut unit = "µs";
    if value > 5000 || value.is_multiple_of(1000) {
        value /= 1000;
        unit = "ms";
        if value > 5000 || value.is_multiple_of(1000) {
            value /= 1000;
            unit = "s";
            if value > 300 || value.is_multiple_of(60) {
                value /= 60;
                unit = "m";
                if value > 300 || value.is_multiple_of(60) {
                    value /= 60;
                    unit = "h";
                    if value > 120 || value.is_multiple_of(24) {
                        value /= 24;
                        unit = if value == 1 { "day" } else { "days" };
                    }
                }
            }
        }
    }
    format!("{value} {unit}")
}
