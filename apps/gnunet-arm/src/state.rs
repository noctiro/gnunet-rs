//! Source command phases with one retained locale and native-byte output.
use crate::{locale::Locale, options::Options};
use gnunet_arm_core::wire::{RequestStatus, ResultCode};
use gnunet_program_host::format::Argument as Value;

mod output;
use output::OutputState;
pub use output::{relative_time, req_string, ret_string};
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
    locale: Locale,
    output: OutputState,
}
impl State {
    /// Initialize source globals from parsed options.
    pub fn new(options: Options) -> Self {
        Self::with_locale(options, Locale::disabled())
    }
    /// Retain the same explicit PROGRAM locale as parsing and diagnostics.
    pub fn with_locale(options: Options, locale: Locale) -> Self {
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
            locale,
            output: OutputState::Active,
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
                            self.err(self.locale.format(
                                b"Cannot stop the `%s' service: ARM is not running.\n",
                                &[Value::Bytes(&name)],
                            ));
                            if !self.output_failed() {
                                self.ret = 4;
                            }
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
                            self.err(self.locale.format(
                                b"Cannot start the `%s' service: ARM is not running.\n",
                                &[Value::Bytes(&name)],
                            ));
                            if !self.output_failed() {
                                self.ret = 4;
                            }
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
                            self.err(
                                self.locale
                                    .text(b"Cannot list services: ARM is not running.\n"),
                            );
                            if !self.output_failed() {
                                self.ret = 4;
                            }
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
                            self.err(
                                self.locale
                                    .text(b"Now only monitoring, press CTRL-C to stop.\n"),
                            );
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
        if matches!(self.output, OutputState::Failed(_)) {
            return;
        }
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
            self.result_failure(kind, status, value);
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
