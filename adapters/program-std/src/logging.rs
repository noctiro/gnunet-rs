//! Caller-owned logging engine; process-global installation is a separate port.
use crate::{
    format::{Argument as Value, Message},
    native::{Calendar, ErrnoGuard, strerror},
    policy::{CallSite, CallSiteCache, Level, Policy},
};
use std::{
    cell::Cell,
    collections::{BTreeMap, VecDeque},
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{self, Write},
    os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::PathBuf,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};
/// Environment captured by the first setup, with force-file re-read per setup.
#[derive(Clone, Default, Debug)]
pub struct Environment {
    /// GNUNET_FORCE_LOG definitions.
    pub force: Option<Vec<u8>>,
    /// GNUNET_LOG definitions.
    pub ordinary: Option<Vec<u8>>,
    /// GNUNET_FORCE_LOGFILE; empty does not override the explicit filename.
    pub force_file: Option<Vec<u8>>,
    /// Presence, including an empty JOURNAL_STREAM value.
    pub journal: bool,
}
impl Environment {
    /// Read this process environment without modifying it.
    #[must_use]
    pub fn capture() -> Self {
        let value = |key| std::env::var_os(key).map(|v| v.as_os_str().as_bytes().to_vec());
        Self {
            force: value("GNUNET_FORCE_LOG"),
            ordinary: value("GNUNET_LOG"),
            force_file: value("GNUNET_FORCE_LOGFILE"),
            journal: std::env::var_os("JOURNAL_STREAM").is_some(),
        }
    }
}
/// Actual native calendar/date and logical absolute time, supplied explicitly.
pub struct Stamp {
    date: Vec<u8>,
    absolute_us: u64,
    calendar: Calendar,
    offset: i64,
}
impl Stamp {
    /// Current wall time with the original logging timeval adjustment formula.
    /// Checked signed intermediates reject overflow rather than reproducing C UB.
    pub fn now(offset: i64) -> io::Result<Self> {
        let base = Calendar::wall()?;
        let absolute_us = (base.seconds as u64)
            .wrapping_mul(1_000_000)
            .wrapping_add(base.micros as u64)
            .wrapping_add_signed(offset);
        let mut seconds = base
            .seconds
            .checked_add(offset / 1_000_000)
            .ok_or_else(|| io::Error::other("logging seconds overflow"))?;
        let fraction = (offset % 1_000_000) * 1_000_000;
        let mut micros = base.micros;
        if offset > 0 {
            micros = native_micros(
                micros
                    .checked_add(fraction)
                    .ok_or_else(|| io::Error::other("logging micros overflow"))?,
            );
            if micros > 1_000_000 {
                micros -= 1_000_000;
                seconds = seconds
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("logging carry overflow"))?;
            }
        } else if micros > -fraction {
            micros = native_micros(micros + fraction);
        } else {
            micros = native_micros(micros + 1_000_000 + fraction);
            seconds = seconds
                .checked_sub(1)
                .ok_or_else(|| io::Error::other("logging borrow overflow"))?;
        }
        Self::from_calendar(Calendar::new(seconds, micros, false)?, absolute_us, offset)
    }
    /// Source log_setup filename calendar: UTC, unshifted, with second precision.
    pub fn setup_now() -> io::Result<Self> {
        let base = Calendar::wall()?;
        Self::controlled_utc(base.seconds, 0)
    }
    /// Deterministic UTC calendar seam. This does not alter the system clock.
    pub fn controlled_utc(seconds: i64, micros: u32) -> io::Result<Self> {
        if micros >= 1_000_000 {
            return Err(io::Error::other("invalid timeval micros"));
        }
        let absolute = (seconds as u64)
            .wrapping_mul(1_000_000)
            .wrapping_add(u64::from(micros));
        Self::from_calendar(
            Calendar::new(seconds, i64::from(micros), true)?,
            absolute,
            0,
        )
    }
    fn from_calendar(calendar: Calendar, absolute_us: u64, offset: i64) -> io::Result<Self> {
        Ok(Self {
            date: calendar.date(),
            absolute_us,
            calendar,
            offset,
        })
    }
    /// Exact timestamp bytes passed to standard/custom loggers.
    #[must_use]
    pub fn date(&self) -> &[u8] {
        &self.date
    }
    /// Logical GNUNET_TIME_absolute_get value used by bulk thresholds.
    #[must_use]
    pub fn absolute_us(&self) -> u64 {
        self.absolute_us
    }
}
/// Synchronous custom logger view; no trailing newline is added to message.
#[derive(Clone, Copy, Debug)]
pub struct Record<'a> {
    /// Original kind, including BULK and arbitrary combinations.
    pub kind: Level,
    /// Component including its native decimal PID.
    pub component: &'a [u8],
    /// Source-defined native date bytes.
    pub date: &'a [u8],
    /// Original formatted C-string prefix, without automatic newline.
    pub message: &'a [u8],
}
/// Unforgeable callback identity tied to its originating logger owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoggerId {
    owner: u64,
    generation: u64,
}
type Custom<'a> = Box<dyn FnMut(Record<'_>) + 'a>;
struct Registration<'a> {
    generation: u64,
    callback: Custom<'a>,
}
struct Bulk {
    message: Vec<u8>,
    component: Vec<u8>,
    kind: Level,
    started: u64,
    repeats: u32,
}
#[derive(Default)]
struct Files {
    template: Option<Vec<u8>>,
    last: Vec<u8>,
    old: VecDeque<Vec<u8>>,
    file: Option<File>,
    process: Option<crate::process_stderr::ProcessStderr>,
}
impl Files {
    fn plan(&mut self, stamp: &Stamp, pid: u32) -> io::Result<Option<PathBuf>> {
        let Some(template) = &self.template else {
            return Ok(None);
        };
        let mut filename = stamp
            .calendar
            .format(template, libc::PATH_MAX as usize + 1)?;
        if let Some(index) = filename.iter().rposition(|&c| c == b'[')
            && filename.get(index + 1) == Some(&b']')
        {
            let mut replaced = filename[..index].to_vec();
            replaced.extend_from_slice(pid.to_string().as_bytes());
            replaced.extend_from_slice(&filename[index + 2..]);
            filename = replaced;
            filename.truncate(libc::PATH_MAX as usize - 1);
        }
        if filename == self.last {
            return Ok(None);
        }
        if !self.last.is_empty() {
            if self.old.len() == 3
                && let Some(old) = self.old.pop_front()
            {
                drop(std::fs::remove_file(OsStr::from_bytes(&old)));
            }
            self.old.push_back(std::mem::take(&mut self.last));
        }
        // C updates last_fn before attempting the open, including on failure.
        self.last = filename;
        Ok(Some(PathBuf::from(OsStr::from_bytes(&self.last))))
    }
}
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);
/// Shared diagnostic scope for one logging/scheduler thread context.
/// Clones share only these sixteen bytes, so callbacks never need a Logger borrow.
#[derive(Clone, Default)]
pub struct ScopeState(Rc<Cell<Option<[u8; 16]>>>);
impl ScopeState {
    /// Copy the currently selected scope, including the unnamed root.
    #[must_use]
    pub fn current(&self) -> Option<[u8; 16]> {
        self.0.get()
    }
    /// Replace the selection and return its original value for restoration.
    #[must_use]
    pub fn replace(&self, scope: Option<[u8; 16]>) -> Option<[u8; 16]> {
        self.0.replace(scope)
    }
}
/// Explicit owner for one native logging thread/context. It does not secretly
/// replace process stderr, install process locale or start a background task.
pub struct Logger<'a> {
    owner: u64,
    generation: u64,
    component: Vec<u8>,
    pid: u32,
    destination_pid: u32,
    policy: Policy,
    skip: i32,
    scope: ScopeState,
    callbacks: Vec<Registration<'a>>,
    bulk: Option<Bulk>,
    files: Files,
    journal: Option<bool>,
    environment_journal: bool,
    extra_logging: bool,
    source_sites: BTreeMap<&'static str, CallSiteCache>,
    logical_clock: Option<crate::shared_clock::SharedClock>,
    translations: Rc<dyn crate::locale::Translations>,
}
impl<'a> Logger<'a> {
    /// Create policy/state only; no file, clock, entropy or environment IO.
    pub fn new(component: &[u8], pid: u32, extra_logging: bool) -> io::Result<Self> {
        Self::with_scope_state(component, pid, extra_logging, ScopeState::default())
    }
    /// Construct with the same explicit scope state as the selected scheduler.
    pub fn with_scope_state(
        component: &[u8],
        pid: u32,
        extra_logging: bool,
        scope: ScopeState,
    ) -> io::Result<Self> {
        let owner = NEXT_OWNER
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .map_err(|_| io::Error::other("logger identity exhausted"))?;
        Ok(Self {
            owner,
            generation: 0,
            component: c_prefix(component).to_vec(),
            pid,
            destination_pid: pid,
            policy: Policy::default(),
            skip: 0,
            scope,
            callbacks: Vec::new(),
            bulk: None,
            files: Files::default(),
            journal: None,
            environment_journal: false,
            extra_logging,
            source_sites: BTreeMap::new(),
            logical_clock: None,
            translations: crate::locale::disabled(),
        })
    }
    /// Refresh only this single-thread fork child's logging identity. No file
    /// is reopened, callback installed, clock replaced or diagnostic emitted.
    /// The original selected filename/PID expansion remains bound to its owned
    /// destination until explicit setup; subsequent records use the real child
    /// PID and no parent callsite/bulk cache. Call only just after the caller's
    /// explicit fresh-process fork, before running service tasks or callbacks.
    pub fn refresh_process_after_fork(&mut self) {
        self.pid = std::process::id();
        self.source_sites.clear();
        self.bulk = None;
    }
    /// Configure source levels/definitions and actual owned file destination.
    /// This component operation is not global fd2 installation. Returned parser
    /// diagnostics must be emitted to the process diagnostic port by its caller.
    pub fn setup(
        &mut self,
        component: &[u8],
        minimum: Option<&[u8]>,
        filename: Option<&[u8]>,
        env: &Environment,
        stamp: &Stamp,
    ) -> io::Result<Vec<u8>> {
        let diagnostics =
            self.policy
                .setup(minimum, env.force.as_deref(), env.ordinary.as_deref())?;
        self.setup_destination(component, filename, env, stamp, &mut io::stderr())?;
        Ok(diagnostics)
    }
    /// Native startup route: parser diagnostics are emitted to the previous
    /// stderr destination before any requested file replacement occurs.
    pub fn setup_routed(
        &mut self,
        component: &[u8],
        minimum: Option<&[u8]>,
        filename: Option<&[u8]>,
        env: &Environment,
        stamp: &Stamp,
        stderr: &mut impl Write,
    ) -> io::Result<()> {
        let diagnostics =
            self.policy
                .setup(minimum, env.force.as_deref(), env.ordinary.as_deref())?;
        self.write_diagnostic(&diagnostics, stderr)?;
        self.setup_destination(component, filename, env, stamp, stderr)
    }
    fn setup_destination(
        &mut self,
        component: &[u8],
        filename: Option<&[u8]>,
        env: &Environment,
        stamp: &Stamp,
        stderr: &mut impl Write,
    ) -> io::Result<()> {
        self.component = c_prefix(component).to_vec();
        self.destination_pid = self.pid;
        self.environment_journal = env.journal;
        let filename = env
            .force_file
            .as_deref()
            .filter(|v| !v.is_empty())
            .or(filename);
        if let Some(filename) = filename {
            // C frees log_file_name before filename_expand. A failed new
            // expansion must not keep rotating the previous template; the
            // already-open diagnostic destination itself remains owned.
            self.files.template = None;
            let clock = if let Some(clock) = &self.logical_clock {
                clock.clone()
            } else {
                let clock =
                    crate::shared_clock::SharedClock::native(0).map_err(io::Error::other)?;
                clock.set_offset(stamp.offset).map_err(io::Error::other)?;
                clock
            };
            let expanded = crate::config_observer::operation(self, &clock, stderr, |observer| {
                gnunet_config::Configuration::default().expand_filename_observed(
                    c_prefix(filename),
                    &gnunet_config::ProcessEnvironment,
                    Some(observer),
                )
            })?
            .map_err(io::Error::other)?;
            self.files.template = Some(expanded.as_os_str().as_bytes().to_vec());
            self.update_file(stamp, stderr)?;
        }
        Ok(())
    }
    /// Share the explicit source locale selection used by PROGRAM/configuration.
    /// Parsed-once rules/cache results retain their original source semantics.
    pub fn set_case_context(&mut self, context: gnunet_config::CaseContext) {
        self.policy.set_case_context(context);
    }
    /// Select the actual shared NLS backend, retaining its handle/capability.
    pub fn set_translations(&mut self, translations: Rc<dyn crate::locale::Translations>) {
        self.translations = translations;
    }
    /// Retain the same selected backend for helper callbacks and startup parsing.
    #[must_use]
    pub fn translations(&self) -> Rc<dyn crate::locale::Translations> {
        Rc::clone(&self.translations)
    }
    /// Bind the same logical offset authority used by PROGRAM/Resolver. This
    /// performs no time or filesystem IO and does not install a hidden task.
    pub fn bind_clock(&mut self, clock: crate::shared_clock::SharedClock) {
        self.logical_clock = Some(clock);
    }
    /// Transfer explicit global fd2 authority into this logger. Any current and
    /// future file destinations are installed into actual process stderr. Dropping
    /// the logger closes its private file fd but leaves process fd2 installed.
    pub fn install_process_stderr(
        &mut self,
        mut capability: crate::process_stderr::ProcessStderr,
    ) -> io::Result<()> {
        if self.files.process.is_some() {
            return Err(io::Error::other(
                "logger already owns process stderr authority",
            ));
        }
        if let Some(file) = &self.files.file {
            capability.install(file)?;
        }
        self.files.process = Some(capability);
        Ok(())
    }
    /// Source direct callsite policy, before skip/debug compile-profile handling.
    pub fn enabled(&self, level: Level, site: CallSite<'_>) -> io::Result<bool> {
        self.policy.enabled(level, &self.component, site)
    }
    /// Exact macro-level cache/debug-culling/skip order; message bytes are data.
    pub fn checked(
        &mut self,
        cache: &mut CallSiteCache,
        kind: Level,
        site: CallSite<'_>,
        message: &[u8],
        stamp: &Stamp,
        stderr: &mut impl Write,
    ) -> io::Result<()> {
        if self.admit(cache, kind, site)? {
            self.nocheck(kind, site.component, message, stamp, stderr)?;
        }
        Ok(())
    }
    fn admit(
        &mut self,
        cache: &mut CallSiteCache,
        kind: Level,
        site: CallSite<'_>,
    ) -> io::Result<bool> {
        if !self.extra_logging && kind.0 & Level::DEBUG.0 != 0 {
            return Ok(false);
        }
        let enabled = cache.cached(|| self.enabled(Level(kind.0 & !Level::BULK.0), site))?;
        if self.skip > 0 {
            self.skip -= 1;
            return Ok(false);
        }
        Ok(enabled)
    }
    /// Macro counterpart that evaluates message arguments and samples time only
    /// after compile-profile/debug/cache/skip admission. Message argument effects
    /// precede the source errno snapshot; native clock/formatting effects do not.
    pub fn checked_lazy(
        &mut self,
        cache: &mut CallSiteCache,
        kind: Level,
        site: CallSite<'_>,
        message: impl FnOnce() -> io::Result<Vec<u8>>,
        stamp: impl FnOnce() -> io::Result<Stamp>,
        stderr: &mut impl Write,
    ) -> io::Result<()> {
        if self.admit(cache, kind, site)? {
            let message = message()?;
            let _errno = ErrnoGuard::new();
            let stamp = stamp()?;
            self.nocheck(kind, site.component, &message, &stamp, stderr)?;
        }
        Ok(())
    }
    /// Explicit log_from macro counterpart, preserving the component/PID cap even
    /// for a source NULL component. Filtering still uses the original callsite.
    pub fn checked_from_lazy(
        &mut self,
        cache: &mut CallSiteCache,
        kind: Level,
        site: CallSite<'_>,
        message: impl FnOnce() -> io::Result<Vec<u8>>,
        stamp: impl FnOnce() -> io::Result<Stamp>,
        stderr: &mut impl Write,
    ) -> io::Result<()> {
        if self.admit(cache, kind, site)? {
            let message = message()?;
            let _errno = ErrnoGuard::new();
            let stamp = stamp()?;
            self.from_nocheck(kind, site.component, &message, &stamp, stderr)?;
        }
        Ok(())
    }
    pub(crate) fn source_lazy(
        &mut self,
        id: &'static str,
        kind: Level,
        site: CallSite<'_>,
        message: impl FnOnce() -> io::Result<Vec<u8>>,
        stamp: impl FnOnce() -> io::Result<Stamp>,
        stderr: &mut impl Write,
    ) -> io::Result<()> {
        let mut cache = self.source_sites.remove(id).unwrap_or_default();
        let result = if site.component.is_some() {
            self.checked_from_lazy(&mut cache, kind, site, message, stamp, stderr)
        } else {
            self.checked_lazy(&mut cache, kind, site, message, stamp, stderr)
        };
        self.source_sites.insert(id, cache);
        result
    }
    /// Source nocheck operation: bypass all threshold/cache/debug/skip tests.
    pub fn nocheck(
        &mut self,
        kind: Level,
        component: Option<&[u8]>,
        message: &[u8],
        stamp: &Stamp,
        stderr: &mut impl Write,
    ) -> io::Result<()> {
        let _errno = ErrnoGuard::new();
        // Source mylog intentionally ignores the updater status, after its
        // actual diagnostics have run. last_fn prevents recursive retry here.
        let _update_failed = self.update_file(stamp, stderr).is_err();
        let message = c_prefix(message);
        let repeat = self
            .bulk
            .as_ref()
            .is_some_and(|last| kind.0 & 64 != 0 && last.started != 0 && message == last.message);
        if repeat {
            let last = self
                .bulk
                .as_mut()
                .ok_or_else(|| io::Error::other("bulk state disappeared"))?;
            last.repeats = last
                .repeats
                .checked_add(1)
                .ok_or_else(|| io::Error::other("bulk repeat counter overflow"))?;
            if stamp.absolute_us.saturating_sub(last.started) > 43_200_000_000
                || last.repeats > 1000
            {
                self.flush_bulk(stamp, stderr)?;
            }
            return Ok(());
        }
        self.flush_bulk(stamp, stderr)?;
        let mut actual = c_prefix(component.unwrap_or(&self.component)).to_vec();
        actual.push(b'-');
        actual.extend_from_slice(self.pid.to_string().as_bytes());
        if component.is_some() {
            actual.truncate(127);
        }
        self.bulk = Some(Bulk {
            message: message[..message.len().min(255)].to_vec(),
            component: actual[..actual.len().min(32)].to_vec(),
            kind,
            started: stamp.absolute_us,
            repeats: 0,
        });
        self.output(
            Record {
                kind,
                component: &actual,
                date: stamp.date(),
                message,
            },
            stderr,
        )
    }
    /// Exact log_from_nocheck wrapper, including the source 127-byte component/PID cap even for None.
    pub fn from_nocheck(
        &mut self,
        kind: Level,
        component: Option<&[u8]>,
        message: &[u8],
        stamp: &Stamp,
        stderr: &mut impl Write,
    ) -> io::Result<()> {
        let component = c_prefix(component.unwrap_or(&self.component)).to_vec();
        self.nocheck(kind, Some(&component), message, stamp, stderr)
    }
    /// Route application diagnostic bytes through this owner's configured destination.
    /// This explicit port does not claim process-global fd2 installation.
    pub fn write_diagnostic(&mut self, bytes: &[u8], stderr: &mut impl Write) -> io::Result<()> {
        match &mut self.files.file {
            Some(file) => {
                file.write_all(bytes)?;
                file.flush()
            }
            None => {
                stderr.write_all(bytes)?;
                stderr.flush()
            }
        }
    }
    fn flush_bulk(&mut self, stamp: &Stamp, stderr: &mut impl Write) -> io::Result<()> {
        let Some(last) = self.bulk.as_mut() else {
            return Ok(());
        };
        if last.started == 0 || last.repeats == 0 {
            return Ok(());
        }
        let text = last.message.strip_suffix(b"\n").unwrap_or(&last.message);
        let elapsed =
            crate::diagnostics::relative_time(stamp.absolute_us.saturating_sub(last.started), true);
        let template = self.translations.gettext(
            Some(b"gnunet"),
            b"Message `%.*s' repeated %u times in the last %s\n",
        )?;
        let mut body = crate::format::render(
            &template,
            &[
                Value::Signed(256),
                Value::Bytes(text),
                Value::Unsigned(u64::from(last.repeats)),
                Value::Bytes(&elapsed),
            ],
        )?;
        body.truncate(575);
        let component = last.component.clone();
        let kind = last.kind;
        last.started = stamp.absolute_us;
        last.repeats = 0;
        self.output(
            Record {
                kind,
                component: &component,
                date: stamp.date(),
                message: &body,
            },
            stderr,
        )
    }
    fn output(&mut self, record: Record<'_>, stderr: &mut impl Write) -> io::Result<()> {
        let journal = *self.journal.get_or_insert(self.environment_journal);
        if !self.callbacks.is_empty() {
            for logger in &mut self.callbacks {
                (logger.callback)(record);
            }
            return Ok(());
        }
        let mut line = Vec::new();
        if record.kind == Level::MESSAGE {
            line.extend_from_slice(b"* ");
        } else {
            if !journal {
                line.extend_from_slice(record.date);
                line.push(b' ');
                line.extend_from_slice(record.component);
            }
            if let Some(scope) = self.scope.current() {
                line.push(b'(');
                line.extend_from_slice(&base32(&scope));
                line.extend_from_slice(b") ");
            } else if !journal {
                line.push(b' ');
            }
            line.extend_from_slice(
                &self
                    .translations
                    .gettext(Some(b"gnunet"), record.kind.name())?,
            );
            line.push(b' ');
        }
        line.extend_from_slice(record.message);
        if !record.message.ends_with(b"\n") {
            line.push(b'\n');
        }
        match &mut self.files.file {
            Some(file) => {
                file.write_all(&line)?;
                file.flush()
            }
            None => {
                stderr.write_all(&line)?;
                stderr.flush()
            }
        }
    }
    /// Add newest-first custom logger. Standard output is suppressed while any exists.
    pub fn logger_add(&mut self, callback: impl FnMut(Record<'_>) + 'a) -> io::Result<LoggerId> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| io::Error::other("callback generation exhausted"))?;
        self.generation = generation;
        self.callbacks.insert(
            0,
            Registration {
                generation,
                callback: Box::new(callback),
            },
        );
        Ok(LoggerId {
            owner: self.owner,
            generation,
        })
    }
    /// Remove the exact live callback; stale/foreign IDs have no effect.
    pub fn logger_remove(&mut self, id: LoggerId) -> io::Result<()> {
        if id.owner != self.owner {
            return Err(io::Error::other("foreign logger ID"));
        }
        let index = self
            .callbacks
            .iter()
            .position(|l| l.generation == id.generation)
            .ok_or_else(|| io::Error::other("stale logger ID"))?;
        drop(self.callbacks.remove(index));
        Ok(())
    }
    /// Add skip count, or reset when zero. Return whether a checked reset was clean;
    /// caller is responsible for the source GNUNET_break diagnostic on false.
    pub fn log_skip(&mut self, count: i32, check_reset: bool) -> io::Result<bool> {
        if count == 0 {
            let clear = self.skip == 0;
            self.skip = 0;
            return Ok(!check_reset || clear);
        }
        self.skip = self
            .skip
            .checked_add(count)
            .ok_or_else(|| io::Error::other("skip overflow"))?;
        Ok(true)
    }
    /// Signed source skip count, including negative values.
    #[must_use]
    pub fn get_log_skip(&self) -> i32 {
        self.skip
    }
    /// Complete source log_skip operation, including its checked-reset break
    /// diagnostic after the counter has been reset. Signed overflow is rejected
    /// by the explicit Rust resource boundary instead of executing C overflow.
    pub fn log_skip_routed(
        &mut self,
        count: i32,
        check_reset: bool,
        clock: &crate::shared_clock::SharedClock,
        stderr: &mut impl Write,
    ) -> io::Result<()> {
        if !self.log_skip(count, check_reset)? {
            let translations = self.translations();
            self.source_lazy(
                "common.log-skip.unbalanced",
                Level::ERROR,
                CallSite {
                    component: None,
                    file: b"common_logging.c",
                    function: b"GNUNET_log_skip",
                    line: 982,
                },
                || {
                    Message::Translated {
                        domain: Some(b"gnunet"),
                        template: b"Assertion failed at %s:%d.\n",
                        arguments: &[Value::Bytes(b"common_logging.c"), Value::Signed(982)],
                    }
                    .render(translations.as_ref())
                },
                || Stamp::now(clock.offset().map_err(io::Error::other)?),
                stderr,
            )?;
        }
        Ok(())
    }
    /// Source GNUNET_log_config_missing, sharing the original common helper's
    /// one first-call macro cache across all configurations/callers.
    pub fn config_missing(
        &mut self,
        kind: Level,
        section: &[u8],
        option: &[u8],
        clock: &crate::shared_clock::SharedClock,
        stderr: &mut impl Write,
    ) -> io::Result<()> {
        let translations = self.translations();
        self.source_lazy(
            "common.config.missing",
            kind,
            CallSite {
                component: None,
                file: b"common_logging.c",
                function: b"GNUNET_log_config_missing",
                line: 1518,
            },
            || {
                Message::Translated {
                    domain: Some(b"gnunet"),
                    template: b"Configuration fails to specify option `%s' in section `%s'!\n",
                    arguments: &[Value::Bytes(option), Value::Bytes(section)],
                }
                .render(translations.as_ref())
            },
            || Stamp::now(clock.offset().map_err(io::Error::other)?),
            stderr,
        )
    }
    /// Source GNUNET_log_config_invalid. required is already caller-selected
    /// data, as in C; only this function's outer format is translated here.
    pub fn config_invalid(
        &mut self,
        kind: Level,
        section: &[u8],
        option: &[u8],
        required: &[u8],
        clock: &crate::shared_clock::SharedClock,
        stderr: &mut impl Write,
    ) -> io::Result<()> {
        let translations = self.translations();
        self.source_lazy("common.config.invalid",kind,CallSite{component:None,file:b"common_logging.c",function:b"GNUNET_log_config_invalid",line:1534},||Message::Translated{domain:Some(b"gnunet"),template:b"Configuration specifies invalid value for option `%s' in section `%s': %s\n",arguments:&[Value::Bytes(option),Value::Bytes(section),Value::Bytes(required)]}.render(translations.as_ref()),||Stamp::now(clock.offset().map_err(io::Error::other)?),stderr)
    }
    /// Save/enter an async scope without entropy or hidden thread-global mutation.
    pub fn scope_enter(&mut self, scope: [u8; 16]) -> Option<[u8; 16]> {
        self.scope.replace(Some(scope))
    }
    /// Restore a previously saved scope, including the unnamed root.
    pub fn scope_restore(&mut self, saved: Option<[u8; 16]>) {
        let _previous = self.scope.replace(saved);
    }
    /// Copy current scope.
    #[must_use]
    pub fn scope_get(&self) -> Option<[u8; 16]> {
        self.scope.current()
    }
    /// Obtain the narrow shared state without retaining a Logger borrow.
    #[must_use]
    pub fn scope_state(&self) -> ScopeState {
        self.scope.clone()
    }
    /// Generate scope bytes through explicit fallible caller entropy.
    pub fn scope_fresh(
        entropy: &mut impl gnunet_crypto::Entropy,
    ) -> Result<[u8; 16], gnunet_types::Error> {
        let mut scope = [0; 16];
        if let Err(error) = entropy.fill(&mut scope) {
            scope.fill(0);
            return Err(error);
        }
        Ok(scope)
    }
    /// Native source convenience using OS entropy. It performs an explicit OS
    /// entropy call, creates no scheduler task and returns failure without an ID.
    /// This scope identifier is diagnostic metadata, not an authentication key.
    pub fn scope_fresh_os() -> io::Result<[u8; 16]> {
        let mut bytes = [0; 16];
        if let Err(error) = getrandom::fill(&mut bytes) {
            bytes.fill(0);
            return Err(io::Error::other(error.to_string()));
        }
        Ok(bytes)
    }
}
fn c_prefix(input: &[u8]) -> &[u8] {
    &input[..input.iter().position(|&b| b == 0).unwrap_or(input.len())]
}
/// Official Crockford byte encoding used in diagnostic IDs.
#[must_use]
pub fn base32(input: &[u8]) -> Vec<u8> {
    let alphabet = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut out = Vec::new();
    let mut bits = 0u16;
    let mut available = 0;
    for byte in input {
        bits = (bits << 8) | u16::from(*byte);
        available += 8;
        while available >= 5 {
            available -= 5;
            out.push(alphabet[usize::from((bits >> available) & 31)]);
        }
    }
    if available > 0 {
        out.push(alphabet[usize::from((bits << (5 - available)) & 31)]);
    }
    out
}

fn native_micros(value: i64) -> i64 {
    let narrowed = value as libc::suseconds_t;
    crate::native::wide_micros(narrowed)
}

impl Logger<'_> {
    #[expect(
        clippy::too_many_arguments,
        reason = "Pinned filesystem diagnostic macros have distinct source site, component, function and native errno arguments"
    )]
    fn filesystem_log(
        &mut self,
        id: &'static str,
        kind: Level,
        component: Option<&[u8]>,
        file: &[u8],
        function: &[u8],
        line: i32,
        body: Message<'_>,
        stamp: &Stamp,
        stderr: &mut impl Write,
    ) -> io::Result<()> {
        let clock = self.logical_clock.clone();
        let fallback_offset = stamp.offset;
        let translations = self.translations();
        self.source_lazy(
            id,
            kind,
            CallSite {
                component,
                file,
                function,
                line,
            },
            || body.render(translations.as_ref()),
            || {
                Stamp::now(clock.as_ref().map_or(Ok(fallback_offset), |v| {
                    v.offset().map_err(io::Error::other)
                })?)
            },
            stderr,
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Native syscall diagnostics retain explicit fixed source function/line, errno and file arguments"
    )]
    fn syscall_log(
        &mut self,
        id: &'static str,
        operation: &[u8],
        path: &[u8],
        errno: i32,
        file: &[u8],
        function: &[u8],
        line: i32,
        kind: Level,
        stamp: &Stamp,
        stderr: &mut impl Write,
    ) -> io::Result<()> {
        let error = strerror(errno);
        let location_line = i64::from(line);
        let values = [
            Value::Bytes(operation),
            Value::Bytes(path),
            Value::Bytes(file),
            Value::Signed(location_line),
            Value::Bytes(&error),
        ];
        let body = Message::Translated {
            domain: Some(b"gnunet"),
            template: b"`%s' failed on file `%s' at %s:%d with error: %s\n",
            arguments: &values,
        };
        self.filesystem_log(
            id,
            kind,
            if file == b"disk.c" {
                Some(b"util-disk")
            } else {
                None
            },
            file,
            function,
            line,
            body,
            stamp,
            stderr,
        )
    }
    fn directory_test(
        &mut self,
        path: &[u8],
        stamp: &Stamp,
        stderr: &mut impl Write,
    ) -> io::Result<i32> {
        match crate::native::path_is_directory(path) {
            Err(error) => {
                let errno = error.raw_os_error().unwrap_or(libc::EIO);
                if errno != libc::ENOENT {
                    self.syscall_log(
                        "disk.directory_test.stat",
                        b"stat",
                        path,
                        errno,
                        b"disk.c",
                        b"GNUNET_DISK_directory_test",
                        478,
                        Level::WARNING,
                        stamp,
                        stderr,
                    )?;
                }
                Ok(-1)
            }
            Ok(false) => {
                let mut body = b"A file already exits with the same name ".to_vec();
                body.extend_from_slice(path);
                body.push(b'\n');
                self.filesystem_log(
                    "disk.directory_test.file",
                    Level::INFO,
                    Some(b"util-disk"),
                    b"disk.c",
                    b"GNUNET_DISK_directory_test",
                    485,
                    Message::Literal(&body),
                    stamp,
                    stderr,
                )?;
                Ok(0)
            }
            Ok(true) => match crate::native::path_access(path, libc::X_OK) {
                Ok(()) => Ok(1),
                Err(error) => {
                    self.syscall_log(
                        "disk.directory_test.access",
                        b"access",
                        path,
                        error.raw_os_error().unwrap_or(libc::EIO),
                        b"disk.c",
                        b"GNUNET_DISK_directory_test",
                        498,
                        Level::WARNING,
                        stamp,
                        stderr,
                    )?;
                    Ok(0)
                }
            },
        }
    }
    fn directory_failure(
        &mut self,
        path: &[u8],
        second_pass: bool,
        stamp: &Stamp,
        stderr: &mut impl Write,
    ) -> io::Result<()> {
        let mut body = b"Creating directory `".to_vec();
        body.extend_from_slice(path);
        body.extend_from_slice(b"' failed\n");
        self.filesystem_log(
            if second_pass {
                "disk.directory_create.second"
            } else {
                "disk.directory_create.first"
            },
            Level::ERROR,
            None,
            b"disk.c",
            b"GNUNET_DISK_directory_create",
            if second_pass { 635 } else { 606 },
            Message::Literal(&body),
            stamp,
            stderr,
        )
    }
    fn create_directory(
        &mut self,
        directory: &[u8],
        stamp: &Stamp,
        stderr: &mut impl Write,
    ) -> io::Result<i32> {
        let len = directory.len();
        let mut position = 1;
        let mut end = len;
        // Exactly the source reverse scan, including its synthetic trailing slash.
        while position <= end {
            if end == len || directory[end] == b'/' {
                let result = self.directory_test(&directory[..end], stamp, stderr)?;
                if result == 0 {
                    self.directory_failure(&directory[..end], false, stamp, stderr)?;
                    return Ok(-1);
                }
                if result == 1 {
                    end += 1;
                    break;
                }
            }
            end -= 1;
        }
        position = position.max(end);
        while position <= len {
            if position == len || directory[position] == b'/' {
                let path = &directory[..position];
                let result = self.directory_test(path, stamp, stderr)?;
                if result == 0 {
                    self.directory_failure(path, true, stamp, stderr)?;
                    return Ok(-1);
                }
                if result == -1
                    && let Err(error) = crate::native::path_mkdir(path)
                {
                    let errno = error.raw_os_error().unwrap_or(libc::EIO);
                    if errno != libc::EEXIST {
                        self.syscall_log(
                            "disk.directory_create.mkdir",
                            b"mkdir",
                            path,
                            errno,
                            b"disk.c",
                            b"GNUNET_DISK_directory_create",
                            649,
                            Level::ERROR,
                            stamp,
                            stderr,
                        )?;
                        return Ok(-1);
                    }
                }
            }
            position += 1;
        }
        Ok(1)
    }
    fn create_directory_for_file(
        &mut self,
        path: &[u8],
        stamp: &Stamp,
        stderr: &mut impl Write,
    ) -> io::Result<i32> {
        if crate::native::path_access(path, libc::W_OK).is_ok() {
            return Ok(1);
        }
        let end = path.iter().rposition(|&v| v == b'/').unwrap_or(0);
        let directory = if end == 0 { b"/" } else { &path[..end] };
        let result = self.create_directory(directory, stamp, stderr)?;
        if result == 1 && crate::native::path_access(directory, libc::W_OK).is_err() {
            Ok(0)
        } else {
            Ok(result)
        }
    }
    fn update_file(&mut self, stamp: &Stamp, stderr: &mut impl Write) -> io::Result<()> {
        let Some(path) = self.files.plan(stamp, self.destination_pid)? else {
            return Ok(());
        };
        let bytes = path.as_os_str().as_bytes();
        if self.create_directory_for_file(bytes, stamp, stderr)? == -1 {
            let errno = crate::native::errno();
            let mut body = b"Failed to create directory for `".to_vec();
            body.extend_from_slice(bytes);
            body.extend_from_slice(b"': ");
            body.extend_from_slice(&strerror(errno));
            body.push(b'\n');
            self.write_diagnostic(&body, stderr)?;
            return Err(io::Error::from_raw_os_error(errno));
        }
        let file = match OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o644)
            .open(&path)
        {
            Ok(file) => crate::process_stderr::lift(file)?,
            Err(error) => {
                let errno = error.raw_os_error().unwrap_or(libc::EIO);
                self.syscall_log(
                    "common.setup_log_file.open",
                    b"open",
                    bytes,
                    errno,
                    b"common_logging.c",
                    b"setup_log_file",
                    418,
                    Level::ERROR,
                    stamp,
                    stderr,
                )?;
                return Err(error);
            }
        };
        if let Some(process) = &mut self.files.process {
            process.install(&file)?;
        }
        self.files.file = Some(file);
        Ok(())
    }
}
