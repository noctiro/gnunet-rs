//! Actual selected logger and bounded synchronous stdout. No OFD flags change.
use gnunet_fs_host::auto_share::{Event, RunReport, Stop};
use gnunet_program_host::{logging::Logger, policy::Level, service, shared_clock::SharedClock};
use std::{
    io::{self, Write},
    time::{Duration, Instant},
};
pub(super) struct Reports {
    logger: Logger<'static>,
    clock: SharedClock,
    verbose: u32,
    first: Option<io::Error>,
    next: Instant,
    stop: Stop,
}
impl Reports {
    pub fn new(logger: Logger<'static>, clock: SharedClock, verbose: u32, stop: Stop) -> Self {
        Self {
            logger,
            clock,
            verbose,
            first: None,
            next: Instant::now(),
            stop,
        }
    }
    pub fn failed(&self) -> bool {
        self.first.is_some()
    }
    pub fn take_failure(&mut self) -> Option<io::Error> {
        self.first.take()
    }
    fn retain(&mut self, result: io::Result<()>) {
        if self.first.is_none() {
            self.first = result.err();
            if self.first.is_some() {
                self.stop.request();
            }
        }
    }
    pub fn log(&mut self, site: &'static str, level: Level, args: std::fmt::Arguments<'_>) {
        if self.failed() {
            return;
        }
        let result = service::diagnostic(&mut self.logger, &self.clock, site, level, args);
        self.retain(result);
    }
    pub fn event(&mut self, event: Event<'_>) {
        match event {
            Event::Published { version, path, uri } => {
                self.log("auto-share.published",Level::INFO,format_args!("original version {version} path={path:?} completed all publication tasks; URI={}",String::from_utf8_lossy(uri)));
                if !self.failed() {
                    let result = (|| {
                        let mut out = io::stdout().lock();
                        out.write_all(uri)?;
                        out.write_all(b"\n")?;
                        out.flush()
                    })();
                    self.retain(result);
                }
            }
            Event::Failed {
                version,
                path,
                error,
            } => self.log(
                "auto-share.attempt-failed",
                Level::WARNING,
                format_args!("version={version:?} path={path:?}: {error}"),
            ),
            Event::Blocked {
                version,
                path,
                reason,
            } => self.log(
                "auto-share.blocked",
                Level::WARNING,
                format_args!("original version={version} path={path:?}: {reason}"),
            ),
            Event::Prepared {
                version,
                path,
                tasks,
            } => self.log(
                "auto-share.prepared",
                Level::INFO,
                format_args!("original version={version} path={path:?} tasks={tasks}"),
            ),
            Event::Removed { path } => self.log(
                "auto-share.removed",
                Level::INFO,
                format_args!("input removed: {path:?}; no new publication scheduled"),
            ),
            Event::Scanned {
                entries,
                objects,
                bytes,
            } => {
                self.log(
                    "auto-share.scan",
                    Level::DEBUG,
                    format_args!(
                        "stable-scan candidate entries={entries} objects={objects} bytes={bytes}"
                    ),
                );
                if self.verbose > 0 {
                    self.progress(format_args!(
                        "scan entries={entries} objects={objects} bytes={bytes}"
                    ));
                }
            }
            Event::Publication {
                version,
                task,
                progress,
            } => {
                if self.verbose > 0 {
                    self.progress(format_args!("version={version} task={task} {progress:?}"));
                }
            }
        }
    }
    fn progress(&mut self, args: std::fmt::Arguments<'_>) {
        if self.failed() || Instant::now() < self.next {
            return;
        }
        self.next = Instant::now() + Duration::from_secs(1);
        let result = (|| {
            let mut out = io::stdout().lock();
            writeln!(out, "{args}")?;
            out.flush()
        })();
        self.retain(result);
    }
    pub fn stopped(&mut self, report: &RunReport) {
        self.log(
            "auto-share.stopped",
            Level::INFO,
            format_args!(
                "scans={} prepared={} completed={} blocked={} failures={}; file worker joined",
                report.scans, report.prepared, report.published, report.blocked, report.failures
            ),
        );
    }
}
