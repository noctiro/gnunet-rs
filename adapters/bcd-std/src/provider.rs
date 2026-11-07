//! Caller-driven original native renderer. No shell or hidden worker is used.
mod directory;
mod template;
mod types;
use directory::Directory;
use gnunet_service_runtime::{
    clock::RuntimeClock,
    process::{
        self, ChildExit, ChildRegistry, DescriptorMap, EnvironmentSnapshot, NativeCommand,
        OriginalChild, ProcessLimits, SpawnResult,
    },
};
use std::{
    cell::Cell,
    ffi::OsString,
    fmt,
    future::{Future, poll_fn},
    os::fd::AsFd,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
pub use types::{Artifact, Bounds, Cause, Limits, RenderRequest, Report, Settings, Stop};

struct Check<'a> {
    clock: &'a dyn RuntimeClock,
    bounds: Bounds,
    stop: &'a Stop,
    last: Cell<Option<u64>>,
}
impl Check<'_> {
    fn run(&self) -> Result<(), Cause> {
        if self.stop.is_stopped() {
            return Err(Cause::Cancelled);
        }
        if Instant::now() >= self.bounds.hard {
            return Err(Cause::Deadline);
        }
        let now = self.clock.sample().map_err(Cause::Clock)?.now.as_micros();
        if self.last.get().is_some_and(|old| now < old) {
            return Err(Cause::Clock(gnunet_types::Error::TimeUncertain));
        }
        self.last.set(Some(now));
        if now >= self.bounds.expires || Instant::now() >= self.bounds.hard {
            return Err(Cause::Deadline);
        }
        if self.stop.is_stopped() {
            return Err(Cause::Cancelled);
        }
        Ok(())
    }
}
/// An error retains actual cleanup ownership when bounded cleanup is unfinished.
#[must_use = "retain take_retirement() and poll it to actual reaping/directory cleanup"]
pub struct RenderFailure {
    /// Original rendering failure, retaining its concrete error source.
    pub cause: Cause,
    /// Independent actual native/cleanup facts.
    pub report: Report,
    retirement: Option<Retirement>,
}
impl RenderFailure {
    /// Move original unfinished child/directory ownership to the same server job slot.
    pub fn take_retirement(&mut self) -> Option<Retirement> {
        self.retirement.take()
    }
}
impl fmt::Debug for RenderFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RenderFailure")
            .field("cause", &self.cause)
            .field("report", &self.report)
            .field("retirement", &self.retirement.is_some())
            .finish()
    }
}
impl fmt::Display for RenderFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.cause.fmt(f)
    }
}
impl std::error::Error for RenderFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

/// Same original registry/child/directory, never a detached PID or global reaper.
/// Ready is a terminal report: check undrained and cleanup_error. Permanent
/// wait loss or failed directory cleanup grants no missing terminal/removal fact.
#[must_use = "keep the original job slot until poll returns Ready"]
pub struct Retirement {
    registry: ChildRegistry,
    child: Option<OriginalChild>,
    png_phase: bool,
    directory: Option<Directory>,
    limits: Limits,
    report: Report,
    timer: Pin<Box<Sleep>>,
    ownership_lost: bool,
    terminal: bool,
}
impl Retirement {
    fn new(limits: Limits) -> Result<Self, Cause> {
        Ok(Self {
            registry: ChildRegistry::new(1).map_err(launch)?,
            child: None,
            png_phase: false,
            directory: None,
            limits,
            report: Report::default(),
            timer: Box::pin(tokio::time::sleep(Duration::ZERO)),
            ownership_lost: false,
            terminal: false,
        })
    }
    fn error(&mut self, error: Cause) {
        self.report
            .cleanup_error
            .get_or_insert_with(|| Arc::new(error));
    }
    fn reap(&mut self) {
        if let Err(error) = self.registry.reap_completed() {
            self.error(launch(error));
        }
        while let Some(event) = self.registry.take_reaped() {
            if self.child.as_ref() != Some(&event.child) {
                self.error(launch(process::LaunchError::Stale));
                self.ownership_lost = true;
                continue;
            }
            self.child = None;
            if self.png_phase {
                self.report.gs_reaped = true;
                self.report.gs_exit = Some(event.exit);
            } else {
                self.report.tex_reaped = true;
                self.report.tex_exit = Some(event.exit);
            }
        }
        if self.child.is_some() && self.registry.pending_children() == 0 {
            self.ownership_lost = true;
            self.error(launch(process::LaunchError::Stale));
        }
    }
    fn signal(&mut self, signal: i32) {
        // Only registry-retained original authority may be signalled. An old
        // child handle after ECHILD could now name a reused PID; never use it.
        let Some(child) = self.registry.children().next().cloned() else {
            if self.child.is_some() {
                self.ownership_lost = true;
            }
            return;
        };
        if signal == libc::SIGKILL {
            self.report.kill_attempted = true;
        } else {
            self.report.term_attempted = true;
        }
        if let Err(error) = self.registry.signal_native(&child, signal) {
            self.error(launch(error));
        }
    }
    fn arm(&mut self, cx: &mut Context<'_>) {
        self.timer
            .as_mut()
            .reset(Instant::now() + self.limits.poll_interval);
        if self.timer.as_mut().poll(cx).is_ready() {
            cx.waker().wake_by_ref();
        }
    }
    /// Poll original cleanup. Owned unreaped children remain pending; lost wait
    /// authority or a post-reap directory error returns a terminal undrained report.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Report> {
        if self.terminal {
            return Poll::Ready(self.report.clone());
        }
        self.reap();
        if self.ownership_lost && self.registry.pending_children() == 0 {
            self.error(launch(process::LaunchError::Stale));
            self.report.undrained = true;
            // The original exit is unknown. Keep actual prior phase receipts,
            // and retain the directory rather than granting removal authority.
            self.child = None;
            self.terminal = true;
            return Poll::Ready(self.report.clone());
        }
        if self.report.kill_attempted && self.registry.pending_children() > 0 {
            // A prior failed signal cannot discard original cleanup authority.
            // Retry at the existing finite poll interval, only while this exact
            // unreaped child remains owned by this registry.
            self.signal(libc::SIGKILL);
        }
        if self.child.is_none() && self.registry.pending_children() == 0 && !self.ownership_lost {
            if let Some(directory) = &self.directory {
                match directory.remove(self.limits.work_files) {
                    Ok(()) => {
                        self.directory = None;
                        self.report.directory_removed = true;
                    }
                    Err(error) => {
                        self.error(error);
                        self.report.undrained = true;
                        // No child wait remains. The failed directory operation
                        // is terminal, not evidence of removal or a retry debt.
                        // Leave its original path in the report and filesystem.
                        self.directory = None;
                        self.terminal = true;
                        return Poll::Ready(self.report.clone());
                    }
                }
            } else {
                self.report.directory_removed = true;
            }
            if self.directory.is_none() {
                self.report.undrained = false;
                self.terminal = true;
                return Poll::Ready(self.report.clone());
            }
        }
        if let Poll::Ready(Err(error)) = self.registry.poll_child_signal(cx) {
            self.error(launch(error));
        }
        self.report.undrained = true;
        self.arm(cx);
        Poll::Pending
    }
}
impl Drop for Retirement {
    fn drop(&mut self) {
        // Exceptional RAII fallback, not the normal async shutdown path. Never
        // discard an original unreaped registry after a single WNOHANG check.
        // This clock-free OS wait is deliberately not time-bounded/preemptible;
        // normal Server cancellation retains and polls this owner instead.
        loop {
            if self.child.is_none() && self.registry.pending_children() > 0 {
                self.child = self.registry.children().next().cloned();
            }
            self.signal(libc::SIGKILL);
            self.reap();
            if self.registry.pending_children() == 0
                && (self.ownership_lost || self.child.is_none())
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        if self.child.is_none()
            && !self.ownership_lost
            && let Some(directory) = &self.directory
        {
            let _cleanup = directory.remove(self.limits.work_files);
        }
    }
}
fn launch(error: process::LaunchError) -> Cause {
    Cause::Launch(error)
}

fn spawn(
    retirement: &mut Retirement,
    settings: &Settings,
    png: bool,
    check: &Check<'_>,
) -> Result<(), Cause> {
    check.run()?;
    let directory = retirement.directory.as_ref().ok_or(Cause::Artifact)?;
    directory.check()?;
    check.run()?;
    let (stdout, stderr) = directory.logs(png)?;
    check.run()?;
    let tool = if png {
        &settings.ghostscript
    } else {
        &settings.pdflatex
    };
    let arguments: &[&str] = if png {
        &[
            "-dSAFER",
            "-dBATCH",
            "-dNOPAUSE",
            "-sDEVICE=png16m",
            "-r150",
            "-dFirstPage=1",
            "-dLastPage=1",
            "-sOutputFile=gns-bcd.png",
            "-f",
            "gns-bcd.pdf",
        ]
    } else {
        &[
            "-no-shell-escape",
            "-no-parse-first-line",
            "-no-mktex=fmt",
            "-no-mktex=pk",
            "-no-mktex=tfm",
            "-interaction=nonstopmode",
            "-halt-on-error",
            "-file-line-error",
            "-jobname=gns-bcd",
            "document.tex",
        ]
    };
    let mut argv = Vec::new();
    argv.try_reserve_exact(arguments.len() + 1)
        .map_err(|_| Cause::Limit)?;
    argv.push(tool.as_os_str().to_owned());
    argv.extend(arguments.iter().map(OsString::from));
    let cwd = directory.path().to_path_buf();
    let mut values = Vec::new();
    values.try_reserve_exact(12).map_err(|_| Cause::Limit)?;
    for key in ["HOME", "TMPDIR", "TEXMFOUTPUT"] {
        values.push((OsString::from(key), cwd.as_os_str().to_owned()));
    }
    for key in [
        "MKTEXPK", "MKTEXTFM", "MKTEXFMT", "MKTEXMF", "MKTEXOFM", "MKTEXOCP",
    ] {
        values.push((OsString::from(key), OsString::from("0")));
    }
    values.push((OsString::from("openout_any"), OsString::from("p")));
    let environment = EnvironmentSnapshot::from_values(values, cwd.clone()).map_err(launch)?;
    let limits = ProcessLimits {
        launch: process::LaunchLimits {
            max_command_bytes: 16 * 1024,
            max_arguments: 32,
            max_children: 1,
            max_environment_bytes: 64 * 1024,
        },
        max_auxiliary_bytes: 4096,
        max_descriptors: 2,
        max_descriptor_number: 3,
    };
    let command = NativeCommand {
        filename: tool.as_os_str().to_owned(),
        argv,
        environment,
        environment_changes: Vec::new(),
        cwd: Some(cwd),
        stdio: 0,
        stdio_snapshot: None,
        listeners: Vec::new(),
        mappings: vec![
            DescriptorMap {
                source: stdout.as_fd(),
                target: 1,
            },
            DescriptorMap {
                source: stderr.as_fd(),
                target: 2,
            },
        ],
    };
    check.run()?;
    let admitted = process::spawn(
        &settings.configuration,
        &settings.launcher,
        command,
        limits,
        &mut retirement.registry,
    )
    .map_err(launch)?;
    match admitted {
        SpawnResult::Refused { error } => {
            return Err(Cause::Io(error.unwrap_or_else(|| {
                std::io::Error::other("native renderer invocation refused")
            })));
        }
        SpawnResult::Admitted(spawned) => {
            retirement.child = Some(spawned.child);
            retirement.png_phase = png;
            if png {
                retirement.report.gs_spawned = true;
            } else {
                retirement.report.tex_spawned = true;
            }
        }
    }
    // An admitted child remains owned even if synchronous native preparation
    // crossed a target. Immediate real cleanup follows this original failure.
    check.run()
}
async fn wait(retirement: &mut Retirement, check: &Check<'_>) -> Result<(), Cause> {
    poll_fn(|cx| {
        check.run()?;
        retirement
            .directory
            .as_ref()
            .ok_or(Cause::Artifact)?
            .budget(retirement.limits)?;
        check.run()?;
        retirement.reap();
        if retirement.child.is_none() {
            if retirement.ownership_lost {
                return Poll::Ready(Err(launch(process::LaunchError::Stale)));
            }
            let exit = if retirement.png_phase {
                retirement.report.gs_exit
            } else {
                retirement.report.tex_exit
            }
            .ok_or(Cause::Artifact)?;
            return Poll::Ready(if matches!(exit, ChildExit::Exited(0)) {
                Ok(())
            } else {
                Err(Cause::Tool {
                    png: retirement.png_phase,
                    exit,
                })
            });
        }
        if let Poll::Ready(Err(error)) = retirement.registry.poll_child_signal(cx) {
            return Poll::Ready(Err(launch(error)));
        }
        retirement.arm(cx);
        Poll::Pending
    })
    .await
}
async fn failure(mut retirement: Retirement, cause: Cause) -> RenderFailure {
    retirement.report.stop_requested |= matches!(cause, Cause::Cancelled);
    retirement.report.deadline |= matches!(cause, Cause::Deadline);
    retirement.signal(if matches!(cause, Cause::Limit) {
        libc::SIGKILL
    } else {
        libc::SIGTERM
    });
    let started = Instant::now();
    let kill = started + retirement.limits.terminate_grace;
    let end = started + retirement.limits.cleanup_grace;
    let mut timer = Box::pin(tokio::time::sleep_until(kill));
    let result = poll_fn(|cx| {
        if let Poll::Ready(report) = retirement.poll(cx) {
            return Poll::Ready(Some(report));
        }
        let now = Instant::now();
        if now >= kill && !retirement.report.kill_attempted {
            retirement.signal(libc::SIGKILL);
        }
        if now >= end {
            return Poll::Ready(None);
        }
        timer
            .as_mut()
            .reset(if now < kill { kill.min(end) } else { end });
        if timer.as_mut().poll(cx).is_ready() {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    })
    .await;
    match result {
        Some(report) => RenderFailure {
            cause,
            report,
            retirement: None,
        },
        None => {
            retirement.report.undrained = true;
            RenderFailure {
                cause,
                report: retirement.report.clone(),
                retirement: Some(retirement),
            }
        }
    }
}
/// The caller must keep this future through cancellation to real retirement.
/// Provider/tool failure never returns an empty/stale artifact as success.
#[expect(
    clippy::result_large_err,
    reason = "Failure returns original child and directory ownership without allocating during cleanup transfer"
)]
pub async fn render(
    request: RenderRequest,
    settings: Arc<Settings>,
    clock: Arc<dyn RuntimeClock>,
    bounds: Bounds,
    stop: Stop,
) -> Result<Artifact, RenderFailure> {
    let fail = |cause| RenderFailure {
        cause,
        report: Report::default(),
        retirement: None,
    };
    settings.validate().map_err(fail)?;
    let check = Check {
        clock: clock.as_ref(),
        bounds,
        stop: &stop,
        last: Cell::new(None),
    };
    check.run().map_err(fail)?;
    let tex = template::build(&request, settings.limits).map_err(fail)?;
    let png = request.png;
    let RenderRequest {
        uri,
        fields,
        fingerprint,
        ..
    } = request;
    drop(fields);
    drop(fingerprint);
    let mut retirement = Retirement::new(settings.limits).map_err(fail)?;
    let prepared = (|| {
        check.run()?;
        let result = Directory::create(&settings.temp_root, &mut retirement.directory);
        retirement.report.directory_path = retirement
            .directory
            .as_ref()
            .map(|d| d.path().to_path_buf());
        result?;
        check.run()?;
        let directory = retirement.directory.as_ref().ok_or(Cause::Artifact)?;
        directory.write(tex.as_bytes(), || check.run())?;
        directory.write_uri(uri.as_bytes(), || check.run())
    })();
    drop(tex);
    drop(uri);
    if let Err(cause) = prepared {
        return Err(failure(retirement, cause).await);
    }
    if let Err(cause) = spawn(&mut retirement, &settings, false, &check) {
        return Err(failure(retirement, cause).await);
    }
    if let Err(cause) = wait(&mut retirement, &check).await {
        return Err(failure(retirement, cause).await);
    }
    if png {
        let pdf = retirement
            .directory
            .as_ref()
            .ok_or(Cause::Artifact)
            .and_then(|dir| dir.artifact(false, settings.limits.output_bytes, || check.run()));
        match pdf {
            Ok(bytes) => drop(bytes),
            Err(cause) => return Err(failure(retirement, cause).await),
        }
        if let Err(cause) = spawn(&mut retirement, &settings, true, &check) {
            return Err(failure(retirement, cause).await);
        }
        if let Err(cause) = wait(&mut retirement, &check).await {
            return Err(failure(retirement, cause).await);
        }
    }
    let output = retirement
        .directory
        .as_ref()
        .ok_or(Cause::Artifact)
        .and_then(|dir| dir.artifact(png, settings.limits.output_bytes, || check.run()));
    let bytes = match output {
        Ok(bytes) => bytes,
        Err(cause) => return Err(failure(retirement, cause).await),
    };
    retirement.report.output_bytes = bytes.len();
    let cleaned = poll_fn(|cx| match retirement.poll(cx) {
        Poll::Ready(report) => Poll::Ready(Ok(report)),
        Poll::Pending => {
            if let Err(cause) = check.run() {
                Poll::Ready(Err(cause))
            } else {
                Poll::Pending
            }
        }
    })
    .await;
    match cleaned {
        Ok(report) if report.cleanup_error.is_none() => match check.run() {
            Ok(()) => Ok(Artifact { bytes, report }),
            Err(cause) => Err(RenderFailure {
                cause,
                report,
                retirement: None,
            }),
        },
        Ok(report) => Err(RenderFailure {
            cause: Cause::Io(std::io::Error::other("renderer cleanup failed")),
            report,
            retirement: None,
        }),
        Err(cause) => Err(failure(retirement, cause).await),
    }
}
