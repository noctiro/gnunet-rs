//! Service Control Manager entry to the shared foreground node driver.
use crate::{Result, options::Options, reactor, run_node};
use std::{
    ffi::c_void,
    fmt::Display,
    future::Future,
    io::{self, Write},
    panic::catch_unwind,
    pin::pin,
    ptr::{self, NonNull},
    sync::atomic::{AtomicBool, Ordering},
    task::Poll,
    time::Duration,
};
use tokio::sync::Notify;
use windows_sys::{
    Win32::{
        Foundation::{ERROR_CALL_NOT_IMPLEMENTED, ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR},
        System::{
            EventLog::{
                DeregisterEventSource, EVENTLOG_ERROR_TYPE, RegisterEventSourceW, ReportEventW,
            },
            Services::{
                RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
                SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
                SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOP_PENDING,
                SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
                StartServiceCtrlDispatcherW,
            },
        },
    },
    core::{PCWSTR, PWSTR, w},
};

const NAME: PCWSTR = w!("gnunet-node");
const NODE_FAILED: u32 = 1;
// The SCM dispatches one service in this dedicated process. Its control
// callback can outlive the node driver and borrows only static state.
static STOP: Notify = Notify::const_new();
static FAILED: AtomicBool = AtomicBool::new(false);

#[expect(
    unsafe_code,
    reason = "Register the exact ServiceMain ABI in the SCM table"
)]
pub(super) fn dispatch() -> Result<()> {
    let entries = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: NAME.cast_mut(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    // SAFETY: the input table is sentinel-terminated and lives through this
    // call. The native service name is a static terminated wide string.
    if unsafe { StartServiceCtrlDispatcherW(entries.as_ptr()) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    if FAILED.load(Ordering::Acquire) {
        return Err(io::Error::other("Windows service failed").into());
    }
    Ok(())
}

extern "system" fn service_main(argc: u32, _argv: *mut PWSTR) {
    let status = match Status::register() {
        Ok(status) => status,
        Err(error) => {
            record_failure(error);
            return;
        }
    };
    let outcome = catch_unwind(|| serve(&status, argc))
        .unwrap_or_else(|_| Err(io::Error::other("Windows service panicked").into()));
    let code = match outcome {
        Ok(()) => 0,
        Err(error) => {
            record_failure(error);
            NODE_FAILED
        }
    };
    if let Err(error) = status.finish(code) {
        record_failure(error);
    }
}

fn serve(status: &Status, argc: u32) -> Result<()> {
    // The first SCM argument is the service name. Node settings come from
    // the installed ImagePath, a single authority for the process inputs.
    if argc != 1 {
        return Err("configure node options in the installed ImagePath".into());
    }
    let options = Options::parse(std::env::args_os().skip(2))?;
    let startup = options.timing().startup();
    let drain = options.timing().transport_drain();
    status.publish(State::Starting(startup))?;
    let mut stop = pin!(STOP.notified());
    reactor()?.block_on(run_node(
        options,
        |cx| match stop.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => Poll::Ready(status.publish(State::Stopping(drain))),
        },
        |_| status.publish(State::Running),
    ))?;
    Ok(())
}

extern "system" fn control(code: u32, _event: u32, _data: *mut c_void, _ctx: *mut c_void) -> u32 {
    match code {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            // A single permit preserves requests received before the node
            // polls. The reactor publishes STOP_PENDING before it drains.
            STOP.notify_one();
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

enum State {
    Starting(Duration),
    Running,
    Stopping(Duration),
    Stopped(u32),
}

// The service status handle belongs to the SCM. The service thread alone
// publishes transitions, including its single final STOPPED notification.
struct Status(NonNull<c_void>);

impl Status {
    #[expect(
        unsafe_code,
        reason = "The dispatcher's registered control function uses static context"
    )]
    fn register() -> io::Result<Self> {
        // SAFETY: the ABI matches HandlerEx and its optional context is unused.
        let handle = unsafe { RegisterServiceCtrlHandlerExW(NAME, Some(control), ptr::null()) };
        NonNull::new(handle)
            .map(Self)
            .ok_or_else(io::Error::last_os_error)
    }

    #[expect(
        unsafe_code,
        reason = "An SCM handle and a fully initialized native status are borrowed by SetServiceStatus"
    )]
    fn publish(&self, state: State) -> io::Result<()> {
        let (state, controls, wait, exit) = match state {
            State::Starting(wait) => (SERVICE_START_PENDING, 0, wait, 0),
            State::Running => (
                SERVICE_RUNNING,
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
                Duration::ZERO,
                0,
            ),
            State::Stopping(wait) => (SERVICE_STOP_PENDING, 0, wait, 0),
            State::Stopped(exit) => (SERVICE_STOPPED, 0, Duration::ZERO, exit),
        };
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: controls,
            dwWin32ExitCode: if exit == 0 {
                NO_ERROR
            } else {
                ERROR_SERVICE_SPECIFIC_ERROR
            },
            dwServiceSpecificExitCode: exit,
            dwCheckPoint: u32::from(!wait.is_zero()),
            dwWaitHint: u32::try_from(wait.as_millis()).unwrap_or(u32::MAX),
        };
        // SAFETY: status is fully initialized and borrowed until the call returns.
        if unsafe { SetServiceStatus(self.0.as_ptr(), &status) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn finish(self, code: u32) -> io::Result<()> {
        self.publish(State::Stopped(code))
    }
}

#[expect(
    unsafe_code,
    reason = "Report one bounded string to an owned local event-source handle"
)]
fn record_failure(error: impl Display) {
    FAILED.store(true, Ordering::Release);
    // SAFETY: NAME is static and NUL terminated, and null selects the local log.
    let source = unsafe { RegisterEventSourceW(ptr::null(), NAME) };
    if !source.is_null() {
        let message = error.to_string();
        let end = message.floor_char_boundary(message.len().min(30_000));
        let wide: Vec<_> = message[..end]
            .encode_utf16()
            .map(|unit| if unit == 0 { 0xfffd } else { unit })
            .chain([0])
            .collect();
        let strings = [wide.as_ptr()];
        // SAFETY: the one string is bounded, terminated and live. No SID or
        // raw attachment is supplied. The event source closes after the call.
        let written = unsafe {
            ReportEventW(
                source,
                EVENTLOG_ERROR_TYPE,
                0,
                NODE_FAILED,
                ptr::null_mut(),
                1,
                0,
                strings.as_ptr(),
                ptr::null(),
            )
        };
        // SAFETY: source is the original handle returned by RegisterEventSourceW.
        let _closed = unsafe { DeregisterEventSource(source) };
        if written != 0 {
            return;
        }
    }
    let _reported = writeln!(io::stderr().lock(), "gnunet-node: {error}");
}
