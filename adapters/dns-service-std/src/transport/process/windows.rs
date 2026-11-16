//! Direct helper creation with IOCP pipes and the original process object.
use super::{Spawned, Stop};
use crate::transport::HelperOptions;
use gnunet_native::process::{Process, ProcessWait};
use gnunet_service_runtime::{
    pipe::{InputWriter, OutputReader},
    process::{Console, EnvironmentSnapshot, LaunchLimits, NativeCommand, Stdio},
};
use std::{
    ffi::OsString,
    future::Future,
    io,
    os::windows::{io::AsHandle, process::ExitStatusExt},
    pin::Pin,
    process::ExitStatus,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
pub(in crate::transport) type Input = InputWriter;
pub(in crate::transport) type Output = OutputReader;
pub(in crate::transport) struct Child {
    native: Process,
    notification: Option<ProcessWait>,
    retry: Pin<Box<Sleep>>,
}
pub(in crate::transport) fn spawn(options: &HelperOptions) -> io::Result<Spawned> {
    let environment = EnvironmentSnapshot::system()?;
    let arguments: [OsString; 6] = [
        options.interface.clone().into(),
        options.ipv6.to_string().into(),
        options.prefix.to_string().into(),
        options.ipv4.to_string().into(),
        options.mask.to_string().into(),
        if options.skip_routing { "1" } else { "0" }.into(),
    ];
    // The privileged helper inherits only the essential Windows loader context;
    // it receives neither supervisor bootstrap handles nor ambient search paths.
    let mut values = Vec::new();
    for name in ["SystemRoot", "WINDIR"] {
        if let Some(value) = environment.variable_os(name.as_ref())? {
            values.try_reserve(1).map_err(io::Error::other)?;
            values.push((OsString::from(name), value.to_owned()));
        }
    }
    let (input, child_input) = gnunet_native::pipe::input_pair()?;
    let (output, child_output) = gnunet_native::pipe::output_pair()?;
    // All fallible pipe registration precedes process creation. Only synchronous
    // child ends enter the native per-launch inheritance allowlist.
    let stdin = InputWriter::new(input)?;
    let stdout = OutputReader::new(output)?;
    let directory = options
        .program
        .parent()
        .ok_or(io::ErrorKind::InvalidInput)?;
    let native = NativeCommand {
        executable: &options.program,
        argv0: options.program.as_os_str(),
        arguments: &arguments,
        environment: &values,
        directory,
        stdio: [
            Stdio::Handle(child_input.as_handle()),
            Stdio::Handle(child_output.as_handle()),
            Stdio::Inherit,
        ],
        exported_handles: &[],
        console: Console::Inherit,
    }
    .launch(LaunchLimits::default())?;
    // Failure after creation retains this exact child for explicit retirement.
    let (notification, startup_error) = match ProcessWait::new(&native) {
        Ok(wait) => (Some(wait), None),
        Err(error) => (None, Some(error)),
    };
    Ok(Spawned {
        child: Child {
            native,
            notification,
            retry: Box::pin(tokio::time::sleep(Duration::from_millis(50))),
        },
        stdin: Some(stdin),
        stdout: Some(stdout),
        startup_error,
    })
}
impl Child {
    pub fn id(&self) -> Option<u32> {
        Some(self.native.id())
    }
    pub fn stop(&self, stop: Stop) -> io::Result<()> {
        match stop {
            // Original stdin EOF and stdout closure are the graceful request.
            Stop::Graceful => Ok(()),
            Stop::Force => match self.native.try_wait()? {
                Some(_) => Ok(()),
                None => self.native.terminate(1),
            },
        }
    }
    pub fn poll_exit(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<ExitStatus>> {
        if let Some(wait) = &mut self.notification {
            return wait
                .poll_exit(cx)
                .map(|result| result.map(ExitStatus::from_raw));
        }
        // A failed notification registration does not lose the process handle
        // or manufacture an exit. Poll that same object on a finite retry timer.
        if let Some(code) = self.native.try_wait()? {
            return Poll::Ready(Ok(ExitStatus::from_raw(code)));
        }
        if self.retry.as_mut().poll(cx).is_ready() {
            self.retry
                .as_mut()
                .reset(Instant::now() + Duration::from_millis(50));
            let _armed = self.retry.as_mut().poll(cx);
        }
        Poll::Pending
    }
}
