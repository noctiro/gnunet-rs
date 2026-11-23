//! Original Windows process and qualified native pipe pairs.
use super::BOOTSTRAP;
use gnunet_native::{
    pipe::{InputWriter, input_pair, output_pair},
    process::{Process, ProcessWait},
};
use gnunet_service_runtime::{
    pipe::OutputReader,
    process::{Console, EnvironmentSnapshot, LaunchLimits, NativeCommand, Stdio},
};
use std::{
    future::poll_fn,
    io,
    os::windows::{io::AsHandle, process::ExitStatusExt},
    path::Path,
    process::ExitStatus,
    time::Duration,
};

pub(super) struct Child {
    process: Process,
    waiter: Option<ProcessWait>,
}
pub(super) type Input = InputWriter;

fn launch(path: &Path, stdio: [Stdio<'_>; 3]) -> io::Result<Child> {
    let environment = EnvironmentSnapshot::system()?;
    let mut values = environment.values().to_vec();
    values.retain(|(key, _)| {
        let key = gnunet_native::os_bytes::encode(key);
        !BOOTSTRAP
            .iter()
            .any(|name| key.eq_ignore_ascii_case(name.as_bytes()))
    });
    let process = NativeCommand {
        executable: path,
        argv0: path.as_os_str(),
        arguments: &[],
        environment: &values,
        directory: environment.current_dir(),
        stdio,
        exported_handles: &[],
        console: Console::Inherit,
    }
    .launch(LaunchLimits::default())?;
    let waiter = ProcessWait::new(&process).ok();
    Ok(Child { process, waiter })
}

pub(super) fn record(path: &Path) -> io::Result<(Child, Option<OutputReader>)> {
    let (read, write) = output_pair()?;
    let output = OutputReader::new(read)?;
    let child = launch(
        path,
        [
            Stdio::Null,
            Stdio::Handle(write.as_handle()),
            Stdio::Inherit,
        ],
    )?;
    Ok((child, Some(output)))
}

pub(super) fn playback(path: &Path) -> io::Result<(Child, Option<Input>)> {
    let (write, read) = input_pair()?;
    let input = InputWriter::new(write);
    let child = launch(
        path,
        [Stdio::Handle(read.as_handle()), Stdio::Null, Stdio::Inherit],
    )?;
    Ok((child, Some(input)))
}

impl Child {
    pub(super) fn terminate(&mut self) -> io::Result<()> {
        if self.process.try_wait()?.is_some() {
            return Ok(());
        }
        if let Err(error) = self.process.terminate(1)
            && self.process.try_wait()?.is_none()
        {
            return Err(error);
        }
        Ok(())
    }

    pub(super) async fn wait(&mut self) -> io::Result<ExitStatus> {
        if let Some(waiter) = self.waiter.as_mut() {
            return poll_fn(|cx| waiter.poll_exit(cx))
                .await
                .map(ExitStatus::from_raw);
        }
        // A notification-registration failure retains the same process object.
        loop {
            if let Some(code) = self.process.try_wait()? {
                return Ok(ExitStatus::from_raw(code));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if !matches!(self.process.try_wait(), Ok(Some(_))) {
            let _requested = self.process.terminate(1);
        }
    }
}

pub(super) async fn write(input: &mut Input, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        input.begin(&bytes[..bytes.len().min(16 * 1024)])?;
        let completed = poll_fn(|cx| input.poll_complete(cx)).await?;
        if completed == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        bytes = &bytes[completed..];
    }
    Ok(())
}

pub(super) fn cancel(input: &mut Option<Input>) -> io::Result<()> {
    if let Some(input) = input {
        input.request_cancel()?;
    }
    Ok(())
}

pub(super) async fn settle(input: Option<Input>) -> io::Result<()> {
    if let Some(mut input) = input
        && input.pending()
        && let Err(error) = poll_fn(|cx| input.poll_complete(cx)).await
        && error.raw_os_error() != Some(995)
        && error.kind() != io::ErrorKind::BrokenPipe
    {
        return Err(error);
    }
    Ok(())
}
