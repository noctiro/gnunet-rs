//! An original helper process with one owned asynchronous pipe.
use super::BOOTSTRAP;
use std::{
    io,
    path::Path,
    process::{ExitStatus, Stdio},
};
use tokio::{
    io::AsyncWriteExt,
    process::{Child as NativeChild, ChildStdin, ChildStdout, Command},
};

pub(super) struct Child(NativeChild);
pub(super) type Input = ChildStdin;

fn spawn(path: &Path, input: Stdio, output: Stdio) -> io::Result<NativeChild> {
    let mut command = Command::new(path);
    command
        .stdin(input)
        .stdout(output)
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    for name in BOOTSTRAP {
        command.env_remove(name);
    }
    command.spawn()
}

pub(super) fn record(path: &Path) -> io::Result<(Child, Option<ChildStdout>)> {
    let mut original = spawn(path, Stdio::null(), Stdio::piped())?;
    let output = original.stdout.take();
    Ok((Child(original), output))
}

pub(super) fn playback(path: &Path) -> io::Result<(Child, Option<Input>)> {
    let mut original = spawn(path, Stdio::piped(), Stdio::null())?;
    let input = original.stdin.take();
    Ok((Child(original), input))
}

impl Child {
    pub(super) fn terminate(&mut self) -> io::Result<()> {
        self.0.start_kill()
    }

    pub(super) async fn wait(&mut self) -> io::Result<ExitStatus> {
        self.0.wait().await
    }
}

pub(super) async fn write(input: &mut Input, bytes: &[u8]) -> io::Result<()> {
    input.write_all(bytes).await
}

pub(super) fn cancel(input: &mut Option<Input>) -> io::Result<()> {
    *input = None;
    Ok(())
}

pub(super) async fn settle(_input: Option<Input>) -> io::Result<()> {
    Ok(())
}
