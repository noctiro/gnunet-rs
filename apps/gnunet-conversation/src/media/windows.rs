//! Native helper process handles and completion-owned private media pipes.
use super::*;
use gnunet_service_runtime::{
    pipe::OutputReader,
    process::{Console, EnvironmentSnapshot, LaunchLimits, NativeCommand, Stdio},
};
use std::{io, os::windows::io::AsHandle};
use tokio::io::{AsyncRead, ReadBuf};

pub(super) fn stop_child(
    registry: &mut ChildRegistry,
    child: &OriginalChild,
    force: bool,
) -> Result<(), Failure> {
    registry.terminate(child, if force { 137 } else { 1 })?;
    Ok(())
}
pub(super) fn cancelled(error: &io::Error) -> bool {
    error.raw_os_error() == Some(995)
}
pub(super) struct Record(Option<OutputReader>);
impl Record {
    pub fn read(&mut self, cx: &mut Context<'_>, bytes: &mut [u8]) -> Poll<io::Result<usize>> {
        let Some(reader) = self.0.as_mut() else {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        };
        let mut buffer = ReadBuf::new(bytes);
        match Pin::new(reader).poll_read(cx, &mut buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buffer.filled().len())),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe => {
                Poll::Ready(Ok(0))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        }
    }
    pub fn close(&mut self) -> Option<io::Error> {
        self.0 = None;
        None
    }
}
pub(super) struct PlaybackPipe {
    writer: Option<gnunet_native::pipe::InputWriter>,
    closing: bool,
}
impl PlaybackPipe {
    pub fn write(&mut self, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        if self.closing {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        }
        let Some(writer) = self.writer.as_mut() else {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        };
        if !writer.pending() {
            writer.begin(bytes)?;
        }
        writer.poll_complete(cx)
    }
    pub fn close(&mut self) -> Option<io::Error> {
        self.closing = true;
        let writer = self.writer.as_mut()?;
        let error = writer.request_cancel().err();
        if !writer.pending() {
            self.writer = None;
        }
        error
    }
    pub fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let Some(writer) = self.writer.as_mut() else {
            return Poll::Ready(Ok(0));
        };
        let Poll::Ready(result) = writer.poll_complete(cx) else {
            return Poll::Pending;
        };
        self.writer = None;
        Poll::Ready(result)
    }
    pub fn closed(&self) -> bool {
        self.writer.is_none()
    }
}
impl Media {
    pub(super) fn launch(
        &mut self,
        bounds: Bounds,
        _c: &gnunet_config::Configuration,
        s: &Settings,
    ) -> Result<(), Failure> {
        let (rec_read, rec_write) = gnunet_native::pipe::output_pair()?;
        let (play_write, play_read) = gnunet_native::pipe::input_pair()?;
        self.record = Some(Record(Some(OutputReader::new(rec_read)?)));
        self.playback = Some(PlaybackPipe {
            writer: Some(gnunet_native::pipe::InputWriter::new(play_write)),
            closing: false,
        });
        let environment = EnvironmentSnapshot::system()?;
        const BOOTSTRAP: &[&[u8]] = &[
            b"GNUNET_OS_CONTROL_PIPE",
            b"LISTEN_PID",
            b"LISTEN_FDS",
            b"LISTEN_FDNAMES",
            b"GNUNET_RS_ACTIVATION_HANDLE",
            b"GNUNET_RS_DETACH_PIPE",
        ];
        let values: Vec<_> = environment
            .values()
            .iter()
            .filter(|(key, _)| {
                let key = gnunet_native::os_bytes::encode(key);
                !BOOTSTRAP.iter().any(|name| key.eq_ignore_ascii_case(name))
            })
            .cloned()
            .collect();
        let clock = self.clock.clone();
        let spawn = |path: &std::path::Path,
                     stdio,
                     registry: &mut ChildRegistry|
         -> Result<OriginalChild, Failure> {
            bounds.check(clock.as_ref())?;
            Ok(registry.spawn(
                NativeCommand {
                    executable: path,
                    argv0: path.as_os_str(),
                    arguments: &[],
                    environment: &values,
                    directory: environment.current_dir(),
                    stdio,
                    exported_handles: &[],
                    console: Console::Inherit,
                },
                LaunchLimits {
                    arguments: 0,
                    handles: 3,
                    command_units: 16384,
                    ..Default::default()
                },
            )?)
        };
        let child = spawn(
            &s.record,
            [
                Stdio::Null,
                Stdio::Handle(rec_write.as_handle()),
                Stdio::Inherit,
            ],
            &mut self.registry,
        )?;
        self.report
            .as_mut()
            .ok_or("media report missing after native recorder admission")?
            .record_child = Some(child);
        let child = spawn(
            &s.playback,
            [
                Stdio::Handle(play_read.as_handle()),
                Stdio::Null,
                Stdio::Inherit,
            ],
            &mut self.registry,
        )?;
        self.report
            .as_mut()
            .ok_or("media report missing after native playback admission")?
            .playback_child = Some(child);
        Ok(())
    }
}
