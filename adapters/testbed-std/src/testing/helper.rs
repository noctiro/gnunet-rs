//! Process and pipe ownership for one enrolled helper.
use super::RunError;
use gnunet_wire::{
    HEADER_LEN, MessageHeader,
    testing::{BarrierKey, FromHelper, ToHelper},
};
use std::{
    io,
    process::{Command, Stdio},
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, ChildStdout},
    sync::{mpsc, watch},
};

const BARRIER_FRAME_SIZE: usize = HEADER_LEN + size_of::<BarrierKey>();
const FINISHED_FRAME_SIZE: usize = HEADER_LEN + size_of::<i32>();

pub(super) struct Process {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
}

enum ProtocolExit {
    Reported,
    Cancelled,
}

pub(super) struct Exit {
    index: usize,
    protocol: io::Result<()>,
    retirement: io::Result<()>,
}

impl Exit {
    pub(super) fn complete(self) -> Result<(), RunError> {
        let index = self.index;
        match (self.protocol, self.retirement) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(source), Ok(())) | (Ok(()), Err(source)) => {
                Err(RunError::Helper { index, source })
            }
            (Err(protocol), Err(retirement)) => Err(RunError::Cleanup {
                failure: Box::new(RunError::Helper {
                    index,
                    source: protocol,
                }),
                source: retirement,
            }),
        }
    }

    pub(super) fn retirement(self) -> Result<(), RunError> {
        self.retirement.map_err(|source| RunError::Helper {
            index: self.index,
            source,
        })
    }
}

impl Process {
    pub(super) fn start(command: Command) -> io::Result<Self> {
        let mut child = tokio::process::Command::from(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("helper stdin unavailable"))?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("helper stdout unavailable"))?;
        Ok(Self {
            child,
            input,
            output,
        })
    }

    pub(super) async fn run(
        mut self,
        index: usize,
        init: Arc<[u8]>,
        replies: mpsc::Receiver<BarrierKey>,
        events: mpsc::Sender<(usize, FromHelper)>,
        mut cancelled: watch::Receiver<bool>,
    ) -> Exit {
        let protocol = tokio::select! {
            result = self.drive(index, init, replies, events) => result,
            _ = cancelled.changed() => Ok(ProtocolExit::Cancelled),
        };
        // Official GNUnet helpers use stdin EOF to shut down their interpreter.
        drop(self.input);
        let retirement = if matches!(protocol, Ok(ProtocolExit::Reported)) {
            tokio::select! {
                exited = self.child.wait() => exited.map(|_| ()),
                _ = cancelled.changed() => Self::retire(&mut self.child).await,
            }
        } else {
            Self::retire(&mut self.child).await
        };
        Exit {
            index,
            protocol: protocol.map(|_| ()),
            retirement,
        }
    }

    async fn drive(
        &mut self,
        index: usize,
        init: Arc<[u8]>,
        mut replies: mpsc::Receiver<BarrierKey>,
        events: mpsc::Sender<(usize, FromHelper)>,
    ) -> io::Result<ProtocolExit> {
        self.input.write_all(&init).await?;
        drop(init);
        let mut reader = Reader {
            bytes: [0; BARRIER_FRAME_SIZE],
            used: 0,
        };
        let mut wire = [0; BARRIER_FRAME_SIZE];
        let mut remaining = 0..0;
        loop {
            tokio::select! {
                message = reader.read(&mut self.output) => {
                    let message = message?;
                    events.send((index, message)).await.map_err(|_| driver_closed())?;
                    if matches!(message, FromHelper::Finished(_)) {
                        return Ok(ProtocolExit::Reported);
                    }
                }
                key = replies.recv(), if remaining.is_empty() => {
                    let Some(key) = key else { return Ok(ProtocolExit::Cancelled) };
                    let message = ToHelper::BarrierCrossable(key);
                    let size = message.encode(&mut wire).map_err(invalid_wire)?;
                    remaining = 0..size;
                }
                written = self.input.write(&wire[remaining.clone()]), if !remaining.is_empty() => {
                    let written = written?;
                    if written == 0 {
                        return Err(io::ErrorKind::WriteZero.into());
                    }
                    remaining.start += written;
                }
            }
        }
    }

    async fn retire(child: &mut Child) -> io::Result<()> {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        if let Err(error) = child.start_kill()
            && child.try_wait()?.is_none()
        {
            return Err(error);
        }
        child.wait().await.map(|_| ())
    }
}

struct Reader {
    bytes: [u8; BARRIER_FRAME_SIZE],
    used: usize,
}

impl Reader {
    // Partial input remains in `self` when select interrupts a read to send a reply.
    async fn read(&mut self, output: &mut (impl AsyncRead + Unpin)) -> io::Result<FromHelper> {
        self.fill(output, HEADER_LEN).await?;
        let size = MessageHeader::decode(&self.bytes)
            .map_err(invalid_wire)?
            .size();
        if !matches!(size, FINISHED_FRAME_SIZE | BARRIER_FRAME_SIZE) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid helper frame length",
            ));
        }
        self.fill(output, size).await?;
        let message = FromHelper::decode(&self.bytes[..size]).map_err(invalid_wire)?;
        self.used = 0;
        Ok(message)
    }

    async fn fill(&mut self, output: &mut (impl AsyncRead + Unpin), end: usize) -> io::Result<()> {
        while self.used < end {
            let count = output.read(&mut self.bytes[self.used..end]).await?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "helper closed its output pipe",
                ));
            }
            self.used += count;
        }
        Ok(())
    }
}

fn invalid_wire(error: gnunet_types::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn driver_closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "helper driver closed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::{Future, poll_fn},
        task::Poll,
    };

    #[tokio::test]
    async fn cancelling_partial_read_preserves_the_current_frame() -> io::Result<()> {
        let (mut output, mut pipe) = tokio::io::duplex(64);
        let first = FromHelper::BarrierReached([0xa5; size_of::<BarrierKey>()]);
        let second = FromHelper::Finished(1);
        let mut first_frame = [0; BARRIER_FRAME_SIZE];
        let mut second_frame = [0; FINISHED_FRAME_SIZE];
        let _size = first.encode(&mut first_frame).map_err(invalid_wire)?;
        let _size = second.encode(&mut second_frame).map_err(invalid_wire)?;
        output.write_all(&first_frame[..6]).await?;
        let mut reader = Reader {
            bytes: [0; BARRIER_FRAME_SIZE],
            used: 0,
        };
        poll_fn(|context| {
            let read = std::pin::pin!(reader.read(&mut pipe));
            Poll::Ready(match read.poll(context) {
                Poll::Pending => Ok(()),
                Poll::Ready(_) => Err(io::Error::other("partial frame completed")),
            })
        })
        .await?;
        output.write_all(&first_frame[6..]).await?;
        output.write_all(&second_frame).await?;
        if reader.read(&mut pipe).await? != first || reader.read(&mut pipe).await? != second {
            return Err(io::Error::other("cancelled read lost frame bytes"));
        }
        Ok(())
    }
}
