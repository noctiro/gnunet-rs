//! Unique native file and bounded request execution; no protocol state lives here.
use super::{Closed, Direction};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
    sync::mpsc::Receiver,
    time::Instant,
};
use tokio::sync::oneshot;
use zeroize::Zeroizing;
pub(super) enum Resource {
    File(File),
    Text(gnunet_native::stdio::Output),
    TextInput(gnunet_native::stdio::TextInput),
}
impl Resource {
    pub(super) fn close(self) -> io::Result<()> {
        match self {
            Self::File(file) => gnunet_native::filesystem::close(file),
            Self::Text(output) => output.close(),
            Self::TextInput(input) => input.close(),
        }
    }
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::File(file) => file.read(bytes),
            Self::TextInput(input) => input.read(bytes),
            Self::Text(_) => Err(io::ErrorKind::InvalidInput.into()),
        }
    }
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::File(file) => file.write(bytes),
            Self::Text(output) => output.write(bytes),
            Self::TextInput(_) => Err(io::ErrorKind::InvalidInput.into()),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::File(file) => file.flush(),
            Self::Text(output) => output.flush(),
            Self::TextInput(_) => Err(io::ErrorKind::InvalidInput.into()),
        }
    }
}
pub(super) struct Work {
    pub buffer: Zeroizing<Vec<u8>>,
    pub requested: usize,
    pub reply: oneshot::Sender<Reply>,
}
pub(super) struct Reply {
    pub buffer: Zeroizing<Vec<u8>>,
    pub result: io::Result<usize>,
}
pub(super) fn run(
    mut file: Resource,
    direction: Direction,
    requests: Receiver<Work>,
    closed: oneshot::Sender<Closed>,
) {
    while let Ok(mut work) = requests.recv() {
        let mut result = match direction {
            Direction::Input => file.read(&mut work.buffer[..work.requested]),
            Direction::Output => file.write(&work.buffer[..work.requested]),
        };
        if result.as_ref().is_ok_and(|count| *count > work.requested) {
            result = Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native binary I/O count exceeded its request",
            ));
        }
        let _original = work.reply.send(Reply {
            buffer: work.buffer,
            result,
        });
    }
    let flush = if direction == Direction::Output {
        file.flush().err()
    } else {
        None
    };
    let close = file.close().err();
    let _original = closed.send(Closed {
        flush,
        close,
        observed_at: Instant::now(),
        transfer_lost: false,
    });
}
pub(super) fn output_file(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(windows)]
    {
        match gnunet_native::paths::create_private_file(path) {
            Ok(file) => Ok(file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                OpenOptions::new().write(true).truncate(true).open(path)
            }
            Err(error) => Err(error),
        }
    }
}
