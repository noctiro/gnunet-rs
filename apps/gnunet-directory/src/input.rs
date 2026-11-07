use crate::{
    Failure, display,
    run::{Facts, Guard},
};
use gnunet_fs::directory::{self, Parser, Segment, Status};
use gnunet_fs_codec::Inflate;
use std::{
    fmt,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Eq, PartialEq)]
struct Snapshot {
    device: u64,
    inode: u64,
    len: u64,
    mode: u32,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
impl Snapshot {
    fn new(m: &Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            len: m.len(),
            mode: m.mode(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        }
    }
}
struct Input {
    file: File,
    path: PathBuf,
    original: Snapshot,
    read: u64,
}
impl Input {
    fn open(path: &Path) -> Result<Self, Failure> {
        // Normal public-file symlinks may be followed. The resulting original
        // regular inode/path snapshot is then checked throughout this read.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        let held = file.metadata()?;
        let named = fs::metadata(path)?;
        if !held.is_file() || !named.is_file() || Snapshot::new(&held) != Snapshot::new(&named) {
            return Err("directory input is not the original regular file".into());
        }
        Ok(Self {
            file,
            path: path.to_owned(),
            original: Snapshot::new(&held),
            read: 0,
        })
    }
    fn verify(&self) -> Result<(), Failure> {
        let held = self.file.metadata()?;
        let named = fs::metadata(&self.path)?;
        if !held.is_file()
            || !named.is_file()
            || Snapshot::new(&held) != self.original
            || Snapshot::new(&named) != self.original
        {
            return Err("original directory input changed during inspection".into());
        }
        Ok(())
    }
    async fn block(
        &mut self,
        buffer: &mut [u8],
        guard: &mut Guard,
        facts: &mut Facts,
    ) -> Result<usize, Failure> {
        guard.check().await?;
        self.verify()?;
        guard.check().await?;
        let remaining = self
            .original
            .len
            .checked_sub(self.read)
            .ok_or("directory input extent overflow")?;
        if remaining == 0 {
            return Ok(0);
        }
        let want = usize::try_from(remaining.min(buffer.len() as u64))?;
        loop {
            guard.check().await?;
            match self.file.read(&mut buffer[..want]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "original directory file ended before its observed extent",
                    )
                    .into());
                }
                Ok(n) => {
                    self.read += n as u64;
                    facts.bytes_read += n as u128;
                    guard.check().await?;
                    self.verify()?;
                    guard.turn().await?;
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => tokio::task::yield_now().await,
                Err(e) => return Err(e.into()),
            }
        }
    }
    async fn finish(&mut self, guard: &mut Guard, facts: &mut Facts) -> Result<(), Failure> {
        guard.check().await?;
        if self.read != self.original.len {
            return Err("parser completed without reading the original extent".into());
        }
        self.verify()?;
        let mut extra = [0u8; 1];
        loop {
            guard.check().await?;
            match self.file.read(&mut extra) {
                Ok(0) => break,
                Ok(n) => {
                    facts.bytes_read += n as u128;
                    return Err("directory file grew beyond its original extent".into());
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => tokio::task::yield_now().await,
                Err(e) => return Err(e.into()),
            }
        }
        guard.check().await?;
        self.verify()?;
        tokio::task::yield_now().await;
        guard.check().await
    }
}
#[derive(Debug)]
struct FileFailure {
    path: PathBuf,
    read: u64,
    parsed: u64,
    cause: Failure,
}
impl fmt::Display for FileFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "directory {:?}: read={} parsed={}: {}",
            self.path, self.read, self.parsed, self.cause
        )
    }
}
impl std::error::Error for FileFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
    }
}
pub(super) async fn inspect(
    path: &Path,
    limits: directory::Limits,
    carry: &mut Vec<u8>,
    plain: &mut Vec<u8>,
    guard: &mut Guard,
    out: &mut impl Write,
    facts: &mut Facts,
) -> Result<(), Failure> {
    guard.check().await?;
    let mut input = Input::open(path).map_err(|cause| {
        Box::new(FileFailure {
            path: path.to_owned(),
            read: 0,
            parsed: 0,
            cause,
        }) as Failure
    })?;
    facts.files_opened += 1;
    guard.check().await?;
    // A complete record cannot exceed this original file's whole extent.
    // Keep at least the header, cap at the selected record policy, and reuse
    // any longer arena from a previous file without shrinking or resetting it.
    let extent = usize::try_from(input.original.len).unwrap_or(usize::MAX);
    let required = limits.max_record_bytes.min(extent.max(12));
    if carry.len() < required {
        let additional = required - carry.len();
        carry.try_reserve_exact(additional)?;
        carry.resize(required, 0);
    }
    let mut parser = Parser::new(carry, limits, directory::Policy::default());
    let mut inflater = Inflate::new();
    let answer: Result<(), Failure> = async {
        guard.check().await?;
        display::begin(out, path, guard, facts).await?;
        let mut block = [0u8; 32768];
        loop {
            let length = input.block(&mut block, guard, facts).await?;
            let mut at = 0;
            loop {
                guard.check().await?;
                let result = parser.feed(
                    Segment {
                        base: parser.offset(),
                        bytes: &block[at..length],
                        final_extent: Some(input.original.len)
                    },
                    plain,
                    &mut inflater
                );
                let progress = match result {
                    Ok(p) => p,
                    Err(e) => {
                        facts.bytes_parsed += e.consumed as u128;
                        return Err(e.into());
                    },
                };
                at += progress.consumed;
                facts.bytes_parsed += progress.consumed as u128;
                // Account actual parser progress before yielding, including a
                // complete final event; no output precedes the next stop gate.
                tokio::task::yield_now().await;
                guard.check().await?;
                match progress.status {
                    Status::Event(event) => display::event(out, event, guard, facts).await?,
                    Status::NeedMore { .. } => {
                        if at != length || length == 0 {
                            return Err("directory parser requested missing bytes without an original input continuation".into());
                        }
                        break;
                    },
                    Status::NeedPlain { required } => {
                        if required > limits.metadata.max_plain_bytes {
                            return Err("directory metadata plaintext resource bound exceeded".into());
                        }
                        if required > plain.len() {
                            let additional = required - plain.len();
                            plain.try_reserve_exact(additional)?;
                            plain.resize(required, 0);
                        } else {
                            return Err("directory parser requested an already available plaintext capacity".into());
                        }
                    },
                    Status::NeedRecord { required } => return Err(format!("directory record requires {required} bytes beyond the selected carry resource profile").into()),
                    Status::Partial(summary) => return Err(format!("directory is partial: extent={} entries={} root={} recovered={}", summary.end, summary.entries, summary.root_seen, summary.recovered).into()),
                    Status::Complete(summary) => {
                        if at != length || summary.end != input.original.len {
                            return Err("directory completion did not consume the original file extent".into());
                        }
                        input.finish(guard, facts).await?;
                        facts.files_validated += 1;
                        return display::complete(out, summary, guard, facts).await;
                    },
                }
                guard.turn().await?;
                // Even when the last event consumed the last byte, feed an empty
                // original segment again to establish Complete or Truncated.
            }
        }
    }.await;
    answer.map_err(|cause| {
        Box::new(FileFailure {
            path: path.to_owned(),
            read: input.read,
            parsed: parser.offset(),
            cause,
        }) as Failure
    })
}
