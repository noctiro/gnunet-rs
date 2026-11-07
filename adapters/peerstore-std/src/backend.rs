//! Bounded standard-library PEERSTORE WAL, exclusive actual writer fence and
//! durable original UID namespace. Any uncertain write latches the owner closed;
//! reopen replays complete checksummed transactions and retires only a torn tail.
use gnunet_peerstore::{Envelope, Filter, Record, Request, Row, Storage};
use gnunet_types::Error;
use sha2::{Digest, Sha512};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    ops::Range,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
const HEADER: usize = 80;
const ENTRY: usize = 16;
const DIGEST: usize = 64;
const MAGIC: &[u8; 8] = b"GPSW1\0\0\0";
/// Explicit live and durable-log limits; no silent quota eviction.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum active rows.
    pub records: usize,
    /// Maximum active complete record bytes.
    pub live_bytes: usize,
    /// Maximum physical WAL bytes, including metadata.
    pub wal_bytes: u64,
    /// Durable compaction threshold, capped by wal_bytes.
    pub checkpoint_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            records: 4096,
            live_bytes: 8 * 1024 * 1024,
            wal_bytes: 16 * 1024 * 1024,
            checkpoint_bytes: 12 * 1024 * 1024,
        }
    }
}
/// Original retained native failure, without replacing uncertain I/O by success.
#[derive(Debug)]
pub struct Failure {
    /// Actual storage stage.
    pub stage: &'static str,
    /// Protocol-level known/unknown classification.
    pub classification: Error,
    /// Original OS failure when present.
    pub io: Option<io::Error>,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PEERSTORE {}: {}", self.stage, self.classification)?;
        if let Some(e) = &self.io {
            write!(f, ": {e}")?
        }
        Ok(())
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.io.as_ref().map(|e| e as _)
    }
}
fn native(stage: &'static str, error: io::Error) -> Failure {
    Failure {
        stage,
        classification: Error::Storage,
        io: Some(error),
    }
}
fn protocol(stage: &'static str, error: Error) -> Failure {
    Failure {
        stage,
        classification: error,
        io: None,
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct Inode(u64, u64);
fn inode(file: &File) -> io::Result<Inode> {
    let m = file.metadata()?;
    if !m.is_file() && !m.is_dir() {
        return Err(io::Error::other("non-regular storage authority"));
    }
    Ok(Inode(m.dev(), m.ino()))
}
struct Stored {
    sequence: u64,
    peer: [u8; 32],
    expiry: u64,
    subsystem: Range<usize>,
    key: Range<usize>,
    value: usize,
    frame: Vec<u8>,
}
impl Stored {
    fn new(sequence: u64, frame: Vec<u8>) -> Result<Self, Error> {
        let Request::Store(e) = Request::decode(&frame)? else {
            return Err(Error::Storage);
        };
        let ss = e.record.subsystem.ok_or(Error::Storage)?;
        let key = e.record.key.ok_or(Error::Storage)?;
        if e.rid != 0 || e.reserved != 0 || e.options > 1 {
            return Err(Error::Storage);
        }
        let ss_size = usize::from(u16::from_be_bytes([frame[56], frame[57]]));
        let key_size = usize::from(u16::from_be_bytes([frame[52], frame[53]]));
        if ss_size != ss.len() + 1 || key_size != key.len() + 1 {
            return Err(Error::Storage);
        }
        let peer = e.record.peer;
        let expiry = e.record.expiry;
        let subsystem = 60..60 + ss.len();
        let key = 60 + ss_size..60 + ss_size + key.len();
        let value = 60 + ss_size + key_size;
        Ok(Self {
            sequence,
            peer,
            expiry,
            subsystem,
            key,
            value,
            frame,
        })
    }
    fn record(&self) -> Record<'_> {
        Record {
            peer: self.peer,
            expiry: self.expiry,
            subsystem: Some(&self.frame[self.subsystem.clone()]),
            key: Some(&self.frame[self.key.clone()]),
            value: &self.frame[self.value..],
        }
    }
    fn same_key(&self, r: Record<'_>) -> bool {
        let o = self.record();
        o.peer == r.peer && o.subsystem == r.subsystem && o.key == r.key
    }
}
/// One actual fenced WAL owner. It performs explicit synchronous disk effects;
/// a caller may place it behind its own bounded worker, never a hidden thread.
pub struct Wal {
    directory: PathBuf,
    path: PathBuf,
    dir: File,
    dir_id: Inode,
    lock: File,
    lock_id: Inode,
    file: File,
    file_id: Inode,
    rows: Vec<Stored>,
    last: u64,
    live_bytes: usize,
    bytes: u64,
    limits: Limits,
    poisoned: bool,
    failure: Option<Failure>,
    recovered_tail: u64,
}
fn header(last: u64) -> [u8; HEADER] {
    let mut b = [0; HEADER];
    b[..8].copy_from_slice(MAGIC);
    b[8..16].copy_from_slice(&last.to_be_bytes());
    let sum = Sha512::digest(&b[..16]);
    b[16..].copy_from_slice(&sum);
    b
}
fn entry(kind: u8, sequence: u64, len: usize) -> Result<[u8; ENTRY], Error> {
    let mut b = [0; ENTRY];
    b[..4].copy_from_slice(
        &u32::try_from(len)
            .map_err(|_| Error::TooLarge)?
            .to_be_bytes(),
    );
    b[4..12].copy_from_slice(&sequence.to_be_bytes());
    b[12] = kind;
    Ok(b)
}
fn checksum(prefix: &[u8], body: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(prefix);
    h.update(body);
    h.finalize().into()
}
fn data(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}
impl Wal {
    /// Open/recover this independent Rust format. Unknown/future/corrupt complete
    /// artifacts are rejected and preserved. Complete valid WAL tails are replayed
    /// even if the previous process lost its STORE_RESULT before restart.
    pub fn open(directory: impl AsRef<Path>, limits: Limits) -> Result<Self, Failure> {
        if limits.records == 0
            || limits.live_bytes < 60
            || limits.checkpoint_bytes == 0
            || limits.checkpoint_bytes > limits.wal_bytes
        {
            return Err(protocol("limits", Error::InvalidInput));
        }
        let minimum = (limits.live_bytes as u64)
            .checked_add(
                (limits.records as u64)
                    .checked_mul((ENTRY + DIGEST) as u64)
                    .ok_or_else(|| protocol("limits", Error::Overflow))?,
            )
            .and_then(|n| n.checked_add((HEADER + 65535 + ENTRY + DIGEST) as u64))
            .ok_or_else(|| protocol("limits", Error::Overflow))?;
        if minimum > limits.wal_bytes {
            return Err(protocol("wal-capacity", Error::InvalidInput));
        }
        fs::create_dir_all(directory.as_ref()).map_err(|e| native("mkdir", e))?;
        if fs::symlink_metadata(directory.as_ref())
            .map_err(|e| native("directory", e))?
            .file_type()
            .is_symlink()
        {
            return Err(protocol("directory-symlink", Error::InvalidInput));
        }
        fs::set_permissions(directory.as_ref(), fs::Permissions::from_mode(0o700))
            .map_err(|e| native("directory-mode", e))?;
        let directory =
            fs::canonicalize(directory.as_ref()).map_err(|e| native("canonical-directory", e))?;
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&directory)
            .map_err(|e| native("directory-open", e))?;
        let dir_id = inode(&dir).map_err(|e| native("directory-id", e))?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(directory.join(".peerstore-rust.lock"))
            .map_err(|e| native("lock-open", e))?;
        lock.try_lock().map_err(|e| match e {
            fs::TryLockError::Error(e) => native("writer-lock", e),
            e @ fs::TryLockError::WouldBlock => Failure {
                stage: "writer-lock",
                classification: Error::Conflict,
                io: Some(e.into()),
            },
        })?;
        let lock_id = inode(&lock).map_err(|e| native("lock-id", e))?;
        let path = directory.join("records.wal");
        let mut file = data(&path).map_err(|e| native("wal-open", e))?;
        let file_id = inode(&file).map_err(|e| native("wal-id", e))?;
        if file_id == lock_id {
            return Err(protocol("wal-lock-alias", Error::Conflict));
        }
        let length = file.metadata().map_err(|e| native("wal-size", e))?.len();
        if length > limits.wal_bytes {
            return Err(protocol("wal-bound", Error::Capacity));
        }
        if length == 0 {
            file.write_all(&header(0))
                .and_then(|()| file.sync_all())
                .and_then(|()| dir.sync_all())
                .map_err(|e| native("initialize-sync", e))?;
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(limits.records)
            .map_err(|_| protocol("row-allocation", Error::Capacity))?;
        let mut wal = Self {
            directory,
            path,
            dir,
            dir_id,
            lock,
            lock_id,
            file,
            file_id,
            rows,
            last: 0,
            live_bytes: 0,
            bytes: 0,
            limits,
            poisoned: false,
            failure: None,
            recovered_tail: 0,
        };
        wal.verify().map_err(|e| native("open-authority", e))?;
        wal.replay()?;
        Ok(wal)
    }
    fn verify(&self) -> io::Result<()> {
        let lock_path = self.directory.join(".peerstore-rust.lock");
        for (path, held, expected, is_dir) in [
            (&self.directory, &self.dir, self.dir_id, true),
            (&lock_path, &self.lock, self.lock_id, false),
            (&self.path, &self.file, self.file_id, false),
        ] {
            let m = fs::symlink_metadata(path)?;
            if m.file_type().is_symlink()
                || m.is_dir() != is_dir
                || Inode(m.dev(), m.ino()) != expected
                || inode(held)? != expected
            {
                return Err(io::Error::other(
                    "original physical storage authority changed",
                ));
            }
        }
        Ok(())
    }
    fn ready(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::OutcomeUnknown)
        } else {
            Ok(())
        }
    }
    fn fail(&mut self, stage: &'static str, error: io::Error) -> Error {
        self.poisoned = true;
        if self.failure.is_none() {
            self.failure = Some(Failure {
                stage,
                classification: Error::OutcomeUnknown,
                io: Some(error),
            })
        }
        Error::OutcomeUnknown
    }
    fn apply(&mut self, row: Stored, replace: bool) -> Result<(), Error> {
        let record = row.record();
        let (removed, count) = self
            .rows
            .iter()
            .filter(|r| replace && r.same_key(record))
            .fold((0usize, 0usize), |(b, n), r| (b + r.frame.len(), n + 1));
        let bytes = self
            .live_bytes
            .checked_sub(removed)
            .and_then(|n| n.checked_add(row.frame.len()))
            .ok_or(Error::Overflow)?;
        if self.rows.len() - count >= self.limits.records || bytes > self.limits.live_bytes {
            return Err(Error::Capacity);
        }
        if replace {
            self.rows.retain(|r| !r.same_key(record))
        }
        self.live_bytes = bytes;
        self.rows.push(row);
        Ok(())
    }
    fn replay(&mut self) -> Result<(), Failure> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| native("replay-seek", e))?;
        let size = self
            .file
            .metadata()
            .map_err(|e| native("replay-size", e))?
            .len();
        let mut h = [0; HEADER];
        self.file
            .read_exact(&mut h)
            .map_err(|e| native("replay-header", e))?;
        if &h[..8] != MAGIC || checksum(&h[..16], &[]) != h[16..] {
            return Err(protocol("wal-header", Error::Storage));
        }
        let checkpoint = u64::from_be_bytes(
            h[8..16]
                .try_into()
                .map_err(|_| protocol("wal-header", Error::Storage))?,
        );
        self.last = checkpoint;
        let mut offset = HEADER as u64;
        let mut last_snapshot = 0;
        let mut incremental = false;
        while offset < size {
            if size - offset < (ENTRY + DIGEST) as u64 {
                break;
            }
            let mut prefix = [0; ENTRY];
            self.file
                .read_exact(&mut prefix)
                .map_err(|e| native("replay-entry", e))?;
            let len = u32::from_be_bytes(
                prefix[..4]
                    .try_into()
                    .map_err(|_| protocol("wal-entry", Error::Storage))?,
            ) as usize;
            let sequence = u64::from_be_bytes(
                prefix[4..12]
                    .try_into()
                    .map_err(|_| protocol("wal-entry", Error::Storage))?,
            );
            let kind = prefix[12];
            if len > 65535 || prefix[13..] != [0, 0, 0] || sequence == 0 || !matches!(kind, 1..=3) {
                return Err(protocol("wal-entry-shape", Error::Storage));
            }
            let total = (ENTRY + DIGEST + len) as u64;
            if size - offset < total {
                break;
            }
            let mut body = Vec::new();
            body.try_reserve_exact(len)
                .map_err(|_| protocol("replay-allocation", Error::Capacity))?;
            body.resize(len, 0);
            self.file
                .read_exact(&mut body)
                .map_err(|e| native("replay-body", e))?;
            let mut sum = [0; 64];
            self.file
                .read_exact(&mut sum)
                .map_err(|e| native("replay-digest", e))?;
            if checksum(&prefix, &body) != sum {
                return Err(protocol("wal-checksum", Error::Storage));
            }
            if kind == 3 {
                if incremental || sequence <= last_snapshot || sequence > checkpoint {
                    return Err(protocol("snapshot-sequence", Error::Replay));
                }
                last_snapshot = sequence;
                let row =
                    Stored::new(sequence, body).map_err(|e| protocol("snapshot-record", e))?;
                self.apply(row, false)
                    .map_err(|e| protocol("snapshot-bound", e))?;
            } else {
                incremental = true;
                if self.last.checked_add(1) != Some(sequence) {
                    return Err(protocol("wal-sequence", Error::Replay));
                }
                if kind == 1 {
                    let replace = matches!(
                        Request::decode(&body),
                        Ok(Request::Store(Envelope { options: 1, .. }))
                    );
                    let row = Stored::new(sequence, body).map_err(|e| protocol("wal-record", e))?;
                    self.apply(row, replace)
                        .map_err(|e| protocol("wal-record-bound", e))?
                } else {
                    if body.len() != 8 {
                        return Err(protocol("wal-expiry", Error::Storage));
                    }
                    let now = u64::from_be_bytes(
                        body[..]
                            .try_into()
                            .map_err(|_| protocol("wal-expiry", Error::Storage))?,
                    );
                    self.rows.retain(|r| r.expiry >= now);
                    self.live_bytes = self.rows.iter().map(|r| r.frame.len()).sum();
                }
                self.last = sequence;
            }
            offset += total;
        }
        if offset < size {
            self.file
                .set_len(offset)
                .and_then(|()| self.file.sync_all())
                .map_err(|e| native("torn-tail-retire", e))?;
            self.recovered_tail = size - offset;
        }
        self.bytes = offset;
        self.file
            .seek(SeekFrom::End(0))
            .map_err(|e| native("replay-end", e))?;
        self.verify().map_err(|e| native("replay-authority", e))?;
        Ok(())
    }
    fn checkpoint(&mut self) -> Result<(), Error> {
        self.ready()?;
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(|_| Error::Entropy)?;
        let path = self.directory.join(format!(
            ".peerstore-tmp-{:032x}",
            u128::from_be_bytes(nonce)
        ));
        let mut tmp = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| self.fail("checkpoint-open", e))?;
        let expected = inode(&tmp).map_err(|e| self.fail("checkpoint-id", e))?;
        let outcome = (|| -> io::Result<u64> {
            tmp.write_all(&header(self.last))?;
            let mut bytes = HEADER as u64;
            for r in &self.rows {
                let e = entry(3, r.sequence, r.frame.len()).map_err(io::Error::other)?;
                tmp.write_all(&e)?;
                tmp.write_all(&r.frame)?;
                tmp.write_all(&checksum(&e, &r.frame))?;
                bytes += (ENTRY + DIGEST + r.frame.len()) as u64;
            }
            tmp.sync_all()?;
            self.verify()?;
            fs::rename(&path, &self.path)?;
            self.dir.sync_all()?;
            Ok(bytes)
        })();
        match outcome {
            Ok(bytes) => {
                self.file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&self.path)
                    .map_err(|e| self.fail("checkpoint-reopen", e))?;
                self.file_id = expected;
                self.bytes = bytes;
                self.verify()
                    .map_err(|e| self.fail("checkpoint-authority", e))?;
                self.file
                    .seek(SeekFrom::End(0))
                    .map_err(|e| self.fail("checkpoint-seek", e))?;
                Ok(())
            }
            Err(e) => {
                if fs::symlink_metadata(&path).is_ok_and(|m| Inode(m.dev(), m.ino()) == expected) {
                    let _cleanup = fs::remove_file(&path);
                }
                Err(self.fail("checkpoint-publish", e))
            }
        }
    }
    fn append(&mut self, kind: u8, sequence: u64, body: &[u8]) -> Result<(), Error> {
        self.ready()?;
        self.verify()
            .map_err(|e| self.fail("append-authority", e))?;
        if self
            .file
            .metadata()
            .map_err(|e| self.fail("append-size", e))?
            .len()
            != self.bytes
        {
            return Err(self.fail(
                "append-size-changed",
                io::Error::other("original WAL length changed"),
            ));
        }
        let prefix = entry(kind, sequence, body.len())?;
        let total = (ENTRY + DIGEST + body.len()) as u64;
        if self.bytes >= self.limits.checkpoint_bytes
            || self
                .bytes
                .checked_add(total)
                .is_none_or(|n| n > self.limits.wal_bytes)
        {
            self.checkpoint()?
        }
        if self
            .bytes
            .checked_add(total)
            .is_none_or(|n| n > self.limits.wal_bytes)
        {
            return Err(Error::Capacity);
        }
        let sum = checksum(&prefix, body);
        self.file
            .write_all(&prefix)
            .and_then(|()| self.file.write_all(body))
            .and_then(|()| self.file.write_all(&sum))
            .and_then(|()| self.file.sync_all())
            .map_err(|e| self.fail("append-sync", e))?;
        self.verify()
            .map_err(|e| self.fail("append-post-authority", e))?;
        self.bytes += total;
        Ok(())
    }
    /// Last known committed live rows; a retained failure remains unresolved.
    #[must_use]
    pub fn records(&self) -> usize {
        self.rows.len()
    }
    /// Last known committed monotonic sequence, including expiration transactions.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.last
    }
    /// Incomplete trailing bytes actually retired during this open.
    #[must_use]
    pub const fn recovered_tail(&self) -> u64 {
        self.recovered_tail
    }
    /// Original unresolved I/O cause, independently from MQ loss.
    #[must_use]
    pub fn failure(&self) -> Option<&Failure> {
        self.failure.as_ref()
    }
    /// Transfer the original retained uncertainty cause to the explicit worker's
    /// terminal report without cloning or replacing its native error.
    pub fn take_failure(&mut self) -> Option<Failure> {
        self.failure.take()
    }
    /// Whether fresh storage operations are forbidden by original uncertainty.
    #[must_use]
    pub const fn poisoned(&self) -> bool {
        self.poisoned
    }
}
impl Storage for Wal {
    fn store(&mut self, record: Record<'_>, replace: bool) -> Result<u64, Error> {
        self.ready()?;
        if record.subsystem.is_none() || record.key.is_none() {
            return Err(Error::InvalidInput);
        }
        let request = Request::Store(Envelope {
            rid: 0,
            options: if replace { 1 } else { 0 },
            reserved: 0,
            record,
        });
        let length = request.encoded_len()?;
        let (removed, count) = self
            .rows
            .iter()
            .filter(|r| replace && r.same_key(record))
            .fold((0usize, 0usize), |(b, n), r| (b + r.frame.len(), n + 1));
        if self.rows.len() - count >= self.limits.records
            || self
                .live_bytes
                .checked_sub(removed)
                .and_then(|n| n.checked_add(length))
                .is_none_or(|n| n > self.limits.live_bytes)
        {
            return Err(Error::Capacity);
        }
        let sequence = self.last.checked_add(1).ok_or(Error::Overflow)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| Error::Capacity)?;
        bytes.resize(length, 0);
        request.encode(&mut bytes)?;
        let row = Stored::new(sequence, bytes)?;
        let live_bytes = self.live_bytes - removed + length;
        self.append(1, sequence, &row.frame)?;
        // Every bound and allocation was checked before actual append/fsync.
        // No fallible in-memory transition follows that committed disk effect.
        if replace {
            self.rows.retain(|r| !r.same_key(record))
        }
        self.rows.push(row);
        self.live_bytes = live_bytes;
        self.last = sequence;
        Ok(sequence)
    }
    fn next(&self, filter: Filter<'_>, after: u64) -> Result<Option<Row<'_>>, Error> {
        self.ready()?;
        let start = self.rows.partition_point(|r| r.sequence <= after);
        Ok(self.rows[start..]
            .iter()
            .find(|r| filter.matches(r.record()))
            .map(|r| Row {
                sequence: r.sequence,
                record: r.record(),
            }))
    }
    fn expire(&mut self, now: u64) -> Result<u64, Error> {
        self.ready()?;
        let count = self.rows.iter().filter(|r| r.expiry < now).count();
        if count == 0 {
            return Ok(0);
        }
        let sequence = self.last.checked_add(1).ok_or(Error::Overflow)?;
        self.append(2, sequence, &now.to_be_bytes())?;
        self.rows.retain(|r| r.expiry >= now);
        self.live_bytes = self.rows.iter().map(|r| r.frame.len()).sum();
        self.last = sequence;
        Ok(count as u64)
    }
}
