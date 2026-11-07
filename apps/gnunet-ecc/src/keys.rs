use crate::{
    Failure,
    options::Print,
    run::{Facts, Guard},
};
use gnunet_crypto::EddsaPrivateKey;
use gnunet_gnsrecord::{decode_base32, encode_base32};
use gnunet_session_crypto::exchange::EcdheSecret;
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use zeroize::Zeroizing;

pub(super) struct Vanity {
    target: [u8; 32],
    bits: usize,
}
impl Vanity {
    pub fn new(prefix: &[u8]) -> Result<Self, Failure> {
        if prefix.len() > 52 {
            return Err("vanity prefix exceeds 256 public-key bits".into());
        }
        let mut encoded = [b'0'; 52];
        encoded[..prefix.len()].copy_from_slice(prefix);
        let mut target = [0u8; 32];
        decode_base32(&encoded, &mut target)?;
        Ok(Self {
            target,
            bits: prefix.len().saturating_mul(5).min(256),
        })
    }
    fn matches(&self, key: &[u8; 32]) -> bool {
        let whole = self.bits / 8;
        let remaining = self.bits % 8;
        key[..whole] == self.target[..whole]
            && (remaining == 0
                || (key[whole] ^ self.target[whole]) & (0xff << (8 - remaining)) == 0)
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct Snapshot {
    dev: u64,
    ino: u64,
    len: u64,
    mode: u32,
    links: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
impl Snapshot {
    fn new(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            len: m.len(),
            mode: m.mode(),
            links: m.nlink(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        }
    }
}
struct Reader {
    file: File,
    path: PathBuf,
    original: Snapshot,
    rows: u64,
}
impl Reader {
    fn open(path: &Path) -> Result<Self, Failure> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let actual = file.metadata()?;
        let named = fs::symlink_metadata(path)?;
        if !actual.is_file() || !named.is_file() || Snapshot::new(&actual) != Snapshot::new(&named)
        {
            return Err("ECC key input is not the original regular file".into());
        }
        if actual.len() == 0 {
            return Err("ECC raw32 key file is empty".into());
        }
        if actual.len() % 32 != 0 {
            return Err("ECC key file has an incomplete raw32 record".into());
        }
        Ok(Self {
            file,
            path: path.to_path_buf(),
            original: Snapshot::new(&actual),
            rows: actual.len() / 32,
        })
    }
    fn verify(&self) -> Result<(), Failure> {
        let actual = self.file.metadata()?;
        let named = fs::symlink_metadata(&self.path)?;
        if !actual.is_file()
            || !named.is_file()
            || Snapshot::new(&actual) != self.original
            || Snapshot::new(&named) != self.original
        {
            return Err("original ECC key file changed during observation".into());
        }
        Ok(())
    }
    async fn record(
        &mut self,
        guard: &mut Guard,
        facts: &mut Facts,
    ) -> Result<Zeroizing<[u8; 32]>, Failure> {
        guard.check().await?;
        self.verify()?;
        guard.check().await?;
        let mut seed = Zeroizing::new([0u8; 32]);
        let mut at = 0;
        while at < seed.len() {
            guard.check().await?;
            match self.file.read(&mut seed[at..]) {
                Ok(0) => return Err("original ECC raw32 record ended prematurely".into()),
                Ok(n) => {
                    at += n;
                    if at == seed.len() {
                        facts.records_read = facts
                            .records_read
                            .checked_add(1)
                            .ok_or("ECC input record count overflow")?;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
            guard.check().await?;
        }
        self.verify()?;
        guard.check().await?;
        Ok(seed)
    }
}
async fn bytes(
    w: &mut dyn Write,
    value: &[u8],
    guard: &mut Guard,
    count: &mut u128,
) -> Result<(), Failure> {
    let mut at = 0;
    while at < value.len() {
        guard.check().await?;
        match w.write(&value[at..]) {
            Ok(0) => {
                return Err(
                    io::Error::new(io::ErrorKind::WriteZero, "zero ECC output write").into(),
                );
            }
            Ok(n) => {
                at += n;
                *count = count
                    .checked_add(n as u128)
                    .ok_or("ECC output count overflow")?;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                tokio::task::yield_now().await;
                continue;
            }
            Err(e) => return Err(e.into()),
        }
        // Positive/whole output facts precede a late cancellation/clock error.
        guard.check().await?;
    }
    Ok(())
}
async fn flush(w: &mut dyn Write, guard: &mut Guard) -> Result<(), Failure> {
    guard.check().await?;
    w.flush()?;
    guard.check().await
}
async fn base32(
    prefix: &[u8],
    value: &[u8],
    w: &mut dyn Write,
    guard: &mut Guard,
    count: &mut u128,
) -> Result<(), Failure> {
    let mut line = Zeroizing::new([0u8; 160]);
    line.get_mut(..prefix.len())
        .ok_or("ECC output prefix bound")?
        .copy_from_slice(prefix);
    let n = encode_base32(
        value,
        line.get_mut(prefix.len()..).ok_or("ECC output bound")?,
    )?;
    let end = prefix
        .len()
        .checked_add(n)
        .ok_or("ECC output size overflow")?;
    *line.get_mut(end).ok_or("ECC output bound")? = b'\n';
    bytes(w, &line[..end + 1], guard, count).await
}
async fn hexadecimal(
    prefix: &[u8],
    value: &[u8],
    w: &mut dyn Write,
    guard: &mut Guard,
    count: &mut u128,
) -> Result<(), Failure> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut line = Zeroizing::new([0u8; 160]);
    let end = value
        .len()
        .checked_mul(2)
        .and_then(|n| n.checked_add(prefix.len()))
        .ok_or("ECC hex size overflow")?;
    if end >= line.len() {
        return Err("ECC hex output bound".into());
    }
    line[..prefix.len()].copy_from_slice(prefix);
    for (i, b) in value.iter().enumerate() {
        line[prefix.len() + i * 2] = HEX[usize::from(b >> 4)];
        line[prefix.len() + i * 2 + 1] = HEX[usize::from(b & 15)];
    }
    line[end] = b'\n';
    bytes(w, &line[..end + 1], guard, count).await
}
pub(super) async fn inspect(
    path: &Path,
    maximum: Option<u32>,
    form: Option<Print>,
    guard: &mut Guard,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    facts: &mut Facts,
) -> Result<(), Failure> {
    guard.check().await?;
    let mut input = Reader::open(path)?;
    guard.check().await?;
    let rows = maximum.map_or(input.rows, |max| input.rows.min(u64::from(max)));
    for index in 0..rows {
        let seed = input.record(guard, facts).await?;
        if maximum.is_some() {
            let key = EddsaPrivateKey::from_seed(*seed);
            let prefix = format!("{index:4}: ");
            base32(
                prefix.as_bytes(),
                key.public_key().as_bytes(),
                stderr,
                guard,
                &mut facts.stderr_bytes,
            )
            .await?;
        } else {
            match form.ok_or("missing ECC print selection")? {
                Print::Private => {
                    base32(b"", seed.as_ref(), stdout, guard, &mut facts.stdout_bytes).await?
                }
                Print::Public | Print::Hex => {
                    let key = EddsaPrivateKey::from_seed(*seed);
                    guard.check().await?;
                    let public = key.public_key();
                    match form {
                        Some(Print::Hex) => {
                            hexadecimal(
                                b"HEX:: ",
                                public.as_bytes(),
                                stdout,
                                guard,
                                &mut facts.stdout_bytes,
                            )
                            .await?
                        }
                        _ => {
                            base32(
                                b"",
                                public.as_bytes(),
                                stdout,
                                guard,
                                &mut facts.stdout_bytes,
                            )
                            .await?
                        }
                    }
                }
            }
        }
        guard.turn().await?;
    }
    guard.check().await?;
    input.verify()?;
    guard.check().await?;
    if maximum.is_some() {
        flush(stderr, guard).await
    } else {
        flush(stdout, guard).await
    }
}
static NEXT: AtomicU64 = AtomicU64::new(0);
pub(super) struct Staging {
    file: Option<File>,
    path: PathBuf,
    target: PathBuf,
    parent: PathBuf,
    parent_id: (u64, u64),
    original: Option<Snapshot>,
    present: bool,
    cleanup_attempted: bool,
    length: u64,
}
impl Staging {
    fn create(target: &Path, owner: &mut Option<Self>) -> Result<(), Failure> {
        if owner.is_some() {
            return Err("ECC staging owner already exists".into());
        }
        let original = match fs::symlink_metadata(target) {
            Ok(m) if m.is_file() && m.len() % 32 == 0 => Some(Snapshot::new(&m)),
            Ok(_) => return Err("ECC generation target must be absent or an empty/raw32 regular file, not a symlink".into()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let parent = target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent_meta = fs::symlink_metadata(parent)?;
        if !parent_meta.is_dir() {
            return Err("ECC target parent must be an existing directory, not a symlink".into());
        }
        for _ in 0..32 {
            let serial = NEXT
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .map_err(|_| "ECC staging serial exhausted")?;
            let name = format!(".gnunet-ecc-{}-{serial}.tmp", std::process::id());
            if target.file_name() == Some(std::ffi::OsStr::new(&name)) {
                continue;
            }
            let path = parent.join(name);
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)
            {
                Ok(file) => {
                    // Retain actual creation before the next fallible metadata call.
                    *owner = Some(Self {
                        file: Some(file),
                        path,
                        target: target.to_path_buf(),
                        parent: parent.to_path_buf(),
                        parent_id: (parent_meta.dev(), parent_meta.ino()),
                        original,
                        present: true,
                        cleanup_attempted: false,
                        length: 0,
                    });
                    owner.as_ref().ok_or("missing ECC staging owner")?.check()?;
                    return Ok(());
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("ECC private sibling allocation exhausted".into())
    }
    fn parent(&self) -> Result<(), Failure> {
        let m = fs::symlink_metadata(&self.parent)?;
        if !m.is_dir() || (m.dev(), m.ino()) != self.parent_id {
            return Err("original ECC publication directory changed".into());
        }
        Ok(())
    }
    fn check(&self) -> Result<(), Failure> {
        self.parent()?;
        let actual = self
            .file
            .as_ref()
            .ok_or("ECC staging descriptor retired")?
            .metadata()?;
        if !actual.is_file() || actual.mode() & 0o077 != 0 || actual.len() != self.length {
            return Err("original ECC staging file changed".into());
        }
        if self.present {
            let named = fs::symlink_metadata(&self.path)?;
            if !named.is_file() || (actual.dev(), actual.ino()) != (named.dev(), named.ino()) {
                return Err("original ECC staging path changed".into());
            }
        }
        Ok(())
    }
    async fn write(
        &mut self,
        seed: &[u8; 32],
        guard: &mut Guard,
        facts: &mut Facts,
    ) -> Result<(), Failure> {
        let mut at = 0;
        while at < seed.len() {
            guard.check().await?;
            self.check()?;
            guard.check().await?;
            match self
                .file
                .as_mut()
                .ok_or("ECC staging descriptor retired")?
                .write(&seed[at..])
            {
                Ok(0) => {
                    return Err(
                        io::Error::new(io::ErrorKind::WriteZero, "zero ECC staging write").into(),
                    );
                }
                Ok(n) => {
                    at += n;
                    self.length = self
                        .length
                        .checked_add(n as u64)
                        .ok_or("ECC staging size overflow")?;
                    facts.staged_bytes = self.length;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
            guard.check().await?;
        }
        Ok(())
    }
    async fn publish(&mut self, guard: &mut Guard, facts: &mut Facts) -> Result<(), Failure> {
        guard.check().await?;
        self.check()?;
        guard.check().await?;
        self.file
            .as_ref()
            .ok_or("ECC staging descriptor retired")?
            .sync_all()?;
        guard.check().await?;
        self.check()?;
        match (self.original, fs::symlink_metadata(&self.target)) {
            (Some(old), Ok(now)) if now.is_file() && Snapshot::new(&now) == old => {}
            (None, Err(e)) if e.kind() == io::ErrorKind::NotFound => {}
            (_, Err(e)) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
            _ => return Err("ECC target changed before publication".into()),
        }
        guard.check().await?;
        if self.original.is_some() {
            // Metadata recheck is not an inter-process compare-and-swap. Rename
            // atomically replaces this explicitly selected regular target.
            fs::rename(&self.path, &self.target)?;
            self.present = false;
            facts.replaced = true;
        } else {
            // Kernel no-clobber publication when the selected target was absent.
            fs::hard_link(&self.path, &self.target)?;
        }
        facts.published = true;
        guard.check().await?;
        if self.present {
            self.check()?;
            fs::remove_file(&self.path)?;
            self.present = false;
        }
        guard.check().await?;
        self.parent()?;
        let parent = File::open(&self.parent)?;
        guard.check().await?;
        let observed = parent.metadata()?;
        if !observed.is_dir() || (observed.dev(), observed.ino()) != self.parent_id {
            return Err("original ECC publication directory descriptor changed".into());
        }
        guard.check().await?;
        parent.sync_all()?;
        facts.directory_synced = true;
        guard.check().await
    }
    /// No time/cancel check can prevent independent original-sibling cleanup.
    pub fn cleanup(&mut self) -> Result<(), Failure> {
        self.cleanup_attempted = true;
        if self.present {
            // Content/length errors must not suppress cleanup of our original
            // created inode. A replaced path/parent is never removed instead.
            self.parent()?;
            let actual = self
                .file
                .as_ref()
                .ok_or("ECC staging descriptor retired")?
                .metadata()?;
            let named = fs::symlink_metadata(&self.path)?;
            if !actual.is_file()
                || !named.is_file()
                || (actual.dev(), actual.ino()) != (named.dev(), named.ino())
            {
                return Err("ECC private sibling ownership changed during cleanup".into());
            }
            fs::remove_file(&self.path)?;
            self.present = false;
        }
        self.file = None;
        Ok(())
    }
    pub fn retained_path(&self) -> Option<PathBuf> {
        self.present.then(|| self.path.clone())
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        if !self.cleanup_attempted {
            let _independent = self.cleanup();
        }
    }
}
pub(super) async fn generate(
    path: &Path,
    count: u32,
    vanity: Option<&Vanity>,
    owner: &mut Option<Staging>,
    guard: &mut Guard,
    stderr: &mut dyn Write,
    facts: &mut Facts,
) -> Result<(), Failure> {
    guard.check().await?;
    Staging::create(path, owner)?;
    guard.check().await?;
    let start = format!("Generating {count} original raw32 keys\n");
    bytes(stderr, start.as_bytes(), guard, &mut facts.stderr_bytes).await?;
    for _ in 0..count {
        loop {
            let seed = guard.candidate(facts).await?;
            let accepted = vanity.is_none_or(|prefix| {
                let key = EddsaPrivateKey::from_seed(*seed);
                prefix.matches(key.public_key().as_bytes())
            });
            guard.check().await?;
            if accepted {
                facts.keys_generated = facts
                    .keys_generated
                    .checked_add(1)
                    .ok_or("ECC generated count overflow")?;
                owner
                    .as_mut()
                    .ok_or("missing ECC staging owner")?
                    .write(&seed, guard, facts)
                    .await?;
                guard.turn().await?;
                break;
            }
            guard.turn().await?;
        }
    }
    owner
        .as_mut()
        .ok_or("missing ECC staging owner")?
        .publish(guard, facts)
        .await?;
    bytes(
        stderr,
        b"Finished complete raw32 publication\n",
        guard,
        &mut facts.stderr_bytes,
    )
    .await?;
    flush(stderr, guard).await
}
pub(super) async fn examples(
    guard: &mut Guard,
    stdout: &mut dyn Write,
    facts: &mut Facts,
) -> Result<(), Failure> {
    let first = guard.candidate(facts).await?;
    let key1 = EcdheSecret::from_bytes(*first);
    guard.check().await?;
    let second = guard.candidate(facts).await?;
    let key2 = EcdheSecret::from_bytes(*second);
    guard.check().await?;
    let public1 = key1.public_key();
    guard.check().await?;
    let public2 = key2.public_key();
    guard.check().await?;
    bytes(stdout, b"ECDHE key 1:\n", guard, &mut facts.stdout_bytes).await?;
    base32(
        b"private: ",
        first.as_ref(),
        stdout,
        guard,
        &mut facts.stdout_bytes,
    )
    .await?;
    hexadecimal(
        b"private(hex): ",
        first.as_ref(),
        stdout,
        guard,
        &mut facts.stdout_bytes,
    )
    .await?;
    base32(
        b"public: ",
        public1.as_bytes(),
        stdout,
        guard,
        &mut facts.stdout_bytes,
    )
    .await?;
    hexadecimal(
        b"public(hex): ",
        public1.as_bytes(),
        stdout,
        guard,
        &mut facts.stdout_bytes,
    )
    .await?;
    bytes(stdout, b"ECDHE key 2:\n", guard, &mut facts.stdout_bytes).await?;
    base32(
        b"private: ",
        second.as_ref(),
        stdout,
        guard,
        &mut facts.stdout_bytes,
    )
    .await?;
    hexadecimal(
        b"private(hex): ",
        second.as_ref(),
        stdout,
        guard,
        &mut facts.stdout_bytes,
    )
    .await?;
    base32(
        b"public: ",
        public2.as_bytes(),
        stdout,
        guard,
        &mut facts.stdout_bytes,
    )
    .await?;
    hexadecimal(
        b"public(hex): ",
        public2.as_bytes(),
        stdout,
        guard,
        &mut facts.stdout_bytes,
    )
    .await?;
    guard.check().await?;
    let shared = key1.exchange_hashed(public2)?.into_secret_bytes();
    guard.check().await?;
    base32(
        b"ECDH shared secret: ",
        shared.as_ref(),
        stdout,
        guard,
        &mut facts.stdout_bytes,
    )
    .await?;
    flush(stdout, guard).await
}
