//! Original marked root, lock/counter fencing and native publication ownership.
use crate::*;
use gnunet_native::filesystem::{
    self, Directory as NativeDirectory, FileIdentity, FileInfo, PrivateFileSnapshot,
};
use std::{ffi::OsStr, fs::File, io::Read};
mod publication;
mod removal;
const MARK: &str = ".testbed-rust-owner";
const LOCK: &str = ".testbed-rust.lock";
const COUNTER: &str = ".testbed-rust.counter";
const MAGIC: &[u8] = b"GNUNET-RUST-TESTBED-DIRECTORY\nversion=1\n";
fn path_bytes(path: &Path) -> usize {
    gnunet_native::os_bytes::encode(path.as_os_str()).len()
}
fn root_fits(path: &Path, limit: usize) -> bool {
    [MARK, LOCK, COUNTER]
        .iter()
        .all(|name| path_bytes(&path.join(name)) <= limit)
}
fn absolute(path: &Path) -> io::Result<PathBuf> {
    std::path::absolute(path)
}
fn split(path: &Path) -> io::Result<(&Path, &OsStr)> {
    let name = path.file_name().ok_or(io::ErrorKind::InvalidInput)?;
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or(io::ErrorKind::InvalidInput)?;
    Ok((parent, name))
}
fn read_small(
    directory: &NativeDirectory,
    name: &str,
    maximum: usize,
    path: &Path,
) -> Result<Vec<u8>, Failure> {
    let mut file = directory
        .open_file(OsStr::new(name))
        .map_err(|error| Failure::io("open metadata", path, error))?;
    let result: Result<Vec<u8>, Failure> = (|| {
        let (bytes, _) = read_original(&mut file, maximum, path)?;
        if !directory
            .same_file(OsStr::new(name), &file)
            .map_err(|error| Failure::io("recheck metadata name", path, error))?
        {
            return Err(Cause::Changed.into());
        }
        Ok(bytes)
    })();
    let close = filesystem::close(file);
    match (result, close) {
        (Ok(bytes), Ok(())) => Ok(bytes),
        (Err(mut original), Err(error)) => {
            original.add(Cause::Io {
                operation: "close metadata",
                path: path.to_owned(),
                error,
            });
            Err(original)
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(Failure::io("close metadata", path, error)),
    }
}
fn read_original(
    file: &mut File,
    maximum: usize,
    path: &Path,
) -> Result<(Vec<u8>, FileInfo), Failure> {
    let before = filesystem::private_data_file_info(file)
        .map_err(|error| Failure::io("qualify metadata", path, error))?;
    let mut bytes = Vec::new();
    let extent = maximum.checked_add(1).ok_or(Fault::Overflow)?;
    bytes
        .try_reserve_exact(extent)
        .map_err(|_| Fault::Capacity)?;
    Read::by_ref(file)
        .take(u64::try_from(extent).map_err(|_| Fault::Overflow)?)
        .read_to_end(&mut bytes)
        .map_err(|error| Failure::io("read metadata", path, error))?;
    if bytes.len() > maximum {
        return Err(Fault::TooLarge.into());
    }
    let after = filesystem::private_data_file_info(file)
        .map_err(|error| Failure::io("recheck metadata", path, error))?;
    if after != before || bytes.len() as u64 != before.bytes {
        return Err(Cause::Changed.into());
    }
    Ok((bytes, before))
}
pub(crate) struct Directory {
    pub path: PathBuf,
    parent: NativeDirectory,
    name: OsString,
    original: NativeDirectory,
    marker: File,
    marker_snapshot: PrivateFileSnapshot,
    lock: File,
    limits: Limits,
    pub fenced: bool,
}
impl Directory {
    pub fn create(options: &Options, allocation: u64) -> Result<(Self, u64), Failure> {
        let (path, parent, name, original) = if let Some(prefix) = &options.prefix {
            let path =
                absolute(prefix).map_err(|error| Failure::io("resolve prefix", prefix, error))?;
            if !root_fits(&path, options.limits.path_bytes) {
                return Err(Fault::TooLarge.into());
            }
            let (parent_path, name) =
                split(&path).map_err(|error| Failure::io("split prefix", &path, error))?;
            let parent = NativeDirectory::open(parent_path)
                .map_err(|error| Failure::io("open prefix parent", parent_path, error))?;
            let original = parent
                .ensure_directory(name)
                .map_err(|error| Failure::io("create/open prefix", &path, error))?;
            let name = name.to_owned();
            (path, parent, name, original)
        } else {
            let parent_path = absolute(&options.temporary_parent).map_err(|error| {
                Failure::io("resolve temporary parent", &options.temporary_parent, error)
            })?;
            let parent = NativeDirectory::open(&parent_path)
                .map_err(|error| Failure::io("open temporary parent", &parent_path, error))?;
            let label = Path::new(&options.label);
            if label.components().count() != 1
                || label.file_name() != Some(options.label.as_os_str())
                || options.label.is_empty()
            {
                return Err(Fault::InvalidInput.into());
            }
            let mut selected = None;
            for n in 0..options.limits.directory_attempts {
                let mut name = options.label.clone();
                name.push(format!("-{}-{allocation}-{n}", std::process::id()));
                let path = parent_path.join(&name);
                if !root_fits(&path, options.limits.path_bytes) {
                    return Err(Fault::TooLarge.into());
                }
                match parent.create_private_directory(&name) {
                    Ok(original) => {
                        selected = Some((path, name, original));
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(Failure::io("create temporary root", path, error)),
                }
            }
            let (path, name, original) = selected.ok_or(Fault::Capacity)?;
            (path, parent, name, original)
        };
        original
            .validate_private()
            .map_err(|error| Failure::io("qualify private root", &path, error))?;
        let initialized = match original.entry_info(OsStr::new(MARK)) {
            Ok(_) => false,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if original
                    .entries()
                    .map_err(|error| Failure::io("inspect empty root", &path, error))?
                    .next()
                    .is_some()
                {
                    return Err(Cause::ForeignDirectory.into());
                }
                Self::publish_initial(&original, MARK, MAGIC, &path)?;
                true
            }
            Err(error) => return Err(Failure::io("inspect marker", &path, error)),
        };
        let mut marker = original
            .open_file(OsStr::new(MARK))
            .map_err(|error| Failure::io("capture marker", &path, error))?;
        let (marker_bytes, marker_info) =
            read_original(&mut marker, MAGIC.len(), &path.join(MARK))?;
        if marker_bytes != MAGIC {
            return Err(Cause::ForeignDirectory.into());
        }
        let lock = match original.create_private_file(OsStr::new(LOCK)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => original
                .open_file_for_update(OsStr::new(LOCK))
                .map_err(|error| Failure::io("open root lock", &path, error))?,
            Err(error) => return Err(Failure::io("create root lock", &path, error)),
        };
        filesystem::private_single_file_identity(&lock)
            .map_err(|error| Failure::io("qualify root lock", &path, error))?;
        lock.try_lock()
            .map_err(|error| Failure::io("lock root", &path, io::Error::other(error)))?;
        let directory = Self {
            path,
            parent,
            name,
            original,
            marker,
            marker_snapshot: PrivateFileSnapshot::new(marker_info, MAGIC),
            lock,
            limits: options.limits,
            fenced: false,
        };
        let counter_path = directory.path.join(COUNTER);
        let high = if initialized {
            Self::publish_initial(&directory.original, COUNTER, b"0\n", &counter_path)?;
            0
        } else {
            let bytes = read_small(&directory.original, COUNTER, 21, &counter_path)?;
            let digits = bytes.strip_suffix(b"\n").ok_or(Cause::Changed)?;
            if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
                return Err(Cause::Changed.into());
            }
            std::str::from_utf8(digits)
                .map_err(|_| Cause::Changed)?
                .parse::<u64>()
                .map_err(|_| Cause::Changed)?
        };
        directory.check()?;
        Ok((directory, high))
    }
    fn publish_initial(
        directory: &NativeDirectory,
        name: &str,
        bytes: &[u8],
        path: &Path,
    ) -> Result<(), Failure> {
        let published = filesystem::publication::publish(
            directory,
            OsStr::new(name),
            bytes,
            filesystem::publication::Destination::Create,
            || Ok(()),
        )
        .map_err(|error| {
            Failure::from(Cause::Publication {
                path: path.to_owned(),
                error: Box::new(error),
            })
        })?;
        let (file, _barrier) = published.into_parts();
        filesystem::close(file).map_err(|error| Failure::io("close initial metadata", path, error))
    }
    pub fn check(&self) -> Result<(), Failure> {
        if self.fenced {
            return Err(Cause::Changed.into());
        }
        self.check_identity()
            .map_err(|error| Failure::io("check original root", &self.path, error))
    }
    fn check_identity(&self) -> io::Result<()> {
        self.original.validate_private()?;
        filesystem::private_single_file_identity(&self.lock)?;
        if !self.parent.same_directory(&self.name, &self.original)? {
            return Err(io::Error::other("original TESTBED root name changed"));
        }
        if FileIdentity::of(NativeDirectory::open(&self.path)?.as_file())?
            != FileIdentity::of(self.original.as_file())?
        {
            return Err(io::Error::other("original TESTBED root path changed"));
        }
        self.marker_snapshot
            .verify(&self.original, OsStr::new(MARK), &self.marker)?;
        if !self.original.same_file(OsStr::new(LOCK), &self.lock)? {
            return Err(io::Error::other("original TESTBED lock name changed"));
        }
        Ok(())
    }
    pub fn counter(&mut self, number: u64) -> Result<(), Failure> {
        let target = self.path.join(COUNTER);
        let outcome = self.publish(
            &target,
            format!("{number}\n").as_bytes(),
            Replace::Allowed,
            None,
        );
        if outcome.is_err() {
            self.fenced = true;
        }
        outcome.map(|_| ())
    }
    pub fn create_home(&self, number: u64) -> Result<NativeDirectory, Failure> {
        self.check()?;
        let name = OsString::from(number.to_string());
        let original = self
            .original
            .create_private_directory(&name)
            .map_err(|error| {
                Failure::io("create configuration home", self.path.join(&name), error)
            })?;
        self.check()?;
        Ok(original)
    }
    pub fn remove_home(&self, number: u64, original: &NativeDirectory) -> Result<(), Failure> {
        self.original
            .remove_directory(OsStr::new(&number.to_string()), original)
            .map_err(|error| {
                Failure::io(
                    "remove original configuration home",
                    self.path.join(number.to_string()),
                    error,
                )
            })
    }
    pub fn locked(&self) -> bool {
        self.lock.metadata().is_ok()
    }
}
