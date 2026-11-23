//! Native package path custody and fixed INF and PE validation.
use gnunet_native::paths::is_regular_file;
use std::{
    ffi::OsString,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf, Prefix},
};
use windows_sys::Win32::{
    Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ,
    },
    System::SystemInformation::{IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64},
};

const INF: &str =
    include_str!("../../../../platform/windows/wfp-driver/package/gnunet-wfp-driver.inf.in");
pub(super) const INF_NAME: &str = "gnunet-wfp-driver.inf";
pub(super) const IMAGE_NAME: &str = "gnunet-wfp-driver.sys";
const CATALOG_NAME: &str = "gnunet-wfp-driver.cat";

pub(super) struct Architecture {
    pub(super) machine: u16,
    inf: &'static str,
}

impl Architecture {
    pub(super) fn new(machine: u16) -> io::Result<Self> {
        let inf = match machine {
            IMAGE_FILE_MACHINE_AMD64 => "amd64",
            IMAGE_FILE_MACHINE_ARM64 => "arm64",
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "WFP deployment requires native x64 or ARM64 Windows",
                ));
            }
        };
        Ok(Self { machine, inf })
    }
}

pub(super) struct Member {
    pub(super) path: Vec<u16>,
    pub(super) file: File,
    length: u64,
}

impl Member {
    fn open(parent: &Path, name: &'static str, maximum: u64) -> io::Result<Self> {
        let path = parent.join(name);
        let file = File::options()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)?;
        let metadata = file.metadata()?;
        if !is_regular_file(&file)?
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || !(1..=maximum).contains(&metadata.len())
        {
            return Err(invalid("invalid WFP package member"));
        }
        Ok(Self {
            path: wide_path(&path)?,
            file,
            length: metadata.len(),
        })
    }

    fn same_bytes(&self, other: &Self) -> io::Result<bool> {
        if self.length != other.length {
            return Ok(false);
        }
        let mut first = &self.file;
        let mut second = &other.file;
        first.rewind()?;
        second.rewind()?;
        let mut remaining = self.length;
        let (mut left, mut right) = ([0u8; 8192], [0u8; 8192]);
        while remaining != 0 {
            let count = remaining.min(left.len() as u64) as usize;
            first.read_exact(&mut left[..count])?;
            second.read_exact(&mut right[..count])?;
            if left[..count] != right[..count] {
                return Ok(false);
            }
            remaining -= count as u64;
        }
        Ok(true)
    }
}

pub(super) struct Package {
    pub(super) image: Member,
    pub(super) inf: Member,
    pub(super) catalog: Member,
    // SetupAPI accepts paths, so protect the entire resolution chain while it runs.
    _directories: Vec<File>,
}

impl Package {
    pub(super) fn open(path: &Path, architecture: &Architecture) -> io::Result<Self> {
        let path = local_absolute(&fs::canonicalize(path)?)?;
        let directories = pin_directories(&path)?;
        let image = Member::open(&path, IMAGE_NAME, 32 * 1024 * 1024)?;
        let inf = Member::open(&path, INF_NAME, 64 * 1024)?;
        let catalog = Member::open(&path, CATALOG_NAME, 16 * 1024 * 1024)?;
        validate_image(&image, architecture)?;
        let mut actual = String::new();
        (&inf.file).take(inf.length).read_to_string(&mut actual)?;
        if !actual
            .trim_start_matches('\u{feff}')
            .lines()
            .eq(INF.replace("@ARCH@", architecture.inf).lines())
        {
            return Err(invalid("WFP INF differs from the native release template"));
        }
        Ok(Self {
            image,
            inf,
            catalog,
            _directories: directories,
        })
    }

    pub(super) fn same_bytes(&self, installed: &Self) -> io::Result<bool> {
        Ok(self.inf.same_bytes(&installed.inf)?
            && self.image.same_bytes(&installed.image)?
            && self.catalog.same_bytes(&installed.catalog)?)
    }
}

fn validate_image(image: &Member, architecture: &Architecture) -> io::Result<()> {
    let mut file = &image.file;
    let mut dos = [0; 64];
    file.read_exact(&mut dos)?;
    let offset = u64::from(u32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]));
    let invalid = || invalid("WFP image must be a matching native PE32+ executable");
    if !dos.starts_with(b"MZ") || offset < dos.len() as u64 || offset + 136 > image.length {
        return Err(invalid());
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut header = [0; 136];
    file.read_exact(&mut header)?;
    let word = |offset| u16::from_le_bytes([header[offset], header[offset + 1]]);
    let optional = u64::from(word(20));
    if !header.starts_with(b"PE\0\0")
        || word(4) != architecture.machine
        || word(6) == 0
        || word(22) & 2 == 0
        || optional < 112
        || offset + 24 + optional > image.length
        || word(24) != 0x020b
        || header[40..44] == [0; 4]
        || word(92) != 1
    {
        return Err(invalid());
    }
    file.rewind()
}

fn pin_directories(path: &Path) -> io::Result<Vec<File>> {
    let mut directories = Vec::new();
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        let file = File::options()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&current)?;
        let metadata = file.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(invalid(
                "WFP package resolution requires ordinary directory ancestors",
            ));
        }
        directories.push(file);
    }
    Ok(directories)
}

pub(super) fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    // DiInstallDriverW requires a fully qualified path shorter than MAX_PATH.
    if !path.is_absolute() || wide.len() >= 260 || wide.contains(&0) {
        return Err(invalid("invalid Windows setup path or MAX_PATH exceeded"));
    }
    wide.push(0);
    Ok(wide)
}

pub(super) fn local_absolute(path: &Path) -> io::Result<PathBuf> {
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(invalid("expected an absolute local disk path"));
    };
    let drive = match prefix.kind() {
        Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
        _ => return Err(invalid("WFP deployment requires a local disk path")),
    };
    if components.next() != Some(Component::RootDir) {
        return Err(invalid("expected an absolute local disk path"));
    }
    let mut result = PathBuf::from(OsString::from_wide(&[u16::from(drive), 58, 92]));
    for component in components {
        let Component::Normal(name) = component else {
            return Err(invalid("invalid component in WFP package path"));
        };
        if name
            .encode_wide()
            .any(|unit| matches!(unit, 0 | 58 | 92 | 47))
            || matches!(name.encode_wide().last(), Some(32 | 46))
        {
            return Err(invalid("invalid component in WFP package path"));
        }
        result.push(name);
    }
    Ok(result)
}

pub(super) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
