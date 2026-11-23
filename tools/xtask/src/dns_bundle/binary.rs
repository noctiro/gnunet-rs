//! Checked copying of original macOS executable headers; no code is executed.
use std::{
    fs,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Architecture {
    X86_64,
    Arm64,
}

impl Architecture {
    pub(super) const fn codesign_name(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Arm64 => "arm64",
        }
    }
}

pub(super) fn architectures(path: &Path) -> io::Result<Vec<Architecture>> {
    let mut file = fs::File::open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file.metadata()?.permissions().mode() & 0o111 == 0 {
            return Err(invalid_binary());
        }
    }
    executable_headers(&mut file)
}

pub(super) fn copy(source: &Path, destination: &Path) -> io::Result<()> {
    let mut source = fs::File::open(source)?;
    if !source.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "binary must be a regular Mach-O executable",
        ));
    }
    drop(executable_headers(&mut source)?);
    source.rewind()?;
    let mut copied = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(destination)?;
    io::copy(&mut source, &mut copied)?;
    drop(executable_headers(&mut copied)?);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        copied.set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

// Public Apple mach-o/{loader,fat}.h layouts. Bound universal metadata before
// seeking to each slice; no input code is executed or mapped into this process.
fn executable_headers(file: &mut fs::File) -> io::Result<Vec<Architecture>> {
    let length = file.metadata()?.len();
    let mut first = [0; 8];
    file.rewind()?;
    file.read_exact(&mut first)?;
    let (little, wide) = match first[..4] {
        [0xcf, 0xfa, 0xed, 0xfe] | [0xfe, 0xed, 0xfa, 0xcf] => {
            return Ok(vec![executable_slice(file, 0, length, None)?]);
        }
        [0xca, 0xfe, 0xba, 0xbe] => (false, false),
        [0xbe, 0xba, 0xfe, 0xca] => (true, false),
        [0xca, 0xfe, 0xba, 0xbf] => (false, true),
        [0xbf, 0xba, 0xfe, 0xca] => (true, true),
        _ => return Err(invalid_binary()),
    };
    let count = word(&first, 4, little);
    if !(1..=16).contains(&count) {
        return Err(invalid_binary());
    }
    let width = if wide { 32 } else { 20 };
    let table_end = 8 + u64::from(count) * width;
    if table_end > length {
        return Err(invalid_binary());
    }
    let mut ranges = [(0, 0); 16];
    let mut architectures = Vec::new();
    for index in 0..count {
        let mut entry = [0; 32];
        file.seek(SeekFrom::Start(8 + u64::from(index) * width))?;
        file.read_exact(&mut entry[..width as usize])?;
        let (offset, size) = if wide {
            (
                double_word(&entry, 8, little),
                double_word(&entry, 16, little),
            )
        } else {
            (
                u64::from(word(&entry, 8, little)),
                u64::from(word(&entry, 12, little)),
            )
        };
        let end = offset.checked_add(size).ok_or_else(invalid_binary)?;
        if offset < table_end
            || end > length
            || ranges[..index as usize]
                .iter()
                .any(|&(start, stop)| offset < stop && start < end)
        {
            return Err(invalid_binary());
        }
        architectures.push(executable_slice(
            file,
            offset,
            size,
            Some(word(&entry, 0, little)),
        )?);
        ranges[index as usize] = (offset, end);
    }
    Ok(architectures)
}
fn executable_slice(
    file: &mut fs::File,
    offset: u64,
    size: u64,
    cpu: Option<u32>,
) -> io::Result<Architecture> {
    if size < 32 {
        return Err(invalid_binary());
    }
    let mut header = [0; 32];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut header)?;
    let little = match header[..4] {
        [0xcf, 0xfa, 0xed, 0xfe] => true,
        [0xfe, 0xed, 0xfa, 0xcf] => false,
        _ => return Err(invalid_binary()),
    };
    let actual_cpu = word(&header, 4, little);
    if cpu.is_some_and(|cpu| cpu != actual_cpu)
        || word(&header, 12, little) != 2 // MH_EXECUTE, not a dylib/object/core.
        || u64::from(word(&header, 20, little)) + 32 > size
    {
        return Err(invalid_binary());
    }
    match actual_cpu {
        0x0100_0007 => Ok(Architecture::X86_64),
        0x0100_000c => Ok(Architecture::Arm64),
        _ => Err(invalid_binary()),
    }
}
fn word(bytes: &[u8], offset: usize, little: bool) -> u32 {
    let value = [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ];
    if little {
        u32::from_le_bytes(value)
    } else {
        u32::from_be_bytes(value)
    }
}
fn double_word(bytes: &[u8], offset: usize, little: bool) -> u64 {
    let value = [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ];
    if little {
        u64::from_le_bytes(value)
    } else {
        u64::from_be_bytes(value)
    }
}
fn invalid_binary() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "--binary requires complete executable Mach-O headers for x86_64/arm64 macOS slices",
    )
}
