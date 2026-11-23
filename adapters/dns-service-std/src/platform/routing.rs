//! The Linux DNS helper's administrator-owned routing selection.
use std::{io, num::NonZeroU32};

pub(super) struct Routing {
    pub(super) table: NonZeroU32,
    pub(super) priority: NonZeroU32,
    pub(super) mark: NonZeroU32,
}

impl Routing {
    fn new(table: u32, priority: u32, mark: u32) -> io::Result<Self> {
        Ok(Self {
            table: NonZeroU32::new(table)
                .filter(|t| !(253..=255).contains(&t.get()) && t.get() != u32::MAX)
                .ok_or_else(|| invalid("TABLE must name an unreserved Linux routing table"))?,
            priority: NonZeroU32::new(priority)
                .filter(|p| p.get() < 32766)
                .ok_or_else(|| invalid("PRIORITY must be between 1 and 32765"))?,
            mark: NonZeroU32::new(mark).ok_or_else(|| invalid("MARK must be nonzero"))?,
        })
    }

    fn standard() -> io::Result<Self> {
        Self::new(53, 1053, 136_708_149)
    }

    fn parse(content: &str) -> io::Result<Self> {
        let (mut table, mut priority, mut mark) = (None, None, None);
        for line in content.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| invalid("expected KEY = NUMBER"))?;
            let (slot, number) = match key.trim() {
                "TABLE" => (&mut table, decimal(value.trim())),
                "PRIORITY" => (&mut priority, decimal(value.trim())),
                "MARK" => (&mut mark, mark_number(value.trim())),
                _ => return Err(invalid("unknown routing key")),
            };
            if slot.is_some() {
                return Err(invalid("duplicate routing key"));
            }
            *slot = Some(number.ok_or_else(|| invalid("invalid routing number"))?);
        }
        Self::new(
            table.ok_or_else(|| invalid("TABLE is required"))?,
            priority.ok_or_else(|| invalid("PRIORITY is required"))?,
            mark.ok_or_else(|| invalid("MARK is required"))?,
        )
    }

    /// Read only the deployment's privileged policy. No caller-supplied path,
    /// environment variable, symlink, or writable ancestor is accepted.
    #[cfg(target_os = "linux")]
    pub(super) fn system() -> io::Result<Self> {
        use gnunet_native::filesystem::Directory;
        use std::{ffi::OsStr, io::Read, os::unix::fs::MetadataExt, path::Path};

        const MAX_BYTES: usize = 4096;
        let root = Directory::open(Path::new("/"))?;
        root.validate_namespace()?;
        let etc = root.open_directory(OsStr::new("etc"))?;
        etc.validate_namespace()?;
        let dir = match etc.open_directory(OsStr::new("gnunet")) {
            Ok(dir) => dir,
            Err(cause) if cause.kind() == io::ErrorKind::NotFound => return Self::standard(),
            Err(cause) => return Err(cause),
        };
        dir.validate_namespace()?;
        let file = match dir.open_file(OsStr::new("dns-routing.conf")) {
            Ok(file) => file,
            Err(cause) if cause.kind() == io::ErrorKind::NotFound => return Self::standard(),
            Err(cause) => return Err(cause),
        };
        let meta = file.metadata()?;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "DNS routing policy must be root-owned and not writable by group or others",
            ));
        }
        let mut bytes = Vec::new();
        file.take((MAX_BYTES + 1) as u64).read_to_end(&mut bytes)?;
        if bytes.len() > MAX_BYTES {
            return Err(invalid("routing policy exceeds 4096 bytes"));
        }
        let content = std::str::from_utf8(&bytes).map_err(|_| invalid("expected UTF-8"))?;
        Self::parse(content)
    }
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("/etc/gnunet/dns-routing.conf: {reason}"),
    )
}

fn decimal(number: &str) -> Option<u32> {
    if number.bytes().all(|b| b.is_ascii_digit()) {
        number.parse().ok()
    } else {
        None
    }
}

fn mark_number(number: &str) -> Option<u32> {
    if let Some(hex) = number.strip_prefix("0x") {
        if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        u32::from_str_radix(hex, 16).ok()
    } else {
        decimal(number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_routing_is_explicit_and_cannot_use_builtin_tables() -> io::Result<()> {
        let standard = Routing::standard()?;
        let configured =
            Routing::parse("# private routing\nTABLE = 300\nPRIORITY=2000\nMARK=0x101")?;
        if (
            standard.table.get(),
            standard.priority.get(),
            standard.mark.get(),
        ) != (53, 1053, 136_708_149)
            || (
                configured.table.get(),
                configured.priority.get(),
                configured.mark.get(),
            ) != (300, 2000, 257)
        {
            return Err(io::Error::other("managed DNS routing values changed"));
        }
        for bad in [
            "TABLE=254\nPRIORITY=1\nMARK=1",
            "TABLE=53\nPRIORITY=32766\nMARK=1",
            "TABLE=53\nPRIORITY=1053\nMARK=0",
            "TABLE=53\nTABLE=300\nPRIORITY=1\nMARK=1",
            "TABLE=53\nPRIORITY=1053",
        ] {
            if Routing::parse(bad).is_ok() {
                return Err(io::Error::other("invalid managed DNS routing was admitted"));
            }
        }
        Ok(())
    }
}
