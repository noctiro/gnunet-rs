//! Complete `pfctl -v -s Interfaces` coverage of the native DNS interface scope.
use std::io;

const MAX_INTERFACES: usize = 4096;
const NAME_BYTES: usize = 15;

struct Interface<'src> {
    name: &'src [u8],
    skipped: bool,
}

pub(super) struct Coverage<'src>(Vec<Interface<'src>>);

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or incomplete PF interface listing",
    )
}

impl<'src> Coverage<'src> {
    pub fn parse(bytes: &'src [u8]) -> io::Result<Self> {
        if bytes.is_empty() || bytes.last() != Some(&b'\n') {
            return Err(invalid());
        }
        let mut interfaces = Vec::new();
        for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
            let (name, skipped) = match line.strip_suffix(b" (skip)") {
                Some(name) => (name, true),
                None => (line, false),
            };
            if name.is_empty()
                || name.len() > NAME_BYTES
                || name.iter().any(|byte| {
                    byte.is_ascii_control()
                        || byte.is_ascii_whitespace()
                        || matches!(byte, b'(' | b')')
                })
                || interfaces.len() == MAX_INTERFACES
            {
                return Err(invalid());
            }
            interfaces.try_reserve(1).map_err(io::Error::other)?;
            interfaces.push(Interface { name, skipped });
        }
        interfaces.sort_unstable_by(|left, right| left.name.cmp(right.name));
        if interfaces
            .windows(2)
            .any(|pair| pair[0].name == pair[1].name)
        {
            return Err(invalid());
        }
        Ok(Self(interfaces))
    }

    pub fn require(&self, name: &[u8]) -> io::Result<()> {
        let position = self
            .0
            .binary_search_by(|interface| interface.name.cmp(name))
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    format!(
                        "native interface {:?} is absent from PF",
                        String::from_utf8_lossy(name)
                    ),
                )
            })?;
        if self.0[position].skipped {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "PF skip bypasses DNS interception on native interface {:?}",
                    String::from_utf8_lossy(name)
                ),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
