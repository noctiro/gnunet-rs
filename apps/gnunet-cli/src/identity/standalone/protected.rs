//! Take sensitive option values before PROGRAM can copy or diagnose argv.

use super::Result;
use gnunet_program_host::getopt::{Argument, Spec};
use std::ffi::OsString;
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
enum Secret {
    Private,
    Read,
    Write,
}

impl Secret {
    fn for_option(short: u8) -> Option<Self> {
        match short {
            b'P' => Some(Self::Private),
            b'R' => Some(Self::Read),
            b'W' => Some(Self::Write),
            _ => None,
        }
    }
}

const PROGRAM_ARGUMENTS: &[(u8, &[u8])] = &[(b'c', b"config"), (b'L', b"log"), (b'l', b"logfile")];

pub(super) struct Value {
    bytes: Zeroizing<Vec<u8>>,
    start: usize,
}

impl Value {
    pub(super) fn payload(&self) -> &[u8] {
        &self.bytes[self.start..]
    }

    pub(super) fn into_payload(self) -> Zeroizing<Vec<u8>> {
        if self.start == 0 {
            return self.bytes;
        }
        Zeroizing::new(self.payload().to_vec())
    }
}

#[derive(Default)]
pub(super) struct Protected {
    pub private: Option<Value>,
    pub read: Option<Value>,
    pub write: Option<Value>,
}

impl Protected {
    pub(super) fn take(argv: &mut [OsString], posix: bool, specs: &[Spec<'_>]) -> Result<Self> {
        let mut protected = Self::default();
        let mut next = None;
        let mut duplicate = false;
        for arg in argv.iter_mut().skip(1) {
            if let Some(required) = next.take() {
                if let Some(secret) = required {
                    duplicate |= protected.replace(arg, secret, 0)?;
                }
                continue;
            }
            let bytes = arg.as_os_str().as_encoded_bytes();
            if bytes == b"--" || posix && (bytes == b"-" || !bytes.starts_with(b"-")) {
                break;
            }
            if let Some((kind, attached)) = required_argument(bytes, specs) {
                match (kind, attached) {
                    (Some(secret), Some(start)) => {
                        duplicate |= protected.replace(arg, secret, start)?
                    }
                    (_, None) => next = Some(kind),
                    (None, Some(_)) => {}
                }
            }
        }
        if duplicate {
            return Err("IDENTITY sensitive option supplied more than once".into());
        }
        Ok(protected)
    }

    fn replace(&mut self, arg: &mut OsString, secret: Secret, start: usize) -> Result<bool> {
        let bytes = Zeroizing::new(std::mem::take(arg).into_encoded_bytes());
        let prefix = std::str::from_utf8(&bytes[..start])?;
        *arg = OsString::from(format!("{prefix}REDACTED"));
        let slot = match secret {
            Secret::Private => &mut self.private,
            Secret::Read => &mut self.read,
            Secret::Write => &mut self.write,
        };
        Ok(slot.replace(Value { bytes, start }).is_some())
    }
}

// The first argument-taking option owns its remaining short cluster or the
// next token. PROGRAM still handles matching, validation and diagnostics.
fn required_argument(bytes: &[u8], specs: &[Spec<'_>]) -> Option<(Option<Secret>, Option<usize>)> {
    let value_options = || {
        specs
            .iter()
            .filter(|spec| spec.argument == Argument::Required)
    };
    if let Some(option) = bytes.strip_prefix(b"--") {
        let equals = option.iter().position(|&byte| byte == b'=');
        let name = &option[..equals.unwrap_or(option.len())];
        if name.is_empty() {
            return None;
        }
        let mut required = value_options()
            .filter(|spec| spec.name.starts_with(name))
            .peekable();
        let matched = required.peek().is_some()
            || PROGRAM_ARGUMENTS
                .iter()
                .any(|(_, full)| full.starts_with(name));
        let sensitive = required.find_map(|spec| Secret::for_option(spec.short));
        return matched.then(|| (sensitive, equals.map(|index| index + 3)));
    }
    for (index, byte) in bytes.strip_prefix(b"-")?.iter().enumerate() {
        if value_options().any(|spec| spec.short == *byte)
            || PROGRAM_ARGUMENTS.iter().any(|(short, _)| short == byte)
        {
            let start = index + 2;
            return Some((
                Secret::for_option(*byte),
                (start < bytes.len()).then_some(start),
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standalone_identity_scrubs_sensitive_options_before_program() -> Result<()> {
        let mut argv = [
            "gnunet-identity",
            "-qPsecret",
            "--read=cipher",
            "-W",
            "plain",
            "-e",
            "-P-public-name",
        ]
        .map(OsString::from);
        let options = super::super::Arguments::new().options();
        let arguments = Protected::take(&mut argv, false, options.specs())?;
        if argv[1] != "-qPREDACTED"
            || argv[2] != "--read=REDACTED"
            || argv[4] != "REDACTED"
            || argv[6] != "-P-public-name"
        {
            return Err("redaction changed public options or retained a sensitive argument".into());
        }
        if arguments.private.ok_or("missing protected key")?.payload() != b"secret"
            || arguments
                .read
                .ok_or("missing protected ciphertext")?
                .payload()
                != b"cipher"
            || arguments
                .write
                .ok_or("missing protected message")?
                .payload()
                != b"plain"
        {
            return Err("the protected fields did not keep their original option payloads".into());
        }
        Ok(())
    }
}
