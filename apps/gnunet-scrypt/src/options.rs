use crate::Failure;
use gnunet_config::{Configuration, ProcessEnvironment};
use gnunet_nse::crypto::WorkBits;
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Filename, Target},
};
use std::{path::PathBuf, time::Duration};

pub(super) struct Arguments {
    key: Target<Filename>,
    proof: Target<Filename>,
    bits: Target<u64>,
    delay: Target<u64>,
    total: Target<u64>,
    hashes: Target<u64>,
}
impl Arguments {
    pub fn new() -> Self {
        let empty = || Filename {
            path: None,
            error: None,
        };
        Self {
            key: Target::new(empty()),
            proof: Target::new(empty()),
            bits: Target::new(0),
            delay: Target::new(0),
            total: Target::new(0),
            hashes: Target::new(0),
        }
    }
    pub fn options(&self) -> Options<'static> {
        let mut o = Options::new();
        o.add(helpers::filename(
            b'k',
            b"keyfile",
            b"FILE",
            b"Raw32 Ed25519 initial key file; default [PEER] PRIVATE_KEY",
            self.key.clone(),
        ));
        o.add(helpers::filename(
            b'o',
            b"outfile",
            b"FILE",
            b"Raw8 proof file; default [NSE] PROOFFILE",
            self.proof.clone(),
        ));
        o.add(helpers::ulong(
            b'b',
            b"bits",
            b"BITS",
            b"Required leading zero bits, 0 selects [NSE] WORKBITS",
            self.bits.clone(),
        ));
        o.add(helpers::relative_time(
            b't',
            b"timeout",
            b"DURATION",
            b"Delay between ten-candidate rounds, not a whole timeout",
            self.delay.clone(),
        ));
        o.add(helpers::relative_time(
            0,
            b"total-timeout",
            b"DURATION",
            b"Optional fixed whole operation timeout, zero is unbounded",
            self.total.clone(),
        ));
        o.add(helpers::ulong(
            0,
            b"max-hashes",
            b"COUNT",
            b"Optional total hash bound, zero is unbounded",
            self.hashes.clone(),
        ));
        o
    }
    pub fn select(&self, c: &Configuration, args: &[Vec<u8>]) -> Result<Settings, Failure> {
        if !args.is_empty() {
            return Err(
                "use -o/--outfile FILE; this utility has no positional file operand".into(),
            );
        }
        let path =
            |target: &Target<Filename>, section: &[u8], name: &[u8]| -> Result<PathBuf, Failure> {
                let selected = target.get()?;
                if let Some(error) = selected.error {
                    return Err(Box::new(FilenameFailure(error)));
                }
                let path = match selected.path {
                    Some(path) => path,
                    None => c.get_filename(section, name, &ProcessEnvironment)?,
                };
                if path.as_os_str().is_empty() || path.file_name().is_none() {
                    return Err("key/proof path requires a filename".into());
                }
                Ok(path)
            };
        let key = path(&self.key, b"PEER", b"PRIVATE_KEY")?;
        let proof = path(&self.proof, b"NSE", b"PROOFFILE")?;
        if key == proof {
            return Err("key and proof must be distinct files".into());
        }
        let bits = self.bits.get()?;
        let bits = if bits == 0 {
            c.get_number(b"NSE", b"WORKBITS")?
        } else {
            bits
        };
        let bits = WorkBits::new(u16::try_from(bits).map_err(|_| "WORKBITS must be 0..511")?)?;
        let delay = match self.delay.get()? {
            u64::MAX => Delay::Forever,
            value => Delay::Finite(Duration::from_micros(value)),
        };
        let total = self.total.get()?;
        let lifetime = (total != 0 && total != u64::MAX).then(|| Duration::from_micros(total));
        let max = self.hashes.get()?;
        Ok(Settings {
            key,
            proof,
            bits,
            delay,
            lifetime,
            max_hashes: (max != 0).then_some(max),
        })
    }
}
pub(super) struct Settings {
    pub key: PathBuf,
    pub proof: PathBuf,
    pub bits: WorkBits,
    pub delay: Delay,
    pub lifetime: Option<Duration>,
    pub max_hashes: Option<u64>,
}

pub(super) enum Delay {
    Finite(Duration),
    Forever,
}

#[derive(Debug)]
struct FilenameFailure(std::rc::Rc<gnunet_config::Error>);
impl std::fmt::Display for FilenameFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for FilenameFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}
